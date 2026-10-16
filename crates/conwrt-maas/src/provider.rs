//! MaasProvider (issue #169, milestones M5): programmatic VM lifecycle.
//!
//! The compute interface `shc-compute create/list/describe/destroy` maps
//! onto MAAS's machine lifecycle: **compose** (VM host creates a machine)
//! → commission to **Ready** → **allocate** → **deploy** → **Deployed**;
//! destroy = **release** (back to Ready) → **delete**. The typed state
//! machine ([`MachineState`]) rejects operations their state does not
//! allow; the MAAS API itself is never contacted directly — everything
//! goes through the [`MaasClient`] seam, so unit tests run against
//! [`crate::mock::MockMaas`] and a live region is only needed for the
//! integration-test milestone (owner-gated).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use conwrt_core::Time;

/// MAAS machine lifecycle state (the statuses the region API reports as
/// `status_name`). Unknown/future statuses parse to [`MachineState::Other`]
/// instead of failing, so a MAAS upgrade degrades queries, not workflows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineState {
    /// Newly enlisted/composed, not yet commissioned.
    New,
    /// Running commissioning.
    Commissioning,
    /// Commissioned, tested, available for allocation.
    Ready,
    /// Allocation in progress.
    Allocating,
    /// Deployment in progress.
    Deploying,
    /// Deployed and running.
    Deployed,
    /// Release in progress.
    Releasing,
    /// Enlisted but not seen on the network.
    Missing,
    /// Marked broken by an operator.
    Broken,
    /// Operator hold.
    Maintenance,
    /// Removed from MAAS.
    Retired,
    /// Commissioning failed.
    FailedCommissioning,
    /// Testing failed.
    FailedTesting,
    /// Deployment failed.
    FailedDeployment,
    /// A status this version does not model.
    Other(String),
}

impl MachineState {
    /// Whether the machine can be allocated (the pool state).
    #[must_use]
    pub fn can_allocate(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Whether the machine is running a deployed workload.
    #[must_use]
    pub fn is_deployed(&self) -> bool {
        matches!(self, Self::Deployed)
    }

    /// Whether the machine is in any failed/broken state.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(
            self,
            Self::FailedCommissioning | Self::FailedTesting | Self::FailedDeployment | Self::Broken
        )
    }
}

impl fmt::Display for MachineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::New => f.write_str("New"),
            Self::Commissioning => f.write_str("Commissioning"),
            Self::Ready => f.write_str("Ready"),
            Self::Allocating => f.write_str("Allocating"),
            Self::Deploying => f.write_str("Deploying"),
            Self::Deployed => f.write_str("Deployed"),
            Self::Releasing => f.write_str("Releasing"),
            Self::Missing => f.write_str("Missing"),
            Self::Broken => f.write_str("Broken"),
            Self::Maintenance => f.write_str("Maintenance"),
            Self::Retired => f.write_str("Retired"),
            Self::FailedCommissioning => f.write_str("Failed commissioning"),
            Self::FailedTesting => f.write_str("Failed testing"),
            Self::FailedDeployment => f.write_str("Failed deployment"),
            Self::Other(s) => write!(f, "Other({s})"),
        }
    }
}

impl FromStr for MachineState {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "New" => Self::New,
            "Commissioning" => Self::Commissioning,
            "Ready" => Self::Ready,
            "Allocating" => Self::Allocating,
            "Deploying" => Self::Deploying,
            "Deployed" => Self::Deployed,
            "Releasing" => Self::Releasing,
            "Missing" => Self::Missing,
            "Broken" => Self::Broken,
            "Maintenance" => Self::Maintenance,
            "Retired" => Self::Retired,
            "Failed commissioning" => Self::FailedCommissioning,
            "Failed testing" => Self::FailedTesting,
            "Failed deployment" => Self::FailedDeployment,
            other => Self::Other(other.to_string()),
        })
    }
}

/// A machine as the MAAS API reports it (the fields the provider needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineRecord {
    /// MAAS system_id (the stable handle for every API call).
    pub system_id: String,
    /// Hostname MAAS assigned.
    pub hostname: String,
    /// Lifecycle state.
    pub state: MachineState,
}

/// A VM to compose (milestones M3 test shape: 2 vCPU / 2 GiB / 20 GiB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmSpec {
    /// Instance hostname (plain DNS label).
    pub name: String,
    /// Virtual CPUs.
    pub cores: u16,
    /// Memory in MiB.
    pub memory_mib: u32,
    /// Root disk in GiB.
    pub disk_gib: u32,
}

impl VmSpec {
    /// Validate against the lab's compose bounds. Mirrors the shc-toolkit
    /// parameter discipline: reject early, never at the API.
    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.name.is_empty()
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ComputeError::InvalidSpec(
                "name must be a non-empty DNS label (alphanumeric or '-')".into(),
            ));
        }
        if !(1..=64).contains(&self.cores) {
            return Err(ComputeError::InvalidSpec("cores must be 1-64".into()));
        }
        if self.memory_mib < 256 || self.memory_mib > 1 << 20 {
            return Err(ComputeError::InvalidSpec(
                "memory_mib must be 256-1048576".into(),
            ));
        }
        if self.disk_gib == 0 || self.disk_gib > 4096 {
            return Err(ComputeError::InvalidSpec("disk_gib must be 1-4096".into()));
        }
        Ok(())
    }
}

/// A VM as the compute interface reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmInfo {
    /// MAAS system_id.
    pub system_id: String,
    /// Hostname.
    pub hostname: String,
    /// Lifecycle state.
    pub state: MachineState,
}

/// The MAAS API seam. Every method is one region-API call shape; the
/// provider owns polling, ordering, and state gating. Implementations:
/// a future HTTP client (live validation, owner-gated) and
/// [`crate::mock::MockMaas`] (tests).
pub trait MaasClient {
    /// Client-specific error detail.
    type Error: fmt::Display;

    /// Compose a VM on a VM host; returns the new machine (state `New`).
    async fn compose(&mut self, spec: &VmSpec) -> Result<MachineRecord, Self::Error>;

    /// All machines the region knows.
    async fn machines(&mut self) -> Result<Vec<MachineRecord>, Self::Error>;

    /// One machine by system_id.
    async fn machine(&mut self, system_id: &str) -> Result<MachineRecord, Self::Error>;

    /// Allocate a Ready machine (reserves it for deployment).
    async fn allocate(&mut self, system_id: &str) -> Result<(), Self::Error>;

    /// Deploy an allocated machine.
    async fn deploy(&mut self, system_id: &str) -> Result<(), Self::Error>;

    /// Release a deployed machine back to the Ready pool.
    async fn release(&mut self, system_id: &str) -> Result<(), Self::Error>;

    /// Delete a machine from MAAS entirely.
    async fn delete(&mut self, system_id: &str) -> Result<(), Self::Error>;
}

/// Failures of the compute lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputeError {
    /// The spec failed validation (nothing was sent to MAAS).
    InvalidSpec(String),
    /// A client call failed; its `Display` text is preserved.
    Client(String),
    /// A machine never reached the state an operation needs.
    NeverReached {
        /// The state that was being awaited.
        wanted: &'static str,
        /// The machine being awaited.
        system_id: String,
        /// Poll attempts made before giving up.
        polls: u32,
    },
    /// The operation is illegal in the machine's current state.
    WrongState {
        /// What was attempted.
        operation: &'static str,
        /// The machine's system_id.
        system_id: String,
        /// The state that blocked it.
        state: MachineState,
    },
}

impl fmt::Display for ComputeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpec(m) => write!(f, "invalid VM spec: {m}"),
            Self::Client(e) => write!(f, "MAAS client error: {e}"),
            Self::NeverReached {
                wanted,
                system_id,
                polls,
            } => write!(
                f,
                "machine {system_id} never reached {wanted} after {polls} polls"
            ),
            Self::WrongState {
                operation,
                system_id,
                state,
            } => write!(f, "cannot {operation} machine {system_id} in state {state}"),
        }
    }
}

impl core::error::Error for ComputeError {}

/// The compute interface (M5): what `shc-compute` exposes, provider-neutral.
pub trait ComputeProvider {
    /// Provider-specific error detail.
    type Error: fmt::Display;

    /// Compose, commission, allocate, and deploy a VM; resolves when
    /// `Deployed`.
    async fn create_vm(&mut self, spec: &VmSpec) -> Result<VmInfo, Self::Error>;

    /// All VMs (machines) the provider knows.
    async fn list_vms(&mut self) -> Result<Vec<VmInfo>, Self::Error>;

    /// One VM by system_id.
    async fn describe_vm(&mut self, system_id: &str) -> Result<VmInfo, Self::Error>;

    /// Release and delete a VM; resolves when it is gone from MAAS.
    async fn destroy_vm(&mut self, system_id: &str) -> Result<(), Self::Error>;
}

/// The MAAS-backed [`ComputeProvider`]: one client + one time source,
/// with bounded polling between lifecycle steps.
pub struct MaasProvider<C: MaasClient, T: Time> {
    client: C,
    time: T,
    poll_ms: u64,
    max_polls: u32,
}

impl<C: MaasClient, T: Time> MaasProvider<C, T> {
    /// Provider over `client`, pacing polls with `time`.
    #[must_use]
    pub fn new(client: C, time: T) -> Self {
        Self {
            client,
            time,
            poll_ms: 1000,
            max_polls: 60,
        }
    }

    /// Builder: override poll interval and attempt bound.
    #[must_use]
    pub fn with_polling(mut self, poll_ms: u64, max_polls: u32) -> Self {
        self.poll_ms = poll_ms;
        self.max_polls = max_polls;
        self
    }

    /// The wrapped client (call-log inspection in tests; retry tooling
    /// in hosts).
    #[must_use]
    pub fn client(&self) -> &C {
        &self.client
    }

    async fn await_state(
        &mut self,
        system_id: &str,
        wanted: &'static str,
        pred: fn(&MachineState) -> bool,
    ) -> Result<MachineRecord, ComputeError> {
        let mut polls = 0u32;
        loop {
            let m = self
                .client
                .machine(system_id)
                .await
                .map_err(|e| ComputeError::Client(e.to_string()))?;
            if pred(&m.state) {
                return Ok(m);
            }
            if m.state.is_failed() {
                return Err(ComputeError::WrongState {
                    operation: "await",
                    system_id: system_id.into(),
                    state: m.state,
                });
            }
            polls += 1;
            if polls >= self.max_polls {
                return Err(ComputeError::NeverReached {
                    wanted,
                    system_id: system_id.into(),
                    polls,
                });
            }
            self.time.sleep_ms(self.poll_ms).await;
        }
    }
}

impl<C: MaasClient, T: Time> ComputeProvider for MaasProvider<C, T> {
    type Error = ComputeError;

    async fn create_vm(&mut self, spec: &VmSpec) -> Result<VmInfo, Self::Error> {
        spec.validate()?;
        let created = self
            .client
            .compose(spec)
            .await
            .map_err(|e| ComputeError::Client(e.to_string()))?;
        let ready = self
            .await_state(&created.system_id, "Ready", MachineState::can_allocate)
            .await?;
        self.client
            .allocate(&ready.system_id)
            .await
            .map_err(|e| ComputeError::Client(e.to_string()))?;
        self.client
            .deploy(&ready.system_id)
            .await
            .map_err(|e| ComputeError::Client(e.to_string()))?;
        let deployed = self
            .await_state(&ready.system_id, "Deployed", MachineState::is_deployed)
            .await?;
        Ok(VmInfo {
            system_id: deployed.system_id,
            hostname: deployed.hostname,
            state: deployed.state,
        })
    }

    async fn list_vms(&mut self) -> Result<Vec<VmInfo>, Self::Error> {
        let machines = self
            .client
            .machines()
            .await
            .map_err(|e| ComputeError::Client(e.to_string()))?;
        Ok(machines
            .into_iter()
            .map(|m| VmInfo {
                system_id: m.system_id,
                hostname: m.hostname,
                state: m.state,
            })
            .collect())
    }

    async fn describe_vm(&mut self, system_id: &str) -> Result<VmInfo, Self::Error> {
        let m = self
            .client
            .machine(system_id)
            .await
            .map_err(|e| ComputeError::Client(e.to_string()))?;
        Ok(VmInfo {
            system_id: m.system_id,
            hostname: m.hostname,
            state: m.state,
        })
    }

    async fn destroy_vm(&mut self, system_id: &str) -> Result<(), Self::Error> {
        let m = self
            .client
            .machine(system_id)
            .await
            .map_err(|e| ComputeError::Client(e.to_string()))?;
        if !m.state.can_allocate() {
            self.client
                .release(system_id)
                .await
                .map_err(|e| ComputeError::Client(e.to_string()))?;
            self.await_state(system_id, "Ready", MachineState::can_allocate)
                .await?;
        }
        self.client
            .delete(system_id)
            .await
            .map_err(|e| ComputeError::Client(e.to_string()))?;
        Ok(())
    }
}
