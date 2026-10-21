//! Scripted, call-recording mocks for the MAAS lab components
//! (the ADR-0003 mock pattern: full fidelity of the SEAM, zero I/O).
//!
//! - [`MockBlockWriter`]: an in-memory disk that records the pipeline's
//!   call order and can be made to fail or corrupt at any gate.
//! - [`MockMaas`]: an in-memory MAAS region whose machines advance one
//!   lifecycle step per poll (the commission/deploy/release cadence),
//!   with an optional stuck machine for timeout tests.
//! - [`NoTime`]: a [`conwrt_core::Time`] that returns immediately and
//!   records the total slept milliseconds.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use conwrt_core::Time;

use crate::flash::{BlockWriter, CloudInitSeed};
use crate::provider::{MaasClient, MachineRecord, MachineState, VmSpec};

/// Immediate time source; records total slept ms for poll-bound asserts.
#[derive(Debug, Default)]
pub struct NoTime {
    /// Sum of every `sleep_ms` argument.
    pub total_ms: u64,
}

impl Time for NoTime {
    async fn sleep_ms(&mut self, ms: u64) {
        self.total_ms += ms;
    }
}

/// In-memory disk for [`crate::flash::execute_flash`] tests.
#[derive(Debug, Default)]
pub struct MockBlockWriter {
    /// Call order, e.g. `["write_image", "read_back", ...]`.
    pub calls: Vec<&'static str>,
    /// Bytes currently "on disk".
    pub disk: Vec<u8>,
    /// Seed the writer received, if any.
    pub seed: Option<CloudInitSeed>,
    /// Fail the next matching call with this message (gate by name).
    pub fail_at: Option<&'static str>,
    /// `read_back` returns zeroed bytes (checksum-gate corruption path).
    pub corrupt_readback: bool,
}

impl MockBlockWriter {
    /// Empty recording disk.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn gate(&mut self, name: &'static str) -> Result<(), String> {
        self.calls.push(name);
        match self.fail_at {
            Some(f) if f == name => Err(format!("{name}: simulated failure")),
            _ => Ok(()),
        }
    }
}

impl BlockWriter for MockBlockWriter {
    type Error = String;

    async fn write_image(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.gate("write_image")?;
        self.disk.clear();
        self.disk.extend_from_slice(image);
        Ok(())
    }

    async fn read_back(&mut self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.gate("read_back")?;
        let mut data = self.disk.iter().take(len).copied().collect::<Vec<_>>();
        if self.corrupt_readback {
            data.fill(0);
        }
        Ok(data)
    }

    async fn grow_partition(&mut self) -> Result<(), Self::Error> {
        self.gate("grow_partition")
    }

    async fn write_seed(&mut self, seed: &CloudInitSeed) -> Result<(), Self::Error> {
        self.gate("write_seed")?;
        self.seed = Some(seed.clone());
        Ok(())
    }
}

/// In-memory MAAS region: machines advance one lifecycle step per
/// `machine()` poll, mirroring the real commission/deploy/release cadence.
#[derive(Debug, Default)]
pub struct MockMaas {
    /// Machines the region currently knows.
    pub machines: Vec<MachineRecord>,
    /// Call log (`"compose sys-1"`, `"machine sys-1"`, ...).
    pub calls: Vec<String>,
    /// system_ids that never advance (timeout tests).
    pub stuck: Vec<String>,
    next_id: usize,
}

impl MockMaas {
    /// Empty region.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&mut self, op: &str, id: &str) {
        self.calls.push(format!("{op} {id}"));
    }

    fn tick(state: &MachineState) -> MachineState {
        match state {
            MachineState::New => MachineState::Commissioning,
            MachineState::Commissioning => MachineState::Ready,
            MachineState::Deploying => MachineState::Deployed,
            MachineState::Releasing => MachineState::Ready,
            other => other.clone(),
        }
    }
}

impl MaasClient for MockMaas {
    type Error = String;

    async fn compose(&mut self, spec: &VmSpec) -> Result<MachineRecord, Self::Error> {
        self.next_id += 1;
        let rec = MachineRecord {
            system_id: format!("sys-{}", self.next_id),
            hostname: spec.name.clone(),
            state: MachineState::New,
        };
        self.record("compose", &rec.system_id);
        self.machines.push(rec.clone());
        Ok(rec)
    }

    async fn machines(&mut self) -> Result<Vec<MachineRecord>, Self::Error> {
        self.calls.push("machines".to_string());
        Ok(self.machines.clone())
    }

    async fn machine(&mut self, system_id: &str) -> Result<MachineRecord, Self::Error> {
        self.record("machine", system_id);
        let rec = self
            .machines
            .iter_mut()
            .find(|m| m.system_id == system_id)
            .ok_or_else(|| format!("404: {system_id} not found"))?;
        if !self.stuck.iter().any(|s| s == system_id) {
            rec.state = Self::tick(&rec.state);
        }
        Ok(rec.clone())
    }

    async fn allocate(&mut self, system_id: &str) -> Result<(), Self::Error> {
        self.record("allocate", system_id);
        if let Some(m) = self.machines.iter_mut().find(|m| m.system_id == system_id) {
            if !m.state.can_allocate() {
                return Err(format!("cannot allocate {} in {}", m.system_id, m.state));
            }
            m.state = MachineState::Allocating;
        }
        Ok(())
    }

    async fn deploy(&mut self, system_id: &str) -> Result<(), Self::Error> {
        self.record("deploy", system_id);
        if let Some(m) = self.machines.iter_mut().find(|m| m.system_id == system_id) {
            m.state = MachineState::Deploying;
        }
        Ok(())
    }

    async fn release(&mut self, system_id: &str) -> Result<(), Self::Error> {
        self.record("release", system_id);
        if let Some(m) = self.machines.iter_mut().find(|m| m.system_id == system_id) {
            if m.state.can_allocate() {
                return Ok(()); // already in the pool; releasing is a no-op
            }
            m.state = MachineState::Releasing;
        }
        Ok(())
    }

    async fn delete(&mut self, system_id: &str) -> Result<(), Self::Error> {
        self.record("delete", system_id);
        self.machines.retain(|m| m.system_id != system_id);
        Ok(())
    }
}
