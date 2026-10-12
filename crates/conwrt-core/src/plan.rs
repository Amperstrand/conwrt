//! Minimal desired-state planning slice (#113): observed state + model facts
//! + one desired-state profile → a typed, inspectable, I/O-free plan.
//!
//! Planning is a **pure function** — no provider, no probes, no mutation.
//! The apply/verify executor (M7 proper) later renders the same `PlanOp`s to
//! shell or ubus, mirroring conwrt 1.x's typed ops pipeline
//! (`scripts/profile/ops.py`). The dry-run purity of this slice is proven by
//! the call-recording `MockProber`: planning after a diagnosis leaves the
//! capability journal untouched.
//!
//! Safety invariant: the planner only emits configuration plans for devices
//! whose OpenWrt identity is **confirmed** (`DeviceState::OpenWrt` requires
//! positive HTTP fingerprints, not just an SSH banner — see `state.rs`).
//! `SshOnly`/`StockVendor`/`Unknown` are rejected: firmware identity is a
//! hard precondition for configuring a device (AGENTS.md identity gates).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::state::DeviceState;
use conwrt_types::DeviceModel;

/// Smart Queue Management (CAKE/fq_codel) — port of the tested 1.x `sqm`
/// use case (`scripts/use_cases/sqm.py`, verified on OpenWrt 24.10.2 QEMU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqmProfile {
    /// Download shaper rate in Kbit/s (85–95% of the measured rate).
    pub download_kbps: u32,
    /// Upload shaper rate in Kbit/s (85–95% of the measured rate).
    pub upload_kbps: u32,
    /// UCI network name to shape (resolved to the real device at apply time).
    pub interface: String,
    /// Queue discipline: `cake` or `fq_codel`.
    pub qdisc: String,
    /// sqm-scripts qos script (e.g. `piece_of_cake.qos`, `layer_cake.qos`).
    pub script: String,
    /// Link-layer adaptation: `none`, `ethernet`, `atm`.
    pub link_layer: String,
    /// Per-packet overhead in bytes (0–512).
    pub overhead: u16,
}

impl SqmProfile {
    /// Parameter bounds mirrored from the 1.x `shell_safe` validators.
    pub fn validate(&self) -> Result<(), Unsupported> {
        if self.download_kbps == 0 {
            return Err(Unsupported::InvalidParams(
                "download_kbps must be ≥ 1".into(),
            ));
        }
        if self.upload_kbps == 0 {
            return Err(Unsupported::InvalidParams("upload_kbps must be ≥ 1".into()));
        }
        if self.overhead > 512 {
            return Err(Unsupported::InvalidParams("overhead must be 0–512".into()));
        }
        if self.interface.is_empty()
            || !self
                .interface
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Unsupported::InvalidParams(
                "interface must be a plain UCI network name (e.g. `wan`)".into(),
            ));
        }
        Ok(())
    }
}

/// A desired-state profile: the outcome wanted, never the steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    /// Eliminate bufferbloat with SQM.
    Sqm(SqmProfile),
}

impl Profile {
    /// Stable profile identifier (matches 1.x use-case names).
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Profile::Sqm(_) => "sqm",
        }
    }

    /// Hardware capability tags the target model must declare (species-level,
    /// from `models/*.json` `capabilities`). SQM is pure software shaping —
    /// no requirements.
    #[must_use]
    pub fn requires(&self) -> &'static [&'static str] {
        match self {
            Profile::Sqm(_) => &[],
        }
    }
}

/// SysV init/service action (renders to `/etc/init.d/<name> <action>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    /// Enable at boot.
    Enable,
    /// (Re)start now.
    Restart,
}

impl fmt::Display for ServiceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceAction::Enable => write!(f, "enable"),
            ServiceAction::Restart => write!(f, "restart"),
        }
    }
}

/// A UCI option value: a literal, or a value the executor must resolve on
/// the device at apply time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UciValue {
    /// Fixed string, safe for single-quoted `uci set`.
    Literal(String),
    /// The Linux network device resolved from a UCI network name at apply
    /// time (direct device, else the default-route interface, else the name
    /// itself) — the 1.x `wan → phy1-sta0` resolution, kept out of the plan
    /// so plans stay device-independent.
    ResolvedDevice,
}

impl fmt::Display for UciValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UciValue::Literal(v) => write!(f, "{v}"),
            UciValue::ResolvedDevice => write!(f, "<resolved-device>"),
        }
    }
}

/// One typed, inspectable plan step. Rendered to shell/ubus by the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanOp {
    /// Install a package if missing (opkg/apk).
    EnsurePackage {
        /// opkg/apk package name.
        name: String,
    },
    /// Delete every section of a type in a UCI config (idempotent
    /// reconfigure).
    ClearUciSections {
        /// UCI config name (file), e.g. `sqm`.
        config: String,
        /// Section type to clear, e.g. `queue`.
        section_type: String,
    },
    /// Resolve the Linux device behind a UCI network name at apply time.
    ResolveNetworkDevice {
        /// UCI network name, e.g. `wan`.
        network: String,
    },
    /// Create/replace one UCI section with ordered options.
    SetUciSection {
        /// UCI config name.
        config: String,
        /// Section name.
        section: String,
        /// Section type.
        section_type: String,
        /// Ordered `(option, value)` pairs.
        options: Vec<(String, UciValue)>,
    },
    /// Persist a UCI config (`uci commit`).
    CommitUci {
        /// UCI config name.
        config: String,
    },
    /// Service management (`/etc/init.d/<name> <action>`).
    Service {
        /// Init script name.
        name: String,
        /// What to do with it.
        action: ServiceAction,
    },
}

impl fmt::Display for PlanOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanOp::EnsurePackage { name } => write!(f, "install package {name}"),
            PlanOp::ClearUciSections {
                config,
                section_type,
            } => write!(f, "clear uci {config}.{section_type} sections"),
            PlanOp::ResolveNetworkDevice { network } => {
                write!(f, "resolve device for network {network}")
            }
            PlanOp::SetUciSection {
                config,
                section,
                section_type,
                options,
            } => {
                write!(f, "uci {config}.{section}={section_type}")?;
                for (option, value) in options {
                    write!(f, "\n  {config}.{section}.{option}={value}")?;
                }
                Ok(())
            }
            PlanOp::CommitUci { config } => write!(f, "uci commit {config}"),
            PlanOp::Service { name, action } => write!(f, "service {name} {action}"),
        }
    }
}

/// How the executor will verify the plan took effect (intent, run later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationCheck {
    /// Human description of what is being checked.
    pub description: String,
    /// Read-only command to run on the device.
    pub command: String,
    /// Substring the output must contain.
    pub expect_contains: String,
}

/// A planned transition: what to do, and how to prove it worked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Profile that produced this plan.
    pub profile_id: String,
    /// Model the plan was built for.
    pub model_id: String,
    /// Ordered steps (packages before config, config before services).
    pub ops: Vec<PlanOp>,
    /// Post-apply verification, all of which must pass.
    pub verification: Vec<VerificationCheck>,
}

/// Why a profile cannot be planned for this device/model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsupported {
    /// Device state does not carry a **confirmed** OpenWrt identity
    /// (e.g. `SshOnly` — SSH answered, OS unconfirmed). Never plan
    /// configuration onto an unconfirmed device.
    UnconfirmedDeviceState(DeviceState),
    /// The model lacks a hardware capability the profile requires.
    MissingCapability {
        /// Model that was checked.
        model: String,
        /// Capability tag that is absent.
        capability: String,
    },
    /// Profile parameters failed validation (bounds ported from 1.x).
    InvalidParams(String),
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unsupported::UnconfirmedDeviceState(state) => write!(
                f,
                "device state `{}` does not confirm OpenWrt identity; refusing to plan",
                state.as_str()
            ),
            Unsupported::MissingCapability { model, capability } => {
                write!(f, "model {model} lacks required capability `{capability}`")
            }
            Unsupported::InvalidParams(why) => write!(f, "invalid profile parameters: {why}"),
        }
    }
}

/// Check a model's declared capability tags against a profile's requirements.
fn capabilities_satisfied(model: &DeviceModel, required: &[&str]) -> Result<(), Unsupported> {
    let tags = model.capability_tags();
    for required_tag in required {
        if !tags.iter().any(|tag| tag == required_tag) {
            return Err(Unsupported::MissingCapability {
                model: model.id.clone(),
                capability: (*required_tag).to_string(),
            });
        }
    }
    Ok(())
}

/// Plan the operations to reach a profile's desired state.
///
/// Pure: consumes the already-classified state, model facts, and the profile;
/// performs no I/O and touches no provider.
pub fn plan_profile(
    state: &DeviceState,
    model: &DeviceModel,
    profile: &Profile,
) -> Result<Plan, Unsupported> {
    if *state != DeviceState::OpenWrt {
        return Err(Unsupported::UnconfirmedDeviceState(*state));
    }
    capabilities_satisfied(model, profile.requires())?;
    match profile {
        Profile::Sqm(sqm) => plan_sqm(model, sqm),
    }
}

fn plan_sqm(model: &DeviceModel, sqm: &SqmProfile) -> Result<Plan, Unsupported> {
    sqm.validate()?;
    let iface = &sqm.interface;
    let literal = |v: String| UciValue::Literal(v);
    let ops = vec![
        PlanOp::EnsurePackage {
            name: "sqm-scripts".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-sqm".into(),
        },
        PlanOp::ClearUciSections {
            config: "sqm".into(),
            section_type: "queue".into(),
        },
        PlanOp::ResolveNetworkDevice {
            network: iface.clone(),
        },
        PlanOp::SetUciSection {
            config: "sqm".into(),
            section: iface.clone(),
            section_type: "queue".into(),
            options: vec![
                ("enabled".into(), literal("1".into())),
                // actual device, not the UCI network name (1.x lesson)
                ("interface".into(), UciValue::ResolvedDevice),
                ("script".into(), literal(sqm.script.clone())),
                ("qdisc".into(), literal(sqm.qdisc.clone())),
                ("linklayer".into(), literal(sqm.link_layer.clone())),
                ("overhead".into(), literal(sqm.overhead.to_string())),
                ("download".into(), literal(sqm.download_kbps.to_string())),
                ("upload".into(), literal(sqm.upload_kbps.to_string())),
                (
                    "linklayer_adaptation_mechanism".into(),
                    literal("default".into()),
                ),
                ("debug_logging".into(), literal("0".into())),
                ("verbosity".into(), literal("5".into())),
            ],
        },
        PlanOp::CommitUci {
            config: "sqm".into(),
        },
        PlanOp::Service {
            name: "sqm".into(),
            action: ServiceAction::Enable,
        },
        PlanOp::Service {
            name: "sqm".into(),
            action: ServiceAction::Restart,
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "shaper rates persisted".into(),
            command: format!("uci -q get sqm.{iface}.download"),
            expect_contains: sqm.download_kbps.to_string(),
        },
        VerificationCheck {
            description: "qdisc active on the device".into(),
            command: "tc qdisc show".into(),
            expect_contains: sqm.qdisc.clone(),
        },
        VerificationCheck {
            description: "service enabled at boot".into(),
            command: "/etc/init.d/sqm enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "sqm".into(),
        model_id: model.id.clone(),
        ops,
        verification,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_with_capabilities(caps: Option<Vec<String>>) -> DeviceModel {
        let caps_json = caps.map(|c| {
            let list: Vec<String> = c.iter().map(|c| format!("\"{c}\"")).collect();
            format!(", \"capabilities\": [{}]", list.join(", "))
        });
        let json = format!(
            "{{\"id\":\"test-model\",\"vendor\":\"Test\",\"description\":\"d\",\
              \"openwrt\":{{\"target\":\"x/y\",\"device\":\"t,d\",\"profile\":\"t_d\",\"version\":\"24\"}},\
              \"mac_oui\":[]{}}}",
            caps_json.unwrap_or_default()
        );
        serde_json::from_str(&json).expect("fixture model parses")
    }

    fn sqm() -> SqmProfile {
        SqmProfile {
            download_kbps: 340_000,
            upload_kbps: 19_000,
            interface: "wan".into(),
            qdisc: "cake".into(),
            script: "piece_of_cake.qos".into(),
            link_layer: "none".into(),
            overhead: 0,
        }
    }

    #[test]
    fn capabilities_gate_rejects_missing_tag() {
        let model = model_with_capabilities(Some(vec!["ethernet".into()]));
        assert!(capabilities_satisfied(&model, &["usb"]).is_err());
        let full = model_with_capabilities(Some(vec!["ethernet".into(), "usb".into()]));
        assert!(capabilities_satisfied(&full, &["usb"]).is_ok());
        let none = model_with_capabilities(None);
        assert!(capabilities_satisfied(&none, &[]).is_ok());
    }

    #[test]
    fn param_bounds_match_1x() {
        assert!(sqm().validate().is_ok());
        assert!(matches!(
            SqmProfile {
                download_kbps: 0,
                ..sqm()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            SqmProfile {
                upload_kbps: 0,
                ..sqm()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            SqmProfile {
                overhead: 513,
                ..sqm()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
        assert!(matches!(
            SqmProfile {
                interface: "eth0; rm -rf /".into(),
                ..sqm()
            }
            .validate(),
            Err(Unsupported::InvalidParams(_))
        ));
    }
}
