//! # conwrt-core
//!
//! The portable conwrt engine core (Tier-A, ADR-0002): capability traits,
//! device-state classification, model identification, and workflows —
//! written once, runnable against any provider (local std, remote agent,
//! MCU, labgrid, mock). The engine contains no platform code and no
//! flashing policy beyond safety gates.
//!
//! Milestone M1 ships the diagnostic vertical slice: [`capability::LinkProbe`]
//! → [`state::classify`] → [`diagnose`](fn@diagnose), plus MAC→model
//! identification over [`conwrt_types::DeviceModel`] data.
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// AFIT is a deliberate choice (ADR-0003): executor-agnostic capability
// traits usable from both embassy and tokio without a runtime trait
// dependency. Send bounds are added at the provider/erasure layer if the
// remote-agent client ever needs them (M3).
#![allow(async_fn_in_trait)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub mod capability;
pub mod fingerprint;
pub mod identify;
pub mod mock;
pub mod plan;
pub mod ssh;
pub mod state;
// Cross-implementation parity harness (Rust half); see
// tests/test_parity_rust_plan.py for the Python half.
#[cfg(any(test, feature = "parity-fixture"))]
pub mod parity;

pub use capability::{HttpProbeResult, LinkProbe, ProbeError, SshBanner, Time};
pub use fingerprint::{FingerprintReport, OpenwrtRelease, confirm, parse_openwrt_release};
pub use identify::{MatchKind, ModelMatch, identify_by_mac};
pub use mock::MockProber;
pub use plan::{
    Plan, PlanOp, Profile, ServiceAction, SqmProfile, UciValue, Unsupported, VerificationCheck,
    plan_profile, plan_profile_for_device, render_shell,
};
pub use ssh::{
    HostKeyView, MemoryTrustStore, Refusal, RefusalReason, TrustDecision, TrustMode, TrustedHow,
    evaluate_host_key,
};
pub use state::{DeviceState, ProbeEvidence};

use conwrt_types::DeviceModel;
use core::net::IpAddr;

/// A read-only diagnostic pass over one target address.
///
/// Gathers probe evidence through the [`LinkProbe`] capability, classifies
/// the device state (pure function over the evidence), and attaches
/// MAC-based model candidates when the registry provides them.
#[derive(Debug, Clone, PartialEq)]
pub struct Diagnosis {
    /// The address that was probed.
    pub ip: IpAddr,
    /// Link-layer MAC observed for the target, if any.
    pub mac: Option<conwrt_types::MacAddress>,
    /// The classified device state.
    pub state: DeviceState,
    /// The raw evidence the classification is based on (audit trail).
    pub evidence: ProbeEvidence,
    /// Human-oriented notes explaining the classification.
    pub notes: Vec<String>,
    /// Model identification candidates derived from `mac` (OUI prefix
    /// matches against the provided models).
    pub model_candidates: Vec<ModelMatch>,
}

/// Run the diagnostic workflow: probe → classify → identify.
///
/// This is the same code path for every provider — mock today, local std /
/// remote agent / MCU tomorrow (ADR-0003's "one workflow, any provider").
pub async fn diagnose<P>(
    prober: &mut P,
    ip: IpAddr,
    models: &[DeviceModel],
) -> Result<Diagnosis, ProbeError>
where
    P: LinkProbe + Time,
{
    let link = prober.link_up().await?;
    let ping = prober.ping(ip).await?;
    prober.sleep_ms(0).await; // pacing hook (no-op on mocks; real providers rate-limit)
    let http = prober.http_get(ip, "/").await?;
    let ssh_banner = prober.ssh_banner(ip).await?;
    let mac = prober.arp_mac(ip).await?;

    let evidence = ProbeEvidence {
        link_up: link,
        ping,
        http,
        ssh_banner,
        authenticated_board: None,
        mac,
    };
    let (state, notes) = state::classify_with_notes(&evidence, state::DEFAULT_RECOVERY_HINTS);
    let model_candidates = match evidence.mac.as_ref() {
        Some(mac) => identify::identify_by_mac_ref(models, mac),
        None => Vec::new(),
    };

    Ok(Diagnosis {
        ip,
        mac: evidence.mac,
        state,
        evidence,
        notes,
        model_candidates,
    })
}

/// Refine a completed diagnosis with a key-authenticated board read.
///
/// Pure: re-classifies the existing evidence with the board signal
/// attached. Only an `SshOnly` verdict can move — every other state was
/// decided by stronger evidence that outranks the board arm in the
/// classifier (identifying HTTP first, contradictions refused).
#[must_use]
pub fn refine_with_authenticated_board(
    mut diagnosis: Diagnosis,
    board: capability::AuthenticatedBoard,
) -> Diagnosis {
    diagnosis.evidence.authenticated_board = Some(board);
    let (state, notes) =
        state::classify_with_notes(&diagnosis.evidence, state::DEFAULT_RECOVERY_HINTS);
    diagnosis.state = state;
    diagnosis.notes = notes;
    diagnosis
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::AuthenticatedBoard;
    use crate::state::ProbeEvidence;
    use std::net::IpAddr;

    fn ssh_only_diagnosis() -> Diagnosis {
        let evidence = ProbeEvidence {
            ssh_banner: Some(crate::capability::SshBanner {
                software: "dropbear_2024.86".into(),
            }),
            ..Default::default()
        };
        let (state, _) = state::classify_with_notes(&evidence, state::DEFAULT_RECOVERY_HINTS);
        assert_eq!(state, crate::state::DeviceState::SshOnly);
        Diagnosis {
            ip: "127.0.0.1".parse::<IpAddr>().expect("ip"),
            mac: None,
            state,
            evidence,
            notes: Vec::new(),
            model_candidates: Vec::new(),
        }
    }

    #[test]
    fn refine_upgrades_ssh_only_to_openwrt() {
        let refined = refine_with_authenticated_board(
            ssh_only_diagnosis(),
            AuthenticatedBoard {
                board_name: "dlink,covr-x1860-a1".into(),
                distrib_id: "OpenWrt".into(),
            },
        );
        assert_eq!(refined.state, crate::state::DeviceState::OpenWrt);
        assert!(refined.evidence.authenticated_board.is_some());
    }

    #[test]
    fn refine_with_empty_board_keeps_ssh_only() {
        let refined = refine_with_authenticated_board(
            ssh_only_diagnosis(),
            AuthenticatedBoard {
                board_name: String::new(),
                distrib_id: String::new(),
            },
        );
        assert_eq!(refined.state, crate::state::DeviceState::SshOnly);
    }
}
