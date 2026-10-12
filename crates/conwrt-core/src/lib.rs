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
pub mod identify;
pub mod mock;
pub mod plan;
pub mod state;

pub use capability::{HttpProbeResult, LinkProbe, ProbeError, SshBanner, Time};
pub use identify::{MatchKind, ModelMatch, identify_by_mac};
pub use mock::MockProber;
pub use plan::{
    Plan, PlanOp, Profile, ServiceAction, SqmProfile, UciValue, Unsupported, VerificationCheck,
    plan_profile,
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
