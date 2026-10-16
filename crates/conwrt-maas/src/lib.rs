//! # conwrt-maas
//!
//! MAAS portable-lab components migrated to Rust (issue #169), per
//! `recipes/raspberry-pi/maas-portable-lab.md` §"Rust Alignment" and
//! `docs/maas-compute-milestones.md` M5:
//!
//! - [`flash`]: the lab's disk-image pipeline — **verify → write → verify →
//!   inject** — as a typed plan executed against a [`flash::BlockWriter`]
//!   capability. The safety-critical property (never write an unverified
//!   image; never inject a cloud-init seed onto an unread-back disk) lives
//!   in this crate, not in providers.
//! - [`provider`]: [`provider::MaasProvider`] — compose/deploy/release/delete
//!   over the [`provider::MaasClient`] seam with a typed MAAS lifecycle
//!   state machine. Unit tests run against [`mock::MockMaas`]; a real HTTP
//!   client lands only with live-MAAS validation (owner-gated).
//!
//! This crate contains no I/O of its own: every effect goes through a
//! capability trait (ADR-0003), so CI proves the workflows without a
//! coordinator, a MAAS region, or a USB disk attached.
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// AFIT capability traits, matching conwrt-core (ADR-0003).
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod flash;
pub mod mock;
pub mod provider;

pub use flash::{BlockWriter, CloudInitSeed, DiskFlashPlan, FlashError, FlashReport, Sha256};
pub use provider::{
    ComputeError, ComputeProvider, MaasClient, MaasProvider, MachineRecord, MachineState, VmInfo,
    VmSpec,
};
