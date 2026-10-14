//! # conwrt-agent-proto
//!
//! The conwrt agent wire protocol (M3, issue #108), built on postcard-rpc
//! per ADR-0004's spike verdict (ADOPT, 2026-10-12): versioned handshake,
//! capability advertisement, exclusive resource leases with controller-loss
//! policies, and resumable firmware-class streams.
//!
//! Layering (ADR-0004):
//! - [`protocol`] — the message types both sides share (no I/O).
//! - [`cobs`] — transport-agnostic COBS framing (the "one codec
//!   everywhere" §2 rule): feed raw transport bytes, get decoded frames.
//! - [`leases`] — the lease table with heartbeat expiry + disconnect
//!   policies.
//!
//! Tier-A crate (ADR-0002): `no_std` + `alloc` by default; the `std`
//! feature (default for host builds) adds the tokio TCP transport
//! ([`wire`]) and the host-side agent ([`agent`]) / controller
//! ([`controller`]) runtimes. MCU apps (Tier C) build with
//! `--no-default-features` and reuse [`protocol`], [`cobs`], and
//! [`leases`] verbatim.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod dispatch;
pub mod leases;
pub mod protocol;
pub mod server;

#[cfg(feature = "std")]
pub mod agent;
#[cfg(feature = "std")]
pub mod controller;
#[cfg(feature = "std")]
pub mod server_tcp;
#[cfg(feature = "std")]
pub mod wire;

pub mod cobs;
pub use cobs::{CobsPump, encode_frame};
