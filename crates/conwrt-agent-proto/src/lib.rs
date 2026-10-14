//! # conwrt-agent-proto
//!
//! The conwrt agent wire protocol (M3, issue #108), built on postcard-rpc
//! per ADR-0004's spike verdict (ADOPT, 2026-10-12): versioned handshake,
//! capability advertisement, exclusive resource leases with controller-loss
//! policies, and resumable firmware-class streams.
//!
//! Layering (ADR-0004):
//! - [`protocol`] — the message types both sides share (no I/O).
//! - [`wire`] — COBS-over-TCP transport for host and device sides.
//! - [`leases`] — the lease table with heartbeat expiry + disconnect
//!   policies.
//!
//! `no_std` note: this crate is Tier-B (std) for M3; the message types in
//! [`protocol`] are `no_std`-compatible (serde+alloc only) so an MCU
//! device-side can reuse them verbatim (ADR-0002).

// Tier-B (std) crate for M3; protocol + leases modules stay no_std-shaped
// (serde + alloc) for the future MCU device side (ADR-0002).
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod agent;
pub mod controller;
pub mod dispatch;
pub mod leases;
pub mod protocol;
pub mod wire;
