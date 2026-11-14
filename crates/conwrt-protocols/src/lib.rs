//! # conwrt-protocols
//!
//! Router-recovery protocol integrations for conwrt.
//!
//! **Libraries-first policy**: maintained crates are used wherever they fit
//! (ADR-0001); this crate is the seam that pins versions and records conwrt's
//! policy defaults, not a place to hand-roll protocols. M2 wires XMODEM via
//! the [`xmodem`] crate (MIT, `no_std`-capable) — the transfer method the
//! 1.x README documents as `serial-xmodem` but never implemented (#106).
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod blankdl;
pub mod serial_io;
pub mod xmodem_transfer;
pub mod zycast;
/// RE-derived receive state machine + model-ID field reader. Host-side
/// validation infrastructure (tests, the fake-Z-Loader simulator, sender
/// preflights) — allocation-using, so gated to std builds; the no_std
/// core keeps the encode/checksum half firmware needs.
#[cfg(feature = "std")]
pub mod zycast_receiver;

pub use xmodem_transfer::{BlockLength, XmodemError, send_firmware};
