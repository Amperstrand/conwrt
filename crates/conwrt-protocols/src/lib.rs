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

pub mod serial_io;
pub mod xmodem_transfer;

pub use xmodem_transfer::{BlockLength, XmodemError, send_firmware};
