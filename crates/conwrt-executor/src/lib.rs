//! # conwrt-executor
//!
//! The standalone-executor core (M6, issue #226 slice 1): the pieces a
//! microcontroller needs to flash a router from recovery mode with no
//! laptop attached — `no_std` + alloc, host-testable without hardware.
//!
//! - [`transfer`] — the receiving half of the agent-protocol image
//!   stream: a bounded RAM window over [`StreamChunk`]s carrying the
//!   protocol's resume token (contiguous received bytes; replays are
//!   trimmed idempotently, ADR-0004 §6).
//! - [`multipart`] — the U-Boot recovery multipart body shape
//!   (WebKit-framed single octet-stream part, byte-compatible with
//!   conwrt 1.x `build_webkit_multipart`).
//! - [`post`] — the recovery HTTP POST pump: staged
//!   headers → bounded-window body streaming → footer → verdict, over
//!   an owned async IO trait (AFIT, per ADR-0002 — no embedded-io in
//!   the public surface).
//!
//! The one-request rule (AGENTS.md, model JSONs): a U-Boot recovery
//! httpd serves exactly one HTTP request. Never GET the page — the POST
//! is the first and only request; a partial POST burns the recovery
//! window and re-arming needs a power cycle. [`post`] encodes that
//! contract: there is no probe/GET path at all.
//!
//! Tier-A crate (ADR-0002): firmware (Tier C) consumes this verbatim;
//! host tests (ring 1 per ADR-0011) drive the real logic against the
//! one-request mock recovery server in `tests/`.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod multipart;
pub mod post;
pub mod transfer;

pub use multipart::Multipart;
pub use post::{HttpIo, PostError, PostOutcome, RecoveryPost, Verdict};
pub use transfer::{TransferError, TransferState};
