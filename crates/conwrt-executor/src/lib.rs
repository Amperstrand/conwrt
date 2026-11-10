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
//! - [`bridge`] — [`TransferSink`](conwrt_agent_proto::server::TransferSink)
//!   over [`TransferState`] (slice 3): what the firmware attaches to
//!   `ServerCore` so stream frames land in the window.
//! - [`trigger`] — the flash-trigger GET: stage two of the GL.iNet
//!   two-stage recovery flow (#232 P1 4298093559), sent only after an
//!   accepted upload verdict.
//! - [`embassy_net`] (feature `embassy-net`, firmware-only) —
//!   [`TcpHttpIo`] over embassy-net 0.9's `TcpSocket`: the wire side of
//!   [`post::RecoveryPost`] on the MCU.
//!
//! The one-request rule (AGENTS.md, model JSONs): a U-Boot recovery
//! httpd serves exactly one HTTP request. Never GET the page — the POST
//! is the first and only request; a partial POST burns the recovery
//! window and re-arming needs a power cycle. [`post`] encodes that
//! contract: there is no probe/GET path at all. The ONE exception is
//! [`trigger`] — the documented second request of two-stage flows
//! (GL.iNet: upload stores, GET `/result` flashes), sent only AFTER an
//! accepted upload verdict; one-request servers (D-Link uIP) never see
//! it because their profiles carry no trigger endpoint.
//!
//! Tier-A crate (ADR-0002): firmware (Tier C) consumes this verbatim;
//! host tests (ring 1 per ADR-0011) drive the real logic against the
//! one-request mock recovery server in `tests/`.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod bridge;
#[cfg(feature = "embassy-net")]
pub mod embassy_net;
pub mod multipart;
pub mod post;
pub mod pump;
pub mod transfer;
pub mod trigger;

pub use bridge::ExecutorTransfer;
#[cfg(feature = "embassy-net")]
pub use embassy_net::TcpHttpIo;
pub use multipart::Multipart;
pub use post::{HttpIo, PostError, PostOutcome, RecoveryPost, Verdict};
pub use pump::{PostPump, PumpStep};
pub use transfer::{TransferError, TransferState};
pub use trigger::{TriggerRequest, TriggerVerdict};
