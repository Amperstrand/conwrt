//! # conwrt-probe-core
//!
//! The shared detection core (#215 slice 5): the PURE detection state
//! machines, extracted from the Python source of truth so the host CLI
//! and the MCU firmware (STM32F746 agent) run ONE detector.
//!
//! Extracted from (species-level logic only — no vocabularies invented):
//! - `scripts/router-probe.py` — HTTP GET/HEAD boot vocabularies
//!   ([`banner`]), the `classify_state` evidence precedence ([`state`]),
//!   and the passive→active probe ordering with per-probe budgets
//!   ([`schedule`]).
//! - `scripts/flash/serial_monitor.py` — the serial boot-milestone
//!   patterns and their latch-once, rolling-buffer semantics
//!   ([`milestones`]).
//! - `scripts/flash/detect.py` — the ordered gate model behind the
//!   scheduler's step sequence.
//!
//! Tier-A crate (ADR-0002): `no_std` + `alloc` by default; the `std`
//! feature (default for host builds) currently adds no extra surface —
//! it exists to mirror [`conwrt_agent_proto`]'s tiering so a future
//! host-only adapter can hang richer matching off it without forking
//! the firmware path.
//!
//! # Fidelity delta (honest accounting)
//!
//! The Python source matches with `re` regexes; a no_std firmware path
//! cannot carry the `regex` crate, so the Tier-A core matches with byte
//! patterns ([`vocab::Pattern`]). Every pattern in the source of truth
//! reduces exactly to a literal or a literal-plus-one-ASCII-digit:
//!
//! | Python regex | Tier-A pattern |
//! |---|---|
//! | `U-Boot \d` | literal `"U-Boot "` + ASCII digit class |
//! | `Starting kernel` | literal |
//! | `init: - preinit -` | literal |
//! | `(?:init\|procd): - init -` | two literals → same milestone |
//! | `root@` | literal |
//!
//! So the current delta for the milestone vocabulary is **none**. The
//! HTTP vocabularies are substring checks in Python already; Tier-A
//! reproduces their exact match order and case sensitivity (including
//! the case-SENSITIVE `"FIRMWARE UPDATE"`, `"uIP"`, `"HTTP/1.1 405"`).
//! Python's lossy UTF-8 decode (`errors="replace"`) before serial
//! matching is equivalent to raw-byte matching for these ASCII-only
//! patterns: replacement can only remove candidate matches, never
//! create them. A host-side `std` adapter MAY layer real regexes for
//! richer, model-JSON-supplied patterns later; anything not reducible
//! to [`vocab::Pattern`] stays host-only and must say so.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod banner;
pub mod milestones;
pub mod schedule;
pub mod state;

pub mod vocab;
// The watcher is a host-side diagnostic (ping/TCP probes, alloc): MCU
// firmware builds --no-default-features and must not see it (ADR-0002 tiering).
#[cfg(feature = "std")]
pub mod watch;
