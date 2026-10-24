//! The wire format lives in `conwrt-protocols::zycast` — the no_std
//! core under the ADR-0002 tier policy (relocated from this crate
//! 2026-10-24, closing #447 into the merged #498 baseline). Re-exported
//! so the sender, the CLI surface, and the golden-vector tests keep
//! their paths — the tests now pin the protocols crate's encoder.
pub use conwrt_protocols::zycast::*;
