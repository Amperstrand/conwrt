//! conwrt-blankdl — the ZTE blank-download flash fence.
//!
//! [`fence`] is the I/O half of the protocol: a deliberately rigid TFTP
//! server that serves ONE pinned image to the stock bootloader's
//! blank-download flow and exits on the ASCII fin packet. The wire core
//! (state machine, option parsing, rollover) lives in
//! `conwrt-protocols::blankdl` per the zycast crate split.

pub mod fence;

pub use fence::{FenceConfig, FenceError, FenceExit, FenceOutcome, PinnedImage, serve};
