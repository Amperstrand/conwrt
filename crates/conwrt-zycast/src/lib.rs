//! conwrt-zycast — ZyXEL Multiboot multicast flash protocol.
//!
//! [`protocol`] is the pure wire format (unit-testable, pinned to the Go
//! reference by golden vectors); [`sender`] is the I/O half: a bounded-loop
//! UDP multicast sender with interface pinning.

pub mod protocol;
pub mod sender;

pub use protocol::{DEFAULT_DELAY_MS, DEFAULT_GROUP, DEFAULT_LOOPS, DEFAULT_PORT, ImageType};
pub use sender::{SendConfig, SendStats, send};
