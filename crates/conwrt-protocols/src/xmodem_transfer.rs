//! XMODEM firmware transfer, built on the [`xmodem`] crate.
//!
//! conwrt policy on top of the library:
//! - pad byte `0x1A` (CP/M EOF, the universal convention),
//! - `max_errors` budget of 16 (crate default — one flaky byte must not
//!   abort, sixteen must),
//! - block length chosen by the caller: 128 bytes for conservative
//!   bootloaders, 1024 for XMODEM-1k (≈8× faster on the same line).
//!
//! Known library limitations, accepted deliberately (bench-serial context;
//! revisit if a target misbehaves — see #106):
//! - a mid-stream `NAK` is counted as an error but the block is **not**
//!   retransmitted; the receiver will abort on the sequence mismatch and
//!   the driver should retry the whole transfer,
//! - mid-stream `CAN` is not honored during block send (crate TODO);
//!   cancellation is reliable at transfer start and via error exhaustion.
//!
//! I/O traits come from the crate itself: `std::io` on std builds, the
//! crate's `xmodem::io` subset on `no_std` (implement it at the driver —
//! embassy UART in M5+).

#[cfg(feature = "std")]
pub use std::io::{Read, Write};

#[cfg(not(feature = "std"))]
pub use xmodem::io::{Read, Write};

pub use xmodem::BlockLength;
pub use xmodem::Error as XmodemError;

/// Errors capped at this many per transfer before aborting.
pub const MAX_ERRORS: u32 = 16;

/// Send `stream` to a receiver over `dev` using XMODEM.
///
/// The receiver negotiates checksum vs CRC mode via its start byte; the
/// transfer returns the number of payload bytes sent. Configure read
/// timeouts on `dev` before calling — the crate counts read timeouts
/// against the error budget.
pub fn send_firmware<D, R>(
    dev: &mut D,
    stream: &mut R,
    block_length: BlockLength,
) -> Result<usize, XmodemError>
where
    D: Read + Write,
    R: Read,
{
    let mut transfer = xmodem::Xmodem::new();
    transfer.max_errors = MAX_ERRORS;
    transfer.pad_byte = 0x1A;
    transfer.block_length = block_length;
    transfer.send(dev, stream)
}
