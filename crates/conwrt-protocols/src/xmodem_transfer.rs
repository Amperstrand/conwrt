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
//! revisit if a target misbehaves — #124).
//! - a mid-stream `NAK` is counted as an error but the block is **not**
//!   retransmitted; the sender advances and completes — the block is lost
//!   receiver-side. [`send_firmware_verified`] is the policy answer: the
//!   whole transfer restarts, and only receiver-side verification
//!   completes it.
//! - mid-stream `CAN` is not honored during block send (crate TODO);
//!   cancellation is reliable at transfer start and via error exhaustion.
//!
//! # Receiver compatibility matrix (#124) — fill per target BEFORE any
//! automated serial flash ships
//!
//! | Bootloader target | Restart-after-abort safe? | Evidence |
//! |---|---|---|
//! | U-Boot `loadx` | unknown — hardware-gated | to verify: mid-transfer abort, then clean restart; confirm no partial write |
//! | Z-Loader (Zyxel) | unknown — hardware-gated | as above |
//! | vendor ROM loaders | unknown — hardware-gated | as above |
//!
//! Every row must be proven on hardware and recorded in the model JSON
//! flash-method entry (`restart_safety`) before `send_firmware_verified`
//! is pointed at that target.
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

/// Whole-transfer retry policy (#124): the sender's `Ok` is a claim, not
/// acceptance — a mid-stream NAK makes the crate report success while a
/// strict receiver has already aborted on the sequence mismatch. The
/// driver MUST verify receiver-side acceptance (CRC of the flashed
/// region, echo compare, bootloader's own checksum) and only a passing
/// verification completes a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Whole-transfer attempts (sender run + verification each).
    pub max_attempts: u32,
    /// Pause between attempts, in driver-defined milliseconds — gives the
    /// receiver time to re-arm its receive state.
    pub restart_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            restart_delay_ms: 200,
        }
    }
}

/// Why a verified transfer failed.
#[derive(Debug)]
pub enum VerifiedError {
    /// The sender side failed every attempt (last library error kept).
    AttemptsExhausted {
        /// Attempts made.
        attempts: u32,
        /// The final attempt's library error.
        last: XmodemError,
    },
    /// The sender claimed success every attempt, but receiver-side
    /// verification never passed — the mid-stream-NAK signature: the
    /// bytes "sent" were not the bytes received.
    Unverified {
        /// Attempts made (each sender-claimed success).
        attempts: u32,
        /// Payload bytes the sender claimed on its final attempt.
        bytes_claimed: usize,
    },
}

/// Bounded whole-transfer retry with receiver-side acceptance
/// verification (#124 driver-level retry policy).
///
/// - `stream_factory` rebuilds the payload reader per attempt: a whole
///   transfer restarts from byte zero, so the stream must rewind (R is
///   `Read`, not `Seek`).
/// - `verify` runs ONLY after a sender-side `Ok` and is the sole path to
///   this function's `Ok` — returning `false` consumes an attempt.
/// - `delay_ms` paces `restart_delay_ms` between attempts (driver-owned
///   sleep; no_std callers bring their own timer).
///
/// On Linux sockets, remember the crate counts read timeouts against the
/// error budget and `WouldBlock`-style timeouts are fatal — configure
/// real timeouts on `dev` before calling.
pub fn send_firmware_verified<D, R, F, W>(
    dev: &mut D,
    mut stream_factory: F,
    block_length: BlockLength,
    policy: &RetryPolicy,
    verify: &mut dyn FnMut() -> bool,
    mut delay_ms: W,
) -> Result<usize, VerifiedError>
where
    D: Read + Write,
    F: FnMut() -> R,
    R: Read,
    W: FnMut(u64),
{
    let mut last_sender_error: Option<XmodemError> = None;
    let mut last_claimed_bytes = 0usize;
    let mut claimed_successes = 0u32;
    let mut attempts = 0u32;

    while attempts < policy.max_attempts {
        if attempts > 0 {
            delay_ms(policy.restart_delay_ms);
        }
        attempts += 1;
        let mut stream = stream_factory();
        match send_firmware(dev, &mut stream, block_length) {
            Ok(bytes) => {
                claimed_successes += 1;
                last_claimed_bytes = bytes;
                if verify() {
                    return Ok(bytes);
                }
            }
            Err(e) => {
                last_sender_error = Some(e);
            }
        }
    }

    // A claimed success that never verified outranks a later sender
    // error for diagnosis: it is the mid-stream-NAK signature (bytes
    // "sent" were not the bytes received).
    if claimed_successes > 0 {
        Err(VerifiedError::Unverified {
            attempts,
            bytes_claimed: last_claimed_bytes,
        })
    } else {
        Err(VerifiedError::AttemptsExhausted {
            attempts,
            last: last_sender_error.expect("no success and no error is unreachable"),
        })
    }
}
