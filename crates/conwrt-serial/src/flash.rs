//! Base64 serial firmware transfer — the Rust port of
//! `scripts/serial-flash.py` (parity-matrix §5) on the [`crate::console`]
//! driver, with verification upgraded to the #405 policy: **a sender's
//! `Ok` is a claim, not acceptance** — the transfer is only complete
//! when the DEVICE's own `sha256sum /tmp/fw.bin` matches the host-side
//! hash of the image (the Python script's `--verify` size check is
//! superseded; a hash equality implies it).
//!
//! Wire format is Python parity: Ctrl-C to a clean prompt, staging
//! clear, then one `echo '<base64>' >> /tmp/fw.b64` line per
//! [`FlashOptions::chunk_size`] raw bytes (512 proven on the bench
//! NR7101 — the tty line buffer tolerates the ~684-char encoded line),
//! paced by [`FlashOptions::chunk_delay`], decode on the device, verify
//! on the device. Every chunk rides [`SerialConsole::send_paced_line`]
//! internally, so a mid-transfer UART break or a dropped `tcp://` bridge
//! runs the #412 close → wait → reopen recovery instead of corrupting
//! the stream silently.
//!
//! AGENTS.md hash rule honored: the host-side digest is SHA-256
//! (`sha2`), the one algorithm BusyBox `sha256sum` prints on-device.

use std::time::Duration;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::console::SerialConsole;
use crate::io::ConsoleError;

/// On-device staging path for the base64 text (Python `FW` layout).
pub const FW_B64_PATH: &str = "/tmp/fw.b64";

/// On-device decoded firmware path.
pub const FW_BIN_PATH: &str = "/tmp/fw.bin";

/// Progress callback cadence in chunks (Python prints every 50).
pub const PROGRESS_EVERY: usize = 50;

/// Raw bytes per serial line (Python `--chunk-size 512`). Proven on the
/// bench; larger values press against the device tty line buffer.
pub const DEFAULT_CHUNK_SIZE: usize = 512;

/// Delay between chunk lines (Python `--delay 0.15`).
pub const DEFAULT_CHUNK_DELAY: Duration = Duration::from_millis(150);

/// Python's opening settle: Ctrl-C to a clean prompt, 1 s before the
/// first command (`s.write(b"\x03\r\n"); time.sleep(1)`).
pub const CTRL_C_SETTLE: Duration = Duration::from_secs(1);

/// Knobs for [`flash_base64`] (the script's CLI options).
#[derive(Debug, Clone)]
pub struct FlashOptions {
    /// Raw bytes per `echo` line.
    pub chunk_size: usize,
    /// Pause between chunk lines (tty pacing).
    pub chunk_delay: Duration,
    /// Collect deadline for the staging-clear command.
    pub clear_timeout: Duration,
    /// Collect deadline for the on-device `base64 -d` (BusyBox decoding
    /// a full image on a MIPS core takes real time).
    pub decode_timeout: Duration,
    /// Collect deadline for the on-device `sha256sum` verification.
    pub verify_timeout: Duration,
}

impl Default for FlashOptions {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            chunk_delay: DEFAULT_CHUNK_DELAY,
            clear_timeout: Duration::from_secs(15),
            decode_timeout: Duration::from_secs(120),
            verify_timeout: Duration::from_secs(30),
        }
    }
}

/// Why a base64 flash failed. All messages are operator-safe.
#[derive(Debug, Error)]
pub enum FlashError {
    /// Transport failure (write, recovery reopen).
    #[error(transparent)]
    Console(#[from] ConsoleError),
    /// `chunk_size` must be at least one byte (`slice::chunks` would
    /// panic otherwise).
    #[error("chunk_size must be > 0")]
    ZeroChunkSize,
    /// The staging-clear command did not complete with rc 0.
    #[error("clearing {FW_B64_PATH} failed (rc {rc}): {output}")]
    ClearFailed {
        /// The collected rc (1 = `__RC1__`, 2 = timeout).
        rc: u8,
        /// Collected console output.
        output: String,
    },
    /// The on-device decode did not complete with rc 0 (missing `base64`
    /// applet, full `/tmp`, wedged console).
    #[error("base64 -d failed on device (rc {rc}): {output}")]
    DecodeFailed {
        /// The collected rc (1 = `__RC1__`, 2 = timeout).
        rc: u8,
        /// Collected console output.
        output: String,
    },
    /// The device's `sha256sum` reply carried no parseable hash line for
    /// [`FW_BIN_PATH`] — the receiver never answered, so acceptance is
    /// refused (#405: no sender-side trust).
    #[error("could not parse device sha256sum reply: {output:?}")]
    HashUnparseable {
        /// The raw collected console output.
        output: String,
    },
    /// The device-reported hash does not equal the image hash — the
    /// bytes that arrived are not the bytes that were sent.
    #[error("sha256 mismatch: image {expected}, device reports {actual} — the transfer is corrupt")]
    HashMismatch {
        /// Host-side SHA-256 of the image.
        expected: String,
        /// What the device's `sha256sum` printed.
        actual: String,
    },
}

/// A completed (device-verified) transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashReport {
    /// Chunk lines delivered.
    pub chunks: usize,
    /// Image bytes transferred.
    pub bytes: usize,
    /// The device-reported SHA-256 (matched against the host hash).
    pub device_sha256: String,
}

/// Host-side SHA-256 hex digest of `image` — lowercase, byte-identical
/// to BusyBox `sha256sum` output.
#[must_use]
pub fn image_sha256(image: &[u8]) -> String {
    let digest = Sha256::digest(image);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Extract the `<64-hex>  /tmp/fw.bin` hash token from a `sha256sum`
/// reply. Tolerates the echoed command line and RC markers around it;
/// returns the lowercase hash. Pure, unit-pinned.
#[must_use]
pub fn parse_device_sha256(output: &str) -> Option<String> {
    for line in output.lines() {
        if line.contains(FW_BIN_PATH) {
            let token = line.split_whitespace().next()?;
            if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Some(token.to_ascii_lowercase());
            }
        }
    }
    None
}

/// Transfer `image` to the device over the console via base64 chunked
/// `echo` lines, decode on-device, then verify receiver-side (#405):
/// parse the device's own `sha256sum` reply and require equality with
/// the host hash. Only a passing verification produces
/// <code>Ok([FlashReport])</code>.
///
/// `progress(sent_bytes, total_bytes)` fires every [`PROGRESS_EVERY`]
/// chunks and at the end (Python's transfer progress lines).
///
/// # Errors
/// [`FlashError`] — most importantly [`FlashError::HashMismatch`]: a
/// transfer that "completed" but did not round-trip is a FAILURE, never
/// a success.
pub fn flash_base64<S, O>(
    console: &mut SerialConsole<S, O>,
    image: &[u8],
    opts: &FlashOptions,
    mut progress: impl FnMut(usize, usize),
) -> Result<FlashReport, FlashError>
where
    S: crate::console::Sleeper,
    O: crate::console::PortOpener,
{
    if opts.chunk_size == 0 {
        return Err(FlashError::ZeroChunkSize);
    }
    let expected = image_sha256(image);
    let total = image.len();

    // Python's opening move: Ctrl-C to a clean prompt, then settle.
    console.send_paced_line("\x03", CTRL_C_SETTLE)?;

    let cleared = console.run(
        &format!("rm -f {FW_B64_PATH} {FW_BIN_PATH}"),
        opts.clear_timeout,
    )?;
    if cleared.rc != 0 {
        return Err(FlashError::ClearFailed {
            rc: cleared.rc,
            output: cleared.output,
        });
    }

    let mut sent = 0usize;
    let mut chunks = 0usize;
    for chunk in image.chunks(opts.chunk_size) {
        let b64 = base64::engine::general_purpose::STANDARD.encode(chunk);
        console.send_paced_line(&format!("echo '{b64}' >> {FW_B64_PATH}"), opts.chunk_delay)?;
        sent = (sent + chunk.len()).min(total);
        chunks += 1;
        if chunks % PROGRESS_EVERY == 0 || sent >= total {
            progress(sent, total);
        }
    }

    let decoded = console.run(
        &format!("base64 -d {FW_B64_PATH} > {FW_BIN_PATH}"),
        opts.decode_timeout,
    )?;
    if decoded.rc != 0 {
        return Err(FlashError::DecodeFailed {
            rc: decoded.rc,
            output: decoded.output,
        });
    }

    let verify = console.run(&format!("sha256sum {FW_BIN_PATH}"), opts.verify_timeout)?;
    // #405: the rc is not trusted (a device echo can carry __RC0__
    // before the command even ran) — the parsed, compared hash is the
    // sole acceptance gate.
    let Some(actual) = parse_device_sha256(&verify.output) else {
        return Err(FlashError::HashUnparseable {
            output: verify.output,
        });
    };
    if actual != expected {
        return Err(FlashError::HashMismatch { expected, actual });
    }

    Ok(FlashReport {
        chunks,
        bytes: sent,
        device_sha256: actual,
    })
}

/// Launch `sysupgrade -n /tmp/fw.bin` on the device (Python
/// `run_sysupgrade` parity: the line is written and NEVER waited on —
/// sysupgrade runs for minutes and reboots the device; its boot output
/// belongs to a boot capture, not this console's collector).
///
/// Only call after [`flash_base64`] returned `Ok` — the #405 gate.
///
/// # Errors
/// [`ConsoleError::Io`] when the write fails.
pub fn trigger_sysupgrade<S, O>(console: &mut SerialConsole<S, O>) -> Result<(), ConsoleError>
where
    S: crate::console::Sleeper,
    O: crate::console::PortOpener,
{
    console.write_raw(format!("sysupgrade -n {FW_BIN_PATH}\r\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(bytes: usize) -> Vec<u8> {
        (0..bytes).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn host_hash_matches_reference_vector() {
        // sha256("") = e3b0c442... — the well-known empty-digest vector,
        // and what BusyBox sha256sum prints for an empty file.
        assert_eq!(
            image_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn parse_extracts_hash_from_busybox_reply() {
        let expected = image_sha256(&image(1000));
        let out = format!("cmd echo __RC0__\r\n{expected}  {FW_BIN_PATH}\r\n__RC0__\r\n");
        assert_eq!(
            parse_device_sha256(&out).as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn parse_survives_echoed_command_and_markers() {
        let expected = image_sha256(b"payload");
        let out = format!("sha256sum /tmp/fw.bin && echo __RC0__\r\n{expected}  /tmp/fw.bin\r\n");
        assert_eq!(
            parse_device_sha256(&out).as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn parse_rejects_missing_or_malformed_hash() {
        assert_eq!(
            parse_device_sha256("sha256sum: can't open '/tmp/fw.bin'"),
            None
        );
        assert_eq!(
            parse_device_sha256("0123  /tmp/fw.bin\r\n__RC0__"),
            None,
            "non-64-hex token must not parse"
        );
        let not_lower = "ABCDEF0123".repeat(6) + "ABCD";
        assert_eq!(
            parse_device_sha256(&format!("{not_lower}  /tmp/fw.bin")).as_deref(),
            Some(not_lower.to_ascii_lowercase().as_str()),
            "uppercase hex normalizes — BusyBox prints lowercase, be liberal"
        );
    }

    #[test]
    fn parse_requires_the_fw_path_on_the_line() {
        let h = image_sha256(b"x");
        assert_eq!(parse_device_sha256(&format!("{h}  /etc/passwd")), None);
    }

    #[test]
    fn chunk_math_matches_python() {
        // ceil division, the Python math.ceil(total / chunk_size)
        let total = 2048usize;
        let opts = FlashOptions::default();
        let chunks = image(total).chunks(opts.chunk_size).count();
        assert_eq!(chunks, total / opts.chunk_size);
        assert_eq!(image(2049).chunks(opts.chunk_size).count(), 5);
        assert_eq!(image(1).chunks(opts.chunk_size).count(), 1);
    }
}
