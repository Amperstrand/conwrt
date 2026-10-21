//! Serial boot capture with power-transition recovery — the Rust port of
//! `scripts/serial-boot-capture.py` (parity-matrix §5), built on the
//! [`crate::io`] transport seam and the #412 break-recovery state
//! machine.
//!
//! Two phases, Python semantics:
//!
//! * **Phase 1 — wait for the power transition** ([`wait_for_break`]):
//!   read single bytes until a `0x00` (or `0xff`) break byte arrives —
//!   the FT232R's rendering of a PoE power-off (AGENTS.md "UART Break
//!   Recovery"). Any other byte means the device was ALREADY booting:
//!   capture continues on the same port with that byte as the first
//!   datum. `max_wait > 0` bounds the wait (typed timeout error).
//! * **Phase 2 — capture** ([`capture_boot`]): after a break, sleep
//!   `recovery_wait` (the script's `--recovery-wait`, default 3 s),
//!   reopen the port FRESH (resets the wedged adapter; reconnects a
//!   `tcp://` bridge), flush stale input, then read chunks until
//!   `silence_timeout` of no data. Raw bytes land in `console.raw`,
//!   lossy text in `console.log` (Python file parity).
//!
//! Milestone detection is NOT a port of the script's ad-hoc
//! `BOOT_MARKERS` table: it is the SHARED vocabulary from
//! [`conwrt_probe_core::BootMilestoneTracker`] (the `serial_monitor.py`
//! extraction — rolling-buffer matching, latch-once), per the §5 rule
//! that matchers are never forked. Milestone timestamps are relative to
//! the start of phase 2.
//!
//! Deliberate delta over the Python (documented, not silent): a break
//! byte or read error DURING phase 2 runs the same close → wait →
//! reopen recovery instead of being captured as garbage — the device
//! power-cycled mid-boot, so the capture continues across the
//! transition. The recovery wait is [`BootCaptureOptions::recovery_wait`]
//! in that path too, and the silence window restarts (the device is
//! rebooting — the #412 `Recovery::BreakByte` deadline-restart rule).

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use conwrt_probe_core::milestones::{BootMilestone, BootMilestoneTracker};
use thiserror::Error;

use crate::collect::{BREAK_BYTE, READ_CHUNK};
use crate::console::{PortOpener, Sleeper};
use crate::io::{ConsoleError, ConsoleIo};

/// Break signatures in phase 1 (Python `wait_for_break`): `0x00` (the
/// FT232R UART break) or `0xff` (all-ones garbage while the line floats).
pub const BREAK_BYTE_ALT: u8 = 0xff;

/// Default silence timeout (Python `--timeout 15`).
pub const DEFAULT_SILENCE_TIMEOUT: Duration = Duration::from_secs(15);

/// Default recovery wait (Python `--recovery-wait 3.0`).
pub const DEFAULT_RECOVERY_WAIT: Duration = Duration::from_secs(3);

/// One boot-capture run's knobs (the script's CLI options).
#[derive(Debug, Clone)]
pub struct BootCaptureOptions {
    /// Silence timeout AFTER data has arrived that ends the capture
    /// (Python `--timeout`).
    pub silence_timeout: Duration,
    /// Seconds to wait after a break before reopening (Python
    /// `--recovery-wait`).
    pub recovery_wait: Duration,
    /// Bound on phase 1; zero waits forever (Python `--max-wait`).
    pub max_wait: Duration,
    /// Session directory receiving `console.raw` + `console.log`
    /// (Python `serial/<session>/`).
    pub log_dir: PathBuf,
}

impl BootCaptureOptions {
    /// Script defaults: 15 s silence, 3 s recovery, unbounded wait.
    #[must_use]
    pub fn new(log_dir: impl Into<PathBuf>) -> Self {
        Self {
            silence_timeout: DEFAULT_SILENCE_TIMEOUT,
            recovery_wait: DEFAULT_RECOVERY_WAIT,
            max_wait: Duration::ZERO,
            log_dir: log_dir.into(),
        }
    }
}

/// How the capture learned the device's power state (Python's two
/// `wait_for_break` outcomes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerTransition {
    /// A break byte arrived: close → recovery wait → fresh reopen.
    BreakDetected,
    /// Real console data arrived with no break — the device was already
    /// on; capture proceeds on the SAME port (the first byte is kept).
    AlreadyOn,
}

/// Everything that can go wrong in a boot capture, typed — messages are
/// operator-safe (the Python module's no-traceback rule).
#[derive(Debug, Error)]
pub enum BootCaptureError {
    /// Phase 1 exceeded `max_wait` with no break and no data.
    #[error("no break byte and no boot data within {max_wait:?} — power-cycle the device?")]
    WaitTimeout {
        /// The bounded phase-1 wait that expired.
        max_wait: Duration,
    },
    /// Transport open/read failures (a failed recovery reopen lands
    /// here too — Python parity: the exception escapes).
    #[error(transparent)]
    Console(#[from] ConsoleError),
    /// The log directory or capture files could not be created/written.
    #[error("cannot write capture log {path}: {source}")]
    LogFile {
        /// The file being written when the failure hit.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
}

/// The capture result: what was observed, when, and where it was logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootCaptureReport {
    /// How phase 1 resolved.
    pub transition: PowerTransition,
    /// Milestones in first-latch order, each with its timestamp relative
    /// to the start of phase 2.
    pub milestones: Vec<(BootMilestone, Duration)>,
    /// Total raw bytes captured.
    pub raw_len: usize,
    /// `console.raw` path (raw bytes).
    pub console_raw: PathBuf,
    /// `console.log` path (lossy text).
    pub console_log: PathBuf,
}

/// Classify a phase-1 byte (Python `wait_for_break`'s `0x00`/`0xff`
/// check). Pure, unit-pinned.
#[must_use]
pub fn is_break_byte(byte: u8) -> bool {
    byte == BREAK_BYTE || byte == BREAK_BYTE_ALT
}

/// Phase 1: wait for the power transition. Takes an OPEN port (the
/// caller opens via its [`PortOpener`]); on break the port is returned
/// CLOSED for the recovery reopen, on data it stays open with the first
/// byte handed back.
fn wait_for_break(
    port: &mut Box<dyn ConsoleIo>,
    max_wait: Duration,
) -> Result<(PowerTransition, Option<u8>), BootCaptureError> {
    let start = Instant::now();
    let mut byte = [0u8; 1];
    loop {
        if !max_wait.is_zero() && start.elapsed() > max_wait {
            return Err(BootCaptureError::WaitTimeout { max_wait });
        }
        match port.read(&mut byte).map_err(ConsoleError::Io)? {
            0 => continue,
            _ => {
                if is_break_byte(byte[0]) {
                    port.close();
                    return Ok((PowerTransition::BreakDetected, None));
                }
                return Ok((PowerTransition::AlreadyOn, Some(byte[0])));
            }
        }
    }
}

/// Run the full two-phase boot capture (Python `main`'s happy path with
/// `capture_boot` inlined): open via `opener`, wait for the transition,
/// then capture with recovery until silence, feeding the shared
/// milestone tracker. Returns the report; `console.raw` and
/// `console.log` are written under `opts.log_dir`.
///
/// # Errors
/// [`BootCaptureError::WaitTimeout`] when phase 1 expires;
/// [`BootCaptureError::Console`] for transport failures (including a
/// failed recovery reopen); [`BootCaptureError::LogFile`] when the
/// capture files cannot be written.
pub fn capture_boot<O: PortOpener, S: Sleeper>(
    opener: &mut O,
    opts: &BootCaptureOptions,
    sleeper: &S,
) -> Result<BootCaptureReport, BootCaptureError> {
    let mut port = opener.open()?;
    let (transition, first_byte) = wait_for_break(&mut port, opts.max_wait)?;

    let mut tracker = BootMilestoneTracker::new();
    let mut milestones: Vec<(BootMilestone, Duration)> = Vec::new();
    std::fs::create_dir_all(&opts.log_dir).map_err(|source| BootCaptureError::LogFile {
        path: opts.log_dir.clone(),
        source,
    })?;
    let open_log = |name: &str| -> Result<File, BootCaptureError> {
        let path = opts.log_dir.join(name);
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| BootCaptureError::LogFile {
                path: path.clone(),
                source,
            })
    };
    let mut raw_file = open_log("console.raw")?;
    let mut log_file = open_log("console.log")?;
    let console_raw = opts.log_dir.join("console.raw");
    let console_log = opts.log_dir.join("console.log");

    if transition == PowerTransition::BreakDetected {
        recover(&mut port, opener, sleeper, opts.recovery_wait)?;
    }

    // Python sets the capture clock AFTER the recovery sleep + reopen:
    // T+0 is the first potential boot byte, never the dark window.
    let start = Instant::now();
    let mut last_data = start;
    let mut raw_len = 0usize;
    if let Some(byte) = first_byte {
        raw_file
            .write_all(&[byte])
            .and_then(|()| raw_file.flush())
            .map_err(|source| BootCaptureError::LogFile {
                path: console_raw.clone(),
                source,
            })?;
        log_file
            .write_all(String::from_utf8_lossy(&[byte]).as_bytes())
            .and_then(|()| log_file.flush())
            .map_err(|source| BootCaptureError::LogFile {
                path: console_log.clone(),
                source,
            })?;
        raw_len += 1;
        last_data = Instant::now();
        milestones.extend(latch(&mut tracker, &[byte], start));
    }

    loop {
        let mut buf = [0u8; READ_CHUNK];
        let chunk: &[u8] = match port.read(&mut buf) {
            Err(_) => {
                recover(&mut port, opener, sleeper, opts.recovery_wait)?;
                last_data = Instant::now();
                continue;
            }
            Ok(0) => &[],
            Ok(n) if n > 0 && buf[0] == BREAK_BYTE => {
                recover(&mut port, opener, sleeper, opts.recovery_wait)?;
                last_data = Instant::now();
                continue;
            }
            Ok(n) => &buf[..n],
        };
        let now = Instant::now();
        if chunk.is_empty() {
            if now.duration_since(last_data) > opts.silence_timeout {
                break;
            }
            continue;
        }
        last_data = now;
        raw_len += chunk.len();
        raw_file
            .write_all(chunk)
            .map_err(|source| BootCaptureError::LogFile {
                path: console_raw.clone(),
                source,
            })?;
        log_file
            .write_all(String::from_utf8_lossy(chunk).as_bytes())
            .and_then(|()| log_file.flush())
            .map_err(|source| BootCaptureError::LogFile {
                path: console_log.clone(),
                source,
            })?;
        milestones.extend(latch(&mut tracker, chunk, start));
        // `raw_file` is flushed on drop; per-chunk flush parity only
        // applies to console.log (Python flushes the text log).
    }
    port.close();

    Ok(BootCaptureReport {
        transition,
        milestones,
        raw_len,
        console_raw,
        console_log,
    })
}

/// Feed one chunk through the shared tracker, keeping only milestones
/// newly latched by it (each with its phase-2-relative timestamp).
fn latch(
    tracker: &mut BootMilestoneTracker,
    chunk: &[u8],
    start: Instant,
) -> Vec<(BootMilestone, Duration)> {
    tracker
        .feed(chunk)
        .into_iter()
        .map(|(milestone, _detail)| (milestone, start.elapsed()))
        .collect()
}

/// The one recovery primitive, #412 `reopen_after_break` semantics:
/// close (idempotent — releases TIOCEXCL even on a wedged handle),
/// sleep the recovery wait, reopen FRESH, flush stale input. Used for
/// the post-break phase-2 entry AND both mid-capture triggers (read
/// error, break chunk).
fn recover<O: PortOpener, S: Sleeper>(
    port: &mut Box<dyn ConsoleIo>,
    opener: &mut O,
    sleeper: &S,
    recovery_wait: Duration,
) -> Result<(), BootCaptureError> {
    port.close();
    sleeper.sleep(recovery_wait);
    *port = opener.open()?;
    port.reset_input_buffer();
    Ok(())
}

/// `serial/<session>` layout helper for callers mirroring the script's
/// default log directory (`Path::new("serial").join(session)`).
#[must_use]
pub fn session_dir(root: &Path, session: &str) -> PathBuf {
    root.join("serial").join(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn break_signatures_are_the_two_phase1_bytes() {
        assert!(is_break_byte(0x00));
        assert!(is_break_byte(0xff));
        assert!(!is_break_byte(b'U'));
        assert!(!is_break_byte(0x01));
    }

    #[test]
    fn defaults_match_the_python_script() {
        let opts = BootCaptureOptions::new("serial/boot");
        assert_eq!(opts.silence_timeout, Duration::from_secs(15));
        assert_eq!(opts.recovery_wait, Duration::from_secs(3));
        assert_eq!(opts.max_wait, Duration::ZERO);
        assert_eq!(opts.log_dir, PathBuf::from("serial/boot"));
    }

    #[test]
    fn session_dir_nests_under_serial() {
        assert_eq!(
            session_dir(Path::new("/tmp"), "nr7101"),
            PathBuf::from("/tmp/serial/nr7101")
        );
    }
}
