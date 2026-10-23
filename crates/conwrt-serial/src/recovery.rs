//! # Wedge recovery (rtl838x livelock field manual, 2026-10-20..22)
//!
//! Encodes the bench-proven recovery channel for SoC livelocks where
//! task context is frozen but interrupt context (and serial BREAK
//! handling) survives:
//!
//! * **sysrq over BREAK** — a UART break followed by a single key char is
//!   delivered to the kernel in *interrupt context* (8250 IRQ path), so it
//!   works when the console's task-side input (getty/echo) is already dead.
//!   Validated 25+ times on a wedged RTL8382: `b` reboots in ~1 s.
//! * **Wedge signature** — DUT network dark + console output still flowing
//!   = livelock (distinguish from total death, power loss, or a normal
//!   reboot loop). Detection must run from the *observer* host: never
//!   probe the DUT's own shell.
//! * **The console must be consumed** — an unread console (printk stream
//!   with no reader) congests the tty layer and can *deepen* a degraded
//!   state; the recovery driver always keeps a reader attached.
//!
//! Refs: Amperstrand/conwrt-bench issue #66 (full instrumented evidence
//! chain), wedge-lab results (BASE 2/2, H1/H2 refuted, H3 boot-deadlock).

use std::io;
use std::time::{Duration, Instant};

use crate::io::ConsoleIo;

/// sysrq functions reachable via BREAK+key on a stock kernel (see
/// Documentation/admin-guide/sysrq.rst). Recovery-relevant subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysrqKey {
    /// Reboot immediately (no sync/umount) — the wedge escape door.
    Reboot,
    /// Show task states (diagnostics during livelock).
    ShowTasks,
    /// Show registers/PC of the interrupted context (diagnostics).
    ShowRegisters,
    /// Show memory.
    ShowMemory,
    /// Crash (panic) — for capturing a dump when reboot is undesired.
    Crash,
}

impl SysrqKey {
    fn as_char(self) -> u8 {
        match self {
            SysrqKey::Reboot => b'b',
            SysrqKey::ShowTasks => b't',
            SysrqKey::ShowRegisters => b'p',
            SysrqKey::ShowMemory => b'm',
            SysrqKey::Crash => b'c',
        }
    }
}

/// Default pause between the break condition and the key byte.
/// Field-tuned on FT232R ↔ RTL8382 at 115200: 200 ms is reliable;
/// shorter pauses occasionally merge break and data framing.
pub const SYSRQ_KEY_DELAY: Duration = Duration::from_millis(200);

/// Send one sysrq function over a UART break on an open console.
///
/// The break is asserted via the transport's break-capable write path;
/// on transports without break support (plain TCP bridges that relay
/// only data bytes) this returns [`RecoveryError::NoBreakSupport`] —
/// sysrq-over-BREAK is a local-adapter capability.
/// Break-capable transports. The stock [`ConsoleIo`] is data-only; local
/// serial adapters implement this to enable sysrq-over-BREAK. TCP console
/// bridges that relay only data bytes do not (they report [`None`]).
pub trait BreakIo: ConsoleIo {
    /// Assert a UART break condition for `dur` (TCSBRK-equivalent).
    fn send_break_for(&mut self, dur: Duration) -> io::Result<()>;
}

/// Send one sysrq function over a UART break on a break-capable console.
pub fn send_sysrq(io: &mut dyn BreakIo, key: SysrqKey) -> Result<(), RecoveryError> {
    io.send_break_for(Duration::from_millis(250))
        .map_err(|e| RecoveryError::Io(e.to_string()))?;
    std::thread::sleep(SYSRQ_KEY_DELAY);
    io.write_all_bytes(&[key.as_char()])
        .map_err(|e| RecoveryError::Io(e.to_string()))?;
    Ok(())
}

/// Classified state of a possibly-wedged device, from observer-side
/// signals only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceState {
    /// Network answers — nothing to do.
    Healthy,
    /// Network dark, console output flowing within `window`:
    /// the livelock signature (IRQ context alive, tasks frozen).
    WedgedLivelock,
    /// Console output recently went quiet too: rebooting, powering up,
    /// or a deeper hang. Recovery is NOT proven safe to skip.
    ConsoleWentQuiet,
    /// No signals at all (observer-side outage or device off).
    Unreachable,
}

/// Classify a device from two observer-side probes: last console output
/// age and network liveness.
pub fn classify(
    console_output_age: Option<Duration>,
    net_alive: bool,
    quiet_threshold: Duration,
) -> DeviceState {
    if net_alive {
        return DeviceState::Healthy;
    }
    match console_output_age {
        None => DeviceState::Unreachable,
        Some(age) if age <= quiet_threshold => DeviceState::WedgedLivelock,
        Some(_) => DeviceState::ConsoleWentQuiet,
    }
}

/// Reboot a wedged device via BREAK + sysrq-b and wait for the boot
/// marker on the console. `boot_marker` is a raw byte pattern that the
/// target's bootloader/kernel prints at boot start (e.g.
/// `b"Starting kernel"` or a bootloader banner).
pub fn reboot_wedged(
    io: &mut dyn BreakIo,
    boot_marker: &[u8],
    timeout: Duration,
) -> Result<RecoveryOutcome, RecoveryError> {
    send_sysrq(io, SysrqKey::Reboot)?;
    let deadline = Instant::now() + timeout;
    let mut seen = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    while Instant::now() < deadline {
        let n = io
            .read(&mut chunk)
            .map_err(|e| RecoveryError::Io(e.to_string()))?;
        if n > 0 {
            seen.extend_from_slice(&chunk[..n]);
            if contains_subslice(&seen, boot_marker) {
                // keep the reader attached through boot: congested console
                // output with no consumer can deepen degraded states.
                drain_until_quiet(io, Duration::from_secs(30))?;
                return Ok(RecoveryOutcome::Rebooting);
            }
        }
    }
    Err(RecoveryError::NoBootMarker {
        captured: seen.len(),
    })
}

/// Keep reading until `quiet` passes with no bytes (bounded).
fn drain_until_quiet(io: &mut dyn ConsoleIo, quiet: Duration) -> Result<(), RecoveryError> {
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut last = Instant::now();
    let mut chunk = [0u8; 4096];
    while Instant::now() < deadline {
        let n = io
            .read(&mut chunk)
            .map_err(|e| RecoveryError::Io(e.to_string()))?;
        if n > 0 {
            last = Instant::now();
        } else if last.elapsed() >= quiet {
            return Ok(());
        }
    }
    Ok(())
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len().max(1)).any(|w| w == needle)
}

/// Result of a successful recovery action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Result of a successful recovery action.
pub enum RecoveryOutcome {
    /// sysrq-b accepted; the boot marker was observed on the console.
    Rebooting,
}

#[derive(Debug)]
/// Failures of the wedge-recovery path.
pub enum RecoveryError {
    /// Underlying console transport failure.
    Io(String),
    /// The transport cannot assert a UART break (sysrq unavailable).
    /// The transport cannot assert a UART break (sysrq unavailable).
    NoBreakSupport,
    /// BREAK+b sent but no boot marker observed within the timeout.
    /// BREAK+b sent but no boot marker observed within the timeout.
    /// `captured` is how many console bytes were seen while waiting.
    NoBootMarker {
        /// Console bytes observed while waiting for the marker.
        captured: usize,
    },
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryError::Io(e) => write!(f, "console io error: {e}"),
            RecoveryError::NoBreakSupport => write!(f, "transport cannot send UART break"),
            RecoveryError::NoBootMarker { captured } => write!(
                f,
                "no boot marker after sysrq-b ({} bytes captured)",
                captured
            ),
        }
    }
}

impl std::error::Error for RecoveryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_table() {
        let t = Duration::from_secs(5);
        assert_eq!(classify(None, true, t), DeviceState::Healthy);
        assert_eq!(
            classify(Some(Duration::from_secs(1)), false, t),
            DeviceState::WedgedLivelock
        );
        assert_eq!(
            classify(Some(Duration::from_secs(60)), false, t),
            DeviceState::ConsoleWentQuiet
        );
        assert_eq!(classify(None, false, t), DeviceState::Unreachable);
    }

    #[test]
    fn marker_matching() {
        assert!(contains_subslice(
            b"xx Starting kernel.\r\n",
            b"Starting kernel"
        ));
        assert!(!contains_subslice(b"booting", b"Starting kernel"));
    }
}
