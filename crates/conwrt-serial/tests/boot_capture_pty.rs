//! Boot-capture integration over a REAL pty pair and the real
//! `serialport-rs` path — the Rust twin of running
//! `scripts/serial-boot-capture.py` against a scripted device. No
//! `/dev/ttyUSB` and no host serial port is ever opened: the slave side
//! of the pty IS the device under test.
//!
//! Pins:
//!
//! * phase 1: `0x00` (and `0xff`) break byte ⇒ BreakDetected, any other
//!   byte ⇒ AlreadyOn on the same port,
//! * post-break: the `--recovery-wait` gap is real (elapsed ≥ wait),
//!   the reopen is fresh, and the boot stream that follows is captured
//!   with milestones latched by the shared probe-core tracker (split
//!   across chunk boundaries included),
//! * `console.raw` / `console.log` land under the session dir,
//! * a break MID-capture runs the same recovery and keeps capturing,
//! * silence timeout ends the capture.
//!
//! The pty MASTER stays alive in the test scope for the whole capture
//! (peer threads write through clones): a master dropped early destroys
//! the pts and fails the slave read — not the behavior under test.

use std::io::Write;
use std::os::fd::AsFd;
use std::thread;
use std::time::{Duration, Instant};

use nix::pty::openpty;
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr};
use nix::unistd::ttyname;

use conwrt_probe_core::milestones::BootMilestone;
use conwrt_serial::boot_capture::{
    BootCaptureError, BootCaptureOptions, PowerTransition, capture_boot,
};
use conwrt_serial::{BootCaptureReport, Sleeper, SpecOpener, StdSleeper};

const RECOVERY_WAIT: Duration = Duration::from_millis(300);
const SILENCE_TIMEOUT: Duration = Duration::from_millis(400);
const BOOT_PREFIX: &str = "Z-LOADER V1.30 | 06/03/2020 08:39:30\r\nMultiboot Listening...\r\n";
const KERNEL_LINES: &str =
    "Starting kernel ...\r\n[    3.873775] init: - preinit -\r\nroot@OpenWrt:~# \r\n";

fn pty_parts() -> (std::fs::File, std::fs::File, String) {
    let pair = openpty(None, None).expect("openpty");
    let mut term = tcgetattr(&pair.slave).expect("tcgetattr slave");
    cfmakeraw(&mut term);
    tcsetattr(
        pair.slave.as_fd(),
        nix::sys::termios::SetArg::TCSANOW,
        &term,
    )
    .expect("setraw slave");
    let slave_path = ttyname(&pair.slave).expect("ttyname slave");
    // Held until the test's scope ends: a pts whose last slave fd closes
    // can refuse the later path-based reopen under CI load with EIO
    // (#422 — same fix as flash_b64's harness).
    (
        std::fs::File::from(pair.master),
        std::fs::File::from(pair.slave),
        slave_path.display().to_string(),
    )
}

fn opts(tag: &str) -> BootCaptureOptions {
    let mut opts = BootCaptureOptions::new(std::env::temp_dir().join(format!(
        "conwrt-serialcap-boot-{}-{tag}",
        std::process::id()
    )));
    opts.recovery_wait = RECOVERY_WAIT;
    opts.silence_timeout = SILENCE_TIMEOUT;
    opts.max_wait = Duration::from_secs(20);
    opts
}

fn run_capture(slave_path: &str, opts: &BootCaptureOptions) -> (BootCaptureReport, Duration) {
    let mut opener = SpecOpener {
        spec: slave_path.to_string(),
        baud: 115_200,
        timeout: Duration::from_millis(100),
    };
    let start = Instant::now();
    let report = capture_boot(&mut opener, opts, &StdSleeper).expect("capture_boot");
    (report, start.elapsed())
}

fn milestone_names(report: &BootCaptureReport) -> Vec<BootMilestone> {
    report.milestones.iter().map(|(m, _)| *m).collect()
}

/// The scripted device: break byte → dark through the recovery window →
/// boot stream (with the KernelStart pattern SPLIT across two writes to
/// pin rolling-buffer matching) → silence.
#[test]
fn break_then_recovery_then_boot_stream_latches_milestones() {
    let (master, _held_slave, slave_path) = pty_parts();
    let device = {
        let mut dev = master.try_clone().expect("clone master");
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            dev.write_all(b"\x00").unwrap();
            thread::sleep(RECOVERY_WAIT + Duration::from_millis(150));
            dev.write_all(BOOT_PREFIX.as_bytes()).unwrap();
            dev.write_all(b"U-Boot 2026.10 (Oct 21 2026)\r\n").unwrap();
            dev.write_all(b"Starting ker").unwrap();
            thread::sleep(Duration::from_millis(60));
            dev.write_all(b"nel ...\r\n").unwrap();
            dev.write_all(KERNEL_LINES.as_bytes()).unwrap();
        })
    };
    let o = opts("break-boot");
    let (report, elapsed) = run_capture(&slave_path, &o);
    device.join().unwrap();
    drop(master);

    assert_eq!(report.transition, PowerTransition::BreakDetected);
    assert!(
        elapsed >= RECOVERY_WAIT,
        "recovery wait missing: {elapsed:?}"
    );
    assert_eq!(
        milestone_names(&report),
        vec![
            BootMilestone::UbootBanner,
            BootMilestone::KernelStart,
            BootMilestone::ProcdPreinit,
            BootMilestone::LoginPrompt,
        ]
    );
    let times: Vec<Duration> = report.milestones.iter().map(|(_, t)| *t).collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]), "times sorted");

    let raw = std::fs::read(&report.console_raw).expect("console.raw");
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("Z-LOADER"), "raw missing preamble: {text:?}");
    assert!(text.contains("Starting kernel ..."), "split marker lost");
    assert!(!raw.contains(&0u8), "break byte must not be captured");
    assert_eq!(report.raw_len, raw.len());
    let log = std::fs::read_to_string(&report.console_log).expect("console.log");
    assert!(log.contains("root@OpenWrt"));

    std::fs::remove_dir_all(&o.log_dir).ok();
}

/// Device already on: real data with no break keeps the SAME port and
/// captures from the first byte.
#[test]
fn already_on_captures_without_reopen() {
    let (master, _held_slave, slave_path) = pty_parts();
    let device = {
        let mut dev = master.try_clone().expect("clone master");
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            dev.write_all(b"U-Boot 2026.10 boot in progress\r\n")
                .unwrap();
            dev.write_all(KERNEL_LINES.as_bytes()).unwrap();
        })
    };
    let o = opts("already-on");
    let (report, _elapsed) = run_capture(&slave_path, &o);
    device.join().unwrap();
    drop(master);

    assert_eq!(report.transition, PowerTransition::AlreadyOn);
    let names = milestone_names(&report);
    assert!(names.contains(&BootMilestone::LoginPrompt));
    let raw = std::fs::read(&report.console_raw).expect("console.raw");
    assert!(raw.starts_with(b"U-Boot"), "first byte kept: {raw:?}");

    std::fs::remove_dir_all(&o.log_dir).ok();
}

/// `0xff` is a break signature too (Python `wait_for_break` parity).
#[test]
fn ff_byte_is_a_break_signature() {
    let (master, _held_slave, slave_path) = pty_parts();
    let device = {
        let mut dev = master.try_clone().expect("clone master");
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            dev.write_all(b"\xff").unwrap();
            // stays dark; silence ends the capture
        })
    };
    let o = opts("ff-break");
    let (report, elapsed) = run_capture(&slave_path, &o);
    device.join().unwrap();
    drop(master);

    assert_eq!(report.transition, PowerTransition::BreakDetected);
    assert!(elapsed >= RECOVERY_WAIT);
    assert!(report.milestones.is_empty());
    assert_eq!(report.raw_len, 0);

    std::fs::remove_dir_all(&o.log_dir).ok();
}

/// A break MID-capture (device power-cycles while booting) runs the
/// same close → wait → reopen recovery and keeps capturing the second
/// boot attempt.
#[test]
fn mid_capture_break_recovers_and_captures_second_boot() {
    let (master, _held_slave, slave_path) = pty_parts();
    let device = {
        let mut dev = master.try_clone().expect("clone master");
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            dev.write_all(b"U-Boot 2026.10 first attempt\r\n").unwrap();
            thread::sleep(Duration::from_millis(150));
            dev.write_all(b"\x00").unwrap();
            thread::sleep(RECOVERY_WAIT + Duration::from_millis(150));
            dev.write_all(KERNEL_LINES.as_bytes()).unwrap();
        })
    };
    let o = opts("mid-break");
    let (report, elapsed) = run_capture(&slave_path, &o);
    device.join().unwrap();
    drop(master);

    assert_eq!(report.transition, PowerTransition::AlreadyOn);
    assert!(
        elapsed >= RECOVERY_WAIT,
        "mid-capture recovery wait missing: {elapsed:?}"
    );
    assert_eq!(
        milestone_names(&report),
        vec![
            BootMilestone::UbootBanner,
            BootMilestone::KernelStart,
            BootMilestone::ProcdPreinit,
            BootMilestone::LoginPrompt,
        ]
    );
    let raw = std::fs::read(&report.console_raw).expect("console.raw");
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("first attempt"), "pre-break bytes kept");
    assert!(text.contains("root@OpenWrt"), "post-recovery bytes kept");
    assert!(!raw.contains(&0u8), "break chunk discarded");

    std::fs::remove_dir_all(&o.log_dir).ok();
}

/// Phase 1 with `max_wait` and a device that never speaks: typed
/// timeout, no hang.
#[test]
fn wait_timeout_is_typed() {
    let (master, _held_slave, slave_path) = pty_parts();
    let mut opener = SpecOpener {
        spec: slave_path,
        baud: 115_200,
        timeout: Duration::from_millis(50),
    };
    let mut o = opts("timeout");
    o.max_wait = Duration::from_millis(300);
    let err = capture_boot(&mut opener, &o, &StdSleeper).expect_err("must time out");
    drop(master);
    assert!(
        matches!(err, BootCaptureError::WaitTimeout { .. }),
        "got: {err}"
    );
}

/// StdSleeper sleeps for real (sanity that the injected sleeper path is
/// the production path in these tests).
#[test]
fn std_sleeper_is_real() {
    let start = Instant::now();
    StdSleeper.sleep(Duration::from_millis(50));
    assert!(start.elapsed() >= Duration::from_millis(50));
}
