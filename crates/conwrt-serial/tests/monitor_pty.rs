//! Console-monitor integration over a real pty pair — the Rust twin of
//! running `scripts/serial-console.py --monitor` against a device. No
//! `/dev/ttyUSB` and no host serial port is ever opened.
//!
//! Pins:
//!
//! * RX boot stream with three stage transitions (uboot → kernel →
//!   openwrt) latches the stage history and lands in both logs,
//! * mailbox commands (special token AND raw bytes) are dispatched to
//!   the wire and logged `[TX]`,
//! * `session.json` is real JSON (parsed back with serde_json) with
//!   the byte counters, final stage, and transition records,
//! * `console.log` carries `[RX …]` markers and the `_format_bytes`
//!   escape rendering; `console.raw` is the exact byte stream.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::pty::openpty;
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr};
use nix::unistd::ttyname;

use conwrt_serial::monitor::{BootStage, MonitorConfig, MonitorSession};
use conwrt_serial::{PortOpener, SpecOpener, open_port};

/// `YYYY-MM-DD HH:MM:SS` now — lexicographic compare works for this
/// fixed-width format. (civil-from-days, Howard Hinnant)
fn humantime_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86_400);
    let (h, _m, s) = (
        secs.rem_euclid(86_400) / 3_600,
        secs.rem_euclid(3_600) / 60,
        secs.rem_euclid(60),
    );
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 9 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

fn pty_parts() -> (std::fs::File, String) {
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
    drop(pair.slave);
    (
        std::fs::File::from(pair.master),
        slave_path.display().to_string(),
    )
}

fn read_until(master: &std::fs::File, needle: &[u8], timeout: Duration) -> Vec<u8> {
    let deadline = std::time::Instant::now() + timeout;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while std::time::Instant::now() < deadline {
        let mut fds = [PollFd::new(master.as_fd(), PollFlags::POLLIN)];
        let t = PollTimeout::try_from(50u32).expect("poll timeout");
        if poll(&mut fds, t).expect("poll") > 0 {
            let mut m = master;
            match m.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if !needle.is_empty() && buf.windows(needle.len()).any(|w| w == needle) {
                        break;
                    }
                }
            }
        }
    }
    buf
}

fn test_paths(tag: &str) -> (PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("conwrt-monitor-{}-{tag}", std::process::id()));
    let mailbox = base.join("mailbox");
    let _ = std::fs::remove_dir_all(&base);
    (base.clone(), mailbox)
}

#[test]
fn monitor_latches_stages_logs_both_streams_and_dispatches_mailbox() {
    let (master, slave_path) = pty_parts();
    let (log_base, mailbox) = test_paths("main");

    let boot_stream: &[&[u8]] = &[
        b"\x00\r\n", // pre-boot noise incl. a NUL — escape-rendered, not a stage
        b"U-Boot 2026.10 (Oct 21 2026)\r\n",
        b"Starting kernel ...\r\n",
        b"BusyBox v1.36 built-in shell (ash)\r\nroot@OpenWrt:~# ",
    ];

    let device = {
        let mut dev = master.try_clone().expect("clone master");
        thread::spawn(move || {
            for chunk in boot_stream {
                dev.write_all(chunk).unwrap();
                thread::sleep(Duration::from_millis(120));
            }
        })
    };

    let mut opener = SpecOpener {
        spec: slave_path,
        baud: 115_200,
        timeout: Duration::from_millis(20),
    };
    let port = opener.open().expect("open port");
    let config = MonitorConfig {
        session_name: "lab-session".to_string(),
        log_dir: log_base.clone(),
        mailbox_path: mailbox.clone(),
    };
    let mut session = MonitorSession::open(port, config).expect("session");

    // drain the boot stream
    let stop = AtomicBool::new(false);
    for _ in 0..80 {
        session.step().expect("step");
        if session.stage() == BootStage::Openwrt {
            break;
        }
        thread::sleep(Duration::from_millis(40));
    }
    assert_eq!(session.stage(), BootStage::Openwrt);

    // mailbox: special token + raw bytes
    std::fs::write(&mailbox, b"CTRLC").unwrap();
    session.step().expect("dispatch ctrlc");
    let m = master;
    let seen_ctrl = read_until(&m, b"\x03", Duration::from_secs(3));
    assert!(seen_ctrl.contains(&0x03), "CTRLC token must hit the wire");
    assert!(!mailbox.exists(), "mailbox consumed (unlinked)");

    std::fs::write(&mailbox, b"help").unwrap();
    session.step().expect("dispatch help");
    let seen_help = read_until(&m, b"help", Duration::from_secs(3));
    assert!(seen_help.ends_with(b"help") || seen_help.windows(4).any(|w| w == b"help"));
    let meta = session.write_session_meta().expect("meta");
    stop.store(true, Ordering::Relaxed);
    device.join().unwrap();

    // session.json is real JSON and carries the truth
    let json: serde_json::Value = serde_json::from_str(&meta).expect("meta must be valid JSON");
    assert_eq!(json["session_name"], "lab-session");
    assert_eq!(json["final_boot_stage"], "openwrt");
    assert_eq!(json["total_tx_bytes"], 1 + 4); // \x03 + "help"
    assert!(json["total_rx_bytes"].as_u64().unwrap() > 0);
    // start_time is the OPEN timestamp: strictly earlier than the
    // meta-write wall clock (the session ran for seconds)
    let now = humantime_now();
    assert!(
        json["start_time"].as_str().unwrap() < now.as_str(),
        "start_time {:?} must predate the meta write",
        json["start_time"]
    );
    assert_eq!(
        json["boot_stage_transitions"]
            .as_array()
            .expect("transitions")
            .len(),
        3
    );

    let session_dir = log_base.join("lab-session");
    let raw = std::fs::read(session_dir.join("console.raw")).expect("console.raw");
    let expected_stream: Vec<u8> = boot_stream.concat();
    assert_eq!(raw, expected_stream, "raw log must be byte-exact");

    let log = std::fs::read_to_string(session_dir.join("console.log")).expect("console.log");
    assert!(log.contains("[RX "), "RX markers: {log:?}");
    assert!(log.contains("[TX "), "TX markers: {log:?}");
    assert!(log.contains("U-Boot 2026.10"), "{log:?}");
    assert!(log.contains("\\0"), "NUL must render escaped: {log:?}");
    assert!(log.contains("Ctrl-C"), "token label logged: {log:?}");

    let _ = std::fs::remove_dir_all(&log_base);
}

/// The Python "FIFO" is a mailbox FILE: absent mailbox is a no-op,
/// present-but-empty is consumed without a write.
#[test]
fn monitor_mailbox_absent_and_empty_are_noops() {
    let (master, slave_path) = pty_parts();
    let (log_base, mailbox) = test_paths("noop");
    let mut opener = SpecOpener {
        spec: slave_path,
        baud: 115_200,
        timeout: Duration::from_millis(10),
    };
    let port: Box<dyn conwrt_serial::ConsoleIo> = opener.open().expect("open");
    let mut session = MonitorSession::open(
        port,
        MonitorConfig {
            session_name: "noop".into(),
            log_dir: log_base.clone(),
            mailbox_path: mailbox.clone(),
        },
    )
    .expect("session");

    session.step().expect("absent mailbox no-op");
    assert!(!mailbox.exists());

    std::fs::write(&mailbox, b"").unwrap();
    session.step().expect("empty mailbox no-op");
    assert!(!mailbox.exists(), "empty mailbox still consumed");
    assert_eq!(session.total_tx(), 0, "nothing may hit the wire");

    drop(session);
    drop(master);
    let _ = std::fs::remove_dir_all(&log_base);
}

/// A dropped peer surfaces as a typed read error out of `step` — the
/// loop stops for the operator, Python reader parity.
#[test]
fn monitor_peer_gone_is_a_typed_error() {
    let (master, slave_path) = pty_parts();
    let (log_base, _mailbox) = test_paths("gone");
    let port = open_port(&slave_path, 115_200, Duration::from_millis(20)).expect("open");
    let mut session = MonitorSession::open(
        port,
        MonitorConfig {
            session_name: "gone".into(),
            log_dir: log_base.clone(),
            mailbox_path: _mailbox,
        },
    )
    .expect("session");
    drop(master);
    // slave read against a master-less pts errors (or stays silent
    // until the pts is reaped); a few steps are enough to observe it
    for _ in 0..10 {
        if session.step().is_err() {
            let _ = std::fs::remove_dir_all(&log_base);
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("expected a typed read error after the peer vanished");
}
