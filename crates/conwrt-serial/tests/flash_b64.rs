//! Base64 flash integration against a MOCK OpenWrt shell riding a real
//! pty pair — the Rust twin of running `scripts/serial-flash.py`
//! against a device. No `/dev/ttyUSB` and no host serial port is ever
//! opened; the slave side of the pty is the console, the master side is
//! a scripted BusyBox-ish shell that REALLY implements the wire
//! protocol: it accumulates the `echo '...' >> /tmp/fw.b64` lines,
//! decodes on `base64 -d`, and computes `sha256sum` over ITS OWN decoded
//! copy — so the verification under test is genuinely receiver-side
//! (#405: a sender's `Ok` is a claim, not acceptance).
//!
//! Pins:
//!
//! * round-trip: chunks delivered byte-exact, decode succeeds, the
//!   device hash equals the host hash, `Ok(FlashReport)`, progress
//!   fires on the `PROGRESS_EVERY` cadence and at the end,
//! * hash mismatch (the device's copy differs) ⇒ `HashMismatch`, never
//!   a success,
//! * decode failure on the device ⇒ `DecodeFailed`,
//! * `trigger_sysupgrade` writes the line and does not wait,
//! * `chunk_size == 0` is refused before any wire traffic.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use nix::pty::openpty;
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr};
use nix::unistd::ttyname;
use sha2::{Digest, Sha256};

use conwrt_serial::flash::{FlashError, FlashOptions, flash_base64, trigger_sysupgrade};
use conwrt_serial::{SerialConsole, image_sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceMode {
    /// Honest BusyBox shell.
    Honest,
    /// `base64 -d` decodes, then the file loses its last byte — a
    /// corrupt transfer the device reports truthfully.
    CorruptTail,
    /// `base64 -d` fails (applet missing / full /tmp).
    DecodeFails,
}

#[derive(Debug, Default)]
struct DeviceState {
    staging: Vec<u8>,
    fw_bin: Vec<u8>,
    sysupgrade_line: Option<String>,
}

struct MockDevice {
    state: Arc<Mutex<DeviceState>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockDevice {
    fn spawn(master: std::fs::File, mode: DeviceMode) -> Self {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let shared = Arc::clone(&state);
        let handle = thread::spawn(move || device_shell(master, mode, shared));
        Self {
            state,
            handle: Some(handle),
        }
    }

    fn join(mut self) -> DeviceState {
        let handle = self.handle.take().expect("handle");
        handle.join().expect("device shell");
        let mut state = self.state.lock().unwrap();
        std::mem::take(&mut *state)
    }
}

/// The scripted BusyBox-ish shell: understands exactly the commands the
/// driver sends; replies carry `\r\n` endings like a real console. The
/// state lock is held only while mutating, never across the reply
/// write (the console's collector is the reader).
fn device_shell(master: std::fs::File, mode: DeviceMode, state: Arc<Mutex<DeviceState>>) {
    let mut writer = master.try_clone().expect("clone master");
    let mut reader = BufReader::new(master);
    loop {
        let mut raw = Vec::new();
        if reader.read_until(b'\n', &mut raw).unwrap_or(0) == 0 {
            return; // console closed — end of session
        }
        let line = String::from_utf8_lossy(&raw).trim().to_string();
        if line.is_empty() || line == "\u{3}" {
            continue;
        }
        if line.starts_with("rm -f /tmp/fw.b64") {
            writer.write_all(b"__RC0__\r\n").unwrap();
        } else if line.starts_with("echo '") && line.ends_with("' >> /tmp/fw.b64") {
            let b64 = &line["echo '".len()..line.len() - "' >> /tmp/fw.b64".len()];
            // `echo` appends a newline per line — the staging file is
            // newline-separated base64, exactly what BusyBox base64 -d eats.
            let mut st = state.lock().unwrap();
            st.staging.extend_from_slice(b64.as_bytes());
            st.staging.push(b'\n');
            // raw paced line: the driver drains the tty echo, no reply
        } else if line.starts_with("base64 -d") {
            if mode == DeviceMode::DecodeFails {
                writer
                    .write_all(b"base64: applet not found\r\n__RC1__\r\n")
                    .unwrap();
                continue;
            }
            let decoded = {
                // BusyBox base64 -d decodes LINE by line: each `echo`
                // line is its own padded segment.
                let st = state.lock().unwrap();
                String::from_utf8_lossy(&st.staging)
                    .lines()
                    .flat_map(|line| {
                        base64::engine::general_purpose::STANDARD
                            .decode(line.trim().as_bytes())
                            .expect("device-side b64 line is well-formed")
                    })
                    .collect::<Vec<u8>>()
            };
            let mut fw = decoded;
            if mode == DeviceMode::CorruptTail {
                fw.pop();
            }
            state.lock().unwrap().fw_bin = fw;
            writer.write_all(b"__RC0__\r\n").unwrap();
        } else if line.starts_with("sha256sum /tmp/fw.bin") {
            let digest = Sha256::digest(&state.lock().unwrap().fw_bin);
            let reply = format!("{}  /tmp/fw.bin\r\n__RC0__\r\n", hex(&digest));
            writer.write_all(reply.as_bytes()).unwrap();
        } else if line.starts_with("sysupgrade") {
            state.lock().unwrap().sysupgrade_line = Some(line);
        }
    }
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

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
    // The openpty slave fd stays open until open_console's own path-based
    // open completes (the caller drops it right after): a pts whose last
    // slave fd closes can refuse the reopen under CI load with EIO (#422
    // live signature: `open pty slave: OpenDevice … I/O error`).
    (
        std::fs::File::from(pair.master),
        std::fs::File::from(pair.slave),
        slave_path.display().to_string(),
    )
}

/// Fast timings for the harness: 5 ms pacing + 20 ms read bound.
///
/// Handoff order in every test: `open_console` BEFORE
/// `MockDevice::spawn`. Two races make the opposite order flake (#422):
/// (1) while no slave fd is open, master READS return EIO — the device
/// thread can read EOF and exit before the console ever opens;
/// (2) if the device thread panics (fd pressure under CI load), it
/// drops the master and the pts node vanishes — the console open then
/// fails with ENOENT on /dev/pts/N. Opening the console first pins the
/// node and the reader thread starts against a live slave.
fn fast_opts() -> FlashOptions {
    FlashOptions {
        chunk_size: 32,
        chunk_delay: Duration::from_millis(5),
        clear_timeout: Duration::from_secs(5),
        decode_timeout: Duration::from_secs(5),
        verify_timeout: Duration::from_secs(5),
    }
}

fn open_console(slave_path: &str) -> SerialConsole {
    // The held openpty slave closes the #422 race window by construction;
    // this bounded retry absorbs any residual load-induced EIO on the
    // reopen instead of failing the test with it.
    let mut last_err = None;
    for attempt in 1..=3 {
        match SerialConsole::with_baud(slave_path, 115_200, Duration::from_millis(20)) {
            Ok(console) => return console,
            Err(e) => {
                eprintln!("open pty slave attempt {attempt} failed: {e}");
                last_err = Some(e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    panic!("open pty slave after 3 attempts: {last_err:?}");
}

fn image(bytes: usize) -> Vec<u8> {
    (0..bytes).map(|i| (i % 251) as u8).collect()
}

/// Round-trip: 2048 bytes at 32 B/chunk = 64 chunks, so the
/// `PROGRESS_EVERY = 50` cadence fires mid-transfer AND at the end.
#[test]
fn round_trip_transfers_and_verifies_sha256_receiver_side() {
    let (master, _held_slave, slave_path) = pty_parts();
    let mut console = open_console(&slave_path);
    drop(_held_slave);
    let device = MockDevice::spawn(master, DeviceMode::Honest);
    let image = image(2048);
    let opts = fast_opts();

    let mut events = Vec::new();
    let report = flash_base64(&mut console, &image, &opts, |sent, total| {
        events.push((sent, total));
    })
    .expect("flash must verify");
    thread::sleep(Duration::from_millis(200)); // let the shell drain
    drop(console);
    let state = device.join();

    assert_eq!(report.chunks, 64);
    assert_eq!(report.bytes, 2048);
    assert_eq!(report.device_sha256, image_sha256(&image));
    assert_eq!(state.fw_bin, image, "device copy must equal the image");
    assert_eq!(state.sysupgrade_line, None, "no sysupgrade unless asked");
    assert_eq!(events.last(), Some(&(2048, 2048)));
    let mid = events.iter().any(|(s, _)| *s == 50 * 32);
    assert!(
        mid,
        "progress must fire on the 50-chunk cadence: {events:?}"
    );
}

/// #405 pinned: the sender did everything right, the DEVICE's copy is
/// corrupt — the driver must refuse, never trust its own `Ok`.
#[test]
fn corrupt_device_copy_fails_hash_verification() {
    let (master, _held_slave, slave_path) = pty_parts();
    let mut console = open_console(&slave_path);
    drop(_held_slave);
    let device = MockDevice::spawn(master, DeviceMode::CorruptTail);
    let image = image(700);
    let err = flash_base64(&mut console, &image, &fast_opts(), |_, _| {}).unwrap_err();
    thread::sleep(Duration::from_millis(100));
    drop(console);
    let state = device.join();

    match err {
        FlashError::HashMismatch { expected, actual } => {
            assert_eq!(expected, image_sha256(&image));
            assert_ne!(actual, expected);
            assert_eq!(state.fw_bin.len(), image.len() - 1);
        }
        other => panic!("expected HashMismatch, got {other:?}"),
    }
}

/// The decode step failing on the device surfaces as `DecodeFailed`
/// with the device output — verification is never reached.
#[test]
fn decode_failure_on_device_surfaces() {
    let (master, _held_slave, slave_path) = pty_parts();
    let mut console = open_console(&slave_path);
    drop(_held_slave);
    let device = MockDevice::spawn(master, DeviceMode::DecodeFails);
    let image = image(300);
    let err = flash_base64(&mut console, &image, &fast_opts(), |_, _| {}).unwrap_err();
    thread::sleep(Duration::from_millis(100));
    drop(console);
    device.join();

    match err {
        FlashError::DecodeFailed { rc, output } => {
            assert_eq!(rc, 1);
            assert!(output.contains("applet not found"), "output: {output}");
        }
        other => panic!("expected DecodeFailed, got {other:?}"),
    }
}

/// After a verified flash, the sysupgrade trigger writes the exact
/// Python-parity line and returns without waiting for a reply.
#[test]
fn trigger_sysupgrade_writes_line_without_waiting() {
    let (master, _held_slave, slave_path) = pty_parts();
    let mut console = open_console(&slave_path);
    drop(_held_slave);
    let device = MockDevice::spawn(master, DeviceMode::Honest);
    let image = image(64);
    flash_base64(&mut console, &image, &fast_opts(), |_, _| {}).expect("flash before sysupgrade");
    trigger_sysupgrade(&mut console).expect("trigger");
    thread::sleep(Duration::from_millis(200)); // shell records the line
    drop(console);
    let state = device.join();

    assert_eq!(
        state.sysupgrade_line.as_deref(),
        Some("sysupgrade -n /tmp/fw.bin")
    );
}

/// `chunk_size == 0` is refused before any wire traffic.
#[test]
fn zero_chunk_size_is_refused() {
    let (master, _held_slave, slave_path) = pty_parts();
    let mut console = open_console(&slave_path);
    drop(_held_slave);
    let device = MockDevice::spawn(master, DeviceMode::Honest);
    let mut opts = fast_opts();
    opts.chunk_size = 0;
    let err = flash_base64(&mut console, b"image", &opts, |_, _| {}).unwrap_err();
    drop(console);
    device.join();
    assert!(matches!(err, FlashError::ZeroChunkSize), "got {err:?}");
}
