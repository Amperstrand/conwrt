//! Integration over a REAL pty pair and the real `serialport-rs` path —
//! the Rust twin of `tests/test_serial_transport.py`'s local-/dev
//! characterization suite. No `/dev/ttyUSB` and no host serial port is
//! ever opened: the slave side of a pty IS the device under test.
//!
//! Pins (1:1 with the Python suite):
//!
//! * open/configure on a real tty device node,
//! * `activate` sends Enter and reads peer bytes,
//! * `run` collects `__RC0__` / `__RC1__` / timeout rc=2,
//! * `send_script` delivers line chunks via `echo '...' >>` staging,
//! * the FT232R break recovery: a `0x00` byte mid-command triggers
//!   close → 3 s wait → reopen fresh → collect succeeds (elapsed ≥ 3 s),
//! * port-goes-away: master closed mid-run ⇒ recovery runs and the
//!   failed reopen propagates (a vanished pts cannot be reopened).

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::thread;
use std::time::{Duration, Instant};

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::pty::openpty;
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr};
use nix::unistd::ttyname;

use conwrt_serial::SerialConsole;

/// Read from the pty master until `needle` appears (bounded by timeout).
fn master_read_until(master: &std::fs::File, needle: &[u8], timeout: Duration) -> Vec<u8> {
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while Instant::now() < deadline && !contains(&buf, needle) {
        let mut fds = [PollFd::new(master.as_fd(), PollFlags::POLLIN)];
        let t = PollTimeout::try_from(50u32).expect("poll timeout");
        let ready = poll(&mut fds, t).expect("poll master");
        if ready > 0 {
            let mut m = master;
            match m.read(&mut chunk) {
                Ok(0) | Err(_) => break, // peer gone
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
    assert!(
        contains(&buf, needle),
        "expected {needle:?} from console, got {buf:?}"
    );
    buf
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn open_slave(path: &str) -> SerialConsole {
    SerialConsole::with_baud(path, 115_200, Duration::from_millis(200)).expect("open pty slave")
}

fn pty_parts() -> (std::fs::File, String) {
    let pair = openpty(None, None).expect("openpty");
    // Raw slave line discipline (no echo, no CR/LF translation): the pair
    // is a deterministic byte pipe, Python `tty.setraw` fixture parity.
    let mut term = tcgetattr(&pair.slave).expect("tcgetattr slave");
    cfmakeraw(&mut term);
    tcsetattr(
        pair.slave.as_fd(),
        nix::sys::termios::SetArg::TCSANOW,
        &term,
    )
    .expect("setraw slave");
    let slave_path = ttyname(&pair.slave).expect("ttyname slave");
    // serialport's TIOCEXCL forbids a second slave holder: drop the fixture
    // fd and let serialport own the pts; the open MASTER keeps it alive.
    drop(pair.slave);
    (
        std::fs::File::from(pair.master),
        slave_path.display().to_string(),
    )
}

fn run_with_peer(
    console: &mut SerialConsole,
    master: &std::fs::File,
    cmd: &str,
    reply: &[u8],
) -> conwrt_serial::CmdOutcome {
    let reply = reply.to_vec();
    let peer = master.try_clone().expect("clone master");
    let needle = format!("{cmd} && echo").into_bytes();
    let handle = thread::spawn(move || {
        master_read_until(&peer, &needle, Duration::from_secs(10));
        let mut p = peer;
        p.write_all(&reply).unwrap();
    });
    let out = console.run(cmd, Duration::from_secs(5)).expect("run");
    handle.join().expect("responder");
    out
}

#[test]
fn open_configures_real_tty_device_node() {
    let (_master, slave_path) = pty_parts();
    let mut console = open_slave(&slave_path);
    console.close();
}

#[test]
fn activate_sends_newline_and_reads_peer_bytes() {
    let (master, slave_path) = pty_parts();
    let mut console = open_slave(&slave_path);
    // NB: bytes queued before the console opens may be flushed by the port
    // open itself — write the peer banner AFTER (Python fixture note).
    thread::sleep(Duration::from_millis(50));
    let mut m = master;
    m.write_all(b"BusyBox v1.36 built-in shell (ash)\r\n")
        .unwrap();
    let out = console.activate().expect("activate");
    assert!(out.contains("BusyBox v1.36"), "activate output: {out:?}");
    // activate() must have sent exactly one newline to the device
    let seen = master_read_until(&m, b"\n", Duration::from_secs(3));
    assert_eq!(seen, b"\n");
    console.close();
}

#[test]
fn run_delivers_single_command_and_collects_rc_ok() {
    let (master, slave_path) = pty_parts();
    let mut console = open_slave(&slave_path);
    let out = run_with_peer(&mut console, &master, "true", b"__RC0__\r\n");
    assert_eq!(out.rc, 0);
    assert!(out.output.contains("__RC0__"));
    console.close();
}

#[test]
fn run_collects_rc_fail() {
    let (master, slave_path) = pty_parts();
    let mut console = open_slave(&slave_path);
    let out = run_with_peer(&mut console, &master, "false", b"__RC1__\r\n");
    assert_eq!(out.rc, 1);
    assert!(out.output.contains("__RC1__"));
    console.close();
}

#[test]
fn run_times_out_with_rc_2_when_device_silent() {
    let (_master, slave_path) = pty_parts();
    let mut console = open_slave(&slave_path);
    let start = Instant::now();
    let out = console.run("true", Duration::from_secs(1)).expect("run");
    assert_eq!(out.rc, 2);
    assert_eq!(out.output, "");
    assert!(start.elapsed() >= Duration::from_secs(1));
    console.close();
}

#[test]
fn send_script_delivers_line_chunks_via_echo_append() {
    let (master, slave_path) = pty_parts();
    let mut console = open_slave(&slave_path);
    let handle = {
        let peer = master.try_clone().unwrap();
        thread::spawn(move || {
            // consume every delivered line, answer the final sh line OK —
            // the exact needles the Python test pins
            master_read_until(
                &peer,
                b"echo 'touch /tmp/x' >> /tmp/conwrt-deploy.sh\n",
                Duration::from_secs(10),
            );
            master_read_until(
                &peer,
                b"sh /tmp/conwrt-deploy.sh && echo __RC0__ || echo __RC1__\n",
                Duration::from_secs(10),
            );
            let mut p = peer;
            p.write_all(b"__RC0__\r\n").unwrap();
        })
    };
    let out = console
        .send_script(&["# a comment", "touch /tmp/x"], Duration::from_secs(5))
        .expect("send_script");
    handle.join().expect("responder");
    assert_eq!(out.rc, 0);
    assert!(out.output.contains("__RC0__"));
    console.close();
}

/// The FT232R break-recovery characterization (Python
/// `test_break_byte_triggers_close_wait_reopen_recovery`): mid-command the
/// peer writes the break byte (device power-off), stays dark past the 3 s
/// recovery window, then boots and emits the marker. The console must
/// recover, succeed, and the recovery wait must be REAL (≥ 3 s).
#[test]
fn break_byte_triggers_close_wait_reopen_recovery() {
    let (master, slave_path) = pty_parts();
    let mut console = open_slave(&slave_path);
    let handle = {
        let peer = master.try_clone().unwrap();
        thread::spawn(move || {
            master_read_until(&peer, b"true && echo __RC0__", Duration::from_secs(10));
            let mut p = peer;
            p.write_all(b"\x00").unwrap(); // UART break (device power-off)
            thread::sleep(Duration::from_millis(3500)); // past the 3s reopen + input flush
            p.write_all(b"__RC0__\r\n").unwrap();
        })
    };
    let start = Instant::now();
    let out = console.run("true", Duration::from_secs(8)).expect("run");
    handle.join().expect("breaker");
    assert_eq!(out.rc, 0, "console did not recover after break: {:?}", out);
    assert!(out.output.contains("__RC0__"));
    // the FT232R recovery wait exists: >= 3s between break and recovery
    assert!(
        start.elapsed() >= Duration::from_secs(3),
        "recovery wait missing: {:?}",
        start.elapsed()
    );
    console.close();
}

/// Port-goes-away: the peer (master) vanishes mid-command. Slave reads
/// fail ⇒ recovery runs (real 3 s wait) ⇒ reopening a master-less pts is
/// refused ⇒ the failure propagates out of `run` (Python parity:
/// `_reopen_after_break` exceptions escape `run()`).
#[test]
fn port_goes_away_recovery_propagates_failed_reopen() {
    let (master, slave_path) = pty_parts();
    let mut console = open_slave(&slave_path);
    let killer = thread::spawn(move || {
        // watch the command go out, THEN drop the LAST master fd — writes
        // have succeeded, so the failure surfaces on read (the recovery
        // path), exactly the wedged-adapter shape.
        master_read_until(&master, b"true && echo __RC0__", Duration::from_secs(10));
        drop(master);
    });
    let start = Instant::now();
    let err = console
        .run("true", Duration::from_secs(8))
        .expect_err("expected error");
    killer.join().expect("killer");
    assert!(
        start.elapsed() >= Duration::from_secs(3),
        "recovery wait missing: {:?}",
        start.elapsed()
    );
    assert!(
        err.to_string().contains("cannot open serial port"),
        "reopen failure should surface, got: {err}"
    );
}
