//! #124 real-receiver cross-check: conwrt's XMODEM sender against lrzsz's
//! `rx` — an independent, battle-tested receiver implementation. The
//! socketpair-scripted receivers in `xmodem_fitness.rs` /
//! `serial_io_spike.rs` pin OUR understanding of the wire; this test
//! pins it against the real world. Skips gracefully when `rx` is not
//! installed (CI without lrzsz); this host has lrzsz 0.12.21 (installed
//! via passwordless sudo for #124 — the "real sender/receiver
//! cross-check" option in the issue).

#![cfg(unix)]

use conwrt_protocols::serial_io::SerialSemantics;
use conwrt_protocols::{BlockLength, xmodem_transfer::send_firmware};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
fn real_lrzsz_rx_accepts_our_sender() {
    let payload: Vec<u8> = (0..8192u32).map(|v| (v % 249) as u8).collect();

    let outfile = std::env::temp_dir().join(format!("conwrt-xmodem-rx-{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&outfile);

    let (mut dev, peer) = match UnixStream::pair() {
        Ok(p) => p,
        Err(e) => panic!("socketpair: {e}"),
    };
    // lrzsz's rx deliberates ~1 s before ACKing EOT (ZMODEM heritage);
    // a shorter deadline makes each EOT retransmission reset that
    // deliberation and the transfer deadlocks. The engine's read
    // deadline must EXCEED the receiver's EOT latency — U-Boot's
    // xyzModem ACKs EOT immediately (source), lrzsz does not.
    dev.set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    dev.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    let child_stdin: Stdio =
        std::os::fd::OwnedFd::from(peer.try_clone().expect("clone stdin")).into();
    let child_stdout: Stdio =
        std::os::fd::OwnedFd::from(peer.try_clone().expect("clone stdout")).into();
    let mut child = match Command::new("rx")
        .arg(&outfile)
        .stdin(child_stdin)
        .stdout(child_stdout)
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping: lrzsz `rx` not installed");
            return;
        }
        Err(e) => panic!("spawn rx: {e}"),
    };

    // If rx wedges, kill it by PID from a detached watchdog (wait() holds
    // no lock the watchdog needs; `finished` disarms the kill on success).
    let rx_pid = child.id();
    let finished = Arc::new(AtomicBool::new(false));
    let finished_wd = finished.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(30));
        if !finished_wd.load(Ordering::Acquire) {
            let _ = Command::new("kill").arg(rx_pid.to_string()).status();
        }
    });

    let mut stream = std::io::Cursor::new(payload.clone());
    let mut mounted = SerialSemantics::new(&mut dev);
    let sent = send_firmware(&mut mounted, &mut stream, BlockLength::OneK)
        .expect("our sender completes against real rx");
    let status = child.wait().expect("wait rx");
    finished.store(true, Ordering::Release);
    assert!(status.success(), "rx exited with {status}");

    let received = std::fs::read(&outfile).expect("rx wrote the file");
    std::fs::remove_file(&outfile).ok();
    assert_eq!(sent, 8192);
    assert_eq!(received, payload, "byte-exact file through a real receiver");
}
