//! Full sysupgrade lifecycle over conwrt's Rust SSH stack — the first
//! *mutating* conwrt-2.0 operation (issue #100; AGENTS.md safety rules
//! encoded, not documented-and-hoped):
//!
//! 1. connect (host-key fingerprint printed for the operator),
//! 2. verify the live board identity against the expected board name,
//!    refusing on mismatch,
//! 3. push the image via scp-over-exec,
//! 4. verify the sha256 **on the device** against the local hash,
//! 5. re-verify the board identity one last time,
//! 6. `sysupgrade -n` (never `-F`),
//! 7. wait for the post-flash SSH banner.
//!
//! ```text
//! cargo run --release -p conwrt-local-std --example sysupgrade -- \
//!     192.168.104.52:22 ~/.ssh/id_ed25519 firmware.bin \
//!     dlink,covr-x1860-a1 --post-flash 192.168.1.1
//! ```

use conwrt_core::ssh::{MemoryTrustStore, TrustMode};
use conwrt_local_std::ssh::{SshAuth, SshError, SshOptions, SshTarget, connect};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

const REMOTE_IMAGE: &str = "/tmp/conwrt-sysupgrade.bin";

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(addr), Some(key), Some(image), Some(expected_board)) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        eprintln!(
            "usage: sysupgrade <host:port> <private-key> <image> <expected-board-name> \
             [--post-flash <ip>]"
        );
        std::process::exit(2);
    };
    let post_flash = flag_value(&mut args, "--post-flash").unwrap_or_else(|| "192.168.1.1".into());

    let image_bytes = std::fs::read(&image).unwrap_or_else(|e| {
        eprintln!("cannot read image {image}: {e}");
        std::process::exit(2);
    });
    let local_sha = hex_lower(&Sha256::digest(&image_bytes));
    println!("image:        {image} ({} bytes)", image_bytes.len());
    println!("local sha256: {local_sha}");

    let target = SshTarget {
        addr,
        user: "root".into(),
        auth: SshAuth::KeyFile {
            path: PathBuf::from(key),
            passphrase: None,
        },
    };
    let mut store = MemoryTrustStore::new();
    let session = connect(
        &target,
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|e| panic!("connect failed: {e}"));
    println!("host key:     {}", session.presented_key.fingerprint);

    verify_board(&session, &expected_board).await;

    println!("uploading via scp-over-exec ...");
    session
        .scp_upload(&image_bytes, REMOTE_IMAGE)
        .await
        .unwrap_or_else(|e| panic!("upload failed: {e}"));

    let sum = session
        .exec(&format!("sha256sum {REMOTE_IMAGE}"))
        .await
        .unwrap_or_else(|e| panic!("on-device sha256sum failed: {e}"));
    if sum.exit_code != Some(0) {
        panic!(
            "sha256sum exited {:?}: {}",
            sum.exit_code,
            String::from_utf8_lossy(&sum.stderr)
        );
    }
    let remote_sha = String::from_utf8_lossy(&sum.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    println!("remote sha256:{remote_sha}");
    if remote_sha != local_sha {
        panic!("SHA256 MISMATCH between host and device — refusing to flash");
    }

    // Last-line identity check immediately before the irreversible step.
    verify_board(&session, &expected_board).await;

    println!("flashing: sysupgrade -n {REMOTE_IMAGE} (config reset; never -F)");
    let outcome = session.exec(&format!("sysupgrade -n {REMOTE_IMAGE}")).await;
    match outcome {
        Ok(output) => {
            // Some platforms manage a clean exit (246 is conwrt's sentinel);
            // a missing status with the channel closing is the normal path.
            println!(
                "sysupgrade channel closed: exit={:?} stdout={} stderr={}",
                output.exit_code,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        Err(SshError::Transport(e)) => {
            // Connection torn down mid-reboot: expected.
            println!("connection closed during sysupgrade (expected): {e}");
        }
        Err(e) => panic!("sysupgrade failed unexpectedly: {e}"),
    }

    wait_for_ssh(&post_flash, Duration::from_secs(900)).await;
    println!(
        "SUCCESS: post-flash SSH answering at {post_flash}; verify with \
         `conwrt diagnose --ip {post_flash}`"
    );
}

async fn verify_board(session: &conwrt_local_std::ssh::SshSession, expected: &str) {
    let board = session
        .exec("cat /tmp/sysinfo/board_name")
        .await
        .unwrap_or_else(|e| panic!("board identity read failed: {e}"));
    let live = String::from_utf8_lossy(&board.stdout).trim().to_string();
    println!("board:        {live}");
    if live != expected {
        panic!(
            "IDENTITY GATE FAILED: live board {live:?} != expected {expected:?} — \
             refusing to flash (AGENTS.md: trust the device, not the claim)"
        );
    }
}

async fn wait_for_ssh(ip: &str, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    println!(
        "waiting for post-flash SSH at {ip}:22 (up to {}s) ...",
        timeout.as_secs()
    );
    loop {
        if tokio::time::Instant::now() > deadline {
            panic!(
                "post-flash SSH did not answer within {}s",
                timeout.as_secs()
            );
        }
        if let Ok(Ok(mut stream)) = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect((ip, 22)),
        )
        .await
        {
            use tokio::io::AsyncReadExt;
            let mut banner = [0u8; 20];
            if tokio::time::timeout(Duration::from_secs(3), stream.read(&mut banner))
                .await
                .is_ok_and(|r| r.is_ok_and(|n| n > 0))
                && banner.starts_with(b"SSH-")
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

fn flag_value<I: Iterator<Item = String>>(args: &mut I, flag: &str) -> Option<String> {
    let mut prev_was_flag = false;
    for arg in args {
        if prev_was_flag {
            return Some(arg);
        }
        prev_was_flag = arg == flag;
    }
    None
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
