//! End-to-end tests: the real fence against a mock ZTE blank-download
//! bootloader, ported from `tests/test_zte_blankdl.py` (which drives the
//! Python daemon as a subprocess). Here the fence runs in-process on a
//! rehearsal bind address and the mock client runs on a thread.
//!
//! IMPROVEMENT OVER THE PYTHON SUITE: fixture images use NON-UNIFORM
//! deterministic content. The Python `make_image` fills with a single
//! byte — which masked the post-wrap offset bug for the entire life of
//! the daemon (the wrong chunk after a rollover is byte-identical to the
//! right one under a uniform fill; see the protocols crate docs). These
//! tests use a byte-position-dependent pattern, so any offset error at
//! any block position — including across the 65 536-block rollover —
//! fails the sha256 pin.

use conwrt_blankdl::{FenceConfig, FenceExit, PinnedImage};
use sha2::{Digest, Sha256};
use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

const OP_RRQ: u16 = 1;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;
const OP_OACK: u16 = 6;
const FIN_STRING: &[u8] = b"OK:zte blank download is done";

/// Non-uniform deterministic image: every byte depends on its position.
fn make_image(size: usize) -> Vec<u8> {
    let mut img = Vec::with_capacity(size);
    // xorshift32 over position-mixed state: fast, deterministic, no
    // uniform runs long enough to hide a block-offset error.
    let mut x: u32 = 0x9E37_79B9;
    for _ in 0..size {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        img.push((x >> 24) as u8);
    }
    img
}

fn sha_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(64);
    for &x in Sha256::digest(b).iter() {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral");
    let p = s.local_addr().expect("addr").port();
    drop(s);
    p
}

/// Run the fence on a background thread; returns a join handle producing
/// the outcome/exit plus the run-record JSON path.
fn spawn_fence(image: Vec<u8>, sha: &str, port: u16) -> thread::JoinHandle<(conwrt_blankdl::FenceOutcome, FenceExit)> {
    let pinned = PinnedImage::from_bytes(image, Some(sha), None).expect("pin");
    let mut cfg = FenceConfig::new(pinned);
    cfg.bind = "127.0.0.1".parse().expect("loopback");
    cfg.port = port;
    cfg.timeout = Duration::from_secs(25);
    thread::spawn(move || conwrt_blankdl::serve(&cfg))
}

/// The mock bootloader (port of `tests/fixtures/zte_blankdl/mock_bootloader.py`).
enum Personality {
    /// The observed real stock U-Boot: RRQ with blksize=1468+timeout=5,
    /// per-block ACKs, NO block-0 ACK after OACK, sends the fin packet.
    Live,
    /// RFC 2347/2348 strict: ACK(0) after OACK, then per-block ACKs.
    Rfc,
    /// Option-less 512-byte blocks: the block-rollover stress class.
    Plain,
}

struct MockBootloader {
    personality: Personality,
    image_size: usize,
    /// blksize the client REQUESTS (Live clamps test uses 65535).
    want_blksize: u32,
    send_fin: bool,
}

impl MockBootloader {
    /// Drive the transfer. Returns (ok, received).
    fn run(&self, server: &str, port: u16, deadline: Duration) -> (bool, Vec<u8>) {
        let s = UdpSocket::bind("127.0.0.1:0").expect("client bind");
        s.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
        let _ = socket2::SockRef::from(&s).set_recv_buffer_size(4 * 1024 * 1024);
        let srv = (server, port);
        let end = Instant::now() + deadline;
        let mut received: Vec<u8> = Vec::new();

        let name = match self.personality {
            Personality::Live => format!("{:04x}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() & 0xFFFF),
            _ => "root_uImage".to_string(),
        };
        let opts = match self.personality {
            Personality::Plain => String::new(),
            _ => format!("blksize\0{}\0timeout\0{}\0", self.want_blksize, 5),
        };
        let rrq = {
            let mut b = Vec::new();
            b.extend_from_slice(&OP_RRQ.to_be_bytes());
            b.extend_from_slice(name.as_bytes());
            b.push(0);
            b.extend_from_slice(b"octet\0");
            b.extend_from_slice(opts.as_bytes());
            b
        };
        s.send_to(&rrq, srv).expect("rrq");

        let mut blksize: usize = 512;
        let mut block: u16 = 0;
        let mut acked_oack = false;
        let mut fin_sent = false;
        let mut last: Option<Vec<u8>> = None;
        let mut rx = [0u8; 65_536];
        while Instant::now() < end {
            let (n, _) = match s.recv_from(&mut rx) {
                Ok(v) => v,
                Err(_) => {
                    // timeout: re-ACK the last block (or retry the RRQ)
                    if let Some(l) = &last {
                        let _ = s.send_to(l, srv);
                    } else {
                        let _ = s.send_to(&rrq, srv);
                    }
                    continue;
                }
            };
            let data = &rx[..n];
            if data.len() < 2 {
                continue;
            }
            let op = u16::from_be_bytes([data[0], data[1]]);
            match op {
                OP_OACK => {
                    let parts: Vec<&[u8]> = data[2..].split(|&b| b == 0).collect();
                    let mut i = 0;
                    while i + 1 < parts.len() {
                        if parts[i].eq_ignore_ascii_case(b"blksize") {
                            blksize = std::str::from_utf8(parts[i + 1])
                                .ok()
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(512);
                        }
                        i += 2;
                    }
                    if matches!(self.personality, Personality::Rfc) {
                        let ack = ack_packet(0);
                        let _ = s.send_to(&ack, srv);
                        last = Some(ack);
                        acked_oack = true;
                    }
                }
                OP_DATA => {
                    if data.len() < 4 {
                        continue;
                    }
                    let b = u16::from_be_bytes([data[2], data[3]]);
                    if matches!(self.personality, Personality::Rfc) && !acked_oack {
                        continue; // strict client rejects DATA before OACK-ACK
                    }
                    let expected = block.wrapping_add(1);
                    if b == expected || (block == 0 && received.is_empty()) {
                        block = b;
                        received.extend_from_slice(&data[4..]);
                    }
                    // b == block: resend of the current block — no append
                    let ack = ack_packet(block);
                    let _ = s.send_to(&ack, srv);
                    last = Some(ack);
                    let payload = data.len() - 4;
                    if payload == 0 || payload < blksize {
                        if self.send_fin {
                            thread::sleep(Duration::from_millis(200));
                            let _ = s.send_to(FIN_STRING, srv);
                            fin_sent = true;
                        }
                        break;
                    }
                }
                OP_ERROR => return (false, received),
                _ => {}
            }
        }
        let ok = received.len() == self.image_size && (fin_sent || !self.send_fin);
        (ok, received)
    }
}

fn ack_packet(block: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(4);
    v.extend_from_slice(&OP_ACK.to_be_bytes());
    v.extend_from_slice(&block.to_be_bytes());
    v
}

// ---------------------------------------------------------------------------

#[test]
fn live_client_full_transfer_and_fin() {
    // The observed real-bootloader flow: blksize 1468, no ACK(0), fin.
    let size = 38_797_312; // the field image size
    let image = make_image(size);
    let sha = sha_hex(&image);
    let port = free_port();
    let fence = spawn_fence(image.clone(), &sha, port);
    let (rc, blob) = MockBootloader {
        personality: Personality::Live,
        image_size: size,
        want_blksize: 1468,
        send_fin: true,
    }
    .run("127.0.0.1", port, Duration::from_secs(60));
    assert!(rc, "live client transfer failed");
    assert_eq!(blob.len(), size);
    assert_eq!(sha_hex(&blob), sha, "received bytes != image");
    let (outcome, exit) = fence.join().expect("fence thread");
    assert_eq!(exit, FenceExit::Fin);
    assert!(outcome.fin);
    assert_eq!(exit.exit_code(), 0);
}

#[test]
fn rfc_client_no_block_skip() {
    // RFC-strict client ACKs block 0 after OACK — no block may be skipped.
    let size = 1468 * 40 + 123; // short final block
    let image = make_image(size);
    let sha = sha_hex(&image);
    let port = free_port();
    let fence = spawn_fence(image.clone(), &sha, port);
    let (rc, blob) = MockBootloader {
        personality: Personality::Rfc,
        image_size: size,
        want_blksize: 1468,
        send_fin: true,
    }
    .run("127.0.0.1", port, Duration::from_secs(30));
    assert!(rc, "rfc client failed or hung");
    assert_eq!(sha_hex(&blob), sha, "received bytes != image (block skip)");
    fence.join().expect("fence thread");
}

#[test]
fn oversize_blksize_clamped() {
    // Client asking blksize=65535 must be clamped to the 1468 protocol max.
    let size = 1468 * 3;
    let image = make_image(size);
    let sha = sha_hex(&image);
    let port = free_port();
    let fence = spawn_fence(image.clone(), &sha, port);
    let (rc, blob) = MockBootloader {
        personality: Personality::Live,
        image_size: size,
        want_blksize: 65_535,
        send_fin: true,
    }
    .run("127.0.0.1", port, Duration::from_secs(30));
    assert!(rc);
    assert_eq!(sha_hex(&blob), sha);
    let (outcome, _exit) = fence.join().expect("fence thread");
    // the RRQ record must show the raw ask; the negotiated OACK carried 1468
    assert_eq!(outcome.rrqs[0].blksize.as_deref(), Some("65535"));
    assert_eq!(blob.len(), size);
}

#[test]
fn plain_512_full_transfer_rollover_nonuniform() {
    // Option-less 512-byte client on a >32 MiB image: the 16-bit block
    // rollover must not corrupt the stream. NON-UNIFORM content — this
    // is the test the Python suite could never catch its offset bug with.
    let bs = 512usize;
    let size = bs * 65_536 + bs; // 65 537 blocks: one block past the wrap
    let image = make_image(size);
    let sha = sha_hex(&image);
    let port = free_port();
    let fence = spawn_fence(image.clone(), &sha, port);
    let (rc, blob) = MockBootloader {
        personality: Personality::Plain,
        image_size: size,
        want_blksize: 512,
        send_fin: true,
    }
    .run("127.0.0.1", port, Duration::from_secs(180));
    assert!(rc, "transfer failed (fence error on block rollover?)");
    assert_eq!(blob.len(), size);
    assert_eq!(
        sha_hex(&blob),
        sha,
        "post-rollover content wrong (offset bug class)"
    );
    fence.join().expect("fence thread");
}

#[test]
fn exact_multiple_image_uses_eof_block() {
    // Exact-multiple images (no short final block) terminate via the
    // empty EOF block instead of stalling.
    let size = 1468 * 4;
    let image = make_image(size);
    let sha = sha_hex(&image);
    let port = free_port();
    let fence = spawn_fence(image.clone(), &sha, port);
    let (rc, blob) = MockBootloader {
        personality: Personality::Live,
        image_size: size,
        want_blksize: 1468,
        send_fin: true,
    }
    .run("127.0.0.1", port, Duration::from_secs(30));
    assert!(rc);
    assert_eq!(sha_hex(&blob), sha);
    let (outcome, _exit) = fence.join().expect("fence thread");
    assert!(outcome.fin);
}

#[test]
fn unpinned_image_refused() {
    let image = make_image(1024);
    let err = PinnedImage::from_bytes(image, None, None).expect_err("must refuse");
    assert!(err.to_string().to_lowercase().contains("refusing"), "got: {err}");
}

#[test]
fn wrong_sha_refused() {
    let image = make_image(1024);
    let pinned = "0".repeat(64);
    let err =
        PinnedImage::from_bytes(image, Some(&pinned), None).expect_err("must refuse");
    assert!(err.to_string().contains("REFUSING"), "got: {err}");
}

#[test]
fn dry_run_never_answers() {
    let size = 2048;
    let image = make_image(size);
    let sha = sha_hex(&image);
    let port = free_port();
    let pinned = PinnedImage::from_bytes(image, Some(&sha), None).expect("pin");
    let mut cfg = FenceConfig::new(pinned);
    cfg.bind = "127.0.0.1".parse().unwrap();
    cfg.port = port;
    cfg.timeout = Duration::from_secs(6);
    cfg.dry_run = true;
    let fence = {
        let cfg = cfg.clone();
        thread::spawn(move || conwrt_blankdl::serve(&cfg))
    };
    let (rc, blob) = MockBootloader {
        personality: Personality::Live,
        image_size: size,
        want_blksize: 1468,
        send_fin: true,
    }
    .run("127.0.0.1", port, Duration::from_secs(6));
    assert!(!rc, "dry-run must not answer — client got data");
    assert!(blob.is_empty());
    let (outcome, exit) = fence.join().expect("fence thread");
    assert_eq!(exit, FenceExit::Timeout);
    assert!(!outcome.rrqs.is_empty(), "RRQ retries observed+logged");
    assert!(outcome.transferred.is_none());
}

/// The fence must survive a client that vanishes mid-transfer and a new
/// RRQ arriving afterwards (the bootloader retries with a fresh name).
#[test]
fn abandoned_transfer_then_new_rrq() {
    let size = 1468 * 8;
    let image = make_image(size);
    let sha = sha_hex(&image);
    let port = free_port();
    let fence = spawn_fence(image.clone(), &sha, port);

    // First client: RRQ, take one block, vanish. (Retries the RRQ until
    // the fence thread has bound — no startup race.)
    {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut rrq = vec![0, OP_RRQ as u8];
        rrq.extend_from_slice(b"aband\x00octet\x00blksize\x001468\x00timeout\x005\x00");
        let mut buf = [0u8; 1600];
        let first = loop {
            s.send_to(&rrq, ("127.0.0.1", port)).unwrap();
            if let Ok((n, _)) = s.recv_from(&mut buf) {
                break n;
            }
        };
        assert!(first >= 2);
    }

    // Second client: full transfer.
    let (rc, blob) = MockBootloader {
        personality: Personality::Live,
        image_size: size,
        want_blksize: 1468,
        send_fin: true,
    }
    .run("127.0.0.1", port, Duration::from_secs(30));
    assert!(rc, "second client transfer failed after abandoned first");
    assert_eq!(sha_hex(&blob), sha);
    let (outcome, exit) = fence.join().expect("fence thread");
    assert_eq!(exit, FenceExit::Fin);
    assert!(outcome.fin);
    assert!(
        outcome.rrqs.len() >= 2,
        "both clients' RRQs recorded (got {})",
        outcome.rrqs.len()
    );
}
