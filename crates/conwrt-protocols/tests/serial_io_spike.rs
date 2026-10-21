//! #124 `embedded-io-async` adaptation spike — HOST RUNTIME PROOFS.
//!
//! Harness choice (documented per the issue): a hand-rolled **poll-based
//! mini-executor** (round-robin `Future::poll`, ~1 ms tick) — not
//! embassy-on-host. The properties under proof are executor-independent:
//! bounded per-poll work, drop-cancellation, cross-thread offload, and a
//! co-scheduled heartbeat proving no starvation while a transfer runs.
//!
//! Proofs:
//! 1. completion — a verified transfer end-to-end, including the
//!    mid-stream-NAK signature where the sender CLAIMS success, the
//!    receiver-side CRC echo refuses it, and the whole transfer restarts
//!    (the async twin of `mid_stream_nak_advances_without_retransmit`);
//! 2. strict-receiver abort (U-Boot `loadx`/xyzModem shape: retransmit
//!    requests, sender error-budget exhausts, restart is clean);
//! 3. cancellation — drop the driver future mid-attempt: the offloaded
//!    engine drains to its bounded end, the transport closes (peer sees
//!    EOF), no hang, executor still healthy;
//! 4. adapter contract — chunk-bounded steps, `WouldBlock` ⇒ `Pending`,
//!    external `wake()` rouses a pending read.

#![cfg(unix)]

use conwrt_protocols::serial_io::{
    AcceptanceCheck, AsyncRead, AsyncWrite, ChunkedSerialIo, NoReArm, ReceiverReArm,
    send_firmware_verified_async,
};
use conwrt_protocols::xmodem_transfer::{BlockLength, RetryPolicy, VerifiedError};
use crc16::State as Crc16State;
use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

const SOH: u8 = 0x01;
const ACK: u8 = 0x06;
const NAK: u8 = 0x15;
const EOT: u8 = 0x04;
const CRC_START: u8 = b'C';
/// Engine-mounted transport read deadline: bounds every blocking engine
/// read (drives the error budget) and bounds cancellation drain.
const READ_DEADLINE: Duration = Duration::from_millis(30);

struct FlagWaker(AtomicBool);

impl Wake for FlagWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

fn noop_waker() -> Waker {
    Waker::noop().clone()
}

/// Poll-based mini-executor: round-robin over spawned tasks, ~1 ms tick.
struct MiniExec {
    tasks: Vec<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl MiniExec {
    fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    fn spawn(&mut self, f: impl Future<Output = ()> + Send + 'static) {
        self.tasks.push(Box::pin(f));
    }

    fn run_until(&mut self, done: impl Fn() -> bool, timeout: Duration) -> bool {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let deadline = Instant::now() + timeout;
        while !done() {
            let mut i = 0;
            while i < self.tasks.len() {
                if self.tasks[i].as_mut().poll(&mut cx).is_ready() {
                    drop(self.tasks.swap_remove(i));
                } else {
                    i += 1;
                }
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }
}

/// Engine side of a socketpair. Transfer mode = blocking with
/// `READ_DEADLINE` (SO_RCVTIMEO → `WouldBlock`, translated by the
/// crate's `SerialSemantics` inside the offload worker); verify mode =
/// non-blocking (the `ChunkedSerialIo` readier).
struct TestSerial {
    sock: UnixStream,
}

impl TestSerial {
    fn new(sock: UnixStream) -> Self {
        let s = Self { sock };
        s.set_transfer_mode();
        s
    }

    fn set_transfer_mode(&self) {
        self.sock.set_nonblocking(false).unwrap();
        self.sock.set_read_timeout(Some(READ_DEADLINE)).unwrap();
        self.sock
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
    }

    fn set_verify_mode(&self) {
        self.sock.set_nonblocking(true).unwrap();
    }

    fn set_write_deadline(&self, d: Duration) {
        self.sock.set_write_timeout(Some(d)).unwrap();
    }
}

impl std::io::Read for TestSerial {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.sock.read(buf)
    }
}

impl std::io::Write for TestSerial {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sock.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

fn recv_frame(peer: &mut UnixStream, expect_no: u8) -> Vec<u8> {
    let mut head = [0u8; 3];
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.read_exact(&mut head).expect("frame head");
    assert_eq!(head[0], SOH, "block start byte");
    assert_eq!(head[1], expect_no, "block number");
    assert_eq!(head[2], !expect_no, "block complement");
    let mut payload = vec![0u8; 128];
    peer.read_exact(&mut payload).expect("frame payload");
    let mut trailer = [0u8; 2];
    peer.read_exact(&mut trailer).expect("frame trailer");
    assert_eq!(
        u16::from_be_bytes(trailer),
        Crc16State::<crc16::XMODEM>::calculate(&payload),
        "CRC-16/XMODEM of block {expect_no}"
    );
    payload
}

fn recv_eot(peer: &mut UnixStream) {
    let mut eot = [0u8; 1];
    peer.read_exact(&mut eot).expect("EOT");
    assert_eq!(eot[0], EOT);
}

fn crc16_of(bytes: &[u8]) -> u16 {
    Crc16State::<crc16::XMODEM>::calculate(bytes)
}

/// Receiver-side acceptance check: reads `OK<crc16-be>` over the async
/// transport view — the bootloader-echo stand-in for U-Boot's
/// `crc32 <addr> <size>` readback (see docs/xmodem-receiver-matrix.md).
/// Only a digest of the ACTUALLY accepted bytes passing completes the
/// transfer; the sender-side claim is never trusted alone.
struct CrcEchoCheck {
    expected: u16,
    calls: Arc<AtomicUsize>,
}

impl AcceptanceCheck<TestSerial> for CrcEchoCheck {
    async fn check(&mut self, io: &mut ChunkedSerialIo<TestSerial>) -> bool {
        io.inner_mut().set_verify_mode();
        let mut buf = [0u8; 4];
        let read = io.read_exact(&mut buf).await;
        io.inner_mut().set_transfer_mode();
        self.calls.fetch_add(1, Ordering::Relaxed);
        match read {
            Ok(()) => buf[..2] == *b"OK" && u16::from_be_bytes([buf[2], buf[3]]) == self.expected,
            Err(_) => false,
        }
    }
}

type OutcomeSlot = Arc<Mutex<Option<(TestSerial, Result<usize, VerifiedError>)>>>;

/// Test-side re-arm: issue the U-Boot-shaped load command and wait for
/// the ready banner — what a real driver does between attempts
/// (`loadx 0x46000000` → `## Ready`).
const REARM_CMD: &[u8] = b"loadx 0x46000000\r";
const REARM_BANNER: &[u8] = b"## Ready\n";
const ABORT_BANNER: &[u8] = b"## aborted\n";

struct UBootPromptReArm {
    calls: Arc<AtomicUsize>,
}

impl ReceiverReArm<TestSerial> for UBootPromptReArm {
    async fn rearm(&mut self, io: &mut ChunkedSerialIo<TestSerial>) {
        io.inner_mut().set_verify_mode();
        let mut abort = [0u8; ABORT_BANNER.len()];
        io.read_exact(&mut abort)
            .await
            .expect("abort/prompt banner from the receiver");
        assert_eq!(&abort, ABORT_BANNER);
        io.write_all(REARM_CMD).await.expect("send loadx");
        let mut banner = [0u8; REARM_BANNER.len()];
        io.read_exact(&mut banner)
            .await
            .expect("ready banner after loadx");
        assert_eq!(&banner, REARM_BANNER);
        io.inner_mut().set_transfer_mode();
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}

/// Drive `send_firmware_verified_async` on a dedicated thread's MiniExec
/// with a co-scheduled heartbeat task — the no-starvation probe. Returns
/// the outcome slot, a completion flag, and the heartbeat tick counter.
fn drive_on_exec(
    serial: TestSerial,
    payload: Vec<u8>,
    policy: RetryPolicy,
    check: impl AcceptanceCheck<TestSerial> + Send + 'static,
    rearm: impl ReceiverReArm<TestSerial> + Send + 'static,
) -> (OutcomeSlot, Arc<AtomicBool>, Arc<AtomicUsize>) {
    let ticks = Arc::new(AtomicUsize::new(0));
    let slot: OutcomeSlot = Arc::default();
    let done = Arc::new(AtomicBool::new(false));
    let done_poll = done.clone();
    let t = ticks.clone();
    let slot_in = slot.clone();
    let done_in = done.clone();
    std::thread::spawn(move || {
        let mut exec = MiniExec::new();
        exec.spawn(async move {
            std::future::poll_fn(|_| {
                t.fetch_add(1, Ordering::Relaxed);
                Poll::<()>::Pending
            })
            .await
        });
        exec.spawn(async move {
            let outcome = send_firmware_verified_async(
                serial,
                &payload,
                BlockLength::Standard,
                policy,
                check,
                rearm,
            )
            .await;
            *slot_in.lock().unwrap() = Some(outcome);
            done_in.store(true, Ordering::Release);
        });
        let _ = exec.run_until(
            || done_poll.load(Ordering::Acquire),
            Duration::from_secs(60),
        );
    });
    (slot, done, ticks)
}

fn wait_until(cond: impl Fn() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !cond() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

/// Mid-stream NAK on attempt 1: the lenient receiver drops block 2 and
/// keeps ACKing; the sender CLAIMS success (pinned crate behavior); the
/// CRC echo of the accepted bytes mismatches; the whole transfer restarts
/// and attempt 2 verifies. The async twin of
/// `mid_stream_nak_advances_without_retransmit`.
#[test]
fn lenient_nak_claimed_success_refused_then_restarted_verified() {
    let payload: Vec<u8> = (0..16384u32).map(|v| (v % 251) as u8).collect();
    let expected = crc16_of(&payload);
    let (dev_sock, peer) = UnixStream::pair().expect("socketpair");

    let transfers_seen = Arc::new(AtomicUsize::new(0));
    let ts = transfers_seen.clone();
    let receiver = std::thread::spawn(move || {
        let mut peer = peer;
        for attempt in 1..=2u32 {
            // Real receivers do NOT re-enter receive mode after an
            // attempt: sit at the prompt until the driver re-arms.
            if attempt > 1 {
                let mut cmd = [0u8; REARM_CMD.len()];
                peer.read_exact(&mut cmd).expect("rearm command");
                assert_eq!(&cmd, REARM_CMD);
                peer.write_all(REARM_BANNER).expect("ready banner");
            }
            peer.write_all(&[CRC_START]).expect("start C");
            ts.fetch_add(1, Ordering::Relaxed);
            let mut accepted: Vec<u8> = Vec::with_capacity(16384);
            for block_no in 1..=128u8 {
                let frame = recv_frame(&mut peer, block_no);
                if attempt == 1 && block_no == 2 {
                    peer.write_all(&[NAK]).expect("nak block 2");
                } else {
                    accepted.extend_from_slice(&frame);
                    peer.write_all(&[ACK]).expect("ack block");
                }
            }
            recv_eot(&mut peer);
            peer.write_all(&[ACK]).expect("ack EOT");
            peer.write_all(b"OK").unwrap();
            peer.write_all(&crc16_of(&accepted).to_be_bytes())
                .expect("crc echo");
            peer.write_all(ABORT_BANNER).expect("back at prompt");
        }
    });

    let calls = Arc::new(AtomicUsize::new(0));
    let check = CrcEchoCheck {
        expected,
        calls: calls.clone(),
    };
    let rearms = Arc::new(AtomicUsize::new(0));
    let (slot, done, ticks) = drive_on_exec(
        TestSerial::new(dev_sock),
        payload.clone(),
        RetryPolicy {
            max_attempts: 3,
            restart_delay_ms: 30,
        },
        check,
        UBootPromptReArm {
            calls: rearms.clone(),
        },
    );

    assert!(
        wait_until(
            || done.load(Ordering::Acquire) && slot.lock().unwrap().is_some(),
            Duration::from_secs(30)
        ),
        "driver did not complete in time"
    );
    let (_, result) = slot.lock().unwrap().take().expect("outcome");
    receiver.join().expect("receiver thread");

    assert_eq!(result.expect("verified transfer"), 16384);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        2,
        "each claimed success verified"
    );
    assert_eq!(
        transfers_seen.load(Ordering::Relaxed),
        2,
        "whole transfer restarted once"
    );
    assert_eq!(
        rearms.load(Ordering::Relaxed),
        1,
        "receiver was re-armed between attempts"
    );
    let final_ticks = ticks.load(Ordering::Relaxed);
    assert!(
        final_ticks >= 20,
        "heartbeat advanced throughout (restart delay alone spans ~30 ticks), got {final_ticks}"
    );
}

/// Strict receiver (U-Boot `loadx`/xyzModem shape): after the sender
/// advances past a NAK'd block, every further response is a retransmit
/// request until the sender's error budget exhausts — attempt 1 FAILS
/// sender-side (no claimed success, no verification call), attempt 2 is
/// clean and verified.
#[test]
fn strict_receiver_abort_exhausts_sender_then_clean_restart_verifies() {
    let payload: Vec<u8> = (0..384u32).map(|v| (v % 253) as u8).collect();
    let expected = crc16_of(&payload);
    let (dev_sock, peer) = UnixStream::pair().expect("socketpair");

    let transfers_seen = Arc::new(AtomicUsize::new(0));
    let ts = transfers_seen.clone();
    let receiver = std::thread::spawn(move || {
        let mut peer = peer;
        peer.write_all(&[CRC_START]).expect("start C");
        ts.fetch_add(1, Ordering::Relaxed);
        recv_frame(&mut peer, 1);
        peer.write_all(&[ACK]).expect("ack block 1");
        recv_frame(&mut peer, 2);
        peer.write_all(&[NAK]).expect("nak block 2");
        recv_frame(&mut peer, 3);
        peer.write_all(&[CRC_START])
            .expect("retransmit request (crc-mode NAK)");

        // Drain the sender's error-budget exhaustion: answer every EOT
        // with another retransmit request until the line falls quiet for
        // 300 ms (the engine gave up) — bounded by a 10 s outer cap.
        peer.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let cap = Instant::now() + Duration::from_secs(10);
        let mut last_activity = Instant::now();
        let mut b = [0u8; 1];
        loop {
            match peer.read(&mut b) {
                Ok(1) => {
                    last_activity = Instant::now();
                    if b[0] == EOT {
                        let _ = peer.write(&[CRC_START]);
                    }
                }
                Ok(_) => {}
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    if Instant::now().duration_since(last_activity) > Duration::from_millis(300)
                        || Instant::now() >= cap
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        // Attempt 1 is over (aborted, bootloader back at its prompt);
        // the driver must re-arm before attempt 2.
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.write_all(ABORT_BANNER)
            .expect("abort banner at prompt");
        let mut cmd = [0u8; REARM_CMD.len()];
        peer.read_exact(&mut cmd).expect("rearm command");
        assert_eq!(&cmd, REARM_CMD);
        peer.write_all(REARM_BANNER).expect("ready banner");

        peer.write_all(&[CRC_START]).expect("start C");
        ts.fetch_add(1, Ordering::Relaxed);
        let mut accepted = Vec::new();
        for block_no in 1..=3u8 {
            accepted.extend_from_slice(&recv_frame(&mut peer, block_no));
            peer.write_all(&[ACK]).expect("ack block");
        }
        recv_eot(&mut peer);
        peer.write_all(&[ACK]).expect("ack EOT");
        peer.write_all(b"OK").unwrap();
        peer.write_all(&crc16_of(&accepted).to_be_bytes())
            .expect("crc echo");
    });

    let calls = Arc::new(AtomicUsize::new(0));
    let check = CrcEchoCheck {
        expected,
        calls: calls.clone(),
    };
    let rearms = Arc::new(AtomicUsize::new(0));
    let (slot, done, ticks) = drive_on_exec(
        TestSerial::new(dev_sock),
        payload.clone(),
        RetryPolicy {
            max_attempts: 3,
            restart_delay_ms: 30,
        },
        check,
        UBootPromptReArm {
            calls: rearms.clone(),
        },
    );

    assert!(
        wait_until(
            || done.load(Ordering::Acquire) && slot.lock().unwrap().is_some(),
            Duration::from_secs(30)
        ),
        "driver did not complete in time"
    );
    let (_, result) = slot.lock().unwrap().take().expect("outcome");
    receiver.join().expect("receiver thread");

    assert_eq!(result.expect("verified transfer"), 384);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "attempt 1 failed sender-side: no claimed success, no verify call"
    );
    assert_eq!(transfers_seen.load(Ordering::Relaxed), 2);
    assert_eq!(
        rearms.load(Ordering::Relaxed),
        1,
        "receiver re-armed once after the aborted attempt"
    );
    assert!(
        ticks.load(Ordering::Relaxed) >= 50,
        "heartbeat advanced through the ~0.5 s sender exhaustion window"
    );
}

/// Cancellation proof: drop the driver future mid-attempt. The offloaded
/// engine drains to its bounded end (read deadline), the worker closes
/// the transport — the peer observes EOF — and a fresh executor still
/// makes progress afterwards.
#[test]
fn dropping_driver_mid_attempt_cancels_bounded() {
    let payload: Vec<u8> = vec![0x5A; 384];
    let (dev_sock, peer) = UnixStream::pair().expect("socketpair");

    let peer_eof = Arc::new(AtomicBool::new(false));
    let eof_flag = peer_eof.clone();
    let receiver = std::thread::spawn(move || {
        let mut peer = peer;
        peer.write_all(&[CRC_START]).expect("start C");
        let _ = recv_frame(&mut peer, 1);
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut b = [0u8; 1];
        loop {
            match peer.read(&mut b) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        eof_flag.store(true, Ordering::Release);
    });

    let calls = Arc::new(AtomicUsize::new(0));
    let check = CrcEchoCheck { expected: 0, calls };
    let mut fut = Box::pin(send_firmware_verified_async(
        TestSerial::new(dev_sock),
        &payload,
        BlockLength::Standard,
        RetryPolicy {
            max_attempts: 3,
            restart_delay_ms: 30,
        },
        check,
        NoReArm,
    ));

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(
        fut.as_mut().poll(&mut cx).is_pending(),
        "first poll spawns the offload attempt and pends"
    );
    std::thread::sleep(Duration::from_millis(50));
    drop(fut);

    assert!(
        wait_until(|| peer_eof.load(Ordering::Acquire), Duration::from_secs(10)),
        "worker must drain bounded and close the transport (peer EOF)"
    );
    receiver.join().expect("receiver thread");

    let ticks = Arc::new(AtomicUsize::new(0));
    let t = ticks.clone();
    let mut exec = MiniExec::new();
    exec.spawn(async move {
        std::future::poll_fn(|_| {
            t.fetch_add(1, Ordering::Relaxed);
            Poll::<()>::Pending
        })
        .await
    });
    let baseline = ticks.load(Ordering::Relaxed);
    let _ = exec.run_until(
        || ticks.load(Ordering::Relaxed) > baseline + 20,
        Duration::from_secs(5),
    );
    assert!(
        ticks.load(Ordering::Relaxed) > baseline + 20,
        "executor still makes progress after cancellation"
    );
}

/// Adapter contract: chunk-bounded steps, `WouldBlock` ⇒ `Pending`, and
/// the externally-called `wake()` rouses a pending read after the
/// producer writes (the device-side IRQ readiness path).
#[test]
fn chunked_adapter_bounded_steps_and_external_wake() {
    let (dev_sock, mut peer) = UnixStream::pair().expect("socketpair");
    let mut io = ChunkedSerialIo::new(TestSerial::new(dev_sock), 256);
    io.inner_mut().set_verify_mode();

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut buf = [0u8; 4096];

    {
        let mut f = Box::pin(io.read(&mut buf));
        assert!(
            f.as_mut().poll(&mut cx).is_pending(),
            "no data yet: WouldBlock must surface as Pending"
        );
    }

    peer.write_all(&[7u8; 700]).expect("peer writes 700");
    {
        let mut f = Box::pin(io.read(&mut buf));
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(n)) => {
                assert!(n <= 256, "one poll moves at most max_chunk bytes (got {n})")
            }
            other => panic!("expected a bounded Ready read, got {other:?}"),
        }
    }

    let out = [0xA5u8; 700];
    {
        let mut f = Box::pin(io.write_all(&out));
        let mut spins = 0;
        while f.as_mut().poll(&mut cx).is_pending() {
            spins += 1;
            assert!(spins < 10_000, "write_all did not complete");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let mut got = vec![0u8; 700];
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.read_exact(&mut got)
        .expect("peer receives all written bytes");
    assert!(got.iter().all(|&b| b == 0xA5));

    // Drain the unread 444 bytes from the chunk-bound check so the wake
    // test below starts from a provably empty line.
    loop {
        let mut f = Box::pin(io.read(&mut buf));
        if !f.as_mut().poll(&mut cx).is_ready() {
            break;
        }
    }

    let flag = Arc::new(FlagWaker(AtomicBool::new(false)));
    let flag_waker = Waker::from(flag.clone());
    let mut cx_flag = Context::from_waker(&flag_waker);
    // The readiness handle is the IRQ-shaped wake path: callable while a
    // read/write future exclusively borrows the adapter (#124 review).
    let readiness = io.readiness();
    {
        let mut f = Box::pin(io.read(&mut buf));
        assert!(
            f.as_mut().poll(&mut cx_flag).is_pending(),
            "drained line: Pending again"
        );
        assert!(
            !flag.0.load(Ordering::Acquire),
            "no spurious wake before wake()"
        );
        peer.write_all(&[1, 2, 3]).expect("producer writes");
        readiness.wake();
        assert!(
            flag.0.load(Ordering::Acquire),
            "readiness wake() must fire the waker registered by the pending poll"
        );
        assert!(f.as_mut().poll(&mut cx_flag).is_ready());
    }
    io.inner_mut().set_transfer_mode();
    let _ = io.into_inner();
}

/// A peer that stops draining mid-transfer must not wedge the flow: the
/// transport's WRITE deadline turns the stalled block-write into a fatal
/// engine error, every attempt ends promptly, and the driver returns
/// bounded (`AttemptsExhausted`) instead of hanging (#124 review: bound
/// worker writes before promising cancellation).
#[test]
fn write_deadline_bounds_a_stalled_peer() {
    let payload: Vec<u8> = vec![0x36; 600_000];
    let (dev_sock, peer) = UnixStream::pair().expect("socketpair");
    let serial = TestSerial::new(dev_sock);
    serial.set_write_deadline(Duration::from_millis(100));

    let peer_gone = Arc::new(AtomicBool::new(false));
    let gone = peer_gone.clone();
    let receiver = std::thread::spawn(move || {
        let mut peer = peer;
        peer.write_all(&[CRC_START]).expect("start C");
        let mut sink = [0u8; 200];
        peer.read_exact(&mut sink)
            .expect("read a little, then stall");
        std::thread::sleep(Duration::from_secs(8));
        gone.store(true, Ordering::Release);
    });

    let calls = Arc::new(AtomicUsize::new(0));
    let check = CrcEchoCheck { expected: 0, calls };
    let (slot, done, _ticks) = drive_on_exec(
        serial,
        payload.clone(),
        RetryPolicy {
            max_attempts: 3,
            restart_delay_ms: 20,
        },
        check,
        NoReArm,
    );

    let t0 = Instant::now();
    assert!(
        wait_until(
            || done.load(Ordering::Acquire) && slot.lock().unwrap().is_some(),
            Duration::from_secs(20)
        ),
        "driver must stay bounded against a stalled peer"
    );
    let elapsed = t0.elapsed();
    let (_, result) = slot.lock().unwrap().take().expect("outcome");
    receiver.join().expect("receiver thread");

    assert!(
        matches!(result, Err(VerifiedError::AttemptsExhausted { attempts, .. }) if attempts == 3),
        "expected bounded exhaustion, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "stalled peer cost {elapsed:?} — write deadline did not bound it"
    );
    assert!(
        peer_gone.load(Ordering::Acquire),
        "peer finished its window without interference"
    );
}
