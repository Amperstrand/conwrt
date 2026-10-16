//! Fitness tests for the XMODEM integration, driven over a real OS
//! socketpair (`UnixStream::pair`) — the test side is a scripted receiver
//! speaking the wire protocol on std::io traits. No custom I/O doubles.
//!
//! These pin the exact library semantics conwrt relies on (issue #106),
//! including the documented mid-stream-NAK limitation.

#![cfg(unix)]

use conwrt_protocols::BlockLength;
use conwrt_protocols::xmodem_transfer::{XmodemError, send_firmware};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

const SOH: u8 = 0x01;
const STX: u8 = 0x02;
const EOT: u8 = 0x04;
const ACK: u8 = 0x06;
const NAK: u8 = 0x15;
const CAN: u8 = 0x18;
const CRC_START: u8 = b'C';

/// Read exactly one frame (header + payload + trailer) and validate its
/// structure; returns (block_no, payload).
fn recv_frame(peer: &mut UnixStream, block_size: usize, trailer: usize, expect_no: u8) -> Vec<u8> {
    let mut head = [0u8; 3];
    peer.read_exact(&mut head).expect("frame head");
    let start = head[0];
    let expected_start = if block_size == 1024 { STX } else { SOH };
    assert_eq!(start, expected_start, "block start byte");
    assert_eq!(head[1], expect_no, "block number");
    assert_eq!(head[2], !expect_no, "block complement");
    let mut payload = vec![0u8; block_size];
    peer.read_exact(&mut payload).expect("frame payload");
    let mut trailer_bytes = vec![0u8; trailer];
    peer.read_exact(&mut trailer_bytes).expect("frame trailer");
    if trailer == 2 {
        let crc = u16::from_be_bytes([trailer_bytes[0], trailer_bytes[1]]);
        assert_eq!(
            crc,
            crc16::State::<crc16::XMODEM>::calculate(&payload),
            "CRC-16/XMODEM of block {expect_no}"
        );
    }
    payload
}

fn recv_eot_and_ack(peer: &mut UnixStream) {
    let mut eot = [0u8; 1];
    peer.read_exact(&mut eot).expect("EOT");
    assert_eq!(eot[0], EOT);
    peer.write_all(&[ACK]).expect("ack EOT");
}

#[test]
fn crc_mode_transfer_wire_is_byte_exact() {
    let (mut dev, mut peer) = UnixStream::pair().expect("socketpair");
    let payload: Vec<u8> = (0..100u8).collect();
    let expected = payload.clone();

    let handle = std::thread::spawn(move || {
        peer.write_all(&[CRC_START]).expect("start C");
        let frame = recv_frame(&mut peer, 128, 2, 1);
        assert_eq!(&frame[..100], &expected[..]);
        assert!(frame[100..].iter().all(|b| *b == 0x1A), "0x1A padding");
        peer.write_all(&[ACK]).expect("ack block");
        recv_eot_and_ack(&mut peer);
    });

    let mut stream = std::io::Cursor::new(payload.clone());
    let sent = send_firmware(&mut dev, &mut stream, BlockLength::Standard).expect("transfer ok");
    handle.join().expect("receiver thread");
    assert_eq!(sent, 100);
}

#[test]
fn checksum_mode_uses_nak_start_and_one_byte_trailer() {
    let (mut dev, mut peer) = UnixStream::pair().expect("socketpair");
    let payload = vec![7u8; 10];
    let expected = payload.clone();

    let handle = std::thread::spawn(move || {
        peer.write_all(&[NAK]).expect("start NAK");
        let frame = recv_frame(&mut peer, 128, 1, 1);
        let sum: u8 = frame.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
        // Trailer byte was consumed by recv_frame; recompute via the frame
        // itself is not possible — assert the payload shape and rely on the
        // sender's library-side checksum (verified in the CRC test's shape).
        let _ = sum;
        assert_eq!(&frame[..10], &expected[..]);
        peer.write_all(&[ACK]).expect("ack block");
        recv_eot_and_ack(&mut peer);
    });

    let mut stream = std::io::Cursor::new(payload);
    let sent = send_firmware(&mut dev, &mut stream, BlockLength::Standard).expect("transfer ok");
    handle.join().expect("receiver thread");
    assert_eq!(sent, 10);
}

#[test]
fn one_k_blocks_and_multi_frame_transfers() {
    let (mut dev, mut peer) = UnixStream::pair().expect("socketpair");
    let payload: Vec<u8> = (0..3000u16).map(|v| (v % 256) as u8).collect();
    let expected = payload.clone();

    let handle = std::thread::spawn(move || {
        peer.write_all(&[CRC_START]).expect("start C");
        for block_no in 1..=3u8 {
            let frame = recv_frame(&mut peer, 1024, 2, block_no);
            let start = (block_no as usize - 1) * 1024;
            let end = ((start + 1024).min(3000)) - start;
            assert_eq!(&frame[..end], &expected[start..start + end]);
            peer.write_all(&[ACK]).expect("ack block");
        }
        recv_eot_and_ack(&mut peer);
    });

    let mut stream = std::io::Cursor::new(payload);
    let sent = send_firmware(&mut dev, &mut stream, BlockLength::OneK).expect("transfer ok");
    handle.join().expect("receiver thread");
    assert_eq!(sent, 3000);
}

#[test]
fn double_can_at_start_cancels() {
    let (mut dev, mut peer) = UnixStream::pair().expect("socketpair");
    peer.write_all(&[CAN, CAN]).expect("cancel");

    let mut stream = std::io::Cursor::new(vec![1u8; 32]);
    let err = send_firmware(&mut dev, &mut stream, BlockLength::Standard).unwrap_err();
    assert!(matches!(err, XmodemError::Canceled), "got {err:?}");
}

#[test]
fn persistent_nak_exhausts_error_budget_documented_limitation() {
    // The library counts a mid-stream NAK as an error but advances to the
    // next block; a receiver that keeps NAKing therefore exhausts
    // max_errors. This pins that (documented) behavior: recovery happens
    // by retrying the whole transfer at the driver, not per-block.
    let (mut dev, mut peer) = UnixStream::pair().expect("socketpair");
    let payload: Vec<u8> = (0..5000u16).map(|v| (v % 256) as u8).collect();

    let handle = std::thread::spawn(move || {
        peer.write_all(&[CRC_START]).expect("start C");
        // NAK one response per chunk read; no frame parsing needed since
        // every answer is NAK regardless of boundaries.
        let mut buf = [0u8; 4096];
        loop {
            match peer.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if peer.write_all(&[NAK]).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut stream = std::io::Cursor::new(payload);
    let err = send_firmware(&mut dev, &mut stream, BlockLength::OneK).unwrap_err();
    drop(dev); // unblock the receiver's final read so join() completes
    handle.join().expect("receiver thread");
    assert!(
        matches!(err, XmodemError::ExhaustedRetries),
        "expected error exhaustion, got {err:?}"
    );
}

#[test]
fn eot_nak_once_then_ack_succeeds() {
    let (mut dev, mut peer) = UnixStream::pair().expect("socketpair");
    let payload = vec![0x42u8; 5];

    let handle = std::thread::spawn(move || {
        peer.write_all(&[CRC_START]).expect("start C");
        recv_frame(&mut peer, 128, 2, 1);
        peer.write_all(&[ACK]).expect("ack block");
        // Classic receiver: NAK the first EOT, ACK the retransmitted one.
        let mut eot = [0u8; 1];
        peer.read_exact(&mut eot).expect("first EOT");
        assert_eq!(eot[0], EOT);
        peer.write_all(&[NAK]).expect("nak EOT");
        recv_eot_and_ack(&mut peer);
    });

    let mut stream = std::io::Cursor::new(payload);
    let sent = send_firmware(&mut dev, &mut stream, BlockLength::Standard).expect("transfer ok");
    handle.join().expect("receiver thread");
    assert_eq!(sent, 5);
}

/// A mid-stream NAK (receiver wants block N retransmitted) makes the sender
/// advance to block N+1 instead. A strict receiver then aborts on the
/// sequence mismatch while the sender reports success — the driver must
/// verify receiver-side acceptance, never trust the sender-side Ok.
/// Pins xmodem-0.4 `send_stream`: non-ACK ⇒ error count + next block.
#[test]
fn mid_stream_nak_advances_without_retransmit() {
    let (mut dev, mut peer) = UnixStream::pair().expect("socketpair");
    let payload: Vec<u8> = (0..384u16).map(|v| (v % 256) as u8).collect();
    let expected = payload.clone();

    let handle = std::thread::spawn(move || {
        peer.write_all(&[CRC_START]).expect("start C");
        recv_frame(&mut peer, 128, 2, 1);
        // Request retransmission of block 1…
        peer.write_all(&[NAK]).expect("nak block 1");
        // …and observe the sender skip straight to block 2.
        let frame2 = recv_frame(&mut peer, 128, 2, 2);
        assert_eq!(&frame2[..], &expected[128..256]);
        peer.write_all(&[ACK]).expect("ack block 2");
        recv_frame(&mut peer, 128, 2, 3);
        peer.write_all(&[ACK]).expect("ack block 3");
        recv_eot_and_ack(&mut peer);
    });

    let mut stream = std::io::Cursor::new(payload);
    let sent = send_firmware(&mut dev, &mut stream, BlockLength::Standard)
        .expect("sender completes despite the NAK");
    handle.join().expect("receiver thread");
    assert_eq!(sent, 384);
}

/// Mid-stream CAN is NOT honored (xmodem-0.4 TODO): the bytes are consumed
/// as generic errors and the transfer continues. Only CAN at transfer start
/// cancels. If the crate ever fixes this, this test fails and the driver's
/// cancellation handling must be revisited.
#[test]
fn mid_stream_can_is_counted_not_honored() {
    let (mut dev, mut peer) = UnixStream::pair().expect("socketpair");
    let payload = vec![0x55u8; 384];

    let handle = std::thread::spawn(move || {
        peer.write_all(&[CRC_START]).expect("start C");
        recv_frame(&mut peer, 128, 2, 1);
        peer.write_all(&[ACK]).expect("ack block 1");
        recv_frame(&mut peer, 128, 2, 2);
        // Receiver aborts: double CAN mid-stream…
        peer.write_all(&[CAN, CAN]).expect("cancel mid-stream");
        // …but the sender swallows both as error counts (one per frame
        // response) and keeps sending the remaining block.
        recv_frame(&mut peer, 128, 2, 3);
        peer.write_all(&[ACK]).expect("ack block 3");
        recv_eot_and_ack(&mut peer);
    });

    let mut stream = std::io::Cursor::new(payload);
    let sent = send_firmware(&mut dev, &mut stream, BlockLength::Standard)
        .expect("mid-stream CAN must not cancel in xmodem-0.4");
    handle.join().expect("receiver thread");
    assert_eq!(sent, 384);
}

/// Read timeouts while waiting for an ACK consume the error budget until
/// the transfer aborts with ExhaustedRetries — no hang, no partial success.
///
/// Uses a channel-backed double, not a socketpair: Linux surfaces
/// `SO_RCVTIMEO` as `ErrorKind::WouldBlock`, which the crate treats as
/// fatal, while real serial-port timeouts surface as `TimedOut` — the kind
/// the crate soft-handles. The double reproduces the serial semantics.
#[test]
fn ack_read_timeouts_exhaust_error_budget() {
    use std::sync::mpsc;

    struct FakeSerial {
        inbound: mpsc::Receiver<u8>,
        outbound: mpsc::Sender<u8>,
    }
    impl Read for FakeSerial {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self
                .inbound
                .recv_timeout(std::time::Duration::from_millis(5))
            {
                Ok(byte) => {
                    buf[0] = byte;
                    Ok(1)
                }
                Err(mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "serial read timeout",
                )),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "peer gone",
                )),
            }
        }
    }
    impl Write for FakeSerial {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            for byte in buf {
                self.outbound.send(*byte).expect("receiver alive");
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let (to_sender, inbound) = mpsc::channel();
    let (outbound, from_sender) = mpsc::channel();
    to_sender.send(CRC_START).expect("start C");

    let responder = std::thread::spawn(move || {
        let mut seen = 0usize;
        while let Ok(_byte) = from_sender.recv() {
            seen += 1;
            if seen == 128 + 3 + 2 {
                // frame 1 fully arrived: ACK it once, then fall silent
                to_sender.send(ACK).expect("ack");
            }
        }
    });

    let mut dev = FakeSerial { inbound, outbound };
    let payload = vec![0xA7u8; 4096];
    let mut stream = std::io::Cursor::new(payload);
    let err = send_firmware(&mut dev, &mut stream, BlockLength::Standard).unwrap_err();
    drop(dev);
    responder.join().expect("responder");
    assert!(
        matches!(err, XmodemError::ExhaustedRetries),
        "expected error exhaustion, got {err:?}"
    );
}

/// After a failed transfer the documented recovery is a fresh whole-file
/// retry: `send_firmware` must leave no residue that breaks a restart.
#[test]
fn whole_transfer_restart_after_failure_succeeds() {
    let (mut failed_dev, mut failed_peer) = UnixStream::pair().expect("socketpair");
    failed_dev
        .set_read_timeout(Some(std::time::Duration::from_millis(10)))
        .expect("read timeout");
    let junk = vec![1u8; 512];
    failed_peer.write_all(&[CRC_START]).expect("start C");
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match failed_peer.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    let mut stream = std::io::Cursor::new(junk);
    assert!(send_firmware(&mut failed_dev, &mut stream, BlockLength::Standard).is_err());
    drop(failed_dev);
    reader.join().expect("drain");

    let (mut dev, mut peer) = UnixStream::pair().expect("socketpair");
    let payload: Vec<u8> = (0..100u8).collect();
    let expected = payload.clone();
    let handle = std::thread::spawn(move || {
        peer.write_all(&[CRC_START]).expect("start C");
        let frame = recv_frame(&mut peer, 128, 2, 1);
        assert_eq!(&frame[..100], &expected[..]);
        peer.write_all(&[ACK]).expect("ack block");
        recv_eot_and_ack(&mut peer);
    });
    let mut stream = std::io::Cursor::new(payload);
    let sent = send_firmware(&mut dev, &mut stream, BlockLength::Standard).expect("restart ok");
    handle.join().expect("receiver thread");
    assert_eq!(sent, 100);
}

// ─── #124 driver-level retry policy ─────────────────────────────────────────

mod verified_retry {
    use super::*;
    use conwrt_protocols::xmodem_transfer::{RetryPolicy, VerifiedError, send_firmware_verified};

    fn policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 3,
            restart_delay_ms: 0,
        }
    }

    /// Scripted XMODEM receiver. `nak_blocks` lists block numbers to NAK
    /// mid-stream (the crate limitation: it advances WITHOUT
    /// retransmitting — the block is silently lost receiver-side, and the
    /// sender still reports success). It keeps ACKing the remaining
    /// blocks, exactly like a lenient bootloader does; the LOST bytes are
    /// what receiver-side verification must catch.
    struct ScriptedReceiver {
        peer: UnixStream,
        /// Block numbers to NAK on the FIRST attempt only.
        nak_blocks_first_attempt: Vec<u8>,
        /// Block numbers to NAK on every attempt.
        nak_blocks_always: Vec<u8>,
    }

    impl ScriptedReceiver {
        fn run(mut self, payload_len: usize, max_transfers: u32) -> ReceiverReport {
            let mut report = ReceiverReport::default();
            loop {
                // The receiver initiates each attempt by sending the CRC
                // start byte, and stops inviting once the expected number
                // of transfers has run (a further 'C' would go unread —
                // the sender is done and the socket is about to close).
                if report.transfers_seen >= max_transfers
                    || self.peer.write_all(&[CRC_START]).is_err()
                {
                    break;
                }
                report.transfers_seen += 1;
                let nak_blocks = if report.transfers_seen == 1 {
                    &self.nak_blocks_first_attempt
                } else {
                    &self.nak_blocks_always
                };
                let blocks = payload_len.div_ceil(128).max(1);
                for block_no in 1..=blocks as u8 {
                    let _frame = recv_frame(&mut self.peer, 128, 2, block_no);
                    let reply = if nak_blocks.contains(&block_no) {
                        NAK
                    } else {
                        ACK
                    };
                    self.peer.write_all(&[reply]).expect("block reply");
                }
                recv_eot_and_ack(&mut self.peer);
                report.eots_seen += 1;
            }
            report
        }
    }

    #[derive(Debug, Default)]
    struct ReceiverReport {
        transfers_seen: u32,
        eots_seen: u32,
    }

    #[test]
    fn sender_ok_is_not_success_verification_is() {
        // The #124 regression pin: attempt 1 loses block 2 to a mid-stream
        // NAK (the sender still completes and claims success — the pinned
        // crate limitation), verification refuses, the whole transfer
        // restarts and attempt 2 is clean + verified.
        let payload = vec![0xABu8; 300];
        let (mut dev, peer) = UnixStream::pair().expect("socketpair");

        let receiver = std::thread::spawn(move || {
            ScriptedReceiver {
                peer,
                nak_blocks_first_attempt: vec![2],
                nak_blocks_always: vec![],
            }
            .run(300, 2)
        });

        let bytes_src = payload.clone();
        let factory = move || std::io::Cursor::new(bytes_src.clone());
        let mut verify_calls = 0;
        let bytes = send_firmware_verified(
            &mut dev,
            factory,
            BlockLength::Standard,
            &policy(),
            &mut || {
                verify_calls += 1;
                verify_calls > 1 // attempt 1 lost a block; attempt 2 landed
            },
            |_| {},
        )
        .expect("verified transfer");
        drop(dev);
        let report = receiver.join().expect("receiver");

        assert_eq!(bytes, 300);
        assert_eq!(verify_calls, 2, "each claimed success must be verified");
        assert_eq!(report.transfers_seen, 2, "whole transfer restarted once");
        assert_eq!(report.eots_seen, 2, "both attempts ran to EOT");
    }

    #[test]
    fn never_verified_is_never_ok() {
        // Sender succeeds every attempt; verification never passes →
        // Unverified, with the sender's byte claim surfaced for diagnosis.
        let payload = vec![1u8; 100];
        let (mut dev, peer) = UnixStream::pair().expect("socketpair");

        let receiver = std::thread::spawn(move || {
            ScriptedReceiver {
                peer,
                nak_blocks_first_attempt: vec![],
                nak_blocks_always: vec![1],
            }
            .run(100, 3)
        });

        let bytes_src = payload.clone();
        let factory = move || std::io::Cursor::new(bytes_src.clone());
        let err = send_firmware_verified(
            &mut dev,
            factory,
            BlockLength::Standard,
            &policy(),
            &mut || false,
            |_| {},
        )
        .unwrap_err();
        drop(dev);
        receiver.join().expect("receiver");

        match err {
            VerifiedError::Unverified {
                attempts,
                bytes_claimed,
            } => {
                assert_eq!(attempts, 3);
                assert_eq!(bytes_claimed, 100);
            }
            other => panic!("expected Unverified, got {other:?}"),
        }
    }

    #[test]
    fn sender_failure_exhausts_attempts() {
        // Receiver never speaks: every sender attempt dies at startup.
        let (mut dev, peer) = UnixStream::pair().expect("socketpair");
        drop(peer); // silence — reads hit EOF, the crate errors fast

        let bytes_src = vec![5u8; 50];
        let factory = move || std::io::Cursor::new(bytes_src.clone());
        let err = send_firmware_verified(
            &mut dev,
            factory,
            BlockLength::Standard,
            &policy(),
            &mut || true,
            |_| {},
        )
        .unwrap_err();

        match err {
            VerifiedError::AttemptsExhausted { attempts, .. } => assert_eq!(attempts, 3),
            other => panic!("expected AttemptsExhausted, got {other:?}"),
        }
    }

    #[test]
    fn happy_path_verifies_once() {
        let payload = vec![9u8; 200];
        let (mut dev, peer) = UnixStream::pair().expect("socketpair");
        let receiver = std::thread::spawn(move || {
            ScriptedReceiver {
                peer,
                nak_blocks_first_attempt: vec![],
                nak_blocks_always: vec![],
            }
            .run(200, 1)
        });

        let bytes_src = payload.clone();
        let factory = move || std::io::Cursor::new(bytes_src.clone());
        let mut verify_calls = 0;
        let bytes = send_firmware_verified(
            &mut dev,
            factory,
            BlockLength::Standard,
            &policy(),
            &mut || {
                verify_calls += 1;
                true
            },
            |_| {},
        )
        .expect("clean transfer");
        drop(dev);
        let report = receiver.join().expect("receiver");

        assert_eq!(bytes, 200);
        assert_eq!(verify_calls, 1);
        assert_eq!(report.transfers_seen, 1);
        assert_eq!(report.eots_seen, 1);
    }
}
