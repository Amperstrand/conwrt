//! Simulated Z-Loader — a faithful fake bootloader for sender e2e tests.
//!
//! Wraps [`ZLoaderReceiver`] (the RE'd receive state machine) behind a real
//! UDP socket: point the actual sender at it and it reassembles exactly the
//! way the NR7101 STAGE-2 blob does — same gates, same rollback-on-out-of-
//! order, same completion semantics. This is the "works against the
//! reverse-engineered code" harness: a protocol change that upsets the
//! simulator would upset the bootloader.
//!
//! Bench use beyond tests: dress-rehearse a flash (loop counts, timing,
//! loss recovery) with zero hardware on the line.

use conwrt_protocols::zycast_receiver::{Decision, DropReason, ZLoaderReceiver};
use std::net::UdpSocket;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

/// Handle to a running simulator.
pub struct SimZLoader {
    /// UDP port the fake bootloader listens on (127.0.0.1).
    pub port: u16,
    result: Receiver<SimResult>,
}

/// What the simulator observed.
#[derive(Debug, Clone)]
pub struct SimResult {
    /// Whether the receiver reached flash-commit readiness.
    pub completed: bool,
    /// Reassembled image (padded to the chunk boundary).
    /// Reassembled image (padded to the chunk boundary).
    pub image: Vec<u8>,
    /// Packets accepted into the reassembly.
    /// Packets accepted into reassembly.
    pub accepted: usize,
    /// Out-of-order drops — each one means the receiver rolled its
    /// descriptor back and waited for a loop restart.
    /// Out-of-order drops — each rolled the descriptor back to chunk 0.
    pub rolled_back: usize,
    /// Checksum mismatches (packet skipped, no state damage).
    pub checksum_errors: usize,
    /// Other drops (malformed, dedup, post-completion ignores).
    pub other_drops: usize,
}

impl SimZLoader {
    /// Spawn a receiver on `127.0.0.1:0`. `drop_first` = seq numbers whose
    /// FIRST arrival is discarded (to force the rollback path); leave empty
    /// for a clean run.
    #[must_use]
    pub fn spawn(drop_first: &[u32]) -> Self {
        let sock = UdpSocket::bind(("127.0.0.1", 0)).expect("bind sim socket");
        let port = sock.local_addr().unwrap().port();
        let drops: Vec<u32> = drop_first.to_vec();
        let (tx, rx): (Sender<SimResult>, Receiver<SimResult>) = mpsc::channel();
        thread::spawn(move || {
            sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
            let mut rxm = ZLoaderReceiver::new();
            let mut dropped_once: Vec<u32> = Vec::new();
            let mut res = SimResult {
                completed: false,
                image: Vec::new(),
                accepted: 0,
                rolled_back: 0,
                checksum_errors: 0,
                other_drops: 0,
            };
            let deadline = std::time::Instant::now() + Duration::from_secs(120);
            while !rxm.is_done() && std::time::Instant::now() < deadline {
                let mut buf = [0u8; 64 * 1024];
                let (n, _) = match sock.recv_from(&mut buf) {
                    Ok(x) => x,
                    Err(_) => continue, // read timeout — loop to deadline check
                };
                // Simulated loss: discard the first arrival of `drop_first`
                // seqs — invisible to the receiver, exactly like wire loss.
                let seq = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
                if drops.contains(&seq) && !dropped_once.contains(&seq) {
                    dropped_once.push(seq);
                    continue;
                }
                match rxm.on_packet(&buf[..n]) {
                    Decision::Accept { .. } => res.accepted += 1,
                    Decision::TypeComplete { .. } | Decision::StreamComplete => {
                        res.accepted += 1;
                    }
                    Decision::Drop(DropReason::OutOfOrder) => res.rolled_back += 1,
                    Decision::Drop(DropReason::Checksum) => res.checksum_errors += 1,
                    Decision::Drop(_) => res.other_drops += 1,
                }
            }
            res.completed = rxm.is_done();
            res.image = rxm.image().to_vec();
            tx.send(res).ok();
        });
        Self { port, result: rx }
    }

    /// Block until the receiver finishes (or the sender gives up) and
    /// return what it saw.
    pub fn finish(self) -> SimResult {
        self.result
            .recv_timeout(Duration::from_secs(180))
            .expect("simulator reported")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sender::{SendConfig, send};
    use conwrt_protocols::zycast::ImageType;
    use std::net::{Ipv4Addr, UdpSocket as StdSocket};

    fn image_of(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
    }

    fn send_to_sim(image: &[u8], sim_port: u16, loops: u32) {
        let cfg = SendConfig {
            group: Ipv4Addr::LOCALHOST,
            port: sim_port,
            interface: "lo".into(),
            loops,
            delay: Duration::from_millis(1),
        };
        let img = image.to_vec();
        let h = thread::spawn(move || {
            send(&img, ImageType::Ras, &cfg, &mut |_| {}).expect("send");
        });
        h.join().expect("sender thread");
    }

    /// e2e: the real sender (real sockets, real wire path on lo) against
    /// the RE'd receiver — clean run reconstructs the image exactly and
    /// the receiver reaches flash-commit readiness.
    #[test]
    fn sender_completes_against_the_reverse_engineered_receiver() {
        let sim = SimZLoader::spawn(&[]);
        let img = image_of(2 * 1024 + 137);
        send_to_sim(&img, sim.port, 1);
        let res = sim.finish();
        assert!(res.completed, "receiver must reach StreamComplete");
        assert_eq!(&res.image[..img.len()], img.as_slice());
        assert_eq!(res.rolled_back, 0, "clean run: no rollbacks");
        assert_eq!(res.checksum_errors, 0);
    }

    /// e2e: a lost packet mid-loop forces the receiver's rollback; the
    /// sender's next loop restart is the retransmission that completes the
    /// stream. This is the bench-proven reason loops exist — now pinned
    /// as a regression test.
    #[test]
    fn loss_is_healed_by_loop_restart_not_by_resend_in_place() {
        let sim = SimZLoader::spawn(&[1]); // first arrival of seq 1 vanishes
        let img = image_of(3 * 1024 + 5);
        send_to_sim(&img, sim.port, 3);
        let res = sim.finish();
        assert!(res.completed, "multi-loop must heal the loss");
        assert!(
            res.rolled_back >= 1,
            "the loss must have triggered rollback"
        );
        assert_eq!(&res.image[..img.len()], img.as_slice());
    }

    /// The mid-stream join case: a bootloader that enters its listen
    /// window AFTER the sender started (our power-cycle timing) catches
    /// the next loop from chunk 0 and still completes.
    #[test]
    fn late_joiner_catches_the_next_loop() {
        // Two simulators on the same port is not possible; emulate the
        // late join by starting the sim AFTER a first sender loop has run
        // into a black hole, then sending again.
        let blackhole = StdSocket::bind(("127.0.0.1", 0)).unwrap();
        let img = image_of(1024 + 9);
        send_to_sim(&img, blackhole.local_addr().unwrap().port(), 1);
        // Now the "bootloader" comes up:
        let sim = SimZLoader::spawn(&[]);
        send_to_sim(&img, sim.port, 1);
        let res = sim.finish();
        assert!(res.completed);
        assert_eq!(&res.image[..img.len()], img.as_slice());
    }
}
