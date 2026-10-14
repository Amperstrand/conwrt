//! COBS-over-TCP transport for both protocol sides (issue #108).
//!
//! Straight out of the #107 spike (verdict: ADOPT — 232 LOC of wire glue,
//! 46 µs/rtt, streaming+resume verified): one COBS codec everywhere
//! ("one codec everywhere", ADR-0004 §2), a shared receive pump so host
//! and device sides do not duplicate the FeedResult dance, and tokio
//! TcpStream halves.

use std::collections::VecDeque;

use postcard_rpc::accumulator::raw::{CobsAccumulator, FeedResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Receive pump shared by both sides: feeds bytes into the COBS accumulator
/// and yields complete (decoded) frames.
pub struct CobsReceiver {
    buf: Box<[u8; 8192]>,
    acc: Box<CobsAccumulator<8192>>,
    pending: VecDeque<Vec<u8>>,
}

impl CobsReceiver {
    /// New pump over a read half.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Box::new([0u8; 8192]),
            acc: Box::new(CobsAccumulator::new()),
            pending: VecDeque::new(),
        }
    }

    /// Read from `rx` until at least one complete frame is buffered, then
    /// return it. `Ok(None)` = clean EOF.
    pub async fn receive(
        &mut self,
        rx: &mut tokio::net::tcp::OwnedReadHalf,
    ) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Ok(Some(frame));
            }
            let n = rx.read(&mut self.buf[..]).await?;
            if n == 0 {
                return Ok(None);
            }
            let mut window = &self.buf[..n];
            while !window.is_empty() {
                window = match self.acc.feed(window) {
                    FeedResult::Consumed => break,
                    FeedResult::OverFull(w) => w,
                    FeedResult::DeserError(w) => w,
                    FeedResult::Success { data, remaining } => {
                        self.pending.push_back(data.to_vec());
                        remaining
                    }
                };
            }
        }
    }
}

impl Default for CobsReceiver {
    fn default() -> Self {
        Self::new()
    }
}

/// COBS frame sender shared by both sides.
pub struct CobsSender {
    tx: tokio::net::tcp::OwnedWriteHalf,
}

impl CobsSender {
    /// Wrap a write half.
    #[must_use]
    pub fn new(tx: tokio::net::tcp::OwnedWriteHalf) -> Self {
        Self { tx }
    }

    /// Encode one frame (COBS + trailing delimiter) and write it fully.
    pub async fn send(&mut self, frame: &[u8]) -> std::io::Result<()> {
        let mut encoded = cobs::encode_vec(frame);
        encoded.push(0);
        self.tx.write_all(&encoded).await
    }
}
