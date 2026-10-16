//! COBS-over-TCP transport for both protocol sides (issue #108).
//!
//! Straight out of the #107 spike (verdict: ADOPT — 232 LOC of wire glue,
//! 46 µs/rtt, streaming+resume verified): the shared [`crate::cobs`] pump
//! ("one codec everywhere", ADR-0004 §2) wrapped in tokio TcpStream
//! halves.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cobs::encode_frame;

/// Receive pump shared by both sides: feeds bytes into the shared COBS
/// pump ([`crate::cobs::CobsPump`]) and yields complete (decoded) frames.
pub struct CobsReceiver {
    buf: Box<[u8; 8192]>,
    pump: crate::cobs::CobsPump,
}

impl CobsReceiver {
    /// New pump over a read half.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Box::new([0u8; 8192]),
            pump: crate::cobs::CobsPump::new(),
        }
    }

    /// Read from `rx` until at least one complete frame is buffered, then
    /// return it. `Ok(None)` = clean EOF.
    pub async fn receive(
        &mut self,
        rx: &mut tokio::net::tcp::OwnedReadHalf,
    ) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(frame) = self.pump.pop_frame() {
                return Ok(Some(frame));
            }
            let n = rx.read(&mut self.buf[..]).await?;
            if n == 0 {
                return Ok(None);
            }
            self.pump.feed(&self.buf[..n]);
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
        let encoded = encode_frame(frame);
        self.tx.write_all(&encoded).await
    }
}
