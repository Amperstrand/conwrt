//! Transport-agnostic COBS framing — the "one codec everywhere" rule
//! (ADR-0004 §2), extracted from the M3 TCP transport so the MCU agent
//! (USB CDC-ACM) and the std agent (tokio TCP) share one implementation.
//!
//! Feed raw transport bytes into [`CobsPump`]; complete frames come out.
//! Encode outbound frames with [`encode_frame`] (COBS + trailing
//! delimiter byte).

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use postcard_rpc::accumulator::raw::{CobsAccumulator, FeedResult};

/// Max buffered bytes per undecoded frame (matches the M3 TCP pump).
pub const ACCUMULATOR_CAPACITY: usize = 8192;

/// COBS deframer over arbitrary byte transports.
///
/// Transport-agnostic by design: the caller owns how bytes arrive
/// (tokio `read`, embassy USB CDC `read_packet`, …) and calls
/// [`CobsPump::feed`] with each chunk.
pub struct CobsPump {
    acc: CobsAccumulator<ACCUMULATOR_CAPACITY>,
    pending: VecDeque<Vec<u8>>,
}

impl CobsPump {
    /// New empty pump.
    #[must_use]
    pub fn new() -> Self {
        Self {
            acc: CobsAccumulator::new(),
            pending: VecDeque::new(),
        }
    }

    /// Feed raw transport bytes; returns the number of complete frames
    /// extracted (available via [`CobsPump::pop_frame`]). Garbage between
    /// delimiters is skipped (the accumulator reports `DeserError` and
    /// resynchronizes on the next delimiter).
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        let mut frames = 0;
        let mut window = bytes;
        while !window.is_empty() {
            window = match self.acc.feed(window) {
                FeedResult::Consumed => break,
                FeedResult::OverFull(w) => w,
                FeedResult::DeserError(w) => w,
                FeedResult::Success { data, remaining } => {
                    self.pending.push_back(data.to_vec());
                    frames += 1;
                    remaining
                }
            };
        }
        frames
    }

    /// Pop the oldest complete frame, if any.
    #[must_use]
    pub fn pop_frame(&mut self) -> Option<Vec<u8>> {
        self.pending.pop_front()
    }

    /// Whether a complete frame is buffered.
    #[must_use]
    pub fn has_frame(&self) -> bool {
        !self.pending.is_empty()
    }
}

impl Default for CobsPump {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode one payload as a wire frame: COBS encoding + trailing delimiter
/// byte (the framing the accumulator on the other side expects).
#[must_use]
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut encoded = cobs::encode_vec(payload);
    encoded.push(0);
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single_frame() {
        let payload: &[u8] = &[0x01, 0x02, 0x00, 0x03, 0xff];
        let wire = encode_frame(payload);
        assert_eq!(wire.last(), Some(&0));

        let mut pump = CobsPump::new();
        assert_eq!(pump.feed(&wire), 1);
        assert_eq!(pump.pop_frame().as_deref(), Some(payload));
        assert!(pump.pop_frame().is_none());
    }

    #[test]
    fn round_trip_split_across_feeds() {
        let a = encode_frame(b"hello agent");
        let b = encode_frame(b"second frame");
        let mut stream = a.clone();
        stream.extend_from_slice(&b);

        let mut pump = CobsPump::new();
        let mid = a.len() / 2;
        let (total_first, total_second) = (pump.feed(&stream[..mid]), pump.feed(&stream[mid..]));
        assert_eq!(total_first + total_second, 2);
        assert_eq!(pump.pop_frame().as_deref(), Some(&b"hello agent"[..]));
        assert_eq!(pump.pop_frame().as_deref(), Some(&b"second frame"[..]));
    }

    #[test]
    fn garbage_frame_is_skipped_and_stream_resyncs() {
        // Undelimited garbage corrupts the COBS length prefix of whatever
        // follows it, so the frame sharing its delimiter is dropped — the
        // accumulator resynchronizes at the NEXT delimiter boundary.
        let frame = encode_frame(b"real frame");
        let mut stream = vec![0xde, 0xad, 0xbe, 0xef, 0x00];
        stream.extend_from_slice(&frame);
        stream.extend_from_slice(&encode_frame(b"after resync"));

        let mut pump = CobsPump::new();
        assert_eq!(pump.feed(&stream), 2);
        assert_eq!(pump.pop_frame().as_deref(), Some(&b"real frame"[..]));
        assert_eq!(pump.pop_frame().as_deref(), Some(&b"after resync"[..]));
    }

    #[test]
    fn empty_payload_frame_round_trips() {
        let wire = encode_frame(b"");
        let mut pump = CobsPump::new();
        assert_eq!(pump.feed(&wire), 1);
        assert_eq!(pump.pop_frame().as_deref(), Some(&[][..]));
    }
}
