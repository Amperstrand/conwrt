//! The firmware bridge from agent-protocol stream frames to the
//! executor's transfer window (#226 slice 3).
//!
//! [`ExecutorTransfer`] implements the protocol's `TransferSink` over a
//! [`TransferState`]: chunks land in the bounded window, acks carry the
//! resume token back to the controller. The window binds lazily to the
//! first chunk's `transfer_id`; a chunk for a **different** transfer id
//! resets the window — a new controller/transfer gets a fresh window
//! (the abandoned one is unrecoverable by design: a POST that started
//! under it burned the one-request recovery window, and one that did
//! not start holds nothing worth resuming across ids).

use alloc::format;
use alloc::string::String;

use conwrt_agent_proto::dispatch::WireError;
use conwrt_agent_proto::protocol::{StreamAck, StreamChunk};
use conwrt_agent_proto::server::TransferSink;

use crate::transfer::{TransferError, TransferState};

/// `TransferSink` over one bounded [`TransferState`] window — what the
/// firmware hands to `ServerCore` so `StreamChunk`/`StreamStatus` flow
/// through the real controller session.
pub struct ExecutorTransfer {
    /// Undrained-byte capacity for a fresh window (the firmware
    /// profile: 8 KiB).
    capacity: usize,
    state: Option<TransferState>,
}

impl ExecutorTransfer {
    /// New sink whose window holds at most `capacity` undrained bytes.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: None,
        }
    }

    /// The live transfer's id, if a window is bound.
    #[must_use]
    pub fn transfer_id(&self) -> Option<u64> {
        self.state.as_ref().map(|s| s.ack().transfer_id)
    }

    /// The bound window, mutably — the drain side for the POST pump
    /// ([`crate::PostPump`]). Single-task composition: the borrow ends
    /// before the next `stream_chunk` lands (the firmware loop is
    /// accept-chunk → pump-step, never interleaved).
    pub fn window(&mut self) -> Option<&mut TransferState> {
        self.state.as_mut()
    }
}

/// Window-level failures surfaced as `Internal` wire errors — the
/// protocol has no dedicated window-error shape, so the message is the
/// controller-side diagnostic (names the failure and the numbers that
/// caused it).
fn window_error(e: TransferError) -> WireError {
    let msg = match e {
        TransferError::MissingTotal => String::from("first chunk carried no total"),
        TransferError::Gap {
            expected_at,
            got_at,
        } => format!("gap: window contiguous to {expected_at}, chunk at {got_at}"),
        TransferError::Backpressure { free, needed } => {
            format!("window full: {free} bytes free, chunk needs {needed}")
        }
        TransferError::Overflow { total, end } => {
            format!("chunk end {end} overflows announced total {total}")
        }
        TransferError::TotalChanged { announced, changed } => {
            format!("total changed mid-transfer: announced {announced}, now {changed}")
        }
        TransferError::EmptyTransfer => String::from("zero-byte transfer refused"),
        // handled by the caller (the per-transfer reset path)
        TransferError::WrongTransfer { expected, got } => {
            format!("transfer {got} while {expected} bound")
        }
    };
    WireError::Internal(msg)
}

impl TransferSink for ExecutorTransfer {
    fn stream_chunk(&mut self, chunk: &StreamChunk) -> Result<StreamAck, WireError> {
        if let Some(state) = &mut self.state {
            match state.accept(chunk) {
                Ok(ack) => return Ok(ack),
                // A chunk for a different transfer id: the bound window
                // belongs to an abandoned transfer — drop it and bind a
                // fresh one to the incoming id.
                Err(TransferError::WrongTransfer { .. }) => {}
                Err(e) => return Err(window_error(e)),
            }
        }
        let mut fresh = TransferState::new(chunk.transfer_id, self.capacity);
        let ack = fresh.accept(chunk).map_err(window_error)?;
        self.state = Some(fresh);
        Ok(ack)
    }

    fn stream_status(&mut self, transfer_id: u64) -> Result<StreamAck, WireError> {
        match &self.state {
            Some(state) if state.ack().transfer_id == transfer_id => Ok(state.ack()),
            _ => Err(WireError::UnknownTransfer(transfer_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use conwrt_agent_proto::protocol::StreamChunk;

    fn chunk(transfer_id: u64, offset: u64, data: &[u8], total: Option<u64>) -> StreamChunk {
        StreamChunk {
            transfer_id,
            offset,
            total,
            data: vec::Vec::from(data),
        }
    }

    #[test]
    fn first_chunk_binds_and_acks() {
        let mut sink = ExecutorTransfer::new(64);
        assert_eq!(sink.transfer_id(), None);
        let ack = sink
            .stream_chunk(&chunk(7, 0, b"abc", Some(10)))
            .expect("accept");
        assert_eq!(ack.transfer_id, 7);
        assert_eq!(ack.contiguous, 3);
        assert!(!ack.done);
        assert_eq!(sink.transfer_id(), Some(7));
    }

    #[test]
    fn status_known_and_unknown() {
        let mut sink = ExecutorTransfer::new(64);
        assert_eq!(
            sink.stream_status(7),
            Err(WireError::UnknownTransfer(7)),
            "nothing bound yet"
        );
        sink.stream_chunk(&chunk(7, 0, b"abc", Some(10))).unwrap();
        assert_eq!(sink.stream_status(7).unwrap().contiguous, 3);
        assert_eq!(sink.stream_status(9), Err(WireError::UnknownTransfer(9)));
    }

    #[test]
    fn wrong_transfer_resets_to_fresh_window() {
        let mut sink = ExecutorTransfer::new(64);
        sink.stream_chunk(&chunk(7, 0, b"abcde", Some(5))).unwrap();
        // new controller/transfer: id 2 lands in a FRESH window at 0
        let ack = sink
            .stream_chunk(&chunk(2, 0, b"xyz", Some(4)))
            .expect("reset accepts");
        assert_eq!(ack.transfer_id, 2);
        assert_eq!(ack.contiguous, 3);
        // the old window is gone: id 7 is unknown now
        assert_eq!(sink.stream_status(7), Err(WireError::UnknownTransfer(7)));
        assert_eq!(sink.stream_status(2).unwrap().contiguous, 3);
    }

    #[test]
    fn first_chunk_gap_is_refused_without_binding() {
        // a reconnecting controller replaying from a stale resume token
        // (offset > 0) into an empty executor: refused, nothing bound
        let mut sink = ExecutorTransfer::new(64);
        let err = sink
            .stream_chunk(&chunk(7, 4096, b"xxxx", Some(8192)))
            .unwrap_err();
        assert!(
            matches!(&err, WireError::Internal(m) if m.contains("gap")),
            "gap surfaced, got {err:?}"
        );
        assert_eq!(sink.transfer_id(), None, "failed first chunk binds nothing");
    }

    #[test]
    fn backpressure_is_surfaced() {
        let mut sink = ExecutorTransfer::new(4);
        sink.stream_chunk(&chunk(7, 0, b"abcd", Some(8))).unwrap();
        let err = sink
            .stream_chunk(&chunk(7, 4, b"efgh", Some(8)))
            .unwrap_err();
        assert!(
            matches!(&err, WireError::Internal(m) if m.contains("window full")),
            "backpressure surfaced, got {err:?}"
        );
    }

    #[test]
    fn missing_total_first_chunk_refused() {
        let mut sink = ExecutorTransfer::new(64);
        let err = sink.stream_chunk(&chunk(7, 0, b"abc", None)).unwrap_err();
        assert!(
            matches!(&err, WireError::Internal(m) if m.contains("total")),
            "missing total surfaced, got {err:?}"
        );
    }

    #[test]
    fn resume_semantics_through_the_sink() {
        // lock-step feed with replay trimming, as the controller drives it
        // (nothing drains through the sink — the POST pump is the drainer
        // — so the transfer fits the window whole)
        let mut sink = ExecutorTransfer::new(16);
        let ack = sink
            .stream_chunk(&chunk(1, 0, b"abcdef", Some(16)))
            .unwrap();
        assert_eq!(ack.contiguous, 6);
        // stale-ack replay of the same span: trimmed, ack unchanged
        let ack = sink
            .stream_chunk(&chunk(1, 0, b"abcdef", Some(16)))
            .unwrap();
        assert_eq!(ack.contiguous, 6);
        // the rest arrives
        let ack = sink
            .stream_chunk(&chunk(1, 6, b"0123456789", Some(16)))
            .unwrap();
        assert_eq!(ack.contiguous, 16);
        assert!(ack.done);
        assert!(sink.stream_status(1).unwrap().done);
    }
}
