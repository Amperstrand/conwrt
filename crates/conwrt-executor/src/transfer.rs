//! Receiving half of the agent-protocol image stream (#226 slice 1).
//!
//! A [`TransferState`] is a bounded RAM window over an in-flight
//! [`StreamChunk`] sequence. The acknowledgement is the protocol's
//! documented resume token — **contiguous received bytes** (replays are
//! idempotent: anything at or below the contiguous point is trimmed on
//! accept, whether those bytes are still buffered or already drained
//! into the consuming operation, so a reconnecting controller may
//! replay from any earlier ack it still holds).
//!
//! The controller is lock-step (`dispatch` — await the ack before the
//! next chunk), so a gap is a protocol violation, not an expected event.

use alloc::collections::VecDeque;

use conwrt_agent_proto::protocol::{StreamAck, StreamChunk};

/// Failures while feeding a transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    /// Chunk for a different transfer than this state tracks.
    WrongTransfer {
        /// The transfer this state belongs to.
        expected: u64,
        /// The transfer the chunk carried.
        got: u64,
    },
    /// First chunk carried no `total` — the executor needs the size for
    /// `Content-Length` before any bytes go on the wire.
    MissingTotal,
    /// Chunk data does not start at or before the contiguous point —
    /// the controller skipped bytes (lock-step violation).
    Gap {
        /// Where the window's contiguous data ends.
        expected_at: u64,
        /// Where the chunk claims to start.
        got_at: u64,
    },
    /// The window is full — drain it before accepting more. With a
    /// lock-step controller this means the consumer stopped pumping.
    Backpressure {
        /// Free bytes left in the window.
        free: usize,
        /// Bytes the chunk wanted to add.
        needed: usize,
    },
    /// The chunk would overflow the announced total.
    Overflow {
        /// Announced total.
        total: u64,
        /// Offset the chunk would reach.
        end: u64,
    },
    /// A later chunk announced a different total than the first —
    /// the resume token and Content-Length derive from it, so a
    /// mid-transfer change is refused outright (review round 1).
    TotalChanged {
        /// The originally announced total.
        announced: u64,
        /// The new, conflicting total.
        changed: u64,
    },
    /// The transfer announced a zero-byte image — no firmware selected.
    /// An empty multipart body would still burn the one-request
    /// recovery window (review round 4).
    EmptyTransfer,
}

/// A bounded window over one image transfer; the resume-token source.
///
/// Capacity is fixed at construction (the executor's RAM budget —
/// 8–16 KiB in the planned firmware profile).
#[derive(Debug)]
pub struct TransferState {
    transfer_id: u64,
    /// Bytes that left the window into the consuming operation — the
    /// ack / resume point.
    drained: u64,
    /// Contiguous received bytes (≥ `drained`).
    contiguous: u64,
    /// Total transfer size, required from the first chunk.
    total: Option<u64>,
    window: VecDeque<u8>,
}

impl TransferState {
    /// New empty window for `transfer_id` holding at most `capacity`
    /// undrained bytes.
    pub fn new(transfer_id: u64, capacity: usize) -> Self {
        Self {
            transfer_id,
            drained: 0,
            contiguous: 0,
            total: None,
            window: VecDeque::with_capacity(capacity),
        }
    }

    /// Current acknowledgement — the resume token. `contiguous` is the
    /// contiguous **received** byte count; `done` means the whole image
    /// was received (the pump may still be draining the tail into the
    /// POST body).
    pub fn ack(&self) -> StreamAck {
        StreamAck {
            transfer_id: self.transfer_id,
            contiguous: self.contiguous,
            done: self.total_is_done(),
        }
    }

    /// Whether the transfer is complete and fully drained.
    pub fn is_complete(&self) -> bool {
        self.total_is_done() && self.window.is_empty()
    }

    /// Total size once the first chunk announced it.
    pub fn total(&self) -> Option<u64> {
        self.total
    }

    fn total_is_done(&self) -> bool {
        self.total.is_some_and(|total| self.contiguous == total)
    }

    /// Accept one chunk into the window, returning the ack to send.
    ///
    /// Chunks may start at or before `contiguous` (a replay after
    /// reconnect overlaps buffered bytes — the overlap is trimmed);
    /// starting *after* `contiguous` is a [`TransferError::Gap`].
    pub fn accept(&mut self, chunk: &StreamChunk) -> Result<StreamAck, TransferError> {
        if chunk.transfer_id != self.transfer_id {
            return Err(TransferError::WrongTransfer {
                expected: self.transfer_id,
                got: chunk.transfer_id,
            });
        }
        let Some(total) = (match (chunk.total, self.total) {
            (Some(new), Some(old)) if new != old => {
                return Err(TransferError::TotalChanged {
                    announced: old,
                    changed: new,
                });
            }
            (Some(new), _) => Some(new),
            (None, Some(old)) => Some(old),
            (None, None) => None,
        }) else {
            return Err(TransferError::MissingTotal);
        };
        if total == 0 {
            return Err(TransferError::EmptyTransfer);
        }
        if self.total.is_none() {
            self.total = Some(total);
        }
        // checked: a hostile offset near u64::MAX must not panic the
        // executor — it is non-contiguous garbage by definition
        let Some(chunk_end) = chunk.offset.checked_add(chunk.data.len() as u64) else {
            return Err(TransferError::Gap {
                expected_at: self.contiguous,
                got_at: chunk.offset,
            });
        };
        if chunk_end > total {
            return Err(TransferError::Overflow {
                total,
                end: chunk_end,
            });
        }
        if chunk.offset > self.contiguous {
            return Err(TransferError::Gap {
                expected_at: self.contiguous,
                got_at: chunk.offset,
            });
        }

        // Trim anything at or before the drained point (fully-duplicate
        // replay) and anything below contiguous (partial duplicate).
        let skip = (self.contiguous - chunk.offset) as usize;
        let new_bytes = &chunk.data[skip.min(chunk.data.len())..];

        let free = self.window.capacity() - self.window.len();
        if new_bytes.len() > free {
            return Err(TransferError::Backpressure {
                free,
                needed: new_bytes.len(),
            });
        }
        self.window.extend(new_bytes.iter().copied());
        self.contiguous += new_bytes.len() as u64;
        Ok(self.ack())
    }

    /// Move up to `buf.len()` buffered bytes out of the window into the
    /// consuming operation, advancing the ack point. Returns how many
    /// bytes were moved (0 = window empty).
    pub fn drain(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.window.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.window.pop_front().expect("drain bounds checked above");
        }
        self.drained += n as u64;
        n
    }

    /// Undrained bytes currently buffered.
    pub fn buffered(&self) -> usize {
        self.window.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn chunk(offset: u64, data: &[u8], total: Option<u64>) -> StreamChunk {
        StreamChunk {
            transfer_id: 7,
            offset,
            total,
            data: alloc::vec::Vec::from(data),
        }
    }

    #[test]
    fn first_chunk_requires_total() {
        let mut t = TransferState::new(7, 1024);
        assert_eq!(
            t.accept(&chunk(0, b"abc", None)),
            Err(TransferError::MissingTotal)
        );
    }

    #[test]
    fn accept_buffer_and_ack_resume_semantics() {
        let mut t = TransferState::new(7, 1024);
        let ack = t.accept(&chunk(0, b"abcdef", Some(10))).unwrap();
        // received (not yet drained) still acks: the resume token
        assert_eq!(ack.contiguous, 6);
        assert!(!ack.done);

        let mut out = [0u8; 4];
        assert_eq!(t.drain(&mut out), 4);
        assert_eq!(&out, b"abcd");
        assert_eq!(t.ack().contiguous, 6);

        t.accept(&chunk(6, b"ghij", Some(10))).unwrap();
        let ack = t.ack();
        assert_eq!(ack.contiguous, 10);
        assert!(ack.done); // fully received
        assert!(!t.is_complete()); // tail still buffered

        let mut out = [0u8; 64];
        assert_eq!(t.drain(&mut out), 6); // only the undrained tail
        assert_eq!(&out[..6], b"efghij");
        assert!(t.is_complete());
    }

    #[test]
    fn replay_overlap_is_trimmed_idempotent() {
        let mut t = TransferState::new(7, 1024);
        t.accept(&chunk(0, b"abcdef", Some(10))).unwrap();
        let mut out = [0u8; 3];
        t.drain(&mut out); // drained=3, window=def

        // controller replays from an old ack point 0: bytes below the
        // contiguous point are trimmed wholesale (drained or buffered)
        let ack = t.accept(&chunk(0, b"abcdef", Some(10))).unwrap();
        assert_eq!(ack.contiguous, 6);
        assert_eq!(t.buffered(), 3); // no duplication in window
    }

    #[test]
    fn gap_is_rejected() {
        let mut t = TransferState::new(7, 1024);
        t.accept(&chunk(0, b"abc", Some(10))).unwrap();
        assert_eq!(
            t.accept(&chunk(5, b"xxxxx", Some(10))),
            Err(TransferError::Gap {
                expected_at: 3,
                got_at: 5
            })
        );
    }

    #[test]
    fn window_full_is_backpressure_not_silent_drop() {
        let mut t = TransferState::new(7, 4);
        t.accept(&chunk(0, b"abcd", Some(8))).unwrap();
        assert!(matches!(
            t.accept(&chunk(4, b"efgh", Some(8))),
            Err(TransferError::Backpressure { free: 0, needed: 4 })
        ));
        // drain frees space; the same chunk now fits
        let mut out = [0u8; 4];
        t.drain(&mut out);
        assert!(t.accept(&chunk(4, b"efgh", Some(8))).is_ok());
    }

    #[test]
    fn overflow_total_rejected() {
        let mut t = TransferState::new(7, 1024);
        assert_eq!(
            t.accept(&chunk(0, b"abcdef", Some(3))),
            Err(TransferError::Overflow { total: 3, end: 6 })
        );
    }

    #[test]
    fn zero_total_rejected() {
        let mut t = TransferState::new(7, 1024);
        assert_eq!(
            t.accept(&chunk(0, b"", Some(0))),
            Err(TransferError::EmptyTransfer)
        );
    }

    #[test]
    fn absurd_offset_is_structured_error_not_panic() {
        let mut t = TransferState::new(7, 1024);
        t.accept(&chunk(0, b"abc", Some(10))).unwrap();
        let mut c = chunk(u64::MAX - 1, b"xyz", Some(10));
        assert_eq!(
            t.accept(&c),
            Err(TransferError::Gap {
                expected_at: 3,
                got_at: u64::MAX - 1
            })
        );
        c.offset = u64::MAX;
        c.data.clear();
        assert!(t.accept(&c).is_err(), "even MAX+0 stays an error");
    }

    #[test]
    fn total_change_mid_transfer_rejected() {
        let mut t = TransferState::new(7, 1024);
        t.accept(&chunk(0, b"abc", Some(10))).unwrap();
        assert_eq!(
            t.accept(&chunk(3, b"defg", Some(12))),
            Err(TransferError::TotalChanged {
                announced: 10,
                changed: 12
            })
        );
        // same total on later chunks is fine
        assert!(t.accept(&chunk(3, b"defg", Some(10))).is_ok());
    }

    #[test]
    fn wrong_transfer_rejected() {
        let mut t = TransferState::new(7, 1024);
        let mut c = chunk(0, b"a", Some(1));
        c.transfer_id = 9;
        assert_eq!(
            t.accept(&c),
            Err(TransferError::WrongTransfer {
                expected: 7,
                got: 9
            })
        );
    }

    #[test]
    fn large_transfer_streaming_through_small_window() {
        // 64 KiB image through a 1 KiB window, lock-step
        let image: alloc::vec::Vec<u8> = (0..64 * 1024u32).map(|i| (i % 251) as u8).collect();
        let mut t = TransferState::new(1, 1024);
        let mut sent = 0usize;
        let mut drained_bytes = vec![];
        while sent < image.len() {
            let end = (sent + 900).min(image.len());
            let ack = t
                .accept(&StreamChunk {
                    transfer_id: 1,
                    offset: sent as u64,
                    total: Some(image.len() as u64),
                    data: alloc::vec::Vec::from(&image[sent..end]),
                })
                .unwrap();
            let mut buf = [0u8; 4096];
            let n = t.drain(&mut buf);
            drained_bytes.extend_from_slice(&buf[..n]);
            sent = end;
            // received-based ack: equals bytes sent; window fully drained
            assert_eq!(ack.contiguous, sent as u64);
            assert_eq!(t.buffered(), 0);
        }
        assert_eq!(drained_bytes, image);
        assert!(t.ack().done);
    }
}
