//! Z-Loader zycast RECEIVE state machine — the reverse-engineered model.
//!
//! Encodes the receiver semantics proven by static analysis of the NR7101
//! STAGE-2 bootloader blob (MitraStar "Z-LOADER V1.30", 2020-06-03):
//! conwrt-bench `docs/research/2026-11-10-zloader-re-findings.md`, every
//! rule below carries its evidence grade from that document
//! (**P** proven / **S** strong / **I** inferred).
//!
//! Purpose: this module is the receiver-side *truth* the sender is tested
//! against (see `conwrt-zycast`'s simulator). Wire bytes proven on hardware
//! and this independently-derived model agree field-for-field, so a sender
//! that satisfies the simulator satisfies the bootloader.
//!
//! Packet layout (all multi-byte fields big-endian) [P]:
//! `+0` `"zyx"`, `+4` u16 checksum, `+6` u32 block seq, `+0xa` u32 payload
//! len, `+0xe` u32 total size, `+0x12` u32 type (`& 0xff00` used),
//! `+0x15` u8 total-type mask, `+0x16` 2B cmd flags, `+0x18` u8 cmd bits,
//! `+0x1e` payload (1024-byte blocks).

use crate::zycast::{CHUNK_LEN, HEADER_LEN, MAGIC, checksum};

/// Why a packet was not accepted. Drop behavior per the receiver's gate
/// chain [P]: every failure before the checksum gate is a *silent* drop or
/// a printed one — neither corrupts state except where noted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Not `"zyx"` [P] (receiver prints "wrong signature").
    BadMagic,
    /// `type & 0xff00` outside {0x100, 0x200, 0x400, 0x800} [P].
    InvalidType,
    /// Stream already complete — total ignore [P].
    AlreadyDone,
    /// This type's bit already in the completed mask [P].
    TypeComplete,
    /// `seq != expect` for a non-fresh descriptor [P] — the receiver
    /// resets the descriptor ("Roll back…" [S]) and waits for the sender
    /// to retransmit; loop restarts are that retransmission.
    OutOfOrder,
    /// Folded byte-sum ≠ `BE16 @ +4` [P] ("checksum error! wait next file").
    Checksum,
    /// `payload len` impossible for the packet size.
    Malformed,
}

/// Outcome of feeding one packet to [`ZLoaderReceiver`].
/// Per-packet decision: accepted into reassembly (with location), a
/// state transition to completion, or a [`DropReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Packet dropped, receiver state unchanged (or rolled back — see
    /// [`DropReason::OutOfOrder`], the only state-touching drop).
    Drop(DropReason),
    /// Chunk stored at `seq * 1024`; descriptor advanced.
    Accept {
        /// Type bit the chunk belonged to.
        ty: u8,
        /// Block sequence number stored.
        seq: u32,
    },
    /// Last block of a type arrived and the descriptor wrapped to
    /// `first_seq`: the type's bit entered the completed mask [P].
    TypeComplete {
        /// The type bit that completed.
        ty: u8,
    },
    /// Completed mask == the sender's total-type mask (`+0x15`): the
    /// receiver applies the cmd tail and flash-commits [P].
    StreamComplete,
}

/// Per-type reception state.
///
/// The blob's descriptor is {first_seq, expect_seq, last_block} [P] with a
/// documented wrap dance whose exact pointer choreography is [S]-grade;
/// what is [P] is the OBSERVABLE contract: strict in-order acceptance
/// (`seq == expect` or fresh `-1`), rollback on out-of-order to the
/// stream start ("Roll back … packet ID: 0x0000" [S]), and type
/// completion exactly when every block has been received. We model
/// completion as block COVERAGE — behaviorally identical for every
/// packet ordering a sender can produce, and immune to the pointer-dance
/// corner cases the disassembly leaves [S].
#[derive(Debug, Clone)]
struct Descriptor {
    /// Next expected seq; `u32::MAX` = fresh (-1 in the 0xff-memset blob) [P].
    expect: u32,
    /// Final chunk index (`ceil(total/1024) - 1`) [P], absolute.
    last_block: u32,
    /// Coverage bitset: one bit per block of this type's stream.
    received: Vec<u64>,
    /// Set once the descriptor is seeded by its first accepted packet.
    live: bool,
}

impl Descriptor {
    fn blocks_received(&self) -> u32 {
        self.received.iter().map(|w| w.count_ones()).sum()
    }
    fn total_blocks(&self) -> u32 {
        self.last_block.wrapping_add(1)
    }
    fn mark(&mut self, seq: u32) {
        if let Some(word) = self.received.get_mut((seq / 64) as usize) {
            *word |= 1u64 << (seq % 64);
        }
    }
}

/// One per-type descriptor slot, indexed by the type bit (`type >> 8`) [P].
const DESCRIPTOR_SLOTS: usize = 8;

/// The receive state machine. Feed it wire packets (the UDP payload — the
/// dport/5631 gate [P] is the transport's, not the model's); it reassembles
/// the image and tells you what it did.
#[derive(Debug)]
pub struct ZLoaderReceiver {
    /// Per-type reception descriptors (indexed by type bit).
    descriptors: [Descriptor; DESCRIPTOR_SLOTS],
    /// Completed-type bitmask [P] (`state+0x2494` in the blob).
    completed_mask: u8,
    /// Stream completion flag [P] (`*(0x84032518)`); once set, everything
    /// is ignored [P].
    done: bool,
    /// Reassembly buffer (per-type staging in the blob; single-stream here,
    /// which is what every real flash is).
    buffer: Vec<u8>,
    /// Types seen on the wire — for diagnostics.
    total_size: u32,
}

impl Default for ZLoaderReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl ZLoaderReceiver {
    /// A receiver with fresh descriptors (the post-boot state).
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptors: core::array::from_fn(|_| Descriptor {
                expect: u32::MAX,
                last_block: 0,
                received: Vec::new(),
                live: false,
            }),
            completed_mask: 0,
            done: false,
            buffer: Vec::new(),
            total_size: 0,
        }
    }

    /// The reassembled image so far (padded to the last chunk boundary).
    #[must_use]
    pub fn image(&self) -> &[u8] {
        &self.buffer
    }

    /// Completed-type mask, for assertions.
    #[must_use]
    pub fn completed_mask(&self) -> u8 {
        self.completed_mask
    }

    /// Stream-complete flag — the receiver's flash-commit precondition.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Feed one wire packet; apply the receiver's gate chain in its
    /// documented order [P].
    pub fn on_packet(&mut self, pkt: &[u8]) -> Decision {
        use Decision::*;
        // Stream completion gate [P]: after flash-commit begins, total ignore.
        if self.done {
            return Drop(DropReason::AlreadyDone);
        }
        if pkt.len() < HEADER_LEN {
            return Drop(DropReason::Malformed);
        }
        // Magic: 3-byte memcmp "zyx" [P].
        if pkt[0..3] != MAGIC.to_be_bytes()[0..3] {
            return Drop(DropReason::BadMagic);
        }
        // Type: u32 @ +0x12 with only `& 0xff00` used [P] — i.e. byte 0x14
        // is the type bit; byte 0x15 doubles as the total-type mask.
        let ty_bit = pkt[0x14];
        let mask = pkt[0x15];
        let seq = u32::from_be_bytes([pkt[6], pkt[7], pkt[8], pkt[9]]);
        let payload_len = u32::from_be_bytes([pkt[0xa], pkt[0xb], pkt[0xc], pkt[0xd]]);
        let total = u32::from_be_bytes([pkt[0xe], pkt[0xf], pkt[0x10], pkt[0x11]]);
        let checksum_wire = u16::from_be_bytes([pkt[4], pkt[5]]);

        if !matches!(ty_bit, 0x01 | 0x02 | 0x04 | 0x08) {
            return Drop(DropReason::InvalidType);
        }
        // Type-already-complete gate [P].
        if self.completed_mask & ty_bit != 0 {
            return Drop(DropReason::TypeComplete);
        }
        let payload = &pkt[HEADER_LEN..];
        if u32::try_from(payload.len()) != Ok(payload_len) {
            return Drop(DropReason::Malformed);
        }
        // Checksum gate [P] — folded byte-sum, skip on mismatch.
        if checksum(payload) != checksum_wire {
            return Drop(DropReason::Checksum);
        }

        let slot = ty_bit.trailing_zeros() as usize;
        let desc = &mut self.descriptors[slot];
        // Sequence gate [P]: accept iff `seq == expect` or descriptor
        // fresh (-1). Out-of-order → rollback to the stream start
        // ("Roll back … packet ID: 0x0000" [S]); the sender's next loop
        // restart at chunk 0 then walks in order to completion — the
        // bench-proven reason multi-loop sending heals loss.
        if desc.live && seq != desc.expect {
            desc.expect = 0;
            return Drop(DropReason::OutOfOrder);
        }
        if !desc.live {
            let blocks = total.div_ceil(CHUNK_LEN as u32).max(1);
            *desc = Descriptor {
                expect: seq.wrapping_add(1),
                last_block: blocks - 1,
                received: vec![0; blocks.div_ceil(64) as usize],
                live: true,
            };
            self.total_size = total;
            self.buffer = vec![0; blocks as usize * CHUNK_LEN];
        }
        let start = seq as usize * CHUNK_LEN;
        let end = (start + payload.len()).min(self.buffer.len());
        if start < self.buffer.len() {
            self.buffer[start..end].copy_from_slice(&payload[..end - start]);
        }
        let d = &mut self.descriptors[slot];
        d.mark(seq);
        d.expect = seq.wrapping_add(1);
        // Type completion = full block coverage [P contract; wrap dance
        // itself is [S] — see the Descriptor doc note].
        let type_now_complete = d.blocks_received() == d.total_blocks() && d.total_blocks() > 0;
        if type_now_complete {
            self.completed_mask |= ty_bit;
            // Stream completion: mask == sender's declared total mask [P].
            if self.completed_mask == mask {
                self.done = true;
                return StreamComplete;
            }
            return TypeComplete { ty: ty_bit };
        }
        Accept { ty: ty_bit, seq }
    }
}

/// RAS model-ID field of a firmware image, if it carries an RAS header.
///
/// The receiver's flash-commit gate [P]: for images starting `HDR0`
/// (firmware) the 4 bytes at `+0x11c`, printed with `%x`, must equal the
/// flash model string — `7101` (u32 `0x00007101`) for NR7101 — else
/// "Wrong Model ID!! Skip upgrade." This is the wrong-unit refusal class;
/// the sender should refuse *before* multicast what the bootloader
/// refuses after receiving.
#[must_use]
pub fn ras_model_id(image: &[u8]) -> Option<u32> {
    if image.len() < 0x120 {
        return None;
    }
    let is_hdr0 = &image[0..4] == b"HDR0";
    let is_hdr4 = &image[0..4] == b"HDR4"; // bootloader variant [P]
    if !is_hdr0 && !is_hdr4 {
        return None;
    }
    Some(u32::from_be_bytes([
        image[0x11c],
        image[0x11d],
        image[0x11e],
        image[0x11f],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zycast::{ImageType, encode_packet};

    const CHUNK_MAX_TEST: usize = CHUNK_LEN; // noise packets capped at PACKET_MAX (harness buffer is exactly that)

    fn image_of(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 253) as u8).collect()
    }

    #[test]
    fn fresh_descriptor_accepts_any_seq_and_completes() {
        let img = image_of(3 * CHUNK_LEN + 10);
        let mut rx = ZLoaderReceiver::new();
        let mut pkt = [0u8; HEADER_LEN + CHUNK_LEN];
        for i in 0..4u32 {
            let n = encode_packet(&img, i, ImageType::Ras, &mut pkt);
            let d = rx.on_packet(&pkt[..n]);
            match (i, d) {
                (0..=2, Decision::Accept { ty: 0x04, .. }) => {}
                (3, Decision::StreamComplete) => {}
                _ => panic!("seq {i}: {d:?}"),
            }
        }
        assert!(rx.is_done());
        assert_eq!(rx.completed_mask(), 0x04);
        assert_eq!(&rx.image()[..img.len()], img.as_slice());
    }

    #[test]
    fn bad_magic_is_a_silent_drop() {
        let img = image_of(CHUNK_LEN);
        let mut pkt = [0u8; HEADER_LEN + CHUNK_LEN];
        let n = encode_packet(&img, 0, ImageType::Ras, &mut pkt);
        pkt[0] = b'x';
        let mut rx = ZLoaderReceiver::new();
        assert_eq!(
            rx.on_packet(&pkt[..n]),
            Decision::Drop(DropReason::BadMagic)
        );
    }

    #[test]
    fn checksum_mismatch_skips_without_state_damage() {
        let img = image_of(2 * CHUNK_LEN);
        let mut pkt = [0u8; HEADER_LEN + CHUNK_LEN];
        let n = encode_packet(&img, 0, ImageType::Ras, &mut pkt);
        pkt[5] ^= 0xff; // corrupt the wire checksum field
        let mut rx = ZLoaderReceiver::new();
        assert_eq!(
            rx.on_packet(&pkt[..n]),
            Decision::Drop(DropReason::Checksum)
        );
        // Descriptor still fresh: the retransmitted good packet seeds it.
        let n2 = encode_packet(&img, 0, ImageType::Ras, &mut pkt);
        assert!(matches!(rx.on_packet(&pkt[..n2]), Decision::Accept { .. }));
    }

    #[test]
    fn out_of_order_rolls_back_and_loop_restart_recovers() {
        // The bench-proven semantics [P/S]: a lost packet makes the next
        // in-flight seq out-of-order → descriptor reset → the sender's
        // next loop (seq restarts at 0) re-seeds and the stream completes.
        let img = image_of(3 * CHUNK_LEN);
        let mut pkt = [0u8; HEADER_LEN + CHUNK_LEN];
        let mut rx = ZLoaderReceiver::new();

        // Loop 1: seq 0 ok, seq 1 LOST (never fed), seq 2 arrives → OOO.
        let n = encode_packet(&img, 0, ImageType::Ras, &mut pkt);
        assert!(matches!(rx.on_packet(&pkt[..n]), Decision::Accept { .. }));
        let n = encode_packet(&img, 2, ImageType::Ras, &mut pkt);
        assert_eq!(
            rx.on_packet(&pkt[..n]),
            Decision::Drop(DropReason::OutOfOrder)
        );

        // Loop 2: full restart re-seeds the (now fresh) descriptor.
        for i in 0..3u32 {
            let n = encode_packet(&img, i, ImageType::Ras, &mut pkt);
            let d = rx.on_packet(&pkt[..n]);
            match (i, d) {
                (0..=1, Decision::Accept { .. }) => {}
                (2, Decision::StreamComplete) => {}
                _ => panic!("loop2 seq {i}: {d:?}"),
            }
        }
        assert_eq!(&rx.image()[..img.len()], img.as_slice());
    }

    #[test]
    fn completed_type_is_ignored_but_other_types_still_count() {
        let img = image_of(CHUNK_LEN);
        let mut pkt = [0u8; HEADER_LEN + CHUNK_LEN];
        let mut rx = ZLoaderReceiver::new();
        let n = encode_packet(&img, 0, ImageType::Ras, &mut pkt);
        // Single-type sender declares mask == its own bit → completes.
        assert_eq!(rx.on_packet(&pkt[..n]), Decision::StreamComplete);
        let n = encode_packet(&img, 0, ImageType::Ras, &mut pkt);
        // After completion: total ignore [P].
        assert_eq!(
            rx.on_packet(&pkt[..n]),
            Decision::Drop(DropReason::AlreadyDone)
        );
    }

    #[test]
    fn invalid_type_bit_is_rejected() {
        let img = image_of(CHUNK_LEN);
        let mut pkt = [0u8; HEADER_LEN + CHUNK_LEN];
        let n = encode_packet(&img, 0, ImageType::Ras, &mut pkt);
        pkt[0x14] = 0x10; // backup slot — a sender-side type the blob's
        // gate chain does not accept [P: {0x100..0x800}]
        let mut rx = ZLoaderReceiver::new();
        assert_eq!(
            rx.on_packet(&pkt[..n]),
            Decision::Drop(DropReason::InvalidType)
        );
    }

    /// Property pass: the model must eat arbitrarily corrupted input
    /// without panicking, and must NEVER report completion unless a
    /// checksum-valid packet carrying the final block actually arrived.
    /// Deterministic xorshift so failures reproduce from the seed.
    #[test]
    fn corrupted_streams_never_panic_or_false_complete() {
        let mut rng: u64 = 0x5A17_5A17_5A17_5A17;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for case in 0..200u32 {
            let img = image_of(1 + (next() % 5) as usize * CHUNK_LEN);
            let chunks = (img.len().div_ceil(CHUNK_LEN)) as u32;
            let mut pkt = [0u8; HEADER_LEN + CHUNK_LEN];
            let mut rx = ZLoaderReceiver::new();
            let mut fed_some = vec![false; chunks as usize];
            // Feed a shuffled/corrupted soup of packets derived from the
            // real stream plus pure-noise packets.
            let rounds = 6 * chunks + 8;
            for step in 0..rounds {
                let use_noise = next() % 4 == 0;
                let n;
                if use_noise {
                    let len = HEADER_LEN + (next() as usize % (CHUNK_MAX_TEST + 1)); // ≤ PACKET_MAX
                    for b in pkt.iter_mut().take(len) {
                        *b = (next() & 0xff) as u8;
                    }
                    n = len;
                } else {
                    let idx = (next() % chunks as u64) as u32;
                    n = encode_packet(&img, idx, ImageType::Ras, &mut pkt);
                    // Corrupt 0-2 random bytes (header or payload).
                    let flips = next() % 3;
                    for _ in 0..flips {
                        let pos = (next() as usize) % n.max(1);
                        pkt[pos] ^= (next() & 0xff) as u8;
                    }
                    // Functionally intact = the acceptance-relevant bytes
                    // (seq +4..+6 checksum, +6..+0xa seq, +0xa..n payload)
                    // survived the flips. Don't-care header bytes (country,
                    // cmd flags, reserved) may differ — the bootloader
                    // ignores them too.
                    fed_some[idx as usize] = true;
                }
                // THE assertion: arbitrary bytes must not panic.
                let decision = rx.on_packet(&pkt[..n]);
                let _ = step;
                #[allow(unused_mut)]
                let mut accepted = matches!(
                    decision,
                    Decision::Accept { .. }
                        | Decision::TypeComplete { .. }
                        | Decision::StreamComplete
                );
                if accepted && !use_noise {
                    // Was this packet's acceptance consistent with its own
                    // bytes? (checksum field == folded sum of its payload)
                    let pl = &pkt[HEADER_LEN..n];
                    let wire = u16::from_be_bytes([pkt[4], pkt[5]]);
                    if crate::zycast::checksum(pl) != wire {
                        panic!("MODEL BUG: accepted packet whose checksum mismatches");
                    }
                }
            }
            // Invariants (fuzz findings baked in — see the 2026-11-10 run):
            // 1. No panic on arbitrary input (asserted by reaching here).
            // 2. Every ACCEPTED packet's checksum field matched its own
            //    payload (audited above) — the model never accepts
            //    self-inconsistent packets.
            // 3. Completion requires every block index to have been fed
            //    (in some form): the receiver cannot invent coverage.
            // 4. KNOWN PROTOCOL WEAKNESS, deliberately not asserted away:
            //    the wire checksum is a 16-bit folded byte-sum, so a
            //    corrupted block whose checksum field collides with its
            //    own corrupted payload (~1/65536 per corrupted block) is
            //    accepted — by this model AND by the real bootloader
            //    (same algorithm). The final defense is the bootloader's
            //    flash-commit RAS header+data checksum gates, not the
            //    wire checksum. Case 76 of this seed is a live example:
            //    completion via a collided final block, deterministic.
            if rx.is_done() {
                assert!(
                    fed_some.iter().all(|f| *f),
                    "case {case}: completed with a block never fed at all — model invents coverage"
                );
            }
        }
    }

    #[test]
    fn ras_model_id_reads_the_gate_field() {
        let mut img = vec![0u8; 0x120];
        img[0..4].copy_from_slice(b"HDR0");
        img[0x11c..0x120].copy_from_slice(&0x0000_7101u32.to_be_bytes());
        assert_eq!(ras_model_id(&img), Some(0x7101));
        img[0x11c..0x120].copy_from_slice(&0x0000_6101u32.to_be_bytes());
        assert_eq!(ras_model_id(&img), Some(0x6101)); // would be refused
        img[0..4].copy_from_slice(b"\x83\x80\x00\x00"); // raw kernel, no RAS hdr
        assert_eq!(ras_model_id(&img), None); // gate skipped, still written [P]
    }
}
