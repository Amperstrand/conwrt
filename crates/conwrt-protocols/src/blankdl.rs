//! # blankdl — ZTE ipq40xx blank-download flash protocol (wire core)
//!
//! Pure wire-format and state-machine half of the ZTE blank-download
//! recovery flow, hardware-proven on the MF286D campaign (#621): when the
//! stock U-Boot finds no kernel volume in the UBI, it builds a network
//! identity, TFTP-pulls a full image from the fixed server address
//! `192.0.0.1:69`, rewrites the web+rootfs NAND regions, and sends an
//! ASCII fin packet back to :69 on success.
//!
//! This module is the no_std-friendly core: TFTP packet framing (the
//! subset the bootloader speaks), RFC 2347 RRQ-option parsing, the
//! single-window transfer state machine with 16-bit block rollover, and
//! the fin-string sentinel. The I/O half — the hardened serving fence —
//! lives in the `conwrt-blankdl` crate (`fence`), mirroring the zycast
//! split (protocol core here, runtime in its own crate).
//!
//! ## Block numbering and rollover (the class of bugs this core prevents)
//!
//! TFTP blocks are 1-indexed 16-bit numbers: block `k` (k = 1, 2, …)
//! carries `image[(k-1)*blksize .. k*blksize)` and the wire number is
//! `k mod 65536` (so k = 65536 sends number 0, k = 65537 sends 1 again).
//! The authoritative stream position is `blocks_sent` (a u64), NEVER the
//! wrapped wire number: the Python original derives the chunk offset
//! from the wire number, which re-reads the image head after the wrap —
//! CONFIRMED by simulation (2026-11-11): a plain 512-byte client on a
//! 65 537-block image receives `image[0..512]` as its 65 537th block.
//! The shipped e2e test cannot catch it because its fixture image is a
//! uniform byte fill (wrong chunk ≡ right chunk); the live bootloader
//! (blksize 1468, 26 429 blocks on a 38.8 MB image) never wraps, so the
//! bug was never field-reachable. This core tracks position explicitly
//! and resolves wrapped ACK numbers to the LATEST candidate ≤ the sent
//! position, and its unit tests use non-uniform images.
//!
//! ## Client personalities (both must work)
//!
//! The live bootloader sends RRQ with `blksize=1468 timeout=5`, ACKs every
//! data block, and never ACKs the OACK; RFC-strict clients ACK block 0
//! after the OACK. The state machine sends DATA(1) eagerly alongside the
//! OACK and answers ACK(0) by resending block 1 — the strict client never
//! observes a skipped block.

#![allow(clippy::cast_possible_truncation)]

/// Fixed server address the stock bootloader pulls from.
pub const PROTO_BIND_IP: &str = "192.0.0.1";
/// Fixed TFTP server port.
pub const PROTO_PORT: u16 = 69;
/// ASCII fin packet the bootloader sends when the flash write completed.
pub const FIN_STRING: &[u8] = b"OK:zte blank download is done";

/// TFTP opcodes (the subset this protocol uses).
pub const OP_RRQ: u16 = 1;
/// Write-request opcode (recognized, never answered).
pub const OP_WRQ: u16 = 2;
/// Data opcode.
pub const OP_DATA: u16 = 3;
/// Acknowledgement opcode.
pub const OP_ACK: u16 = 4;
/// Error opcode (client-reported, logged).
pub const OP_ERROR: u16 = 5;
/// Option-acknowledgement opcode.
pub const OP_OACK: u16 = 6;

/// Block-size negotiation bounds. 1468 is the largest the stock client
/// asks for and the protocol max we will serve; requests beyond it are
/// clamped, not honored.
pub const DEFAULT_BLKSIZE: usize = 512;
/// Smallest negotiated blksize served.
pub const MIN_BLKSIZE: usize = 8;
/// Largest negotiated blksize served (the stock client's ask).
pub const MAX_BLKSIZE: usize = 1468;

/// Per-block resend attempts before the fence gives up on a client.
pub const RETRIES: u32 = 8;
/// How long without an ACK before the in-flight block is resent.
pub const ACK_DEADLINE_MS: u64 = 1_000;
/// Hard per-transfer ceiling: 38 MiB at the worst realistic pace.
pub const TRANSFER_DEADLINE_MS: u64 = 900_000;

/// Largest DATA packet this protocol can emit (opcode + block + payload).
pub const MAX_WIRE: usize = 4 + MAX_BLKSIZE;

/// Size of the TFTP block-number space: wire numbers cycle through
/// `0..=65535`, so the wrap modulus is 65_536, not `u16::MAX`.
pub const BLOCK_COUNT: u64 = 65_536;

/// Wire block number for the 1-based block index `k`: `k mod 65_536`
/// (k = 65536 sends number 0, k = 65537 sends 1 again).
#[must_use]
pub fn block_number(k: u64) -> u16 {
    (k % BLOCK_COUNT) as u16
}

/// Parsed RRQ: filename, mode, and the RFC 2347 options this protocol
/// negotiates (blksize, timeout). Unknown options are ignored — the fence
/// only ever OACKs what it implements.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RrqInfo<'a> {
    /// Requested filename (the bootloader derives a per-boot name; the
    /// fence serves any name, aliased to the pinned image).
    pub filename: &'a str,
    /// Transfer mode ("octet" in practice).
    pub mode: &'a str,
    /// Requested blksize, verbatim (clamp before use).
    pub blksize: Option<&'a str>,
    /// Requested timeout, verbatim (clamp before use).
    pub timeout: Option<&'a str>,
}

/// Parse an RRQ body (everything after the opcode): `name\0mode\0[k\0v\0]…`.
/// Never fails — malformed input yields empty fields, mirroring the
/// Python original's error-replacement behavior.
#[must_use]
pub fn parse_rrq(body: &[u8]) -> RrqInfo<'_> {
    let mut fields = body.split(|&b| b == 0).filter(|s| !s.is_empty());
    let filename = fields.next().map(|s| core::str::from_utf8(s).unwrap_or("")).unwrap_or("");
    let mode = fields.next().map(|s| core::str::from_utf8(s).unwrap_or("")).unwrap_or("");
    let mut info = RrqInfo { filename, mode, blksize: None, timeout: None };
    let mut key = fields.next();
    while let Some(k) = key {
        let Some(v) = fields.next() else { break };
        let k = core::str::from_utf8(k).unwrap_or("");
        let v = core::str::from_utf8(v).unwrap_or("");
        match k.to_ascii_lowercase().as_str() {
            "blksize" => info.blksize = Some(v),
            "timeout" => info.timeout = Some(v),
            _ => {}
        }
        key = fields.next();
    }
    info
}

/// Clamp a requested blksize into `[MIN_BLKSIZE, MAX_BLKSIZE]`; unparsable
/// values fall back to the 512 default.
#[must_use]
pub fn clamp_blksize(raw: Option<&str>) -> usize {
    match raw.and_then(|s| s.parse::<usize>().ok()) {
        Some(v) => v.clamp(MIN_BLKSIZE, MAX_BLKSIZE),
        None => DEFAULT_BLKSIZE,
    }
}

/// Clamp a requested timeout option into `[1, 30]` seconds; default 5.
#[must_use]
pub fn clamp_timeout(raw: Option<&str>) -> u32 {
    match raw.and_then(|s| s.parse::<u32>().ok()) {
        Some(v) => v.clamp(1, 30),
        None => 5,
    }
}

/// Frame a DATA packet into `buf`; returns the written slice.
#[must_use]
pub fn data_packet<'a>(buf: &'a mut [u8], block: u16, chunk: &[u8]) -> &'a [u8] {
    buf[..2].copy_from_slice(&OP_DATA.to_be_bytes());
    buf[2..4].copy_from_slice(&block.to_be_bytes());
    buf[4..4 + chunk.len()].copy_from_slice(chunk);
    &buf[..4 + chunk.len()]
}

/// Frame an OACK echoing the negotiated blksize/timeout options. Returns
/// an empty slice when the client sent no options (option-less clients
/// get no OACK at all).
#[must_use]
pub fn oack_packet<'a>(
    buf: &'a mut [u8],
    blksize: usize,
    timeout_secs: u32,
    had_options: bool,
) -> &'a [u8] {
    fn push_field(buf: &mut [u8], n: &mut usize, s: &[u8]) {
        buf[*n..*n + s.len()].copy_from_slice(s);
        *n += s.len();
        buf[*n] = 0;
        *n += 1;
    }
    fn push_decimal(buf: &mut [u8], n: &mut usize, v: u64) {
        let mut tmp = [0u8; 20];
        let mut m = 0;
        let mut v = v;
        if v == 0 {
            tmp[m] = b'0';
            m += 1;
        }
        while v > 0 {
            tmp[m] = b'0' + (v % 10) as u8;
            v /= 10;
            m += 1;
        }
        for &d in tmp[..m].iter().rev() {
            buf[*n] = d;
            *n += 1;
        }
        buf[*n] = 0;
        *n += 1;
    }
    if !had_options {
        return &buf[..0];
    }
    let mut n = 2;
    buf[..2].copy_from_slice(&OP_OACK.to_be_bytes());
    push_field(buf, &mut n, b"blksize");
    push_decimal(buf, &mut n, blksize as u64);
    push_field(buf, &mut n, b"timeout");
    push_decimal(buf, &mut n, u64::from(timeout_secs));
    &buf[..n]
}

/// Outcome of feeding an ACK to the transfer state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckAction {
    /// Send this packet next (normal advance).
    Send,
    /// Send this packet, counting as a loss-recovery retransmit.
    Retransmit,
    /// Transfer complete (the EOF block was ACKed).
    Complete,
    /// Nothing to do (already complete).
    Nothing,
}

/// Single-window TFTP transfer state machine.
///
/// The authoritative position is `blocks_sent` (1-based count of data
/// blocks sent); the wire number is derived from it. ACKs from the client
/// advance, rewind, or complete the transfer per the classic single-window
/// rules — the stream never runs ahead of the client's ACKs.
#[derive(Debug, Clone)]
pub struct Transfer {
    blksize: usize,
    /// 1-based count of DATA blocks sent (never wrapped).
    blocks_sent: u64,
    /// 1-based count of blocks the client has ACKed (never wrapped).
    blocks_acked: u64,
    /// Resends of the current in-flight block since its last ACK.
    pub resends: u32,
    /// Image length the transfer was started with.
    image_len: usize,
    /// EOF (empty) block was sent — exact-multiple images only.
    eof_sent: bool,
    /// Client ACKed the terminating block.
    completed: bool,
}

impl Transfer {
    /// New transfer over an image of `image_len` bytes at `blksize`.
    #[must_use]
    pub fn new(image_len: usize, blksize: usize) -> Self {
        Self {
            blksize,
            blocks_sent: 0,
            blocks_acked: 0,
            resends: 0,
            image_len,
            eof_sent: false,
            completed: false,
        }
    }

    /// Blocks sent so far (progress/stat).
    #[must_use]
    pub fn blocks_sent(&self) -> u64 {
        self.blocks_sent
    }

    /// Blocks the client has ACKed (never wrapped).
    #[must_use]
    pub fn blocks_acked(&self) -> u64 {
        self.blocks_acked
    }

    /// Whether the transfer completed (terminating block ACKed).
    #[must_use]
    pub fn is_completed(&self) -> bool {
        self.completed
    }

    /// Whether the EOF block was sent.
    #[must_use]
    pub fn eof_sent(&self) -> bool {
        self.eof_sent
    }

    /// Wire number of the last block sent (0 before the first).
    #[must_use]
    pub fn last_block_number(&self) -> u16 {
        self.wire_number(self.blocks_sent)
    }

    fn wire_number(&self, k: u64) -> u16 {
        block_number(k)
    }

    /// Prepare the next DATA (or EOF) packet into `buf`.
    ///
    /// * normal: block `blocks_sent+1` carries the next chunk
    /// * exact-multiple images end with an empty EOF block
    /// * a short final block terminates the stream by itself
    ///
    /// Returns `None` when the transfer is already complete.
    pub fn advance<'a>(&mut self, image: &[u8], buf: &'a mut [u8]) -> Option<&'a [u8]> {
        debug_assert_eq!(image.len(), self.image_len);
        if self.completed {
            return None;
        }
        let off = self.blocks_sent as usize * self.blksize; // authoritative position
        if self.blocks_sent > 0 && off >= self.image_len {
            if self.image_len % self.blksize == 0 && !self.eof_sent {
                // exact multiple: no short block will occur — signal EOF
                self.blocks_sent += 1;
                self.eof_sent = true;
                self.resends = 0;
                let n = self.wire_number(self.blocks_sent);
                return Some(data_packet(buf, n, &[]));
            }
            return None; // short-block image already terminated
        }
        self.blocks_sent += 1;
        let chunk = &image[off..(off + self.blksize).min(self.image_len)];
        let n = self.wire_number(self.blocks_sent);
        self.resends = 0;
        Some(data_packet(buf, n, chunk))
    }

    /// Rebuild the DATA packet for an arbitrary already-started block
    /// index `k` (1-based, unwrapped) into `buf` — the retransmit path.
    fn packet_for_index<'a>(&self, image: &[u8], buf: &'a mut [u8], k: u64) -> &'a [u8] {
        let off = ((k as usize).saturating_sub(1)) * self.blksize;
        let n = self.wire_number(k);
        if off >= self.image_len {
            data_packet(buf, n, &[]) // EOF block
        } else {
            data_packet(buf, n, &image[off..(off + self.blksize).min(self.image_len)])
        }
    }

    /// The current in-flight packet (last prepared block), for resends.
    pub fn resend_packet<'a>(&self, image: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
        self.packet_for_index(image, buf, self.blocks_sent)
    }

    /// Feed a client ACK. Returns the action plus, when a packet must be
    /// sent, its bytes written into `buf`.
    ///
    /// Classic single-window rules with the strict-client extension:
    ///   * ACK(0) right after our DATA(1) = the RFC client accepting the
    ///     OACK — resend block 1, never skip
    ///   * ACK(last) — advance (or complete on the EOF block)
    ///   * stale/behind ACK — rewind to the client's position and
    ///     retransmit exactly the block it is missing; the stream NEVER
    ///     runs ahead of the client's ACKs
    pub fn on_ack<'a>(
        &mut self,
        acked: u16,
        image: &[u8],
        buf: &'a mut [u8],
    ) -> (AckAction, Option<&'a [u8]>) {
        if self.completed {
            return (AckAction::Nothing, None);
        }
        // Resolve the wrapped wire number to an unwrapped block count.
        let acked_k = self.resolve_ack(acked);
        self.blocks_acked = acked_k;

        // Strict client: ACK(0) accepting the OACK while block 1 (or the
        // first block after a fresh RRQ) is in flight.
        if acked == 0 && self.blocks_sent == 1 && !self.eof_sent {
            let pkt = self.packet_for_index(image, buf, 1);
            return (AckAction::Send, Some(pkt));
        }

        if acked_k == self.blocks_sent {
            // client caught up with everything we sent
            if self.eof_sent {
                self.completed = true;
                return (AckAction::Complete, None);
            }
            // A short final block terminates the stream by itself: the
            // ACK of that block IS completion (the Python original never
            // marked short-block images complete — the fin packet was the
            // only signal; tracking it here makes the fence's stats
            // honest for every image shape).
            let pos_end = self.blocks_sent as usize * self.blksize;
            if pos_end >= self.image_len && self.image_len % self.blksize != 0 {
                self.completed = true;
                return (AckAction::Complete, None);
            }
            return match self.advance(image, buf) {
                Some(pkt) => (AckAction::Send, Some(pkt)),
                None => (AckAction::Nothing, None),
            };
        } else if acked_k < self.blocks_sent {
            // behind: rewind to the client's position, retransmit the
            // missing block
            let want = acked_k + 1; // next block the client needs
            let data_blocks =
                u64::try_from(self.image_len.div_ceil(self.blksize)).unwrap_or(u64::MAX);
            if self.eof_sent && want <= data_blocks {
                self.eof_sent = false; // rewound below the EOF block
            }
            self.blocks_sent = want; // position regresses
            let pkt = self.packet_for_index(image, buf, want);
            return (AckAction::Retransmit, Some(pkt));
        }
        // ahead of us (impossible from a correct client): ignore
        (AckAction::Nothing, None)
    }

    /// Map a wrapped ACK number to the unwrapped 1-based block count the
    /// client most plausibly means. Wire numbers repeat every 65 536
    /// blocks, so `acked` means one of `acked, acked+65_536, …`; a
    /// sequential client ACKs its latest position, so we resolve to the
    /// LARGEST candidate that does not run ahead of what we have sent.
    /// (Without this, the first ACK after a wrap rewinds the stream a
    /// full cycle and the client appends the wrong chunk forever after.)
    fn resolve_ack(&self, acked: u16) -> u64 {
        let base = u64::from(acked) % BLOCK_COUNT;
        let mut best = 0;
        let mut cand = base;
        while cand <= self.blocks_sent {
            best = cand;
            cand += BLOCK_COUNT;
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf() -> [u8; MAX_WIRE] {
        [0u8; MAX_WIRE]
    }

    #[test]
    fn wire_numbers_follow_tftp_rollover() {
        let t = Transfer::new(512 * 70_000, 512);
        assert_eq!(t.wire_number(1), 1);
        assert_eq!(t.wire_number(65_535), 65_535);
        assert_eq!(t.wire_number(65_536), 0);
        assert_eq!(t.wire_number(65_537), 1);
    }

    #[test]
    fn prewrap_sequence_matches_client_view() {
        // 3 blocks of 4 bytes + short 4th
        let image = vec![0xA0u8; 20];
        let mut t = Transfer::new(image.len(), 8);
        let mut b = buf();
        // block 1 = image[0..8]
        let p = t.advance(&image, &mut b).unwrap();
        assert_eq!(&p[2..4], &1u16.to_be_bytes());
        assert_eq!(&p[4..], &image[0..8]);
        // ACK(1) -> block 2
        let (act, p) = t.on_ack(1, &image, &mut b);
        assert_eq!(act, AckAction::Send);
        assert_eq!(&p.unwrap()[2..4], &2u16.to_be_bytes());
        // duplicate ACK(1) (behind) -> retransmit block 2, not skip
        let (act, p) = t.on_ack(1, &image, &mut b);
        assert_eq!(act, AckAction::Retransmit);
        let p = p.unwrap();
        assert_eq!(&p[2..4], &2u16.to_be_bytes());
        assert_eq!(&p[4..], &image[8..16]);
        // catch-up ACK(2) -> short final block 3
        let (act, p) = t.on_ack(2, &image, &mut b);
        assert_eq!(act, AckAction::Send);
        let p = p.unwrap();
        assert_eq!(p.len(), 4 + 4);
        assert_eq!(&p[4..], &image[16..20]);
        // ACK(3): short block terminated the stream -> complete, nothing sent
        let (act, p) = t.on_ack(3, &image, &mut b);
        assert_eq!(act, AckAction::Complete);
        assert!(p.is_none());
    }

    #[test]
    fn strict_client_ack_zero_resends_block_one() {
        let image = vec![0x11u8; 24];
        let mut t = Transfer::new(image.len(), 8);
        let mut b = buf();
        _ = t.advance(&image, &mut b); // DATA(1) eagerly sent with OACK
        let (act, p) = t.on_ack(0, &image, &mut b); // RFC client accepts OACK
        assert_eq!(act, AckAction::Send);
        let p = p.unwrap();
        assert_eq!(&p[2..4], &1u16.to_be_bytes()); // block 1 AGAIN — no skip
        assert_eq!(&p[4..], &image[0..8]);
    }

    #[test]
    fn exact_multiple_uses_eof_block() {
        let image = vec![0x22u8; 16]; // 2 blocks of 8
        let mut t = Transfer::new(image.len(), 8);
        let mut b = buf();
        _ = t.advance(&image, &mut b);
        _ = t.on_ack(1, &image, &mut b); // -> block 2
        let (act, _p) = t.on_ack(2, &image, &mut b); // -> EOF block 3
        assert_eq!(act, AckAction::Send);
        assert!(t.eof_sent());
        let (act, p) = t.on_ack(3, &image, &mut b); // EOF ACKed -> complete
        assert_eq!(act, AckAction::Complete);
        assert!(p.is_none());
        assert!(t.is_completed());
    }

    #[test]
    fn rollover_position_survives_wrap() {
        // 512-byte blocks past the 16-bit wrap: block 65536 is number 0
        // and carries image[65535*512..], block 65537 is number 1 and
        // carries image[65536*512..] — the Python-original offset bug.
        let bs = 512usize;
        let image_len = bs * 65_537 + 4; // 65537 full blocks + short tail
        let image: Vec<u8> = (0..image_len).map(|i| (i % 251) as u8).collect();
        let mut t = Transfer::new(image_len, bs);
        let mut b = buf();

        // Fast-forward: send+ACK everything up to block 65535. Each ACK
        // advances one block, so after the loop block 65536 (wire number
        // 0) is in flight.
        for k in 1..=65_535u64 {
            if t.blocks_sent() < k {
                let _ = t.advance(&image, &mut b);
            }
            let ack_no = (k % 65_536) as u16;
            let _ = t.on_ack(ack_no, &image, &mut b);
        }
        assert_eq!(t.blocks_sent(), 65_536);
        // block 65536 is wire number 0
        assert_eq!(t.last_block_number(), 0);

        // ACK(0) post-wrap means "I have 65536 blocks" -> next is 65537
        let (act, p) = t.on_ack(0, &image, &mut b);
        assert_eq!(act, AckAction::Send);
        let p = p.unwrap();
        assert_eq!(&p[2..4], &1u16.to_be_bytes()); // wire number 1 again
        let off = 65_536 * bs;
        assert_eq!(&p[4..], &image[off..off + bs]); // CORRECT chunk, not the head

        // Post-wrap ACK(1) means block 65537 (resolve to the LATEST
        // candidate <= blocks_sent) — not a rewind to block 1.
        let (act, p) = t.on_ack(1, &image, &mut b);
        assert_eq!(act, AckAction::Send);
        let p = p.unwrap();
        assert_eq!(&p[2..4], &2u16.to_be_bytes());
        let off = 65_537 * bs;
        assert_eq!(&p[4..], &image[off..off + 4]); // short final block, correct tail
        // ACK(2) -> short block terminated the stream: complete
        let (act, p) = t.on_ack(2, &image, &mut b);
        assert_eq!(act, AckAction::Complete);
        assert!(p.is_none());
        assert!(t.is_completed());
    }

    #[test]
    fn parse_rrq_live_and_plain() {
        // live: per-boot name + blksize/timeout options
        let body = b"3fa2\0octet\0blksize\01468\0timeout\0\x35\0";
        let info = parse_rrq(body);
        assert_eq!(info.filename, "3fa2");
        assert_eq!(info.mode, "octet");
        assert_eq!(info.blksize, Some("1468"));
        assert_eq!(info.timeout, Some("5"));
        // plain: name + mode only
        let info = parse_rrq(b"root_uImage\0octet\0");
        assert_eq!(info.filename, "root_uImage");
        assert_eq!(info.blksize, None);
    }

    #[test]
    fn clamps() {
        assert_eq!(clamp_blksize(Some("65535")), MAX_BLKSIZE);
        assert_eq!(clamp_blksize(Some("4")), MIN_BLKSIZE);
        assert_eq!(clamp_blksize(Some("bogus")), DEFAULT_BLKSIZE);
        assert_eq!(clamp_blksize(None), DEFAULT_BLKSIZE);
        assert_eq!(clamp_timeout(Some("99")), 30);
        assert_eq!(clamp_timeout(None), 5);
    }

    #[test]
    fn oack_echoes_negotiated_values() {
        let mut b = [0u8; 64];
        let pkt = oack_packet(&mut b, 1468, 5, true);
        assert_eq!(&pkt[..2], &OP_OACK.to_be_bytes());
        let s = core::str::from_utf8(&pkt[2..]).unwrap();
        assert_eq!(s, "blksize\01468\0timeout\05\0");
        let pkt = oack_packet(&mut b, 512, 5, false);
        assert!(pkt.is_empty()); // option-less client gets no OACK
    }
}
