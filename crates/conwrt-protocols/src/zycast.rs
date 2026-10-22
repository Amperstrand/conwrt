//! # zycast — ZyXEL multicast flash protocol
//!
//! Rust port of ZyXEL's proprietary "Multiboot" multicast flash protocol:
//! firmware images are streamed as UDP multicast to `225.0.0.0:5631`,
//! split into 1024-byte chunks under a 30-byte big-endian header, with no
//! acknowledgement — the Z-Loader bootloader in its multicast listen
//! window reassembles the chunks across repeated sender loops and writes
//! the image to flash when a complete, checksum-consistent file arrives.
//!
//! Wire-compatible with the hardware-tested Go implementation in
//! `cmd/zycast/` and derived from `zycast.c` (Bjørn Mork, GPL-2.0,
//! openwrt/firmware-utils) — the protocol source of truth. The core
//! encoding here is `no_std` (pure byte math); the sender runtime is
//! `std`-gated and uses the [`socket2`] crate for `SO_BINDTODEVICE`
//! interface binding (libraries-first, ADR-0001; the Go implementation
//! made the same syscall by hand).
//!
//! NR7101 flash envelope (bench-tested, AGENTS.md): the bootloader
//! auto-enters its ~7 s multicast listen window on EVERY boot, so the
//! sender must be running BEFORE the target is power-cycled, must use a
//! BOUNDED loop count (an unbounded sender plus listen-on-every-boot is
//! the documented infinite-reflash hazard), and must be dead before the
//! next power cycle of any ZyXEL device on the same L2 domain.

#![allow(clippy::cast_possible_truncation)]

use core::fmt;

/// Header magic `"zyx\0"` (big-endian on the wire).
pub const MAGIC: u32 = 0x7A79_7800;
/// Fixed per-packet header length.
pub const HEADER_LEN: usize = 30;
/// Maximum payload chunk length.
pub const CHUNK_LEN: usize = 1024;
/// Default multicast group.
pub const DEFAULT_GROUP: &str = "225.0.0.0";
/// Default multicast UDP port.
pub const DEFAULT_PORT: u16 = 5631;
/// Default inter-packet delay (matches the Go/C reference: ~75 s per
/// 7.6 MB loop).
pub const DEFAULT_PACKET_DELAY_MS: u64 = 10;
/// Default pause between sender loops.
pub const DEFAULT_LOOP_GAP_MS: u64 = 200;

/// Target-partition bitmap carried in header bytes 20/21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    /// 0x01 — bootloader partition.
    Bootbase,
    /// 0x02 — ROM data partition.
    Rom,
    /// 0x04 — RAS firmware (kernel); the default for firmware images.
    Ras,
    /// 0x08 — ROMD partition.
    Romd,
    /// 0x10 — backup kernel slot (kernel2).
    Backup,
}

impl ImageType {
    /// Wire bitmap bit for this image type.
    #[must_use]
    pub const fn bit(self) -> u8 {
        match self {
            Self::Bootbase => 0x01,
            Self::Rom => 0x02,
            Self::Ras => 0x04,
            Self::Romd => 0x08,
            Self::Backup => 0x10,
        }
    }

    /// Parse the CLI/Go-spelling of an image type.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "bootbase" => Some(Self::Bootbase),
            "rom" => Some(Self::Rom),
            "ras" => Some(Self::Ras),
            "romd" => Some(Self::Romd),
            "backup" => Some(Self::Backup),
            _ => None,
        }
    }
}

impl fmt::Display for ImageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bootbase => "bootbase",
            Self::Rom => "rom",
            Self::Ras => "ras",
            Self::Romd => "romd",
            Self::Backup => "backup",
        })
    }
}

/// ZyXEL payload checksum: byte sum accumulated in a `u32` (wrapping,
/// exactly like the Go/C originals), folded once into 16 bits.
///
/// NOTE: this is a plain fold — no one's-complement, no zero substitution
/// (it is NOT the internet checksum).
#[must_use]
pub fn checksum(data: &[u8]) -> u16 {
    let mut total: u32 = 0;
    for &b in data {
        total = total.wrapping_add(u32::from(b));
    }
    total.wrapping_add(total >> 16) as u16
}

/// Number of chunks a file of `file_len` bytes splits into.
#[must_use]
pub fn chunk_count(file_len: usize) -> usize {
    file_len.div_ceil(CHUNK_LEN)
}

/// Encode the packet for chunk `index` of `image` into `out`.
///
/// `out` must be at least [`HEADER_LEN`] + the chunk length (at most
/// [`PACKET_MAX`]). Returns the number of bytes written.
///
/// # Panics
/// If `index` is not a valid chunk of `image` or `out` is too small.
#[must_use]
pub fn encode_packet(image: &[u8], index: u32, ty: ImageType, out: &mut [u8]) -> usize {
    let start = index as usize * CHUNK_LEN;
    assert!(
        start < image.len() || image.is_empty() && start == 0,
        "chunk {index} out of range for {}-byte image",
        image.len()
    );
    let end = (start + CHUNK_LEN).min(image.len());
    let chunk = &image[start..end];
    let wire_len = HEADER_LEN + chunk.len();
    let out_len = out.len();
    let buf = out
        .get_mut(..wire_len)
        .unwrap_or_else(|| panic!("out buffer too small: need {wire_len}, have {out_len}"));

    buf[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    buf[4..6].copy_from_slice(&checksum(chunk).to_be_bytes());
    buf[6..10].copy_from_slice(&index.to_be_bytes());
    buf[10..14].copy_from_slice(&(chunk.len() as u32).to_be_bytes());
    buf[14..18].copy_from_slice(&(image.len() as u32).to_be_bytes());
    buf[18..20].fill(0); // unused
    buf[20] = ty.bit();
    buf[21] = ty.bit(); // "images": same bitmap as type (Go parity)
    buf[22] = b'F'; // country "FF"
    buf[23] = b'F';
    buf[24] = 0x01; // FLAG_SET_DEBUG
    buf[25..30].fill(0); // reserved
    buf[HEADER_LEN..].copy_from_slice(chunk);
    wire_len
}

/// Largest possible wire packet (full chunk).
pub const PACKET_MAX: usize = HEADER_LEN + CHUNK_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vectors generated from the Go implementation's semantics
    /// (cmd/zycast/main.go, hardware-tested) — see docs/zycast.md §6.
    #[test]
    fn checksum_goldens() {
        assert_eq!(checksum(b""), 0x0000);
        assert_eq!(checksum(&[0xff; 1024]), 0xFC03);
        // 0xAA+0xBB+0xCC+0xDD+0xEE = 1020 = 0x03FC
        assert_eq!(checksum(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]), 0x03FC);
        // 9+8+7+6+5 = 35 = 0x23
        assert_eq!(checksum(&[9, 8, 7, 6, 5]), 0x0023);
    }

    #[test]
    fn chunk_counts() {
        assert_eq!(chunk_count(0), 0);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(1024), 1);
        assert_eq!(chunk_count(1025), 2);
        assert_eq!(chunk_count(2053), 3);
    }

    #[test]
    fn image_type_roundtrip() {
        for ty in [
            ImageType::Bootbase,
            ImageType::Rom,
            ImageType::Ras,
            ImageType::Romd,
            ImageType::Backup,
        ] {
            assert_eq!(ImageType::parse(&ty.to_string()), Some(ty));
        }
        assert_eq!(ImageType::parse("nope"), None);
        assert_eq!(ImageType::Ras.bit(), 0x04);
    }

    /// Full 35-byte packet for a 5-byte RAS image, chunk 0 — golden hex
    /// produced independently (python struct, replicating the Go layout).
    #[test]
    fn encode_packet_golden_first_chunk() {
        let image = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut out = [0u8; PACKET_MAX];
        let n = encode_packet(&image, 0, ImageType::Ras, &mut out);
        assert_eq!(n, 35);
        let expected =
            hex("7a79780003fc000000000000000500000005000004044646010000000000aabbccddee");
        assert_eq!(&out[..n], &expected[..]);
    }

    /// Tail chunk (index 2) of a 2048+5-byte image: 5-byte payload,
    /// file_len 2053 = 0x805, payload checksum 0x0023.
    #[test]
    fn encode_packet_golden_tail_chunk() {
        let mut image = vec![0u8; 2048];
        for (i, b) in image.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        image.extend_from_slice(&[9, 8, 7, 6, 5]);
        assert_eq!(image.len(), 2053);

        let mut out = [0u8; PACKET_MAX];
        let n = encode_packet(&image, 2, ImageType::Ras, &mut out);
        assert_eq!(n, 35);
        let expected =
            hex("7a79780000230000000200000005000008050000040446460100000000000908070605");
        assert_eq!(&out[..n], &expected[..]);
    }

    /// A full-size middle chunk must fill the packet to PACKET_MAX and
    /// place the chunk at offset 30.
    #[test]
    fn encode_packet_full_chunk() {
        let image = vec![0xA5; 3 * CHUNK_LEN];
        let mut out = [0u8; PACKET_MAX];
        let n = encode_packet(&image, 1, ImageType::Ras, &mut out);
        assert_eq!(n, PACKET_MAX);
        assert_eq!(
            out[4..6],
            checksum(&image[CHUNK_LEN..2 * CHUNK_LEN]).to_be_bytes()
        );
        assert!(out[HEADER_LEN..].iter().all(|&b| b == 0xA5));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }
}

/// Multicast sender runtime (Linux: `SO_BINDTODEVICE` via [`socket2`]).
#[cfg(feature = "std")]
pub mod sender {
    use super::{ImageType, PACKET_MAX, chunk_count, encode_packet};
    use std::io;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use std::time::Duration;

    /// Sender configuration.
    #[derive(Debug, Clone)]
    pub struct SendConfig {
        /// Multicast group (IPv4).
        pub group: Ipv4Addr,
        /// Multicast UDP port.
        pub port: u16,
        /// Egress network interface name (`SO_BINDTODEVICE`).
        pub iface: String,
        /// Target partition bitmap.
        pub image_type: ImageType,
        /// Loop bound: `None` = unlimited (discouraged — see module docs).
        pub loops: Option<u32>,
        /// Inter-packet delay.
        pub packet_delay: Duration,
        /// Pause between loops.
        pub loop_gap: Duration,
    }

    impl Default for SendConfig {
        fn default() -> Self {
            Self {
                group: Ipv4Addr::new(225, 0, 0, 0),
                port: super::DEFAULT_PORT,
                iface: String::new(),
                image_type: ImageType::Ras,
                loops: Some(3),
                packet_delay: Duration::from_millis(super::DEFAULT_PACKET_DELAY_MS),
                loop_gap: Duration::from_millis(super::DEFAULT_LOOP_GAP_MS),
            }
        }
    }

    /// Counters reported after [`send`] returns.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct SendStats {
        /// Completed whole-image loops.
        pub loops_completed: u32,
        /// Total packets sent.
        pub packets_sent: u64,
    }

    /// Stream `image` as zycast multicast.
    ///
    /// `stop` is polled between packets (and between loops) — return
    /// `true` to unwind; `on_loop` is called with `(loop_index_1_based,
    /// chunks)` when a loop completes. Errors abort immediately; a stop
    /// returns the stats collected so far.
    pub fn send<F, L>(
        image: &[u8],
        cfg: &SendConfig,
        mut stop: F,
        mut on_loop: L,
    ) -> io::Result<SendStats>
    where
        F: FnMut() -> bool,
        L: FnMut(u32, usize),
    {
        if image.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty image"));
        }
        if cfg.iface.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no egress interface configured",
            ));
        }
        let chunks = chunk_count(image.len());
        let dst = SocketAddrV4::new(cfg.group, cfg.port);

        let sock_raw = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        // SO_BINDTODEVICE pins egress to the named interface so the
        // multicast leaves the right L2 segment (and only that one).
        // The Go original falls back to IP_MULTICAST_IF on non-Linux;
        // this port targets Linux/OpenWrt senders only.
        sock_raw.bind_device(Some(cfg.iface.as_bytes()))?;
        let any = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        sock_raw.bind(&any.into())?;
        let sock: UdpSocket = sock_raw.into();

        let mut stats = SendStats::default();
        let mut pkt = [0u8; PACKET_MAX];
        loop {
            for index in 0..chunks as u32 {
                if stop() {
                    return Ok(stats);
                }
                let n = encode_packet(image, index, cfg.image_type, &mut pkt);
                sock.send_to(&pkt[..n], dst)?;
                stats.packets_sent += 1;
                std::thread::sleep(cfg.packet_delay);
            }
            stats.loops_completed += 1;
            on_loop(stats.loops_completed, chunks);
            if let Some(max) = cfg.loops {
                if stats.loops_completed >= max {
                    return Ok(stats);
                }
            }
            if stop() {
                return Ok(stats);
            }
            std::thread::sleep(cfg.loop_gap);
        }
    }
}
