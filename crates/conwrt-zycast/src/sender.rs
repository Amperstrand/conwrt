//! Multicast sender — the I/O half of the protocol.
//!
//! Interface pinning uses `SO_BINDTODEVICE` via socket2 (the primary
//! mechanism of the Go reference; its `IP_MULTICAST_IF` fallback is
//! address-based and skipped here — on Linux bind-to-device is the correct
//! tool and needs no route-table guessing). Loops are BOUNDED because the
//! bootloader listens on every boot: an unlimited sender is a reflash loop
//! (the September incident class), so the loop count is always finite.

use crate::protocol::{
    CHUNK_SIZE, HEADER_LEN, ImageType, LOOP_PAUSE_MS, chunk_at, chunk_count, header,
};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

/// Sender configuration.
pub struct SendConfig {
    /// Multicast group address.
    pub group: Ipv4Addr,
    /// Multicast port.
    pub port: u16,
    /// Egress interface name.
    pub interface: String,
    /// Number of send loops (bounded by design).
    pub loops: u32,
    /// Inter-packet delay.
    pub delay: Duration,
}

/// Result of a completed send.
#[derive(Debug, Clone, Copy)]
pub struct SendStats {
    /// Loops completed.
    pub loops: u32,
    /// Packets sent.
    pub packets: u32,
    /// Total wall time.
    pub elapsed: Duration,
}

fn pinned_socket(interface: &str) -> io::Result<UdpSocket> {
    // An empty name would make SO_BINDTODEVICE "succeed" while leaving the
    // socket unbound — flash packets would follow the default multicast
    // route onto whatever segment it points at. Fail closed instead.
    if interface.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name must not be empty (an unset --interface would send the \
             multicast stream out the default route — toward unintended listeners)",
        ));
    }
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
    sock.bind_device(Some(interface.as_bytes()))
        .map_err(|e| io::Error::new(e.kind(), format!("bind to device {interface:?}: {e}")))?;
    Ok(UdpSocket::from(sock))
}

/// Send `image` in bounded multicast loops. `progress` receives human
/// status lines (loop completions).
pub fn send(
    image: &[u8],
    ty: ImageType,
    cfg: &SendConfig,
    progress: &mut dyn FnMut(&str),
) -> io::Result<SendStats> {
    let sock = pinned_socket(&cfg.interface)?;
    let dest = SocketAddrV4::new(cfg.group, cfg.port);
    let total = chunk_count(image.len());
    let file_len = image.len() as u32;
    let mut pkt = vec![0u8; HEADER_LEN + CHUNK_SIZE];
    let mut packets: u32 = 0;
    let start = Instant::now();

    for lp in 1..=cfg.loops {
        for pid in 0..total {
            let chunk = chunk_at(image, pid);
            pkt[..HEADER_LEN].copy_from_slice(&header(chunk, pid, file_len, ty));
            pkt[HEADER_LEN..HEADER_LEN + chunk.len()].copy_from_slice(chunk);
            sock.send_to(&pkt[..HEADER_LEN + chunk.len()], dest)?;
            packets += 1;
            thread::sleep(cfg.delay);
        }
        let rate = packets as f64 / start.elapsed().as_secs_f64().max(0.001);
        progress(&format!(
            "loop {}/{} complete ({} chunks, {rate:.0} pkt/s, {:?} elapsed)",
            lp,
            cfg.loops,
            total,
            start.elapsed()
        ));
        if lp < cfg.loops {
            thread::sleep(Duration::from_millis(LOOP_PAUSE_MS));
        }
    }
    Ok(SendStats {
        loops: cfg.loops,
        packets,
        elapsed: start.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_interface_name_is_rejected_fail_closed() {
        let err = send(
            &[0u8; 10],
            ImageType::Ras,
            &SendConfig {
                group: Ipv4Addr::new(225, 0, 0, 0),
                port: 5631,
                interface: String::new(),
                loops: 1,
                delay: Duration::from_millis(1),
            },
            &mut |_| {},
        )
        .expect_err("empty interface must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err_ws = send(
            &[0u8; 10],
            ImageType::Ras,
            &SendConfig {
                group: Ipv4Addr::new(225, 0, 0, 0),
                port: 5631,
                interface: "   ".into(),
                loops: 1,
                delay: Duration::from_millis(1),
            },
            &mut |_| {},
        )
        .expect_err("whitespace interface must fail");
        assert_eq!(err_ws.kind(), io::ErrorKind::InvalidInput);
    }

    /// Loopback round-trip: a receiver joined on lo must collect every
    /// chunk byte-identically. Ignored by default — it needs multicast
    /// loopback on lo, which containers often lack. Run locally:
    /// `cargo test -p conwrt-zycast -- --ignored`.
    #[test]
    #[ignore]
    fn loopback_roundtrip_delivers_every_chunk() {
        let group = Ipv4Addr::new(225, 0, 0, 9);
        let rx = UdpSocket::bind(("0.0.0.0", 5639)).expect("bind rx");
        rx.join_multicast_v4(&group, &Ipv4Addr::LOCALHOST)
            .expect("join lo");
        rx.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        let image: Vec<u8> = (0..3000).map(|i| (i * 13 % 241) as u8).collect();
        let cfg = SendConfig {
            group,
            port: 5639,
            interface: "lo".into(),
            loops: 1,
            delay: Duration::from_millis(1),
        };
        let sender_image = image.clone();
        let handle = thread::spawn(move || {
            send(&sender_image, ImageType::Ras, &cfg, &mut |_| {}).expect("send")
        });
        let stats = handle.join().unwrap();

        let mut got = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while got.len() < image.len() && Instant::now() < deadline {
            let mut buf = [0u8; HEADER_LEN + CHUNK_SIZE];
            match rx.recv_from(&mut buf) {
                Ok((n, _)) => {
                    assert_eq!(&buf[..4], &crate::protocol::MAGIC.to_be_bytes());
                    got.extend_from_slice(&buf[HEADER_LEN..n]);
                }
                Err(_) => break,
            }
        }
        assert_eq!(stats.packets, chunk_count(image.len()));
        assert_eq!(got, image, "reassembled payload must be byte-identical");
    }
}
