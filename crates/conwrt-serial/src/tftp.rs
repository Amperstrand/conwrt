//! Minimal read-only TFTP server for rescue staging (RFC 1350 + the
//! blksize option, RFC 2348). Serves one directory over UDP; U-Boot's
//! `tftpboot` is the intended client (it negotiates blksize and ACKs
//! every block — the ACK-paced transfer class that survives flaky
//! links, per recipes/SERIAL-TRANSFER-DOCTRINE.md).
//!
//! Own-the-server doctrine (owner directive 2026-10-24): conwrt should
//! not depend on a system tftpd for rescues. Read-only by construction:
//! RRQ is the only request served; WRQ gets an error reply.

use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// TFTP error codes (RFC 1350): 0 = not defined (see message).
pub const ERROR_NOT_DEFINED: u16 = 0;
/// TFTP error code 4: illegal TFTP operation (e.g. WRQ on read-only).
pub const ERROR_ILLEGAL_OP: u16 = 4;

fn err_packet(code: u16, msg: &str) -> Vec<u8> {
    let mut p = vec![0u8, 5];
    p.extend_from_slice(&code.to_be_bytes());
    p.extend_from_slice(msg.as_bytes());
    p.push(0);
    p
}

/// A parsed RRQ/WRQ: opcode, filename, mode, and request-ordered options.
pub type Request = (u16, String, String, Vec<(String, String)>);

/// Parse an RRQ/WRQ packet: (opcode, filename, mode, options).
/// Options are returned in request order as (name, value) pairs.
pub fn parse_request(pkt: &[u8]) -> Result<Request, String> {
    if pkt.len() < 4 {
        return Err("short packet".into());
    }
    let opcode = u16::from_be_bytes([pkt[0], pkt[1]]);
    if opcode != 1 && opcode != 2 {
        return Err(format!("not a request (opcode {opcode})"));
    }
    let mut parts = pkt[2..].split(|&b| b == 0);
    let file = parts
        .next()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .ok_or("no filename")?;
    let mode = parts
        .next()
        .map(|b| String::from_utf8_lossy(b).to_ascii_lowercase())
        .ok_or("no mode")?;
    let mut opts = Vec::new();
    while let (Some(n), Some(v)) = (parts.next(), parts.next()) {
        opts.push((
            String::from_utf8_lossy(n).to_ascii_lowercase(),
            String::from_utf8_lossy(v).into_owned(),
        ));
    }
    Ok((opcode, file, mode, opts))
}

/// Build an OACK carrying the accepted options (blksize only for now).
pub fn oack_blksize(blksize: u16) -> Vec<u8> {
    let mut p = vec![0u8, 6];
    p.extend_from_slice(b"blksize\0");
    p.extend_from_slice(blksize.to_string().as_bytes());
    p.push(0);
    p
}

/// Build DATA block n (header only when payload empty).
pub fn data_packet(n: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8, 3];
    p.extend_from_slice(&n.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && !name.starts_with('/')
        && !name.contains('\\')
        && name.len() < 128
}

/// Serve `root` on `bind` for a single client session (one RRQ), then
/// return. `first_pkt`/`peer` come from the caller's recv loop; this is
/// the unit-testable transfer engine.
/// One step of a pure TFTP transfer state machine (sans-io, no_std-
/// portable core — the audit's R6 / the STM32 precondition): feed the
/// request packet in, then ACK packets and timeouts; send what it says.
#[derive(Debug, PartialEq)]
pub enum SessionStep {
    /// Bytes to transmit to the peer now.
    Send(Vec<u8>),
    /// Transfer finished; total data bytes served.
    Done(u64),
    /// Fatal for this session, with reason.
    Fail(String),
}

/// Pure read-only TFTP session over caller-owned file bytes.
pub struct TftpSession {
    blksize: u16,
    negotiated: bool,
    /// block number currently in flight (awaiting its ACK)
    in_flight: u16,
    /// bytes already ACKed
    sent: u64,
    /// the packet to (re)send on timeout
    last_packet: Vec<u8>,
    /// terminator pending: exact-multiple files need a final empty block
    terminator_pending: bool,
    finished: bool,
}

impl TftpSession {
    /// Start a session from an RRQ/WRQ packet. Returns the first step
    /// (OACK when options were requested, first DATA otherwise, error
    /// replies included as Send+Fail).
    pub fn start(pkt: &[u8], data: &[u8]) -> (SessionStep, Option<Self>) {
        let parsed = match parse_request(pkt) {
            Ok(p) => p,
            Err(e) => return (SessionStep::Fail(e), None),
        };
        let (opcode, file, mode, opts) = parsed;
        if opcode == 2 {
            return (
                SessionStep::Send(err_packet(ERROR_ILLEGAL_OP, "read-only server")),
                None,
            );
        }
        if mode != "octet" && mode != "netascii" {
            return (SessionStep::Send(err_packet(0, "bad mode")), None);
        }
        if !is_safe_name(&file) {
            return (SessionStep::Send(err_packet(0, "bad filename")), None);
        }
        let _ = data; // name validation only; the shell maps name->bytes
        let mut blksize: u16 = 512;
        for (n, v) in &opts {
            if n == "blksize" {
                match v.parse::<u16>() {
                    Ok(b) => blksize = b.clamp(8, 65464),
                    Err(_) => return (SessionStep::Send(err_packet(0, "bad blksize")), None),
                }
            }
        }
        if !opts.is_empty() {
            // wait for the block-0 OACK before any data
            let sess = TftpSession {
                blksize,
                negotiated: false,
                in_flight: 0,
                sent: 0,
                last_packet: oack_blksize(blksize),
                terminator_pending: false,
                finished: false,
            };
            return (SessionStep::Send(oack_blksize(blksize)), Some(sess));
        }
        // no options: straight to block 1
        let mut sess = TftpSession {
            blksize,
            negotiated: true,
            in_flight: 0,
            sent: 0,
            last_packet: Vec::new(),
            terminator_pending: false,
            finished: false,
        };
        let step = sess.advance(data);
        (step, Some(sess))
    }

    fn advance(&mut self, data: &[u8]) -> SessionStep {
        if self.finished {
            return SessionStep::Done(self.sent);
        }
        let end = ((self.sent as usize) + self.blksize as usize).min(data.len());
        let payload_len = end - self.sent as usize;
        let block = self.in_flight.wrapping_add(1);
        let pkt = data_packet(block, &data[self.sent as usize..end]);
        self.in_flight = block;
        self.last_packet = pkt.clone();
        // exact multiple: after the last full block we still owe a terminator
        self.terminator_pending = payload_len == self.blksize as usize && end == data.len();
        SessionStep::Send(pkt)
    }

    /// Feed a received packet (expected: ACKs).
    pub fn on_packet(&mut self, pkt: &[u8], data: &[u8]) -> SessionStep {
        if self.finished {
            return SessionStep::Done(self.sent);
        }
        if pkt.len() >= 4 && pkt[0] == 0 && pkt[1] == 4 {
            let n = u16::from_be_bytes([pkt[2], pkt[3]]);
            if !self.negotiated && n == 0 {
                // OACK ACKed — data may flow
                self.negotiated = true;
                return self.advance(data);
            }
            if n == self.in_flight && self.negotiated {
                self.sent += self.last_packet.len().saturating_sub(4) as u64;
                if self.terminator_pending {
                    // send the zero-length terminator
                    let block = self.in_flight.wrapping_add(1);
                    let pkt = data_packet(block, b"");
                    self.in_flight = block;
                    self.last_packet = pkt.clone();
                    self.terminator_pending = false;
                    return SessionStep::Send(pkt);
                }
                let end = self.sent as usize;
                if end >= data.len() {
                    self.finished = true;
                    return SessionStep::Done(self.sent);
                }
                return self.advance(data);
            }
        }
        SessionStep::Fail(format!(
            "unexpected packet in state (block {})",
            self.in_flight
        ))
    }

    /// Caller timer expired: retransmit the in-flight packet.
    pub fn on_timeout(&mut self) -> SessionStep {
        if self.finished {
            return SessionStep::Done(self.sent);
        }
        SessionStep::Send(self.last_packet.clone())
    }
}

/// Serve a single client session over the std UDP shell (RRQ only;
/// the block/OACK/retry logic is the pure [`TftpSession`]).
pub fn serve_one(
    sock: &UdpSocket,
    root: &Path,
    pkt: &[u8],
    peer: SocketAddr,
    max_retries: u32,
) -> Result<u64, String> {
    let (opcode, file, mode, opts) = parse_request(pkt)?;
    if opcode == 2 {
        let _ = sock.send_to(&err_packet(ERROR_ILLEGAL_OP, "read-only server"), peer);
        return Err("WRQ refused (read-only)".into());
    }
    if mode != "octet" && mode != "netascii" {
        let _ = sock.send_to(&err_packet(0, "bad mode"), peer);
        return Err(format!("mode {mode:?}"));
    }
    if !is_safe_name(&file) {
        let _ = sock.send_to(&err_packet(0, "bad filename"), peer);
        return Err(format!("unsafe name {file:?}"));
    }
    let path: PathBuf = root.join(&file);
    let mut data = Vec::new();
    std::fs::File::open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?
        .read_to_end(&mut data)
        .map_err(|e| format!("read: {e}"))?;

    // blksize negotiation (U-Boot asks; default 512)
    let mut blksize: u16 = 512;
    for (n, v) in &opts {
        if n == "blksize" {
            blksize = v
                .parse::<u16>()
                .map_err(|_| "bad blksize".to_string())?
                .clamp(8, 65464);
        }
    }
    if !opts.is_empty() {
        sock.send_to(&oack_blksize(blksize), peer)
            .map_err(|e| e.to_string())?;
        // RFC 2348: the client ACKs the OACK as block 0 before data
        // flows — consume it, or it desyncs the block loop into
        // re-sending block 1 (found by the loopback test)
        let mut acked = false;
        for _ in 0..max_retries {
            sock.set_read_timeout(Some(Duration::from_secs(1))).ok();
            let mut b4 = [0u8; 4];
            if let Ok((4, from)) = sock.recv_from(&mut b4) {
                if from == peer && u16::from_be_bytes([b4[2], b4[3]]) == 0 {
                    acked = true;
                    break;
                }
            }
        }
        if !acked {
            return Err("OACK never ACKed (block 0)".into());
        }
    }

    let mut block: u16 = 1;
    let mut sent = 0u64;
    while sent < data.len() as u64 || block == 1 {
        let end = ((sent as usize) + blksize as usize).min(data.len());
        let payload = &data[sent as usize..end];
        let pkt = data_packet(block, payload);
        let mut acked = false;
        for _ in 0..max_retries {
            sock.send_to(&pkt, peer).map_err(|e| e.to_string())?;
            sock.set_read_timeout(Some(Duration::from_secs(1))).ok();
            let mut buf = [0u8; 4];
            match sock.recv_from(&mut buf) {
                Ok((4, from)) if from == peer => {
                    let n = u16::from_be_bytes([buf[2], buf[3]]);
                    if n == block {
                        acked = true;
                        break;
                    }
                }
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
        if !acked {
            return Err(format!("block {block} never ACKed"));
        }
        sent = end as u64;
        block = block.wrapping_add(1);
        if payload.is_empty() {
            break;
        }
        if sent >= data.len() as u64 {
            // RFC 1350: a file that is an exact multiple of blksize
            // needs a terminating ZERO-length block (Codex P2) — the
            // last full block alone does not signal EOF
            let term = data_packet(block, b"");
            for _ in 0..max_retries {
                sock.send_to(&term, peer).map_err(|e| e.to_string())?;
                sock.set_read_timeout(Some(Duration::from_secs(1))).ok();
                let mut b4 = [0u8; 4];
                if let Ok((4, from)) = sock.recv_from(&mut b4) {
                    if from == peer && u16::from_be_bytes([b4[2], b4[3]]) == block {
                        break;
                    }
                }
            }
            break;
        }
    }
    Ok(sent)
}

/// Run a read-only TFTP server until `stop` becomes true. Each RRQ is
/// one `serve_one` session; errors are returned, not fatal.
pub fn serve_until(bind: SocketAddr, root: &Path, stop: &dyn Fn() -> bool) -> Vec<String> {
    let sock = match UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => return vec![format!("bind {bind}: {e}")],
    };
    let mut errors = Vec::new();
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
    while !stop() {
        let mut buf = [0u8; 2048];
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                if let Err(e) = serve_one(&sock, root, &buf[..n], peer, 8) {
                    errors.push(e);
                }
            }
            Err(_) => continue, // timeout: re-check stop
        }
    }
    errors
}

/// Public re-export for sibling modules (watch uses it for host-side
/// pre-gates; the implementation stays private-tested below).
pub fn sha256_hex_pub(data: &[u8]) -> String {
    crate::flash::image_sha256(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rrq_with_options() {
        let mut p = vec![0, 1];
        p.extend_from_slice(b"img.bin\0");
        p.extend_from_slice(b"octet\0");
        p.extend_from_slice(b"blksize\0");
        p.extend_from_slice(b"1468\0");
        let (op, file, mode, opts) = parse_request(&p).unwrap();
        assert_eq!((op, file.as_str(), mode.as_str()), (1, "img.bin", "octet"));
        assert_eq!(opts, vec![("blksize".to_string(), "1468".to_string())]);
    }

    #[test]
    fn refuses_wrq_and_bad_names() {
        assert!(parse_request(&[0, 2, b'a', 0, b'o', b'c', b't', b'e', b't', 0]).is_ok());
        assert!(!is_safe_name("../etc/passwd"));
        assert!(!is_safe_name("/abs"));
        assert!(!is_safe_name(""));
        assert!(is_safe_name("owrt-25.12.6-initramfs-kernel.bin"));
    }

    #[test]
    fn packet_codecs() {
        let o = oack_blksize(1468);
        assert_eq!(&o[..2], &[0, 6]);
        assert!(o.ends_with(b"1468\0"));
        let d = data_packet(7, b"xy");
        assert_eq!(d, vec![0, 3, 0, 7, b'x', b'y']);
        let e = err_packet(ERROR_ILLEGAL_OP, "no");
        assert_eq!(&e[..4], &[0, 5, 0, 4]);
    }

    fn ack(n: u16) -> Vec<u8> {
        vec![0, 4, (n >> 8) as u8, n as u8]
    }

    /// Golden packet sequences against the PURE session (no sockets):
    /// (1) options path: OACK -> ACK0 -> data blocks -> Done;
    /// (2) exact-multiple file emits the zero-length terminator;
    /// (3) timeout re-sends the in-flight packet;
    /// (4) WRQ refused.
    #[test]
    fn session_golden_sequences() {
        let rrq_opts = {
            let mut p = vec![0, 1];
            p.extend_from_slice(b"f.bin\0octet\0blksize\0");
            p.extend_from_slice(b"1000\0");
            p
        };
        let data: Vec<u8> = (0..2500u32).map(|i| (i % 251) as u8).collect(); // 2.5 blocks @1000
        let (step, sess) = TftpSession::start(&rrq_opts, &data);
        let _ = &step;
        let mut sess = sess.expect("session starts");
        assert!(matches!(step, SessionStep::Send(_)));
        // OACK ack
        match sess.on_packet(&ack(0), &data) {
            SessionStep::Send(p) => {
                assert_eq!(&p[..4], &[0, 3, 0, 1]);
                assert_eq!(p.len(), 4 + 1000);
            }
            other => panic!("block1: {other:?}"),
        }
        // ack block 1 -> block 2
        match sess.on_packet(&ack(1), &data) {
            SessionStep::Send(p) => assert_eq!(&p[..4], &[0, 3, 0, 2]),
            other => panic!("block2: {other:?}"),
        }
        // timeout re-sends block 2 identically
        match sess.on_timeout() {
            SessionStep::Send(p) => assert_eq!(&p[..4], &[0, 3, 0, 2]),
            other => panic!("timeout: {other:?}"),
        }
        // ack 2 -> final partial block (500 bytes < blksize)
        match sess.on_packet(&ack(2), &data) {
            SessionStep::Send(p) => {
                assert_eq!(&p[..4], &[0, 3, 0, 3]);
                assert_eq!(p.len(), 4 + 500);
            }
            other => panic!("block3: {other:?}"),
        }
        // ack 3 -> Done(2500)
        assert_eq!(sess.on_packet(&ack(3), &data), SessionStep::Done(2500));

        // exact multiple: 2000 bytes @1000 -> terminator after block 2
        let data2: Vec<u8> = (0..2000u32).map(|i| (i % 253) as u8).collect();
        let (step, s2) = TftpSession::start(&rrq_opts, &data2);
        let _ = &step;
        let mut s2 = s2.expect("session starts");
        assert!(matches!(step, SessionStep::Send(_)));
        s2.on_packet(&ack(0), &data2);
        s2.on_packet(&ack(1), &data2);
        match s2.on_packet(&ack(2), &data2) {
            SessionStep::Send(p) => assert_eq!(p, data_packet(3, b""), "terminator"),
            other => panic!("terminator: {other:?}"),
        }
        assert_eq!(s2.on_packet(&ack(3), &data2), SessionStep::Done(2000));

        // WRQ refused
        let wrq = vec![0, 2, b'x', 0, b'o', b'c', b't', b'e', b't', 0];
        let (step, none) = TftpSession::start(&wrq, &data);
        assert!(none.is_none());
        match step {
            SessionStep::Send(p) => assert_eq!(&p[..4], &[0, 5, 0, 4]),
            other => panic!("wrq: {other:?}"),
        }
    }

    #[test]
    fn end_to_end_over_loopback() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("conwrt-tftp-test");
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = std::fs::File::create(dir.join("hello.bin")).unwrap();
        f.write_all(&[0xAB; 5000]).unwrap();
        drop(f);

        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let handle = {
            let server = server.try_clone().unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let (n, peer) = server.recv_from(&mut buf).unwrap();
                serve_one(&server, &dir, &buf[..n], peer, 8).unwrap()
            })
        };
        // client: RRQ with blksize, OACK, ACK loop
        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut rrq = vec![0, 1];
        rrq.extend_from_slice(b"hello.bin\0octet\0blksize\0");
        rrq.extend_from_slice(b"1024\0");
        c.send_to(&rrq, addr).unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = c.recv_from(&mut buf).unwrap();
        eprintln!("first reply: {:?}", &buf[..n.min(40)]);
        assert_eq!(&buf[..2], &[0, 6]); // OACK
        c.send_to(&[0, 4, 0, 0], addr).unwrap(); // ACK block 0
        let mut got = 0usize;
        let mut block: u16 = 1;
        loop {
            let (n, _) = c.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..2], &[0, 3]);
            assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), block);
            got += n - 4;
            c.send_to(&[0, 4, (block >> 8) as u8, block as u8], addr)
                .unwrap();
            if n - 4 < 1024 {
                break;
            }
            block += 1;
        }
        let served = handle.join().unwrap();
        assert_eq!(got as u64, served);
        assert_eq!(got, 5000);
    }
}
