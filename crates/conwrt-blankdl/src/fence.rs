//! The flash fence — hardened TFTP server for the ZTE blank-download flow.
//!
//! Serves ONE pinned image to the stock bootloader's blank-download flow
//! (U-Boot `lr`: the volume-not-found handler builds a network identity,
//! pulls the image from the protocol's fixed server `192.0.0.1:69`,
//! rewrites the web+rootfs NAND regions, and sends the ASCII fin packet
//! back to :69 on success).
//!
//! Safety model (deliberately rigid, ported from the hardware-proven
//! Python daemon, `scripts/zte-blankdl-flashd.py`):
//!
//! * the image sha256 MUST be pinned before the flash window — the
//!   fence refuses to serve anything unpinned; there is no force flag
//! * any requested RRQ filename is aliased to the pinned image (the
//!   bootloader derives a per-boot 4-hex-digit name)
//! * binds the protocol's fixed server address by default; overriding
//!   it is for dress rehearsals and is loudly flagged
//! * the fin packet is a raw ASCII UDP payload whose first bytes decode
//!   as a bogus TFTP opcode — it is matched BEFORE opcode dispatch
//! * dry-run mode answers nothing; it only logs what it saw
//!
//! Field-proven envelope (MF286D, 2026-11-10, RECOVERY-2026-11-10.md):
//! 38,797,312-byte image at blksize 1468 in ~10 s, fin received, modem
//! re-provisioned from a genuinely clean state.

use conwrt_protocols::blankdl::{
    self as wire, AckAction, Transfer, FIN_STRING, MAX_WIRE, OP_ACK, OP_ERROR, OP_RRQ,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// The fence refuses to run longer than this without a fin packet
/// (operator-configurable; the field-proven flash takes ~15 s).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
/// Socket receive poll interval.
const POLL: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// Pinned image
// ---------------------------------------------------------------------------

/// An image plus its verified sha256 — the ONLY thing the fence will serve.
#[derive(Debug, Clone)]
pub struct PinnedImage {
    /// Image bytes.
    pub bytes: Vec<u8>,
    /// Lowercase hex sha256 of `bytes`.
    pub sha256_hex: String,
    /// Where it came from (run records).
    pub path: PathBuf,
}

impl PinnedImage {
    /// Load and pin: the sha MUST be provided (`expect`) and MUST match.
    /// Refusing unpinned and refusing mismatches are both hard errors —
    /// there is no force path.
    pub fn load(path: &Path, expect_sha: Option<&str>) -> Result<Self, FenceError> {
        let bytes = fs::read(path).map_err(|e| FenceError::Image(format!("{}: {e}", path.display())))?;
        Self::from_bytes(bytes, expect_sha, Some(path))
    }

    /// Build from memory (tests, embedded images).
    pub fn from_bytes(
        bytes: Vec<u8>,
        expect_sha: Option<&str>,
        path: Option<&Path>,
    ) -> Result<Self, FenceError> {
        let sha256_hex = hex_lower(&Sha256::digest(&bytes));
        let expect = expect_sha
            .ok_or_else(|| FenceError::Unpinned)?;
        let expect = expect.trim().to_ascii_lowercase();
        if expect != sha256_hex {
            return Err(FenceError::ShaMismatch {
                actual: sha256_hex,
                pinned: expect,
            });
        }
        Ok(Self { bytes, sha256_hex, path: path.map(Path::to_path_buf).unwrap_or_default() })
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }
}

fn hex_lower(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[usize::from(x >> 4)] as char);
        s.push(HEX[usize::from(x & 0x0f)] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Configuration, outcome, errors
// ---------------------------------------------------------------------------

/// Fence configuration.
#[derive(Debug, Clone)]
pub struct FenceConfig {
    /// Bind address. The default is the protocol's fixed server address;
    /// any other value is a dress rehearsal and is flagged in the log.
    pub bind: IpAddr,
    /// Bind port (TFTP 69).
    pub port: u16,
    /// The pinned image to serve.
    pub image: PinnedImage,
    /// Overall run deadline without a fin packet.
    pub timeout: Duration,
    /// Log only — never answer anything.
    pub dry_run: bool,
    /// Where to write `run.json` + `flash.log`.
    pub log_dir: Option<PathBuf>,
}

impl FenceConfig {
    /// Config with the protocol defaults for everything but the image.
    #[must_use]
    pub fn new(image: PinnedImage) -> Self {
        Self {
            bind: wire::PROTO_BIND_IP.parse().expect("static bind IP"),
            port: wire::PROTO_PORT,
            image,
            timeout: DEFAULT_TIMEOUT,
            dry_run: false,
            log_dir: None,
        }
    }
}

/// One observed RRQ (the bootloader's per-boot name is recorded).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RrqRecord {
    /// Wall clock of the request.
    pub t: SystemTime,
    /// Client address.
    pub client: String,
    /// Requested filename.
    pub name: String,
    /// Requested blksize (verbatim; negotiated value is clamped).
    pub blksize: Option<String>,
}

/// Non-TFTP UDP payloads seen on the port (other than fin).
#[derive(Debug, Clone, serde::Serialize)]
pub struct OtherUdp {
    /// Wall clock.
    pub t: SystemTime,
    /// Client address.
    pub client: String,
    /// First bytes, hex.
    pub data_hex: String,
}

/// Run record — what happened, serialized as `run.json`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FenceOutcome {
    /// Image path served.
    pub image: PathBuf,
    /// Image sha256 (hex).
    pub sha256: String,
    /// Image size in bytes.
    pub bytes: usize,
    /// The fin packet was seen — flash complete.
    pub fin: bool,
    /// When the fin packet arrived.
    pub fin_time: Option<SystemTime>,
    /// Bytes handed to the client (None until a transfer starts).
    pub transferred: Option<u64>,
    /// When the transfer reached its terminal state.
    pub completed: Option<SystemTime>,
    /// Every RRQ observed.
    pub rrqs: Vec<RrqRecord>,
    /// Non-TFTP payloads (other than fin).
    pub other_udp: Vec<OtherUdp>,
    /// Run start.
    pub started: SystemTime,
}

impl Default for FenceOutcome {
    fn default() -> Self {
        Self {
            image: PathBuf::new(),
            sha256: String::new(),
            bytes: 0,
            fin: false,
            fin_time: None,
            transferred: None,
            completed: None,
            rrqs: Vec::new(),
            other_udp: Vec::new(),
            started: SystemTime::UNIX_EPOCH,
        }
    }
}

impl FenceOutcome {
    /// Was the flash served to completion AND acknowledged by fin?
    #[must_use]
    pub fn success(&self) -> bool {
        self.fin
    }
}

/// How the fence run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceExit {
    /// Fin packet seen — flash complete (process exit 0).
    Fin,
    /// Deadline passed without a fin packet (exit 2). The transfer may
    /// still have completed — check the device.
    Timeout,
    /// The client stopped ACKing (or the run was invalid) — exit 1.
    Error,
}

impl FenceExit {
    /// Process exit code for this outcome.
    #[must_use]
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Fin => 0,
            Self::Timeout => 2,
            Self::Error => 1,
        }
    }
}

/// Fence errors — all fatal before or during a run.
#[derive(Debug)]
pub enum FenceError {
    /// No sha256 pin provided.
    Unpinned,
    /// Image sha256 does not match the pin.
    ShaMismatch {
        /// Hash of the bytes actually loaded.
        actual: String,
        /// The pinned hash that did not match.
        pinned: String,
    },
    /// Image could not be read.
    Image(String),
    /// Socket/bind failure.
    Socket(String),
}

impl fmt::Display for FenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unpinned => write!(
                f,
                "REFUSING to serve unpinned image: pass --expect-sha256 or path#sha256:<hex>"
            ),
            Self::ShaMismatch { actual, pinned } => {
                write!(f, "REFUSING: image sha256 {actual} != pinned {pinned}")
            }
            Self::Image(m) => write!(f, "image error: {m}"),
            Self::Socket(m) => write!(f, "socket error: {m}"),
        }
    }
}

impl std::error::Error for FenceError {}

// ---------------------------------------------------------------------------
// The serving loop
// ---------------------------------------------------------------------------

struct RunLog {
    file: Option<fs::File>,
}

impl RunLog {
    fn line(&mut self, msg: &str) {
        eprintln!("[conwrt-blankdl] {msg}");
        if let Some(f) = &mut self.file {
            let _ = writeln!(f, "{msg}");
        }
    }
}

/// Serve the pinned image until fin, timeout, or client failure.
///
/// This is the whole daemon. It binds, answers RRQs from any client with
/// the (only) pinned image, drives the single-window transfer state
/// machine per ACK, resends the in-flight block once per
/// [`wire::ACK_DEADLINE_MS`] with at most [`wire::RETRIES`] attempts, and
/// watches every packet for the fin string before opcode dispatch.
pub fn serve(config: &FenceConfig) -> (FenceOutcome, FenceExit) {
    let mut log = RunLog { file: None };
    if let Some(dir) = &config.log_dir {
        if let Err(e) = fs::create_dir_all(dir) {
            log.line(&format!("warning: cannot create log dir {}: {e}", dir.display()));
        } else {
            match fs::File::create(dir.join("flash.log")) {
                Ok(f) => log.file = Some(f),
                Err(e) => log.line(&format!("warning: cannot open flash.log: {e}")),
            }
        }
    }

    if config.bind.to_string() != wire::PROTO_BIND_IP {
        log.line(&format!(
            "NON-STANDARD BIND {} — real blank-download clients only talk to {}",
            config.bind,
            wire::PROTO_BIND_IP
        ));
    }

    let image = &config.image;
    log.line(&format!(
        "image pinned: {} ({} bytes, sha256 {})",
        image.path.display(),
        image.len(),
        image.sha256_hex
    ));

    let sock = match UdpSocket::bind(SocketAddr::new(config.bind, config.port)) {
        Ok(s) => s,
        Err(e) => {
            log.line(&format!("bind {}:{} failed: {e}", config.bind, config.port));
            return (outcome_of(config), FenceExit::Error);
        }
    };
    if let Err(e) = sock.set_read_timeout(Some(POLL)) {
        log.line(&format!("set_read_timeout failed: {e}"));
        return (outcome_of(config), FenceExit::Error);
    }
    #[cfg(unix)]
    {
        // 4 MiB receive buffer, as the Python daemon: bursts of ACKs at
        // blksize 1468 must not overflow between polls.
        if let Err(e) = socket2::SockRef::from(&sock).set_recv_buffer_size(4 * 1024 * 1024) {
            log.line(&format!("warning: SO_RCVBUF could not be enlarged (continuing): {e}"));
        }
    }
    log.line(&format!(
        "listening on {}:{}{}",
        config.bind,
        config.port,
        if config.dry_run { " (dry-run)" } else { "" }
    ));

    let mut outcome = outcome_of(config);
    let exit = serve_loop(&sock, config, &mut outcome, &mut log);

    if let Some(dir) = &config.log_dir {
        let p = dir.join("run.json");
        match serde_json::to_string_pretty(&outcome) {
            Ok(json) => {
                if let Err(e) = fs::write(&p, json + "\n") {
                    log.line(&format!("warning: cannot write {}: {e}", p.display()));
                } else {
                    log.line(&format!("run record: {}", p.display()));
                }
            }
            Err(e) => log.line(&format!("warning: run record serialize: {e}")),
        }
    }
    if !outcome.fin && outcome.transferred.is_some() {
        log.line(
            "no fin packet, but a transfer happened — verify on the device \
             (boot may lag the write by ~15 s)",
        );
    }
    (outcome, exit)
}

fn outcome_of(config: &FenceConfig) -> FenceOutcome {
    FenceOutcome {
        image: config.image.path.clone(),
        sha256: config.image.sha256_hex.clone(),
        bytes: config.image.len(),
        started: SystemTime::now(),
        fin: false,
        fin_time: None,
        transferred: None,
        completed: None,
        rrqs: Vec::new(),
        other_udp: Vec::new(),
    }
}

fn serve_loop(
    sock: &UdpSocket,
    config: &FenceConfig,
    outcome: &mut FenceOutcome,
    log: &mut RunLog,
) -> FenceExit {
    let image = &config.image.bytes;
    let deadline = Instant::now() + config.timeout;
    let mut xfer: Option<Transfer> = None;
    let mut xfer_client_ip: Option<IpAddr> = None;
    let mut xfer_created: Option<Instant> = None;
    let mut last_activity = Instant::now();
    let mut rx = [0u8; 2048];
    let mut pkt_buf = [0u8; MAX_WIRE];

    while Instant::now() < deadline {
        // Block-level resend timer: an in-flight block with no ACK for
        // ACK_DEADLINE is resent, up to RETRIES times, then we give up.
        if let Some(x) = &xfer {
            let in_flight = x.blocks_sent() > x.blocks_acked() && !x.is_completed();
            if in_flight
                && last_activity.elapsed() >= Duration::from_millis(wire::ACK_DEADLINE_MS)
            {
                if x.resends >= wire::RETRIES {
                    log.line(&format!(
                        "block {} resent {} times without ACK — giving up",
                        x.last_block_number(),
                        x.resends
                    ));
                    return FenceExit::Error;
                }
                let pkt = x.resend_packet(image, &mut pkt_buf);
                let client =
                    SocketAddr::new(xfer_client_ip.expect("in-flight implies client"), config.port);
                let _ = sock.send_to(pkt, client);
                if let Some(x) = xfer.as_mut() {
                    x.resends += 1;
                }
                last_activity = Instant::now();
                continue;
            }
        }

        let (n, addr) = match sock.recv_from(&mut rx) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                if let Some(created) = xfer_created {
                    if Instant::now() > created + Duration::from_millis(wire::TRANSFER_DEADLINE_MS) {
                        log.line("transfer stalled past hard deadline");
                        break;
                    }
                }
                continue;
            }
            Err(e) => {
                log.line(&format!("recv error: {e}"));
                continue;
            }
        };
        let data = &rx[..n];
        last_activity = Instant::now();

        // The fin packet is a raw ASCII UDP payload whose first bytes
        // decode as a bogus opcode — match BEFORE dispatch.
        if data.windows(FIN_STRING.len()).any(|w| w == FIN_STRING) {
            log.line(&format!(
                "FIN: {:?} from {} — blank download done, flash complete",
                String::from_utf8_lossy(&data[..data.len().min(60)]),
                addr.ip()
            ));
            outcome.fin = true;
            outcome.fin_time = Some(SystemTime::now());
            return FenceExit::Fin;
        }

        let op = if data.len() >= 2 {
            u16::from_be_bytes([data[0], data[1]])
        } else {
            0
        };

        match op {
            OP_RRQ => {
                let info = wire::parse_rrq(&data[2..]);
                let blksize_raw = info.blksize.map(str::to_owned);
                log.line(&format!(
                    "RRQ from {}: name={:?} mode={} blksize={:?} (aliased to pinned image)",
                    addr.ip(),
                    info.filename,
                    info.mode,
                    info.blksize
                ));
                outcome.rrqs.push(RrqRecord {
                    t: SystemTime::now(),
                    client: addr.ip().to_string(),
                    name: info.filename.to_owned(),
                    blksize: blksize_raw,
                });
                if config.dry_run {
                    continue;
                }
                let blksize = wire::clamp_blksize(info.blksize);
                let timeout_s = wire::clamp_timeout(info.timeout);
                let had_options = info.blksize.is_some() || info.timeout.is_some();
                log.line(&format!(
                    "negotiated {}: blksize={blksize} timeout={timeout_s}s (client asked blksize={:?})",
                    addr.ip(),
                    info.blksize
                ));
                let mut t = Transfer::new(image.len(), blksize);
                if had_options {
                    let mut oack = [0u8; 64];
                    let pkt = wire::oack_packet(&mut oack, blksize, timeout_s, true);
                    let _ = sock.send_to(pkt, addr);
                }
                // First DATA packet goes out eagerly alongside the OACK so
                // both the live client (no ACK(0)) and strict clients can
                // proceed.
                if let Some(pkt) = t.advance(image, &mut pkt_buf) {
                    let _ = sock.send_to(pkt, addr);
                }
                xfer = Some(t);
                xfer_client_ip = Some(addr.ip());
                xfer_created = Some(Instant::now());
            }
            OP_ACK if xfer.is_some() && xfer_client_ip == Some(addr.ip()) => {
                if data.len() < 4 {
                    continue;
                }
                let acked = u16::from_be_bytes([data[2], data[3]]);
                let Some(t) = xfer.as_mut() else { continue };
                match t.on_ack(acked, image, &mut pkt_buf) {
                    (AckAction::Send, Some(pkt)) => {
                        let _ = sock.send_to(pkt, addr);
                    }
                    (AckAction::Retransmit, Some(pkt)) => {
                        let _ = sock.send_to(pkt, addr);
                        t.resends += 1;
                        last_activity = Instant::now();
                    }
                    (AckAction::Complete, None) => {
                        if outcome.completed.is_none() {
                            outcome.transferred = Some(u64::try_from(image.len()).unwrap_or(0));
                            outcome.completed = Some(SystemTime::now());
                            log.line(&format!(
                                "transfer complete: {} bytes, last block {} to {}",
                                image.len(),
                                t.last_block_number(),
                                addr.ip()
                            ));
                        }
                    }
                    _ => {}
                }
            }
            OP_ERROR => {
                log.line(&format!(
                    "client error from {}: {:?}",
                    addr.ip(),
                    String::from_utf8_lossy(&data[..data.len().min(80)])
                ));
            }
            _ => {
                log.line(&format!(
                    "non-TFTP payload from {}: {:?}",
                    addr.ip(),
                    String::from_utf8_lossy(&data[..data.len().min(80)])
                ));
                outcome.other_udp.push(OtherUdp {
                    t: SystemTime::now(),
                    client: addr.ip().to_string(),
                    data_hex: hex_lower(&data[..data.len().min(80)]),
                });
            }
        }
    }
    FenceExit::Timeout
}
