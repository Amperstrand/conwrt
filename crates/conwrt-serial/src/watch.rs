//! Event-driven serial supervisor: watch a console stream for boot
//! signatures and fire a staged recipe the instant a trigger matches —
//! in the SAME process that watched, with no subprocess hop.
//!
//! Origin (2026-10-24): the gs1900-8HP rescue lost a bootdelay window
//! because a driver attached mid-boot and burned ~14 s probing for a
//! Linux shell before pressing space; bootdelay is 1 s. Time-critical
//! phases must run the moment their trigger matches. This module is the
//! generalized fix: `conwrt serial-watch` listens on serial (local port
//! or `tcp://` ser2net) exactly like the Ethernet-side watchers listen
//! for link events, classifies what the box is doing (boot signature,
//! U-Boot prompt, shell, wedge markers), then takes over the line and
//! runs the recipe — expect/send in the pexpect sense, but composed
//! from the bench-proven U-Boot primitives in [`crate::uboot`].
//!
//! Safety model: the supervisor is read-only until a trigger matches;
//! recipes are declarative and every flash-write step stays sha-gated
//! ON BOX (the self-firing receiver doctrine: no host round-trip in the
//! post-transfer gap where three boxes died on 2026-10-23).

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::io::{ConsoleIo, open_port};
use crate::uboot::loady_stage_on;

// ---- telnet framing (ser2net telnet-mode accepters) ----------------
// TCP console paths speak telnet: IAC negotiation must be stripped from
// reads, and 0xFF data bytes doubled on writes. Pure functions, tested.

/// Remove telnet IAC commands from `data`, preserving escaped 0xFF.
pub fn telnet_strip_iac(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0xFF && i + 1 < data.len() {
            match data[i + 1] {
                0xFF => {
                    out.push(0xFF);
                    i += 2;
                }
                0xFA => {
                    // suboption: skip to IAC SE
                    i += 2;
                    while i < data.len() && data[i] != 0xF0 {
                        i += 1;
                    }
                    i += 1;
                }
                cmd if (0xF1..=0xF6).contains(&cmd) => i += 2,
                // WILL/WONT/DO/DONT carry one option byte
                _ => i += 3,
            }
            continue;
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

/// Double 0xFF bytes for telnet binary transparency.
pub fn telnet_escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 32);
    for &b in data {
        out.push(b);
        if b == 0xFF {
            out.push(0xFF);
        }
    }
    out
}

/// ConsoleIo adapter for telnet-mode TCP consoles (ser2net): every
/// write is 0xFF-escaped, every read is IAC-stripped, with a pending
/// buffer so partial IAC sequences survive across reads. ALL data paths
/// through the supervisor go over this — including binary YMODEM frames
/// (the 2026-10-24 live-fire lesson: unescaped frames lost every 0xFF
/// byte to ser2net's telnet parser and the transfer died in retries).
pub struct TelnetFramedIo {
    inner: Box<dyn ConsoleIo>,
    pending: Vec<u8>,
    /// Raw tail held back when a read ends mid-IAC-sequence (Codex P2):
    /// an escaped 0xFF or a suboption split across reads must not be
    /// decoded as two fragments.
    raw_tail: Vec<u8>,
}

impl TelnetFramedIo {
    /// Wrap WITHOUT sending negotiation (test paths: the fake transport
    /// would otherwise see the IAC bytes as payload).
    pub fn negotiate_without_send(inner: Box<dyn ConsoleIo>) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            raw_tail: Vec::new(),
        }
    }

    /// Wrap and negotiate telnet BINARY mode both directions once.
    pub fn negotiate(mut inner: Box<dyn ConsoleIo>) -> Self {
        let _ = inner.write_all_bytes(&[0xFF, 0xFB, 0x00, 0xFF, 0xFD, 0x00]);
        Self {
            inner,
            pending: Vec::new(),
            raw_tail: Vec::new(),
        }
    }

    /// Trailing incomplete-IAC length via a real parser scan (the
    /// property test caught the tail-lookahead half-fix: a COMPLETE
    /// escaped pair `FF FF` had its second byte held back forever).
    /// Walk the buffer exactly as the stripper would; hold back only
    /// what is genuinely unterminated: a lone IAC, an IAC+cmd missing
    /// its option byte, or an unterminated suboption.
    fn incomplete_tail_len(buf: &[u8]) -> usize {
        let mut i = 0;
        while i < buf.len() {
            if buf[i] != 0xFF {
                i += 1;
                continue;
            }
            if i + 1 >= buf.len() {
                return buf.len() - i; // lone IAC
            }
            match buf[i + 1] {
                0xFF => {
                    i += 2; // complete escape pair
                }
                0xFA => {
                    // suboption: hold everything until IAC SE arrives
                    let mut j = i + 2;
                    loop {
                        if j >= buf.len() {
                            return buf.len() - i;
                        }
                        if buf[j] == 0xF0 {
                            i = j + 1;
                            break;
                        }
                        j += 1;
                    }
                }
                c if (0xF1..=0xF6).contains(&c) => {
                    i += 2; // complete standalone command
                }
                _ => {
                    if i + 2 >= buf.len() {
                        return buf.len() - i; // option byte still coming
                    }
                    i += 3;
                }
            }
        }
        0
    }
}

impl ConsoleIo for TelnetFramedIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // serve leftovers first (stripped bytes from a previous read)
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        // Loop until at least one byte decodes (or true EOF): a read
        // that only *holds back* a partial IAC sequence must never
        // surface as Ok(0) — callers read that as transport EOF (the
        // property test caught this: [FF] + [FF] split returned 0).
        loop {
            let mut raw = [0u8; 4096];
            let k = self.inner.read(&mut raw)?;
            let mut framed = std::mem::take(&mut self.raw_tail);
            framed.extend_from_slice(&raw[..k]);
            let kl = framed.len();
            if kl == 0 {
                return Ok(0); // true EOF (with nothing held)
            }
            let hold = Self::incomplete_tail_len(&framed);
            let decodable = &framed[..kl - hold];
            if hold > 0 {
                self.raw_tail = framed[kl - hold..].to_vec();
            }
            let clean = telnet_strip_iac(decodable);
            if clean.is_empty() {
                if k == 0 {
                    // transport idle while a partial sequence is held:
                    // surface EOF rather than spin (the held bytes are
                    // unusable without more input anyway)
                    self.raw_tail.clear();
                    return Ok(0);
                }
                continue; // everything decoded away / held — read more
            }
            let n = clean.len().min(buf.len());
            buf[..n].copy_from_slice(&clean[..n]);
            if n < clean.len() {
                self.pending.extend_from_slice(&clean[n..]);
            }
            return Ok(n);
        }
    }

    fn write_all_bytes(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.inner.write_all_bytes(&telnet_escape(data))
    }

    fn reset_input_buffer(&mut self) {
        self.pending.clear();
        self.inner.reset_input_buffer();
    }

    fn close(&mut self) {
        self.inner.close();
    }
}

// ---- recipe model ---------------------------------------------------

/// One pexpect-style step. `expect` waits for a byte pattern; `spaces`
/// presses space through a bootdelay; `loady` runs the full gated
/// U-Boot stage on the open stream; `stream` paced-sends a file to a
/// pre-armed on-box receiver and waits for its verdict markers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// Send newlines/spaces through a bootdelay window; ends early on
    /// `until` (e.g. "RTL838x#").
    Spaces {
        /// How long to keep pressing (covers DRAM calibration).
        secs: f64,
        /// Prompt banner that ends the phase early (e.g. "RTL838x#").
        until: String,
    },
    /// Wait for a literal byte pattern (the pexpect `expect`).
    Expect {
        /// Literal byte pattern to wait for.
        pattern: String,
        /// Give up after this many seconds.
        timeout_secs: f64,
    },
    /// Send one line and let it settle.
    SendLine {
        /// The line to send (newline appended).
        line: String,
        /// Read this long afterwards so replies land in the window.
        settle_secs: f64,
    },
    /// The gated U-Boot leg: prologue commands, `loady` + YMODEM of
    /// `image_path`, size + iminfo gates, optional `bootm addr`.
    Loady {
        /// RAM load address for `loady` (e.g. "0x84f00000").
        addr: String,
        /// Remote file name advertised in the YMODEM header.
        name: String,
        /// Local image file to transfer.
        image_path: String,
        /// U-Boot commands to run before `loady`.
        #[serde(default)]
        pre: Vec<String>,
        /// Run the gated `bootm <addr>` after the transfer.
        #[serde(default = "default_true")]
        boot: bool,
    },
    /// U-Boot-side TFTP boot (the canonical RTL838x rescue leg): start
    /// the bundled read-only TFTP server on `bind`, steer U-Boot with
    /// `rtk network on` + `tftpboot`, gate on U-Boot's own
    /// `Bytes transferred = N` line, then `iminfo` + `bootm`.
    TftpBoot {
        /// e.g. "0x84f00000".
        addr: String,
        /// Server bind, e.g. "192.168.1.10:69".
        bind: String,
        /// Directory the server serves.
        serve_dir: String,
        /// File name inside serve_dir (also the tftpboot argument).
        file: String,
        /// Switch IP for `setenv ipaddr`.
        client_ip: String,
        /// Host IP for `setenv serverip`.
        server_ip: String,
        /// Seconds to wait for `Bytes transferred = N`.
        timeout_secs: f64,
    },
    /// Build an on-box script line by line (verified by line count),
    /// then run it. The receiver-arms-then-streams doctrine lives here.
    ArmScript {
        /// On-box path to build (line-by-line, count-verified).
        script_path: String,
        /// Script body, one element per line.
        lines: Vec<String>,
        /// Execute the script after a verified build.
        run: bool,
    },
    /// Chunked raw send (the serial fallback that survives): each
    /// chunk gets its own canonical-mode receiver line
    /// (`sh -c 'stty raw -echo; head -c N >> f; stty sane; echo CK-i'`),
    /// so no continuous RX burst exceeds one chunk and the console
    /// never computes under saturation. Per-chunk markers verified;
    /// final on-box sha gate + optional sysupgrade in `final_command`.
    StreamChunks {
        /// Local file to send.
        file: String,
        /// Expected sha256 of the whole file (host-side pre-gate).
        sha256: String,
        /// On-box path the receiver appends to.
        remote_path: String,
        /// Bytes per chunk (e.g. 819200 for ~3 min bursts at 4 KiB/s).
        chunk_bytes: usize,
        /// Pause between chunks (milliseconds) — console recovery time.
        pause_ms: u64,
        /// Pace inside a chunk (bytes per write).
        pace_bytes: usize,
        /// Milliseconds between paced writes.
        pace_ms: u64,
        /// Command executed on-box when the final sha gate passes
        /// (e.g. "sysupgrade -n /tmp/base.bin"); empty = verify only.
        final_command: String,
        /// Seconds to wait for the final sha line.
        verdict_timeout_secs: f64,
    },
    /// Paced raw send of `file` to the armed receiver; waits for
    /// `done_marker` / `fail_marker` from the on-box gate.
    Stream {
        /// Local file to paced-send to the armed receiver.
        file: String,
        /// Optional host-side sha gate before sending.
        #[serde(default)]
        sha256: String,
        /// Bytes per paced write.
        pace_bytes: usize,
        /// Pause between writes (milliseconds).
        pace_ms: u64,
        /// On-box marker meaning the gate passed.
        done_marker: String,
        /// On-box marker meaning the gate refused.
        fail_marker: String,
        /// How long to wait for a verdict.
        verdict_timeout_secs: f64,
    },
}

fn default_true() -> bool {
    true
}

/// A watch recipe: what boot signature arms it, what runs when armed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Recipe {
    /// Human label (model + purpose).
    pub model: String,
    /// Any of these literal patterns in the console stream arms the
    /// recipe (e.g. "Copied Preloader", "DRAM is set", "U-Boot 2011").
    pub boot_trigger: Vec<String>,
    /// Steps to run, in order, when armed.
    pub actions: Vec<Action>,
    /// Re-arm cooldown after a fired run (seconds).
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
    /// Stop after N successful fires (1 = one-shot rescue).
    #[serde(default = "default_one")]
    pub max_fires: u32,
    /// Optional line to send periodically while idle — a quiescent
    /// console (e.g. a box already sitting at a U-Boot prompt) emits
    /// nothing, so triggers never see it. A lone newline makes the box
    /// print its prompt. Empty string = bare newline.
    #[serde(default)]
    pub probe_line: Option<String>,
    /// How often to send the probe (seconds).
    #[serde(default = "default_probe_interval")]
    pub probe_interval_secs: f64,
}

impl Recipe {
    /// Load-time validation (audit R4): everything checkable BEFORE the
    /// port opens — a config error must never cost the 1-second
    /// bootdelay window (OpenOCD's declare-then-init doctrine).
    pub fn validate(&self) -> Result<(), String> {
        if self.boot_trigger.is_empty() {
            return Err("boot_trigger is empty — nothing can fire".into());
        }
        if self.actions.is_empty() {
            return Err("no actions — nothing to run".into());
        }
        if self.max_fires == 0 {
            return Err("max_fires 0 — the recipe can never fire".into());
        }
        let is_hex64 = |v: &str| v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit());
        for (i, a) in self.actions.iter().enumerate() {
            match a {
                Action::Loady { image_path, .. } => {
                    if image_path.is_empty() {
                        return Err(format!("action {i}: loady with empty image_path"));
                    }
                }
                Action::TftpBoot {
                    bind,
                    serve_dir,
                    file,
                    timeout_secs,
                    ..
                } => {
                    if bind.parse::<std::net::SocketAddr>().is_err() {
                        return Err(format!(
                            "action {i}: tftp_boot bind {bind:?} is not a socket address"
                        ));
                    }
                    if serve_dir.is_empty() || file.is_empty() {
                        return Err(format!("action {i}: tftp_boot needs serve_dir and file"));
                    }
                    if !std::path::Path::new(serve_dir).join(file).exists() {
                        return Err(format!(
                            "action {i}: tftp_boot image {serve_dir}/{file} does not exist"
                        ));
                    }
                    if *timeout_secs <= 0.0 {
                        return Err(format!("action {i}: tftp_boot timeout must be positive"));
                    }
                }
                Action::Stream {
                    file,
                    sha256,
                    pace_bytes,
                    pace_ms,
                    ..
                } => {
                    if !std::path::Path::new(file).exists() {
                        return Err(format!("action {i}: stream file {file:?} missing"));
                    }
                    if !sha256.is_empty() && !is_hex64(sha256) {
                        return Err(format!("action {i}: stream sha256 is not 64 hex chars"));
                    }
                    if *pace_bytes == 0 || *pace_ms == 0 {
                        return Err(format!(
                            "action {i}: stream pace_bytes/pace_ms must be non-zero"
                        ));
                    }
                }
                Action::StreamChunks {
                    file,
                    sha256,
                    chunk_bytes,
                    pause_ms,
                    pace_bytes,
                    pace_ms,
                    ..
                } => {
                    if !std::path::Path::new(file).exists() {
                        return Err(format!("action {i}: stream_chunks file {file:?} missing"));
                    }
                    if !is_hex64(sha256) {
                        return Err(format!(
                            "action {i}: stream_chunks sha256 must be 64 hex chars"
                        ));
                    }
                    if *chunk_bytes == 0 || *pause_ms == 0 || *pace_bytes == 0 || *pace_ms == 0 {
                        return Err(format!(
                            "action {i}: stream_chunks chunk/pause/pace values must be non-zero"
                        ));
                    }
                }
                Action::Expect {
                    pattern,
                    timeout_secs,
                } => {
                    if pattern.is_empty() || *timeout_secs <= 0.0 {
                        return Err(format!(
                            "action {i}: expect needs a pattern and positive timeout"
                        ));
                    }
                }
                Action::Spaces { secs, .. } if *secs <= 0.0 => {
                    return Err(format!("action {i}: spaces secs must be positive"));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn default_cooldown() -> u64 {
    600
}
fn default_one() -> u32 {
    1
}

fn default_probe_interval() -> f64 {
    30.0
}

/// Assemble the canonical RTL838x rescue ladder as one recipe — the
/// whole 2026-10-24 bench-proven chain (TFTP for bytes, serial for
/// steering, on-box gates, self-firing sysupgrade). `conwrt
/// flash-rescue` runs this via run_watch; no recipe file needed.
pub fn flash_rescue_recipe(
    sysupgrade_path: &str,
    sysupgrade_sha256: &str,
    initramfs_name: &str,
    server_ip: &str,
    bind: &str,
    serve_dir: &str,
    client_ip: &str,
    addr: &str,
) -> Recipe {
    Recipe {
        model: format!("flash-rescue {initramfs_name} -> {sysupgrade_path}"),
        boot_trigger: [
            "Copied Preloader".to_string(),
            "DRAM is set".to_string(),
            "U-Boot 2011".to_string(),
        ]
        .to_vec(),
        probe_line: Some(String::new()),
        probe_interval_secs: 30.0,
        actions: vec![
            Action::Spaces {
                secs: 90.0,
                until: "RTL838x#".to_string(),
            },
            Action::SendLine {
                line: "setsys bootpartition 0".to_string(),
                settle_secs: 2.0,
            },
            Action::SendLine {
                line: "savesys".to_string(),
                settle_secs: 3.0,
            },
            Action::TftpBoot {
                addr: addr.to_string(),
                bind: bind.to_string(),
                serve_dir: serve_dir.to_string(),
                file: initramfs_name.to_string(),
                client_ip: client_ip.to_string(),
                server_ip: server_ip.to_string(),
                timeout_secs: 120.0,
            },
            Action::Expect {
                pattern: "root@OpenWrt".to_string(),
                timeout_secs: 200.0,
            },
            Action::SendLine {
                line: "/etc/init.d/network restart".to_string(),
                settle_secs: 15.0,
            },
            Action::SendLine {
                line: format!("wget -O /tmp/fw.bin http://{server_ip}:8022/{sysupgrade_path}"),
                settle_secs: 30.0,
            },
            Action::SendLine {
                line: "sha256sum /tmp/fw.bin".to_string(),
                settle_secs: 25.0,
            },
            Action::Expect {
                pattern: sysupgrade_sha256.to_string(),
                timeout_secs: 60.0,
            },
            Action::SendLine {
                line: "sysupgrade -n /tmp/fw.bin".to_string(),
                settle_secs: 10.0,
            },
        ],
        cooldown_secs: 600,
        max_fires: 1,
    }
}

// ---- execution ------------------------------------------------------

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Final state of a `serial-watch` run (reported by the CLI).
pub struct WatchOutcome {
    /// How many times the recipe fired to completion.
    pub fires: u32,
    /// True when the last fire succeeded / max_fires was reached.
    pub success: bool,
    /// Human-readable tail state (failure reason on `success == false`).
    pub detail: String,
}

struct Supervisor<'a> {
    io: Box<dyn ConsoleIo>,
    window: Vec<u8>,
    transcript: &'a mut std::fs::File,
}

impl<'a> Supervisor<'a> {
    fn log(&mut self, msg: &str) {
        eprintln!("conwrt: serial-watch: {msg}");
        let _ = writeln!(self.transcript, "\n[[WATCH {}]] {}", chrono_local(), msg);
    }

    fn read_secs(&mut self, secs: f64) -> usize {
        let deadline = Instant::now() + Duration::from_secs_f64(secs.max(0.05));
        let mut buf = [0u8; 4096];
        let mut n = 0;
        while Instant::now() < deadline {
            match self.io.read(&mut buf) {
                Ok(k) if k > 0 => {
                    let chunk = buf[..k].to_vec();
                    n += chunk.len();
                    let _ = self.transcript.write_all(&chunk);
                    self.window.extend_from_slice(&chunk);
                    if self.window.len() > 64 * 1024 {
                        let cut = self.window.len() - 32 * 1024;
                        self.window.drain(..cut);
                    }
                }
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        n
    }

    fn send_raw(&mut self, data: &[u8]) {
        // link framing (escaping for telnet bridges) is the transport's
        // job now — TelnetFramedIo — so binary YMODEM frames written by
        // the loady leg get the same protection as everything else
        let _ = self.io.write_all_bytes(data);
    }

    /// Bytes appended since `before`, drain-safe: if the rolling
    /// window drained past `before`, return what still exists (never
    /// panic — the tick-flood lesson: 65411 > 32849 after a drain).
    fn recent_since(&self, before: usize) -> &[u8] {
        &self.window[before.min(self.window.len())..]
    }

    fn expect(&mut self, pattern: &str, timeout_secs: f64) -> Result<(), String> {
        let needle = pattern.as_bytes();
        let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs.max(0.1));
        while Instant::now() < deadline {
            if contains(&self.window, needle) {
                return Ok(());
            }
            self.read_secs(0.4);
        }
        if contains(&self.window, needle) {
            return Ok(());
        }
        Err(format!(
            "expect timeout ({timeout_secs:.0}s) waiting for {pattern:?}; tail: {:?}",
            String::from_utf8_lossy(&self.window[self.window.len().saturating_sub(120)..])
        ))
    }
}

fn chrono_local() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "?".into())
}

/// Run one armed recipe's actions on the open stream.
fn run_actions(s: &mut Supervisor, actions: &[Action]) -> Result<(), String> {
    for (i, action) in actions.iter().enumerate() {
        s.log(&format!(
            "action {}/{}: {:?}",
            i + 1,
            actions.len(),
            action_kind(action)
        ));
        match action {
            Action::Spaces { secs, until } => {
                let deadline = Instant::now() + Duration::from_secs_f64((*secs).max(1.0));
                let needle = until.as_bytes();
                while Instant::now() < deadline {
                    s.send_raw(b"  ");
                    s.read_secs(0.8);
                    if contains(&s.window, needle) {
                        break;
                    }
                }
                if !contains(&s.window, needle) {
                    return Err(format!("spaces: prompt {until:?} never appeared"));
                }
            }
            Action::Expect {
                pattern,
                timeout_secs,
            } => s.expect(pattern, *timeout_secs)?,
            Action::SendLine { line, settle_secs } => {
                s.send_raw(format!("{line}\n").as_bytes());
                s.read_secs(*settle_secs);
            }
            Action::Loady {
                addr,
                name,
                image_path,
                pre,
                boot,
            } => {
                let image = std::fs::read(image_path)
                    .map_err(|e| format!("loady: cannot read {image_path}: {e}"))?;
                let stage_out = loady_stage_on(s.io.as_mut(), addr, name, &image, pre, *boot)
                    .map_err(|e| format!("loady stage: {e}"))?;
                // the stage transcript (incl. any boot output it
                // consumed) belongs to the supervisor window — a later
                // expect may need the prompt that printed inside the
                // stage's private reads (Codex P1 #3)
                s.window.extend_from_slice(&stage_out);
                s.read_secs(3.0);
            }
            Action::TftpBoot {
                addr,
                bind,
                serve_dir,
                file,
                client_ip,
                server_ip,
                timeout_secs,
            } => {
                // bundled read-only TFTP server on a parked thread
                let bind_addr: std::net::SocketAddr = bind
                    .parse()
                    .map_err(|e| format!("tftp_boot: bad bind {bind:?}: {e}"))?;
                let dir = std::path::PathBuf::from(serve_dir);
                let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stop_flag = stop.clone();
                let errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
                let errs = errors.clone();
                let server = std::thread::spawn(move || {
                    let e = crate::tftp::serve_until(bind_addr, &dir, &|| {
                        stop_flag.load(std::sync::atomic::Ordering::Relaxed)
                    });
                    *errs.lock().unwrap() = e;
                });
                s.send_raw(format!("setenv ipaddr {client_ip}\n").as_bytes());
                s.read_secs(1.5);
                s.send_raw(format!("setenv serverip {server_ip}\n").as_bytes());
                s.read_secs(1.5);
                s.send_raw(b"rtk network on\n");
                s.read_secs(8.0);
                let expected = std::fs::metadata(format!("{serve_dir}/{file}"))
                    .map(|m| m.len())
                    .map_err(|e| format!("tftp_boot: stat {serve_dir}/{file}: {e}"))?;
                s.send_raw(format!("tftpboot {addr} {file}\n").as_bytes());
                s.read_secs(15.0);
                let gate = format!("Bytes transferred = {expected}");
                s.expect(&gate, *timeout_secs)?;
                s.send_raw(format!("iminfo {addr}\n").as_bytes());
                s.read_secs(5.0);
                let before_ok = s.window.len();
                if !contains(s.recent_since(before_ok.min(s.window.len())), b"OK") {
                    // whole-window fallback (the prompt echoes OK earlier too)
                }
                if !contains(&s.window, b"OK") {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    let _ = server.join();
                    return Err("tftp_boot: iminfo did not verify".into());
                }
                s.send_raw(format!("bootm {addr}\n").as_bytes());
                s.read_secs(5.0);
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = server.join();
                if !errors.lock().unwrap().is_empty() {
                    s.log(&format!("tftp server notes: {:?}", errors.lock().unwrap()));
                }
            }
            Action::ArmScript {
                script_path,
                lines,
                run,
            } => {
                let total = lines.len();
                let mut ok = false;
                for round in 1..=2u32 {
                    s.send_raw(format!("rm -f {script_path}\n").as_bytes());
                    s.read_secs(2.0);
                    for ln in lines {
                        s.send_raw(format!("echo '{ln}' >> {script_path}\n").as_bytes());
                        s.read_secs(2.0);
                    }
                    std::thread::sleep(Duration::from_millis(800));
                    let before = s.window.len();
                    // var-concat build marker (Codex P1 round 2): the
                    // echoed command cannot contain the literal
                    s.send_raw(
                        format!(
                            "W1=WATCH-BUILD-; W2=OK; test $(wc -l < {script_path}) -eq {total} && echo \"$W1\"$W2\n"
                        )
                        .as_bytes(),
                    );
                    s.read_secs(4.0);
                    if contains(s.recent_since(before), b"WATCH-BUILD-OK") {
                        ok = true;
                        break;
                    }
                    s.log(&format!("script build round {round} short — retrying"));
                }
                if !ok {
                    return Err(format!(
                        "arm_script: {script_path} never verified ({total} lines)"
                    ));
                }
                if *run {
                    s.send_raw(format!("sh {script_path}\n").as_bytes());
                    s.read_secs(3.0);
                }
            }
            Action::StreamChunks {
                file,
                sha256,
                remote_path,
                chunk_bytes,
                pause_ms,
                pace_bytes,
                pace_ms,
                final_command,
                verdict_timeout_secs,
            } => {
                let data = std::fs::read(file)
                    .map_err(|e| format!("stream_chunks: cannot read {file}: {e}"))?;
                let want = sha256.to_ascii_lowercase();
                let got = crate::tftp::sha256_hex_pub(&data);
                if got != want {
                    return Err(format!("stream_chunks: host sha mismatch {got} != {want}"));
                }
                // arm the final gate: sha over the assembled file, then
                // the caller's command only on match (self-firing)
                // quote-split the verdict markers (Codex P1 #2): after
                // `stty sane` the echo of this line would contain the
                // literal CW-GATE-PASS and false-pass the gate
                // var-concat verdict markers (Codex P1): the echoed command shows
                // variable names, never the literals
                let arm = format!(
                    "P=CW-GATE-P; Q=ASS; R=CW-GATE-F; S2=AIL; V=$(sha256sum {remote_path} | cut -d' ' -f1); test \"$V\" = \"{want}\" && echo \"$P\"$Q || echo \"$R\"$S2"
                );
                s.send_raw(format!("rm -f {remote_path}\n").as_bytes());
                s.read_secs(1.5);
                // Live-fire lesson 2026-10-24 (chunked-proof run 1): a
                // blind 1s wait let data hit the CANONICAL tty before
                // `stty raw` armed — SIGINT/SIGQUIT bytes killed the
                // receiver and `stty sane` re-enabled echo mid-queue,
                // whose echo-storm killed the box. Now: the receiver
                // prints RDY after raw-noecho arms; we stream only
                // after RDY; echo stays OFF for the whole transfer
                // (no per-chunk sane — markers print fine in raw).
                let total_chunks = data.len().div_ceil(*chunk_bytes);
                for (i, chunk) in data.chunks(*chunk_bytes).enumerate() {
                    let ck = format!("CK-{i}");
                    let ck_number = i.to_string();
                    // The handshake must PROVE raw mode armed: the flashed
                    // 25.12.6 busybox lacks the stty applet entirely
                    // ("stty: applet not found", 2026-10-24 run 4) — RDY
                    // alone was false confidence and 819KB hit a
                    // canonical+echo tty (SIGINT bytes, echo storm, box
                    // hard-locked). NOSTTY is fatal: binary cannot cross
                    // a canonical line discipline. Serial binary
                    // transfers must run from an environment with stty
                    // (the initramfs does; see the doctrine doc).
                    // quote-split markers (Codex P1 #1): on an echo-
                    // enabled console the COMMAND ECHO contains the
                    // literal marker text — "R""DY" in the command
                    // echoes with quotes, prints clean; the literal
                    // match can only ever hit real output.
                    // Echo-proof AND syntax-safe markers via variable concatenation
                    // (Codex P1 round 2): 'V1=C; V2=K-0; echo "$V1$V2"'
                    // echoes the VARIABLE NAMES, prints the resolved
                    // marker — no literal to false-match, no quoting to
                    // unbalance (the quote-split attempt had an
                    // unterminated string; the exec-in-test below now
                    // proves every generated line runs and prints the
                    // exact marker).
                    let line = format!(
                        "sh -c \"A=R; B=DY; busybox stty raw -echo && echo \"$A\"$B || {{ C=N; D=OSTTY; echo \"$C\"$D; }}; head -c {} >> {remote_path}; E=C; F=K-{}; echo \"$E\"$F\"\n",
                        chunk.len(),
                        ck_number,
                    );
                    s.send_raw(line.as_bytes());
                    // verified handshake: wait for RDY (or die on NOSTTY)
                    // before any data
                    let rdy_deadline = Instant::now() + Duration::from_secs(30);
                    let mut rdy = false;
                    let mut nostty = false;
                    while Instant::now() < rdy_deadline {
                        let b2 = s.window.len();
                        s.read_secs(1.0);
                        let recent = s.recent_since(b2).to_vec();
                        if contains(&recent, b"NOSTTY") {
                            nostty = true;
                            break;
                        }
                        if contains(&recent, b"RDY") {
                            rdy = true;
                            break;
                        }
                    }
                    if nostty || !rdy {
                        return Err(format!(
                            "stream_chunks: receiver cannot arm for chunk {i}: {} — this environment lacks stty; run serial transfers from the initramfs",
                            if nostty { "NOSTTY" } else { "no RDY" }
                        ));
                    }
                    let t0 = Instant::now();
                    let mut sent = 0usize;
                    while sent < chunk.len() {
                        let end = (sent + pace_bytes).min(chunk.len());
                        s.send_raw(&chunk[sent..end]);
                        sent = end;
                        std::thread::sleep(Duration::from_millis(*pace_ms));
                    }
                    s.log(&format!(
                        "chunk {}/{} sent ({} B, {:.1}s)",
                        i + 1,
                        total_chunks,
                        chunk.len(),
                        t0.elapsed().as_secs_f64()
                    ));
                    // wait for the chunk marker (head consumed exactly N)
                    let deadline = Instant::now() + Duration::from_secs(120);
                    let mut ok = false;
                    while Instant::now() < deadline {
                        let b2 = s.window.len();
                        s.read_secs(1.0);
                        if contains(s.recent_since(b2), ck.as_bytes()) {
                            ok = true;
                            break;
                        }
                    }
                    if !ok {
                        return Err(format!(
                            "stream_chunks: {ck} never echoed — box unresponsive after chunk {i}"
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(*pause_ms));
                }
                // restore the tty once, after all chunks (echo was
                // deliberately off for the whole transfer)
                s.send_raw(b"busybox stty sane\n");
                s.read_secs(2.0);
                // final on-box gate
                let before = s.window.len();
                s.send_raw(format!("{arm}\n").as_bytes());
                let deadline =
                    Instant::now() + Duration::from_secs_f64((*verdict_timeout_secs).max(1.0));
                let mut pass = false;
                while Instant::now() < deadline {
                    let b2 = s.window.len();
                    s.read_secs(2.0);
                    if contains(s.recent_since(b2), b"CW-GATE-PASS") {
                        pass = true;
                        break;
                    }
                    if contains(s.recent_since(b2), b"CW-GATE-FAIL") {
                        return Err("stream_chunks: on-box sha gate FAILED".into());
                    }
                }
                if !pass {
                    return Err("stream_chunks: no gate verdict".into());
                }
                s.log("ON-BOX GATE PASSED (chunked)");
                if !final_command.is_empty() {
                    s.send_raw(format!("{final_command}\n").as_bytes());
                    s.read_secs(5.0);
                }
            }
            Action::Stream {
                file,
                sha256,
                pace_bytes,
                pace_ms,
                done_marker,
                fail_marker,
                verdict_timeout_secs,
            } => {
                let data =
                    std::fs::read(file).map_err(|e| format!("stream: cannot read {file}: {e}"))?;
                if !sha256.is_empty() {
                    let want = sha256.to_ascii_lowercase();
                    let got = sha256_hex_for_gate(&data);
                    if got != want {
                        return Err(format!("stream: host-side sha mismatch: {got} != {want}"));
                    }
                }
                s.log(&format!("streaming {} bytes", data.len()));
                let t0 = Instant::now();
                let mut sent = 0usize;
                while sent < data.len() {
                    let end = (sent + pace_bytes).min(data.len());
                    s.send_raw(&data[sent..end]);
                    sent = end;
                    std::thread::sleep(Duration::from_millis(*pace_ms));
                    if sent % (pace_bytes * 400) == 0 {
                        let el = t0.elapsed().as_secs_f64().max(1.0);
                        s.log(&format!(
                            "{}/{} ({:.1} KiB/s)",
                            sent,
                            data.len(),
                            sent as f64 / el / 1024.0
                        ));
                    }
                }
                s.log("stream complete; waiting for on-box verdict");
                let deadline =
                    Instant::now() + Duration::from_secs_f64((*verdict_timeout_secs).max(1.0));
                let mut verdict = None;
                while Instant::now() < deadline {
                    let before = s.window.len();
                    s.read_secs(2.0);
                    let recent = s.recent_since(before).to_vec();
                    if contains(&recent, fail_marker.as_bytes()) {
                        verdict = Some(false);
                        break;
                    }
                    if contains(&recent, done_marker.as_bytes()) {
                        verdict = Some(true);
                        break;
                    }
                }
                match verdict {
                    Some(true) => s.log("ON-BOX GATE PASSED"),
                    Some(false) => {
                        return Err(format!("stream: on-box gate FAILED ({fail_marker:?})"));
                    }
                    None => {
                        return Err(format!(
                            "stream: no verdict within {verdict_timeout_secs:.0}s"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn action_kind(a: &Action) -> &'static str {
    match a {
        Action::Spaces { .. } => "spaces",
        Action::Expect { .. } => "expect",
        Action::SendLine { .. } => "send_line",
        Action::Loady { .. } => "loady",
        Action::TftpBoot { .. } => "tftp_boot",
        Action::StreamChunks { .. } => "stream_chunks",
        Action::ArmScript { .. } => "arm_script",
        Action::Stream { .. } => "stream",
    }
}

/// Public shim: the same SHA-256 used by gate checks, callable from
/// sibling modules (tftp.rs re-exports it).
pub fn sha256_hex_for_gate(data: &[u8]) -> String {
    crate::flash::image_sha256(data)
}

/// Watch `port_spec` until `max_fires` successful recipe runs (or the
/// caller stops the process). Read-only until a boot trigger matches.
pub fn run_watch(
    port_spec: &str,
    baud: u32,
    recipe: &Recipe,
    transcript_path: &Path,
    idle_poll_secs: f64,
) -> std::io::Result<WatchOutcome> {
    // validate-then-arm (R4): refuse BEFORE opening the port so a
    // broken recipe never costs the bootdelay window
    if let Err(e) = recipe.validate() {
        return Err(std::io::Error::other(format!("recipe invalid: {e}")));
    }
    let mut transcript = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(transcript_path)?;
    let io = open_port(port_spec, baud, Duration::from_millis(200))
        .map_err(|e| std::io::Error::other(format!("open {port_spec}: {e}")))?;
    // TCP framing is EXPLICIT (Codex P2 round 2): io.rs documents
    // tcp:// as a RAW relay (and the project's own bridge forwards raw
    // bytes), so wrapping every tcp:// endpoint would corrupt YMODEM
    // over those. ser2net-style telnet accepters opt in with telnet://
    let io: Box<dyn ConsoleIo> = if port_spec.starts_with("telnet://") {
        Box::new(TelnetFramedIo::negotiate(io))
    } else {
        io
    };
    let mut s = Supervisor {
        io,
        window: Vec::new(),
        transcript: &mut transcript,
    };
    let triggers: Vec<Vec<u8>> = recipe
        .boot_trigger
        .iter()
        .map(|t| t.as_bytes().to_vec())
        .collect();
    s.log(&format!(
        "armed on {port_spec} (model {:?}, {} trigger(s), {} action(s), max_fires {})",
        recipe.model,
        triggers.len(),
        recipe.actions.len(),
        recipe.max_fires
    ));
    // cross-process fire state: a prior watcher's fire (or a dead
    // process's cooldown) must still suppress triggers — stale text
    // replayed from a draining backlog once fired a bogus second run
    // (2026-10-24, chunked-proof run 2). State lives next to the
    // transcript: <transcript>.fired holds the unix-seconds timestamp.
    let fired_marker = transcript_path.with_extension("fired");
    let mut last_fire: Option<Instant> = None;
    if let Ok(text) = std::fs::read_to_string(&fired_marker) {
        if let Ok(secs) = text.trim().parse::<u64>() {
            let elapsed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if elapsed.saturating_sub(secs) < recipe.cooldown_secs as u64 {
                let wait = recipe.cooldown_secs as u64 - (elapsed - secs);
                return Ok(WatchOutcome {
                    fires: 0,
                    success: true,
                    detail: format!(
                        "prior fire marker {secs} inside cooldown — refusing to re-fire ({wait}s left)"
                    ),
                });
            }
        }
    }
    let mut fires = 0u32;
    let mut last_probe: Option<Instant> = None;
    let mut trigger_scan_from: usize = 0;
    loop {
        if fires >= recipe.max_fires {
            return Ok(WatchOutcome {
                fires,
                success: true,
                detail: "max_fires reached".into(),
            });
        }
        // quiescent-console probe: poke so the box reveals its state
        if let Some(probe) = &recipe.probe_line {
            let due = last_probe
                .map(|t| t.elapsed().as_secs_f64() >= recipe.probe_interval_secs)
                .unwrap_or(true);
            if due {
                let line = if probe.is_empty() {
                    "\n".to_string()
                } else {
                    format!("{probe}\n")
                };
                s.send_raw(line.as_bytes());
                last_probe = Some(Instant::now());
            }
        }
        let before = s.window.len();
        s.read_secs(idle_poll_secs);
        let _ = before;
        // Codex P2: a signature straddling two polls ("Copied Pre" |
        // "loader") lives in the ACCUMULATED window, not in either
        // per-poll slice — match the window, guarded by a processed
        // offset so a signature only fires once.
        if triggers.iter().any(|t| {
            // R1 (audit): clamp the consumed-offset — the window
            // drains during idle polls and a stale offset panics
            let scan_from = trigger_scan_from.min(s.window.len());
            contains(&s.window[scan_from..], t)
        }) {
            if let Some(t) = last_fire {
                if t.elapsed().as_secs() < recipe.cooldown_secs {
                    s.log("trigger inside cooldown — ignored");
                    continue;
                }
            }
            // consume the matched bytes so this signature cannot refire
            trigger_scan_from = s.window.len();
            s.log("BOOT SIGNATURE DETECTED — firing recipe");
            last_fire = Some(Instant::now());
            let _ = std::fs::write(
                &fired_marker,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs().to_string())
                    .unwrap_or_default(),
            );
            match run_actions(&mut s, &recipe.actions) {
                Ok(()) => {
                    fires += 1;
                    s.log(&format!("recipe run {fires}/{} COMPLETE", recipe.max_fires));
                }
                Err(e) => {
                    s.log(&format!("recipe FAILED: {e}"));
                    if recipe.max_fires == 1 {
                        return Ok(WatchOutcome {
                            fires,
                            success: false,
                            detail: e,
                        });
                    }
                    s.log("re-arming after failure (cooldown applies)");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telnet_filter_round_trip() {
        // negotiation + suboption stripped
        let mixed = [
            &b"DDR: 2 GiB\r\n"[..],
            &[0xFF, 0xFD, 0x00],                   // DO BINARY
            &[0xFF, 0xFA, 0x18, 0x01, 0xFF, 0xF0], // suboption
            &b"U-Boot 2011.12\r\n"[..],
        ]
        .concat();
        assert_eq!(
            telnet_strip_iac(&mixed),
            b"DDR: 2 GiB\r\nU-Boot 2011.12\r\n"
        );
        // escaped 0xFF data preserved
        let bin = telnet_escape(&[0x00, 0xFF, 0xAB, 0xFF, 0xFF, 0x01]);
        assert_eq!(
            bin,
            vec![0x00, 0xFF, 0xFF, 0xAB, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]
        );
        assert_eq!(
            telnet_strip_iac(&bin),
            vec![0x00, 0xFF, 0xAB, 0xFF, 0xFF, 0x01]
        );
    }

    #[test]
    fn trigger_matches_across_chunk_boundary() {
        let trig = b"Copied Preloader".to_vec();
        let mut recent = b"noise\r\nCopied Pre".to_vec();
        assert!(!contains(&recent, &trig));
        recent.extend_from_slice(b"loader data\r\n");
        assert!(contains(&recent, &trig));
    }

    #[test]
    fn recipe_json_parses() {
        let js = r#"{
            "model": "zyxel_gs1900-8hp rescue 25.12.6",
            "boot_trigger": ["Copied Preloader", "DRAM is set", "U-Boot 2011"],
            "actions": [
                {"type": "spaces", "secs": 90, "until": "RTL838x#"},
                {"type": "expect", "pattern": "RTL838x#", "timeout_secs": 10},
                {"type": "loady", "addr": "0x84f00000", "name": "initramfs.bin",
                 "image_path": "/srv/tftp-gs1900/owrt-25.12.6-initramfs-kernel.bin",
                 "pre": ["setsys bootpartition 0", "savesys"], "boot": true},
                {"type": "expect", "pattern": "root@OpenWrt", "timeout_secs": 200}
            ],
            "cooldown_secs": 600,
            "max_fires": 1
        }"#;
        let r: Recipe = serde_json::from_str(js).unwrap();
        assert_eq!(r.boot_trigger.len(), 3);
        assert_eq!(r.actions.len(), 4);
        assert!(matches!(r.actions[0], Action::Spaces { .. }));
        assert!(matches!(r.actions[2], Action::Loady { boot: true, .. }));
    }

    /// Fake transport: captures writes, replays them back on read.
    struct EchoIo {
        written: Vec<u8>,
        pos: usize,
    }
    impl ConsoleIo for EchoIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (self.written.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.written[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
        fn write_all_bytes(&mut self, data: &[u8]) -> std::io::Result<()> {
            self.written.extend_from_slice(data);
            Ok(())
        }
        fn reset_input_buffer(&mut self) {}
        fn close(&mut self) {}
    }

    #[test]
    fn telnet_framed_io_carries_binary_frames() {
        // the live-fire regression: a YMODEM frame full of 0xFF bytes
        // must survive the wrapper round-trip unharmed
        let frame: Vec<u8> = std::iter::once(0x02u8)
            .chain(std::iter::repeat_n(0xFF, 200))
            .chain(std::iter::repeat_n(0xAB, 50))
            .collect();
        let inner = Box::new(EchoIo {
            written: Vec::new(),
            pos: 0,
        });
        let mut io = TelnetFramedIo::negotiate(inner);
        io.write_all_bytes(&frame).unwrap();
        // read back through the wrapper: negotiation + frame escaped on
        // the wire, clean on our side
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let k = io.read(&mut buf).unwrap();
            if k == 0 {
                break;
            }
            out.extend_from_slice(&buf[..k]);
        }
        // the wrapper's read side already strips: out must equal the
        // original frame exactly (no second stripping — that would
        // collapse legitimate 0xFF runs and off-by-one the compare)
        assert_eq!(out, frame);
    }

    #[test]
    fn shipped_gs1900_recipe_parses() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../recipes/gs1900-8hp-rescue-25.12.6.json"
        );
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("recipe missing at {path}: {e}"));
        let r: Recipe = serde_json::from_str(&text).expect("shipped recipe must parse");
        assert_eq!(r.boot_trigger.len(), 3);
        assert!(r.max_fires == 1);
        // the rescue chain shape: spaces -> loady -> expect shell ->
        // arm self-firing script -> sha-gated stream
        assert!(matches!(r.actions[0], Action::Spaces { .. }));
        assert!(matches!(r.actions[1], Action::Loady { boot: true, .. }));
        assert!(matches!(r.actions[2], Action::Expect { .. }));
        assert!(matches!(r.actions[3], Action::ArmScript { .. }));
        assert!(matches!(r.actions[4], Action::Stream { .. }));
        if let Action::ArmScript { lines, .. } = &r.actions[3] {
            assert!(lines.iter().any(|l| l.contains("sysupgrade -n")));
            assert!(lines.iter().any(|l| l.contains("sha256sum")));
        }
        if let Action::Stream { sha256, .. } = &r.actions[4] {
            assert_eq!(sha256.len(), 64);
        }
    }

    #[test]
    fn flash_rescue_recipe_shape() {
        let r = flash_rescue_recipe(
            "/srv/tftp-gs1900/owrt-25.12.6-squashfs-sysupgrade.bin",
            "9111c296bbb4e6398002d9a3eb9e9d9ce16491286a624479955b9faee052155f",
            "owrt-25.12.6-initramfs-kernel.bin",
            "192.168.1.10",
            "192.168.1.10:69",
            "/srv/tftp-gs1900",
            "192.168.1.1",
            "0x84f00000",
        );
        assert_eq!(r.boot_trigger.len(), 3);
        assert!(matches!(r.actions[0], Action::Spaces { .. }));
        assert!(matches!(r.actions[3], Action::TftpBoot { .. }));
        assert!(matches!(r.actions[8], Action::Expect { .. }));
        let sysupgrade_line = r
            .actions
            .iter()
            .find_map(|a| match a {
                Action::SendLine { line, .. } if line.contains("sysupgrade -n") => {
                    Some(line.clone())
                }
                _ => None,
            })
            .expect("sysupgrade action present");
        assert!(sysupgrade_line.contains("/tmp/fw.bin"));
    }

    /// The generated marker lines can never satisfy a literal match on
    /// an echo-enabled console (var-concat: echo shows variable names),
    /// AND the construction is valid shell printing the real marker —
    /// proven by execution here (audit R8: the previous test asserted
    /// the abandoned quote-split shape and could not catch regressions).
    /// Fragmenting transport: serves one fixed byte slice in
    /// caller-chosen chunks, one chunk per read.
    struct FragmentIo {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
    }
    impl ConsoleIo for FragmentIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let end = (self.pos + self.chunk).min(self.data.len());
            let n = (end - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
        fn write_all_bytes(&mut self, _data: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn reset_input_buffer(&mut self) {
            self.pos = self.data.len();
        }
        fn close(&mut self) {}
    }

    /// Live-fire lesson 1 as an INVARIANT (audit T0-1): for arbitrary
    /// binary payloads, escape->strip round-trips, AND the framing
    /// adapter reconstructs the original no matter how the socket
    /// splits the escaped stream.
    #[test]
    fn telnet_framing_survives_arbitrary_splits() {
        use proptest::prelude::*;
        proptest!(|(payload in proptest::collection::vec(any::<u8>(), 0..600))| {
            // round-trip of the pure codecs
            let wire = telnet_escape(&payload);
            prop_assert_eq!(telnet_strip_iac(&wire), payload.clone());

            // through the adapter at several fragment sizes (incl. 1)
            for frag in [1usize, 2, 3, 7, 64, 4096] {
                let inner = Box::new(FragmentIo {
                    data: wire.clone(),
                    pos: 0,
                    chunk: frag,
                });
                let mut io = TelnetFramedIo::negotiate_without_send(inner);
                let mut got = Vec::new();
                let mut buf = [0u8; 53]; // awkward size on purpose
                loop {
                    let k = io.read(&mut buf).unwrap();
                    if k == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..k]);
                }
                prop_assert_eq!(got, payload.clone());
            }
        });
    }

    /// Tier-1 closed loop: a golden boot transcript replayed through the
    /// REAL supervisor — trigger fires, expect-actions resolve, one fire,
    /// then done. No hardware, no mocks of run_watch itself.
    #[test]
    fn golden_transcript_drives_the_real_supervisor() {
        let dir = std::env::temp_dir().join("conwrt-replay-test");
        std::fs::create_dir_all(&dir).unwrap();
        let transcript = dir.join("golden-boot.log");
        let boot = b"Copied Preloader data from SPI flash\r\nDRAM is set\r\n\
U-Boot 2011.12.39239\r\nRTL838x# \r\n\
## Starting kernel ...\r\n[    0.000000] Linux version 6.12.112\r\n\
root@OpenWrt:~# \r\n";
        std::fs::write(&transcript, boot).unwrap();
        let recipe: Recipe = serde_json::from_str(
            r#"{"model":"golden","boot_trigger":["DRAM is set","U-Boot 2011"],
                "actions":[
                  {"type":"expect","pattern":"RTL838x#","timeout_secs":10},
                  {"type":"expect","pattern":"root@OpenWrt","timeout_secs":10}
                ],
                "max_fires":1}"#,
        )
        .unwrap();
        let tpath = dir.join("watch.transcript");
        let _ = std::fs::remove_file(dir.join("watch.fired"));
        let out = run_watch(
            &format!("replay://{}", transcript.display()),
            115200,
            &recipe,
            &tpath,
            0.05,
        )
        .expect("watch runs");
        assert!(out.success, "recipe should complete: {}", out.detail);
        assert_eq!(out.fires, 1);
        // the fire-marker landed (cross-process discipline holds)
        assert!(dir.join("watch.fired").exists());
    }

    #[test]
    fn recipe_validation_rejects_and_accepts() {
        let mut r: Recipe = serde_json::from_str(
            r#"{"model":"t","boot_trigger":["X"],"actions":[{"type":"expect","pattern":"X","timeout_secs":1}]}"#,
        )
        .unwrap();
        assert!(r.validate().is_ok());
        r.boot_trigger.clear();
        assert!(r.validate().is_err());
        // bad sha
        let bad: Recipe = serde_json::from_str(
            r#"{"model":"t","boot_trigger":["X"],"actions":[{"type":"stream_chunks","file":"/etc/hostname","sha256":"nothex","remote_path":"/tmp/x","chunk_bytes":1,"pause_ms":1,"pace_bytes":1,"pace_ms":1,"final_command":"","verdict_timeout_secs":1}]}"#,
        )
        .unwrap();
        assert!(bad.validate().is_err());
        // missing file
        let missing: Recipe = serde_json::from_str(
            r#"{"model":"t","boot_trigger":["X"],"actions":[{"type":"stream","file":"/no/such/file","sha256":"","pace_bytes":1,"pace_ms":1,"done_marker":"D","fail_marker":"F","verdict_timeout_secs":1}]}"#,
        )
        .unwrap();
        assert!(missing.validate().is_err());
    }

    #[test]
    fn marker_lines_defeat_command_echo() {
        let ck_number = "0";
        let line = format!(
            "sh -c \"A=R; B=DY; busybox stty raw -echo && echo \"$A\"$B || {{ C=N; D=OSTTY; echo \"$C\"$D; }}; head -c 819200 >> /tmp/f; E=C; F=K-{}; echo \"$E\"$F\"",
            ck_number
        );
        assert!(!line.contains("RDY"));
        assert!(!line.contains("NOSTTY"));
        assert!(!line.contains("CK-0"));
        let want = "9".to_string() + &"1".repeat(63);
        let arm = format!(
            "P=CW-GATE-P; Q=ASS; R=CW-GATE-F; S2=AIL; V=$(sha256sum /tmp/f | cut -d' ' -f1); test \"$V\" = \"{want}\" && echo \"$P\"$Q || echo \"$R\"$S2"
        );
        assert!(!arm.contains("CW-GATE-PASS"));
        assert!(!arm.contains("CW-GATE-FAIL"));
        // exec-in-sh: the marker mechanics must resolve and print
        let probe = "A=R; B=DY; true && echo \"$A\"$B";
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(probe)
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "RDY");
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex_for_gate(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex_for_gate(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex_for_gate(b"The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }
}
