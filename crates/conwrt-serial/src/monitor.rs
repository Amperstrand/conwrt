//! Serial console monitor — the Rust port of `scripts/serial-console.py`'s
//! monitoring core (parity-matrix §5): dual logging, boot-stage
//! detection, and command injection over a mailbox file, plus the boot
//! stage vocabulary from `scripts/serial_baud.py`.
//!
//! What is ported (the semantics a programmatic consumer needs):
//!
//! * **Dual logging** — `console.raw` (exact bytes) and `console.log`
//!   (timestamped `[RX …]` / `[TX …]` lines with byte escapes, the
//!   Python `_format_bytes` rendering).
//! * **Boot-stage detection** — [`detect_boot_stage`] +
//!   [`BOOT_SIGNATURES`] ported 1:1 from `serial_baud.py` (the
//!   `tests/test_serial_console.py` oracle); stage transitions are
//!   latched into a history and reported in `session.json`.
//! * **Command injection** — the Python "FIFO" is a mailbox FILE:
//!   commands appear at a path, are read once, and the file is
//!   unlinked. Special tokens ([`CMD_TOKENS`]: `ESCAPE`, `ENTER`,
//!   `CTRLC`, …) map to control bytes; anything else goes out verbatim
//!   and is logged as `[TX]`.
//! * **Session metadata** — `session.json` with byte counters, final
//!   boot stage, and the transition history.
//!
//! What deliberately stays Python (adapter-facing TTY work, not
//! console-driver semantics): interactive stdin passthrough, port
//! enumeration, `--auto-baud` sweeps, adapter diagnostics, and the
//! hardware loopback test.
//!
//! The monitor is a single-threaded poll loop ([`MonitorSession::step`]
//! and [`MonitorSession::run_until`]) over the [`crate::io::ConsoleIo`]
//! seam — no break recovery here, matching the Python reader (a wedged
//! adapter stops the loop with a typed error for the operator).

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use thiserror::Error;

use crate::collect::READ_CHUNK;
use crate::io::{ConsoleError, ConsoleIo};

/// Default mailbox path (Python `cmd_fifo`).
pub const CMD_MAILBOX_PATH: &str = "/tmp/conwrt-serial-cmd";

/// Poll cadence of the monitor loop (Python's 10 ms sleeps).
pub const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The Python byte-escape rendering (`_format_bytes`): printable ASCII
/// passes through, control bytes render as escapes, `\n` keeps a real
/// newline. Pure.
#[must_use]
pub fn format_bytes(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    for &byte in data {
        match byte {
            0x0a => out.push_str("\\n\n"),
            0x0d => out.push_str("\\r"),
            0x08 => out.push_str("\\b"),
            0x1b => out.push_str("\\e"),
            0x09 => out.push_str("\\t"),
            0x00 => out.push_str("\\0"),
            0x20..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out
}

/// Coarse boot stages (the `serial_baud.py` vocabulary). Serializes to
/// the Python stage strings (`as_str` parity for `session.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BootStage {
    /// Nothing recognized yet.
    #[default]
    Unknown,
    /// U-Boot / bootloader banners.
    Uboot,
    /// ZyXEL Z-Loader / BootBase.
    Zloader,
    /// Kernel boot messages.
    Kernel,
    /// OpenWrt userspace.
    Openwrt,
    /// Kernel panic.
    Panic,
}

impl BootStage {
    /// Stable machine name (the Python stage strings).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            BootStage::Unknown => "unknown",
            BootStage::Uboot => "uboot",
            BootStage::Zloader => "zloader",
            BootStage::Kernel => "kernel",
            BootStage::Openwrt => "openwrt",
            BootStage::Panic => "panic",
        }
    }
}

/// One stage's pattern set: the stage and its literal signatures.
pub type StageSignatures = (BootStage, &'static [&'static [u8]]);

/// The stage vocabulary in Python dict order — the FIRST stage whose
/// pattern matches wins (that priority is behavior, not accident:
/// `uboot` beats `openwrt` on a line carrying both).
pub const BOOT_SIGNATURES: &[StageSignatures] = &[
    (
        BootStage::Uboot,
        &[
            b"U-Boot",
            b"u-boot",
            b"Bootloader",
            b"bootmenu",
            b"Hit any key to stop autoboot",
            b"Net:   ",
            b"eth0: ",
            b"ethaddr=",
        ],
    ),
    (
        BootStage::Zloader,
        &[
            b"Z-Loader",
            b"Z-LOADER",
            b"ZyNOS",
            b"BootBase",
            b"Multiboot",
            b"Press ENTER to debug mode",
            b"multiboot listening",
            b"Multiboot Listening",
        ],
    ),
    (
        BootStage::Kernel,
        &[
            b"[    0.000000] Linux version",
            b"Starting kernel",
            b"Booting Linux",
            b"Decompressing Linux",
        ],
    ),
    (
        BootStage::Openwrt,
        &[
            b"OpenWrt",
            b"LEDE",
            b"BusyBox",
            b"dropbear",
            b"Starting OpenWrt",
            b"Router login",
        ],
    ),
    (BootStage::Panic, &[b"Kernel panic", b"not syncing"]),
];

/// Classify one chunk against the vocabulary; no match keeps the
/// current stage. Pure — the `serial_baud.py` `detect_boot_stage`.
#[must_use]
pub fn detect_boot_stage(chunk: &[u8], current: BootStage) -> BootStage {
    for (stage, patterns) in BOOT_SIGNATURES {
        for pattern in *patterns {
            if contains(chunk, pattern) {
                return *stage;
            }
        }
    }
    current
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// One mailbox special token: its literal, the bytes it sends, and the
/// human label for the `[TX]` log line.
pub type CmdToken = (&'static [u8], (&'static [u8], &'static str));

/// Special mailbox tokens → (bytes, label) (Python `tokens` dict).
pub const CMD_TOKENS: &[CmdToken] = &[
    (b"ESCAPE", (b"\x1b", "ESC")),
    (b"ESC", (b"\x1b", "ESC")),
    (b"ENTER", (b"\r", "CR")),
    (b"RETURN", (b"\r", "CR")),
    (b"CTRLC", (b"\x03", "Ctrl-C")),
    (b"CTRL-D", (b"\x04", "Ctrl-D")),
    (b"CTRL-Z", (b"\x1a", "Ctrl-Z")),
    (b"TAB", (b"\x09", "Tab")),
];

/// Resolve one mailbox command to (wire bytes, human label). Pure.
#[must_use]
pub fn resolve_command(cmd: &[u8]) -> (Vec<u8>, String) {
    for (token, (bytes, label)) in CMD_TOKENS {
        if cmd == *token {
            return (bytes.to_vec(), (*label).to_string());
        }
    }
    (cmd.to_vec(), String::from_utf8_lossy(cmd).into_owned())
}

/// One boot-stage transition.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StageTransition {
    /// Wall-clock time of the transition.
    pub timestamp: String,
    /// Previous stage.
    pub from: BootStage,
    /// New stage.
    pub to: BootStage,
    /// Seconds since monitor start.
    pub elapsed_s: f64,
}

/// Why the monitor failed. Messages are operator-safe.
#[derive(Debug, Error)]
pub enum MonitorError {
    /// Transport failure.
    #[error(transparent)]
    Console(#[from] ConsoleError),
    /// A log file could not be created or written.
    #[error("cannot write monitor log {path}: {source}")]
    LogFile {
        /// The file being written when the failure hit.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
}

/// Monitor knobs.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Session name (log directory name).
    pub session_name: String,
    /// Base log directory; the session directory is `<log_dir>/<name>`.
    pub log_dir: PathBuf,
    /// Mailbox file for command injection.
    pub mailbox_path: PathBuf,
}

impl MonitorConfig {
    /// Python defaults: logs under `serial/<name>`, mailbox at
    /// `/tmp/conwrt-serial-cmd`.
    #[must_use]
    pub fn new(session_name: impl Into<String>) -> Self {
        Self {
            session_name: session_name.into(),
            log_dir: PathBuf::from("serial"),
            mailbox_path: PathBuf::from(CMD_MAILBOX_PATH),
        }
    }
}

/// The monitoring session: poll the port, log both streams, latch boot
/// stages, dispatch mailbox commands, and finalize `session.json`.
pub struct MonitorSession {
    config: MonitorConfig,
    port: Box<dyn ConsoleIo>,
    raw_file: File,
    log_file: File,
    started: Instant,
    start_wall: String,
    total_rx: u64,
    total_tx: u64,
    stage: BootStage,
    stage_history: Vec<StageTransition>,
}

impl MonitorSession {
    /// Open the port (via the opener) and create the session directory
    /// with empty logs. The session header mirrors the Python banner.
    ///
    /// # Errors
    /// [`MonitorError::Console`] when the port cannot be opened;
    /// [`MonitorError::LogFile`] for the session directory or files.
    pub fn open(port: Box<dyn ConsoleIo>, config: MonitorConfig) -> Result<Self, MonitorError> {
        let dir = config.log_dir.join(&config.session_name);
        std::fs::create_dir_all(&dir).map_err(|source| MonitorError::LogFile {
            path: dir.clone(),
            source,
        })?;
        let open = |name: &str| {
            let path = dir.join(name);
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|source| MonitorError::LogFile { path, source })
        };
        let mut log_file = open("console.log")?;
        let raw_file = open("console.raw")?;
        let header = format!(
            "\n{}\nSerial session: {}\nPort: (console spec)\nStarted: {}\n{}\n\n",
            "=".repeat(70),
            config.session_name,
            wall_clock(),
            "=".repeat(70)
        );
        log_file
            .write_all(header.as_bytes())
            .and_then(|()| log_file.flush())
            .map_err(|source| MonitorError::LogFile {
                path: dir.join("console.log"),
                source,
            })?;
        // no input flush on open — Python parity: the reader logs
        // whatever arrives, including bytes queued while the session
        // was being set up
        let start_wall = wall_clock();
        Ok(Self {
            config,
            port,
            raw_file,
            log_file,
            started: Instant::now(),
            start_wall,
            total_rx: 0,
            total_tx: 0,
            stage: BootStage::Unknown,
            stage_history: Vec::new(),
        })
    }

    /// One poll cycle: drain the port into both logs (with stage
    /// latching), then dispatch one mailbox command if present.
    ///
    /// # Errors
    /// [`MonitorError::Console`] on a port read/write failure (the
    /// loop stops — the operator reopens, Python parity);
    /// [`MonitorError::LogFile`] on log write failure.
    pub fn step(&mut self) -> Result<(), MonitorError> {
        let mut buf = [0u8; READ_CHUNK];
        match self.port.read(&mut buf) {
            Err(e) => return Err(ConsoleError::Io(e).into()),
            Ok(0) => {}
            Ok(n) => self.log_rx(&buf[..n])?,
        }
        self.dispatch_mailbox()?;
        Ok(())
    }

    /// Run [`MonitorSession::step`] until `stop` is true, sleeping
    /// [`POLL_INTERVAL`] between cycles.
    ///
    /// # Errors
    /// As [`MonitorSession::step`].
    pub fn run_until(&mut self, stop: &AtomicBool) -> Result<(), MonitorError> {
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            self.step()?;
            std::thread::sleep(POLL_INTERVAL);
        }
        Ok(())
    }

    /// Received bytes → raw log (exact) + human log (`[RX ts] …`) +
    /// boot-stage latch.
    fn log_rx(&mut self, data: &[u8]) -> Result<(), MonitorError> {
        self.total_rx += data.len() as u64;
        self.raw_file
            .write_all(data)
            .map_err(|source| MonitorError::LogFile {
                path: self.raw_path(),
                source,
            })?;
        let line = format!("[RX {}] {}", wall_clock_ms(), format_bytes(data));
        self.log_file
            .write_all(line.as_bytes())
            .and_then(|()| self.log_file.flush())
            .map_err(|source| MonitorError::LogFile {
                path: self.log_path(),
                source,
            })?;
        let new_stage = detect_boot_stage(data, self.stage);
        if new_stage != self.stage {
            self.stage_history.push(StageTransition {
                timestamp: wall_clock(),
                from: self.stage,
                to: new_stage,
                elapsed_s: self.started.elapsed().as_secs_f64(),
            });
            self.stage = new_stage;
        }
        Ok(())
    }

    /// Sent bytes → human log (`[TX ts] …`).
    fn log_tx(&mut self, data: &[u8], label: &str) -> Result<(), MonitorError> {
        self.total_tx += data.len() as u64;
        let line = format!(
            "\n[TX {}] {} ({})\n",
            wall_clock_ms(),
            format_bytes(data),
            label
        );
        self.log_file
            .write_all(line.as_bytes())
            .and_then(|()| self.log_file.flush())
            .map_err(|source| MonitorError::LogFile {
                path: self.log_path(),
                source,
            })?;
        Ok(())
    }

    /// Read the mailbox (read-all + unlink, the Python semantics) and
    /// send the resolved bytes. Missing mailbox is a no-op.
    fn dispatch_mailbox(&mut self) -> Result<(), MonitorError> {
        let Ok(cmd) = std::fs::read(&self.config.mailbox_path) else {
            return Ok(());
        };
        let _ = std::fs::remove_file(&self.config.mailbox_path);
        if cmd.is_empty() {
            return Ok(());
        }
        let (bytes, label) = resolve_command(&cmd);
        self.port
            .write_all_bytes(&bytes)
            .map_err(ConsoleError::Io)?;
        self.log_tx(&bytes, &label)
    }

    /// Write `session.json` (name, counters, final stage, transitions)
    /// and return the serialized record.
    ///
    /// # Errors
    /// [`MonitorError::LogFile`] when the metadata cannot be written.
    pub fn write_session_meta(&mut self) -> Result<String, MonitorError> {
        let meta = SessionMeta {
            session_name: self.config.session_name.clone(),
            start_time: self.start_wall.clone(),
            elapsed_s: self.started.elapsed().as_secs_f64(),
            total_rx_bytes: self.total_rx,
            total_tx_bytes: self.total_tx,
            final_boot_stage: self.stage,
            boot_stage_transitions: self.stage_history.clone(),
        };
        let json = serde_json::to_string_pretty(&meta).map_err(|source| MonitorError::LogFile {
            path: self.session_dir().join("session.json"),
            source: std::io::Error::other(source),
        })?;
        let path = self.session_dir().join("session.json");
        std::fs::write(&path, json.as_bytes())
            .map_err(|source| MonitorError::LogFile { path, source })?;
        Ok(json)
    }

    /// The wall-clock timestamp captured when the session OPENED (the
    /// value `session.json` reports as `start_time`).
    #[must_use]
    pub fn start_wall(&self) -> &str {
        &self.start_wall
    }

    /// Bytes received so far.
    #[must_use]
    pub fn total_rx(&self) -> u64 {
        self.total_rx
    }

    /// Bytes transmitted so far.
    #[must_use]
    pub fn total_tx(&self) -> u64 {
        self.total_tx
    }

    /// The current boot stage.
    #[must_use]
    pub fn stage(&self) -> BootStage {
        self.stage
    }

    /// The stage transition history so far.
    #[must_use]
    pub fn stage_history(&self) -> &[StageTransition] {
        &self.stage_history
    }

    fn session_dir(&self) -> PathBuf {
        self.config.log_dir.join(&self.config.session_name)
    }

    fn raw_path(&self) -> PathBuf {
        self.session_dir().join("console.raw")
    }

    fn log_path(&self) -> PathBuf {
        self.session_dir().join("console.log")
    }
}

/// The `session.json` record (Python `_write_session_meta`'s keys).
#[derive(Debug, Clone, Serialize)]
struct SessionMeta {
    session_name: String,
    start_time: String,
    elapsed_s: f64,
    total_rx_bytes: u64,
    total_tx_bytes: u64,
    final_boot_stage: BootStage,
    boot_stage_transitions: Vec<StageTransition>,
}

fn wall_clock() -> String {
    humantime(SystemTime::now())
}

fn wall_clock_ms() -> String {
    humantime(SystemTime::now())
}

/// `YYYY-MM-DD HH:MM:SS` (millisecond precision is Python-only
/// cosmetics; both call sites share one rendering).
fn humantime(t: SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    let (h, m, s) = ((secs % 86_400) / 3_600, (secs % 3_600) / 60, secs % 60);
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}")
}

/// Days-since-epoch → (y, m, d) — Howard Hinnant's civil-from-days.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_renders_escapes() {
        assert_eq!(
            format_bytes(b"hi\r\n\x1b\x00\x7f\xff"),
            "hi\\r\\n\n\\e\\0\\x7f\\xff"
        );
    }

    /// test_serial_console.py::TestDetectBootStage — 1:1.
    #[test]
    fn boot_stage_detection_matches_python_oracle() {
        assert_eq!(
            detect_boot_stage(b"U-Boot 1.1.3 (Jun 15 2009)", BootStage::Unknown),
            BootStage::Uboot
        );
        assert_eq!(
            detect_boot_stage(b"Z-LOADER V1.30", BootStage::Unknown),
            BootStage::Zloader
        );
        assert_eq!(
            detect_boot_stage(b"Starting kernel ...", BootStage::Unknown),
            BootStage::Kernel
        );
        assert_eq!(
            detect_boot_stage(b"BusyBox v1.36 built-in shell", BootStage::Unknown),
            BootStage::Openwrt
        );
        assert_eq!(
            detect_boot_stage(b"Kernel panic - not syncing", BootStage::Unknown),
            BootStage::Panic
        );
        assert_eq!(
            detect_boot_stage(b"random noise", BootStage::Kernel),
            BootStage::Kernel
        );
    }

    #[test]
    fn uboot_priority_beats_openwrt_on_shared_chunk() {
        // dict order: uboot patterns checked first
        assert_eq!(
            detect_boot_stage(b"OpenWrt U-Boot 2026", BootStage::Unknown),
            BootStage::Uboot
        );
    }

    #[test]
    fn command_tokens_resolve() {
        assert_eq!(resolve_command(b"CTRLC").0, b"\x03");
        assert_eq!(resolve_command(b"ENTER").1, "CR");
        assert_eq!(
            resolve_command(b"help"),
            (b"help".to_vec(), "help".to_string())
        );
    }

    #[test]
    fn humantime_renders_epoch_plus_one_day() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(86_400 + 3_661);
        assert_eq!(humantime(t), "1970-01-02 01:01:01");
    }
}
