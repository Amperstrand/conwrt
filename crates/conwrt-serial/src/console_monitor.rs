//! # Serial console monitor (Rust port of `scripts/serial-console.py`)
//!
//! The always-attached console consumer: dual logging (raw + timestamped
//! human log with `[RX]`/`[TX]` direction markers), boot-stage detection
//! via the shared [`BootMilestoneTracker`], and FIFO command injection
//! with token translation (`ESCAPE`/`ENTER`/`CTRLC`).
//!
//! Recovery rule (see [`crate::recovery`]): during degraded states the
//! console MUST be consumed — an unread printk stream congests the tty
//! layer and can deepen the state. This monitor is that consumer.
//!
//! Deltas over the Python (documented, not silent):
//! * session metadata (`session.json`) is written at end-of-session with
//!   byte counts per direction (the Python wrote it incrementally);
//! * injection tokens are the same, but the FIFO path is explicit rather
//!   than derived from `/tmp` + session name.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::{Duration, SystemTime};

use conwrt_probe_core::milestones::{BootMilestone, BootMilestoneTracker};

use crate::io::ConsoleIo;

/// Where monitor output goes.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Session directory (created if missing); files: `console.raw`,
    /// `console.log`, `session.json`.
    pub session_dir: PathBuf,
}

/// A dual-format console session recorder.
pub struct SessionLog {
    raw: File,
    human: File,
    started: SystemTime,
    rx_bytes: u64,
    tx_bytes: u64,
    milestones: Vec<(BootMilestone, Duration)>,
    tracker: BootMilestoneTracker,
}

impl SessionLog {
    /// Create the session files under `dir`.
    pub fn create(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let raw = OpenOptions::new().create(true).append(true)
            .open(dir.join("console.raw"))?;
        let human = OpenOptions::new().create(true).append(true)
            .open(dir.join("console.log"))?;
        Ok(Self {
            raw, human,
            started: SystemTime::now(),
            rx_bytes: 0, tx_bytes: 0,
            milestones: Vec::new(),
            tracker: BootMilestoneTracker::new(),
        })
    }

    fn stamp(&self) -> String {
        let el = self.started.elapsed().unwrap_or_default();
        format!("[{:8.3}]", el.as_secs_f64())
    }

    /// Record received bytes: raw tee + milestone scan + human line.
    pub fn record_rx(&mut self, data: &[u8]) -> io::Result<()> {
        self.rx_bytes += data.len() as u64;
        self.raw.write_all(data)?;
        for (m, _detail) in self.tracker.feed(data) {
            let t = self.started.elapsed().unwrap_or_default();
            self.milestones.push((m, t));
            writeln!(self.human, "{} [STAGE] {:?}", self.stamp(), m)?;
        }
        let printable: String = data.iter()
            .map(|&b| if (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\r' {
                b as char
            } else { '.' })
            .collect();
        writeln!(self.human, "{} [RX] {}", self.stamp(), printable.trim_end())
    }

    /// Record sent bytes with a `[TX]` marker.
    pub fn record_tx(&mut self, data: &[u8]) -> io::Result<()> {
        self.tx_bytes += data.len() as u64;
        let printable: String = data.iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        writeln!(self.human, "{} [TX] {}", self.stamp(), printable)
    }

    /// Write `session.json` (idempotent; call at exit or periodically).
    pub fn write_session_meta(&self, dir: &Path, spec: &str) -> io::Result<()> {
        // hand-rolled JSON: keeps the crate serde-free (session.json is a
        // flat diagnostic artifact, not a protocol surface)
        let started = self
            .started
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let milestones = self
            .milestones
            .iter()
            .map(|(m, t)| format!(
                "{{\"stage\":\"{}\",\"at_s\":{:.3}}}",
                m.as_str(),
                t.as_secs_f64()
            ))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            "{{\"port\":\"{spec}\",\"started_unix\":{started},\
\"rx_bytes\":{},\"tx_bytes\":{},\"milestones\":[{milestones}]}}\n",
            self.rx_bytes, self.tx_bytes
        );
        std::fs::write(dir.join("session.json"), json)
    }
}

/// Translate an injection token to bytes. Mirrors the Python tokens.
pub fn translate_token(line: &str) -> Vec<u8> {
    match line.trim() {
        "ESCAPE" => vec![0x1b],
        "ENTER" => vec![b'\r'],
        "CTRLC" => vec![0x03],
        s => s.as_bytes().to_vec(),
    }
}

/// Monitor loop: consume the console, honor injection commands, until the
/// transport dies or `stop` receives. Returns IO error on transport failure.
pub fn run_monitor(
    io: &mut dyn ConsoleIo,
    cfg: &MonitorConfig,
    inject: &Receiver<Vec<u8>>,
) -> io::Result<(u64, u64)> {
    let mut log = SessionLog::create(&cfg.session_dir)?;
    let mut buf = [0u8; 4096];
    loop {
        // non-blocking-ish: transport read is bounded by its timeout
        let n = io.read(&mut buf)?;
        if n > 0 {
            log.record_rx(&buf[..n])?;
        }
        // drain all pending injections
        while let Ok(cmd) = inject.try_recv() {
            io.write_all_bytes(&cmd)?;
            log.record_tx(&cmd)?;
        }
        if n == 0 {
            // idle: let the injection channel breathe
            std::thread::sleep(Duration::from_millis(20));
        }
        // periodic session meta
        if (log.rx_bytes + log.tx_bytes) % 65536 < 4096 {
            let _ = log.write_session_meta(&cfg.session_dir, "monitor");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        assert_eq!(translate_token("ESCAPE"), vec![0x1b]);
        assert_eq!(translate_token("ENTER"), vec![b'\r']);
        assert_eq!(translate_token("CTRLC"), vec![0x03]);
        assert_eq!(translate_token("help"), b"help".to_vec());
    }

    #[test]
    fn session_log_dual_output() {
        let dir = std::env::temp_dir().join(format!("conwrt-mon-{}", std::process::id()));
        let mut log = SessionLog::create(&dir).unwrap();
        log.record_rx(b"Starting kernel ...\r\n").unwrap();
        log.record_tx(b"uname -a\n").unwrap();
        let raw = std::fs::read(dir.join("console.raw")).unwrap();
        assert_eq!(raw, b"Starting kernel ...\r\n");
        let human = std::fs::read_to_string(dir.join("console.log")).unwrap();
        assert!(human.contains("[RX] Starting kernel"));
        assert!(human.contains("[TX] uname -a"));
        log.write_session_meta(&dir, "/dev/null").unwrap();
        let meta = std::fs::read_to_string(dir.join("session.json")).unwrap();
        assert!(meta.contains("rx_bytes"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
