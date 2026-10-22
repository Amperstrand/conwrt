//! The console driver (parity of `scripts/serial_transport.py`'s
//! `SerialConsole`): askfirst activation, RC-marker command execution with
//! FT232R break recovery, and linted line-chunked script delivery.
//!
//! Every timed wait and the port open live behind traits ([`Sleeper`],
//! [`PortOpener`]) so the driver's semantics — wire bytes, sleep cadence,
//! close → 3 s wait → reopen → flush recovery, deadline reset on break —
//! are pinned by tests over mocks (`tests/driver_mock.rs`), while the
//! production path ([`StdSleeper`], [`SpecOpener`]) drives real
//! `serialport-rs` ports and TCP bridges, exercised over pty pairs and
//! localhost listeners in the integration tests.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::collect::{
    BREAK_BYTE, CollectStep, Collector, READ_CHUNK, ReadOutcome, Recovery, rc_command_line,
};
use crate::io::{ConsoleError, ConsoleIo, open_port};
use crate::lint::{
    echo_append_line, is_skippable_line, lint_script, rm_deploy_line, sh_runner_line,
};

/// Every timed wait in the driver, with the Python defaults
/// (`scripts/serial_transport.py`). Injectable wholesale so tests run with
/// tiny (or recorded) waits without touching the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleTiming {
    /// Per-read bound (`timeout` in Python's `open_serial`).
    pub read_timeout: Duration,
    /// The FT232R recovery wait: close, wait for the device to boot,
    /// reopen fresh (AGENTS.md "UART Break Recovery" — 3 s).
    pub break_recover_wait: Duration,
    /// `activate()`: how long to wait for the askfirst shell to answer
    /// Enter before reading.
    pub activate_wait: Duration,
    /// `run()`/`send_script()`: settle time between the activating Enter
    /// and the command (stale banner must drain before the input flush).
    pub pre_command_settle: Duration,
    /// After an RC marker: wait for trailing output, then one drain read.
    pub marker_drain_wait: Duration,
    /// Between two delivered script lines (tty pacing).
    pub script_line_gap: Duration,
    /// After the `rm -f` staging-clear line, before the first append.
    pub script_init_wait: Duration,
}

impl Default for ConsoleTiming {
    fn default() -> Self {
        Self {
            read_timeout: Duration::from_millis(200),
            break_recover_wait: Duration::from_secs(3),
            activate_wait: Duration::from_millis(800),
            pre_command_settle: Duration::from_millis(300),
            marker_drain_wait: Duration::from_millis(300),
            script_line_gap: Duration::from_millis(120),
            script_init_wait: Duration::from_millis(200),
        }
    }
}

/// Injectable sleep. Production uses [`StdSleeper`]; tests record the
/// waits (or run them for real at pty level).
pub trait Sleeper {
    /// Block the current thread for `duration`.
    fn sleep(&self, duration: Duration);
}

/// Real `thread::sleep`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdSleeper;

impl Sleeper for StdSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Injectable port factory: break recovery works by re-running the opener
/// (local `/dev` reopen; TCP reconnect — no session reuse, Python parity).
pub trait PortOpener {
    /// Open a fresh transport.
    ///
    /// # Errors
    /// Whatever [`open_port`] produces — a failed recovery reopen
    /// propagates to the caller of `run`/`send_script` (Python parity:
    /// an exception out of `_reopen_after_break`).
    fn open(&mut self) -> Result<Box<dyn ConsoleIo>, ConsoleError>;
}

/// Production opener: resolves the port spec (`/dev` path or `tcp://`)
/// every time it runs.
#[derive(Debug, Clone)]
pub struct SpecOpener {
    /// Port spec (`/dev/...` or `tcp://HOST:PORT`).
    pub spec: String,
    /// Baud rate (ignored for `tcp://`).
    pub baud: u32,
    /// Read timeout for the opened transport.
    pub timeout: Duration,
}

impl PortOpener for SpecOpener {
    fn open(&mut self) -> Result<Box<dyn ConsoleIo>, ConsoleError> {
        open_port(&self.spec, self.baud, self.timeout)
    }
}

/// The serial console driver.
///
/// Mirrors `scripts/serial_transport.py`'s `SerialConsole` method-for-
/// method: [`activate`](Self::activate), [`run`](Self::run),
/// [`send_script`](Self::send_script), [`send_script_file`](Self::send_script_file).
///
/// SSH transports should be preferred whenever the device is reachable —
/// this driver is for bootstrap and recovery.
pub struct SerialConsole<S = StdSleeper, O = SpecOpener> {
    opener: O,
    timing: ConsoleTiming,
    sleeper: S,
    port: Box<dyn ConsoleIo>,
}

impl SerialConsole<StdSleeper, SpecOpener> {
    /// Open a console at 115200 baud with a 200 ms read timeout and
    /// default timings (Python `SerialConsole(port)`).
    ///
    /// # Errors
    /// [`ConsoleError::Connect`] / [`ConsoleError::OpenDevice`] when the
    /// transport cannot be opened.
    pub fn open(spec: &str) -> Result<Self, ConsoleError> {
        Self::with_baud(spec, 115_200, Duration::from_millis(200))
    }

    /// Open with an explicit baud and read timeout (Python
    /// `SerialConsole(port, baud, timeout)`).
    ///
    /// # Errors
    /// See [`SerialConsole::open`].
    pub fn with_baud(spec: &str, baud: u32, read_timeout: Duration) -> Result<Self, ConsoleError> {
        Self::new(
            SpecOpener {
                spec: spec.to_string(),
                baud,
                timeout: read_timeout,
            },
            ConsoleTiming::default(),
            StdSleeper,
        )
    }
}

impl<S: Sleeper, O: PortOpener> SerialConsole<S, O> {
    /// Assemble a driver from explicit parts (tests inject mocks here).
    ///
    /// # Errors
    /// The initial [`PortOpener::open`] failure propagates.
    pub fn new(mut opener: O, timing: ConsoleTiming, sleeper: S) -> Result<Self, ConsoleError> {
        let port = opener.open()?;
        Ok(Self {
            opener,
            timing,
            sleeper,
            port,
        })
    }

    /// Close the underlying transport (Python `close`).
    pub fn close(&mut self) {
        self.port.close();
    }

    /// Activate the askfirst console: send Enter, wait, read whatever came
    /// back. No break recovery here — a single bounded read (Python
    /// parity).
    ///
    /// # Errors
    /// Transport write/read failures propagate.
    pub fn activate(&mut self) -> Result<String, ConsoleError> {
        self.port.write_all_bytes(b"\n")?;
        self.sleeper.sleep(self.timing.activate_wait);
        let mut buf = [0u8; READ_CHUNK];
        let n = self.port.read(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
    }

    /// Run ONE command and collect until its RC marker (or timeout).
    ///
    /// Command-FIFO semantics (Python `run`): flush stale input, send
    /// Enter to activate, settle, flush the banner, send
    /// `<cmd> && echo __RC0__ || echo __RC1__`, then collect with break
    /// recovery. `rc`: 0 marker, 1 marker, 2 timeout.
    ///
    /// # Errors
    /// [`ConsoleError::MultiLineCommand`] for a command containing `\n`;
    /// transport failures that recovery could not paper over.
    pub fn run(
        &mut self,
        cmd: &str,
        timeout: Duration,
    ) -> Result<crate::collect::CmdOutcome, ConsoleError> {
        if cmd.contains('\n') {
            return Err(ConsoleError::MultiLineCommand);
        }
        self.port.reset_input_buffer();
        self.port.write_all_bytes(b"\n")?;
        self.sleeper.sleep(self.timing.pre_command_settle);
        self.port.reset_input_buffer();
        self.port
            .write_all_bytes(format!("{}\n", rc_command_line(cmd)).as_bytes())?;
        self.collect(timeout)
    }

    /// Deliver a script line-by-line (linted first), assembled on the
    /// device via `echo '...' >> /tmp/conwrt-deploy.sh`, then run it with
    /// `sh` and collect the RC marker. Long single lines never hit the
    /// tty line buffer because every delivered line is short.
    ///
    /// # Errors
    /// [`ConsoleError::Lint`] when the script is refused; transport
    /// failures that recovery could not paper over.
    pub fn send_script(
        &mut self,
        lines: &[impl AsRef<str>],
        timeout: Duration,
    ) -> Result<crate::collect::CmdOutcome, ConsoleError> {
        lint_script(lines)?;
        self.port.reset_input_buffer();
        self.port.write_all_bytes(b"\n")?;
        self.sleeper.sleep(self.timing.pre_command_settle);
        self.port.reset_input_buffer();
        self.port
            .write_all_bytes(format!("{}\n", rm_deploy_line()).as_bytes())?;
        self.sleeper.sleep(self.timing.script_init_wait);
        for line in lines {
            let line = line.as_ref();
            if is_skippable_line(line) {
                continue;
            }
            self.port
                .write_all_bytes(format!("{}\n", echo_append_line(line)).as_bytes())?;
            self.sleeper.sleep(self.timing.script_line_gap);
        }
        self.port
            .write_all_bytes(format!("{}\n", sh_runner_line()).as_bytes())?;
        self.collect(timeout)
    }

    /// [`SerialConsole::send_script`] over a file's lines (Python
    /// `send_script_file`). Splits on `\n` (stripping a trailing `\r`),
    /// which covers shell scripts; Python's `splitlines()` also splits
    /// exotic Unicode line breaks that carry no meaning in `/bin/sh`.
    ///
    /// # Errors
    /// [`ConsoleError::ScriptFile`] when the file cannot be read; then as
    /// [`SerialConsole::send_script`].
    pub fn send_script_file(
        &mut self,
        path: &Path,
        timeout: Duration,
    ) -> Result<crate::collect::CmdOutcome, ConsoleError> {
        let content = std::fs::read_to_string(path).map_err(|source| ConsoleError::ScriptFile {
            path: path.display().to_string(),
            source,
        })?;
        let lines: Vec<String> = content.lines().map(str::to_owned).collect();
        self.send_script(&lines, timeout)
    }

    /// The `_collect` loop, Python parity:
    ///
    /// * deadline checked before every read; expiry ⇒ `rc = 2`,
    /// * read error ⇒ break recovery, deadline NOT extended,
    /// * chunk starting with [`BREAK_BYTE`] ⇒ break recovery, deadline
    ///   RESTARTED (the device is rebooting — fresh window),
    /// * marker ⇒ settle, one drain read (errors propagate — Python does
    ///   not guard that read), finish.
    fn collect(&mut self, timeout: Duration) -> Result<crate::collect::CmdOutcome, ConsoleError> {
        let mut collector = Collector::new();
        let mut deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Ok(collector.expire());
            }
            let mut buf = [0u8; READ_CHUNK];
            let outcome = match self.port.read(&mut buf) {
                Err(_) => ReadOutcome::Error,
                Ok(0) => ReadOutcome::Data(&[]),
                Ok(n) => {
                    if buf[0] == BREAK_BYTE {
                        ReadOutcome::Break
                    } else {
                        ReadOutcome::Data(&buf[..n])
                    }
                }
            };
            match collector.feed(outcome) {
                CollectStep::Reading => {}
                CollectStep::Recover(recovery) => {
                    self.reopen_after_break()?;
                    if matches!(recovery, Recovery::BreakByte) {
                        deadline = Instant::now() + timeout;
                    }
                }
                CollectStep::MarkerHit(marker) => {
                    self.sleeper.sleep(self.timing.marker_drain_wait);
                    let mut drain = [0u8; READ_CHUNK];
                    let n = self.port.read(&mut drain)?;
                    return Ok(collector.finish(marker, &drain[..n]));
                }
            }
        }
    }

    /// FT232R break recovery (AGENTS.md "UART Break Recovery"): close the
    /// port — this resets the adapter's wedged internal state — wait out
    /// the device's boot, reopen FRESH, flush stale input.
    ///
    /// # Errors
    /// The reopen failure propagates: Python's `_reopen_after_break` let
    /// `open_serial` exceptions escape `run()` too.
    pub(crate) fn reopen_after_break(&mut self) -> Result<(), ConsoleError> {
        self.port.close();
        self.sleeper.sleep(self.timing.break_recover_wait);
        self.port = self.opener.open()?;
        self.port.reset_input_buffer();
        Ok(())
    }

    /// Paced raw line write for crate-internal bulk drivers (the base64
    /// flash chunk loop): the line goes out verbatim with `\r\n` (no RC
    /// marker, no collection — Python `serial-flash.py`'s per-chunk
    /// `echo '...' >> file` pacing), then one recovery-classified drain
    /// read: a read error or a chunk starting with [`BREAK_BYTE`] runs
    /// the same break recovery as [`SerialConsole::run`].
    ///
    /// # Errors
    /// [`ConsoleError::Io`] on write; recovery reopen failures propagate.
    pub(crate) fn send_paced_line(
        &mut self,
        line: &str,
        gap: Duration,
    ) -> Result<(), ConsoleError> {
        self.port
            .write_all_bytes(format!("{line}\r\n").as_bytes())?;
        self.sleeper.sleep(gap);
        let mut buf = [0u8; READ_CHUNK];
        match self.port.read(&mut buf) {
            Err(_) => self.reopen_after_break()?,
            Ok(n) if n > 0 && buf[0] == BREAK_BYTE => self.reopen_after_break()?,
            _ => {}
        }
        Ok(())
    }

    /// Raw byte write with no pacing, no marker, no collection — the
    /// trigger channel for commands whose output belongs to a LATER
    /// collection (`sysupgrade -n /tmp/fw.bin` deliberately never waits).
    ///
    /// # Errors
    /// [`ConsoleError::Io`] when the write fails.
    pub(crate) fn write_raw(&mut self, data: &[u8]) -> Result<(), ConsoleError> {
        self.port.write_all_bytes(data).map_err(ConsoleError::Io)
    }

    /// Marker-free command collection for streams whose output would
    /// swallow (or echo) an RC tail: the command goes out verbatim and
    /// chunks are collected until `enough` says stop, `quiet` of no
    /// NEW data passes after first output (the Python read-until-prompt
    /// intent: a truncated stream ends at its silence, not at the whole
    /// deadline), or `timeout` expires. Every read is #412
    /// recovery-classified (read error or break chunk ⇒ close → wait →
    /// reopen; the deadline keeps ticking). The echoed command line is
    /// part of the returned text — callers filter (the marker collector
    /// cannot serve big echoing streams: the echoed `__RC0__` tail ends
    /// collection immediately).
    ///
    /// # Errors
    /// [`ConsoleError::Io`] on write; recovery reopen failures
    /// propagate.
    pub(crate) fn run_raw_collect(
        &mut self,
        cmd: &str,
        timeout: Duration,
        quiet: Duration,
        enough: &mut dyn FnMut(&str) -> bool,
    ) -> Result<String, ConsoleError> {
        self.port.write_all_bytes(format!("{cmd}\r\n").as_bytes())?;
        let deadline = Instant::now() + timeout;
        let mut collected = String::new();
        let mut last_data = Instant::now();
        loop {
            if Instant::now() >= deadline {
                return Ok(collected);
            }
            let mut buf = [0u8; READ_CHUNK];
            match self.port.read(&mut buf) {
                Err(_) => self.reopen_after_break()?,
                Ok(0) => {
                    // a truncated stream ends at its own silence, not
                    // at the whole deadline (Python read-until-prompt)
                    if !collected.is_empty() && last_data.elapsed() > quiet {
                        return Ok(collected);
                    }
                }
                Ok(n) if n > 0 && buf[0] == crate::collect::BREAK_BYTE => {
                    self.reopen_after_break()?;
                }
                Ok(n) => {
                    last_data = Instant::now();
                    collected.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if enough(&collected) {
                        return Ok(collected);
                    }
                }
            }
        }
    }
}
