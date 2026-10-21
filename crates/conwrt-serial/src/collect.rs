//! The collection state machine (pure — no I/O, no clock).
//!
//! [`Collector`] is the heart of `SerialConsole._collect` from
//! `scripts/serial_transport.py`, factored so every decision is testable by
//! injecting bytes and events:
//!
//! * `__RC0__` in the buffer ⇒ command succeeded (`rc = 0`),
//! * `__RC1__` ⇒ failed (`rc = 1`) — if both markers are present, success
//!   wins (Python checks `RC_OK` first),
//! * a read **error** ⇒ FT232R/bridge recovery (close → 3 s wait →
//!   reopen → flush input); the collect deadline keeps ticking,
//! * a chunk whose **first byte is `0x00`** ⇒ the UART-break signature ⇒
//!   the same recovery AND the collect deadline restarts (the device is
//!   rebooting; give it a fresh window),
//! * deadline expiry ⇒ `rc = 2` (timeout) with whatever output arrived.
//!
//! The driver ([`crate::console::SerialConsole`]) owns the port, the clock,
//! and the sleeps; this module only decides *what to do next*.

/// Success marker echoed by the RC tail (`&& echo __RC0__`).
pub const RC_OK: &str = "__RC0__";

/// Failure marker echoed by the RC tail (`|| echo __RC1__`).
pub const RC_FAIL: &str = "__RC1__";

/// The UART-break signature: the FT232R surfaces a device power-cycle as
/// sustained low = a stream of `0x00` bytes with framing errors; the first
/// one is the trigger (AGENTS.md "UART Break Recovery").
pub const BREAK_BYTE: u8 = 0x00;

/// Read size per collection step (Python reads 4096 per iteration).
pub const READ_CHUNK: usize = 4096;

/// The RC-marker tail appended to every command line: the device echoes
/// exactly one of the markers back, which is how `rc` is learned over a
/// byte stream with no exit-status channel.
pub fn rc_command_line(cmd: &str) -> String {
    format!("{cmd} && echo {RC_OK} || echo {RC_FAIL}")
}

/// One read result, classified the way `scripts/serial_transport.py`'s
/// `_collect` classifies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome<'a> {
    /// A chunk of console output (possibly empty — read timeout with no
    /// data). Only a chunk that is non-empty AND starts with
    /// [`BREAK_BYTE`] is a [`ReadOutcome::Break`].
    Data(&'a [u8]),
    /// The chunk began with [`BREAK_BYTE`]: the whole chunk is discarded
    /// (the adapter is wedged — its bytes are garbage).
    Break,
    /// The transport read failed (wedged local adapter, dropped bridge).
    Error,
}

/// Why the driver must run the close → wait → reopen → flush recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// Break byte seen: recovery **and the collect deadline restarts** —
    /// the device is power-cycling and needs a fresh window.
    BreakByte,
    /// I/O error: recovery only — the deadline keeps ticking (a bridge
    /// flap should not extend the command's timeout budget).
    IoError,
}

/// Which RC marker was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// `__RC0__` — command succeeded.
    Ok,
    /// `__RC1__` — command failed.
    Fail,
}

/// What the driver should do after feeding one [`ReadOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectStep {
    /// Keep reading (deadline unchanged).
    Reading,
    /// Run break recovery; restart the deadline only for
    /// [`Recovery::BreakByte`].
    Recover(Recovery),
    /// Marker seen: wait the drain interval, perform one more read, then
    /// [`Collector::finish`] with those drained bytes.
    MarkerHit(Marker),
}

/// One command result, mirroring Python's `(rc, output)` tuple:
/// `rc` is `0` (marker `__RC0__`), `1` (marker `__RC1__`), or `2`
/// (collect deadline expired — device silent). `output` is the collected
/// console output, UTF-8-lossily decoded with `\r` stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutcome {
    /// 0 = success marker, 1 = failure marker, 2 = timeout.
    pub rc: u8,
    /// Collected (and `\r`-stripped) console output.
    pub output: String,
}

/// Decode collected bytes for the caller: UTF-8 lossy (Python
/// `errors="replace"`) with `\r` stripped.
fn render(buf: &[u8]) -> String {
    String::from_utf8_lossy(buf).replace('\r', "")
}

/// The pure output-collecting state machine (see module docs).
///
/// Feed it classified read outcomes; it never touches a port or a clock.
#[derive(Debug, Default, Clone)]
pub struct Collector {
    buf: Vec<u8>,
}

impl Collector {
    /// New empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one classified read outcome; returns the next driver step.
    ///
    /// Marker check order matches Python: `RC_OK` before `RC_FAIL` — a
    /// buffer containing both resolves as success.
    pub fn feed(&mut self, outcome: ReadOutcome<'_>) -> CollectStep {
        match outcome {
            ReadOutcome::Error => return CollectStep::Recover(Recovery::IoError),
            ReadOutcome::Break => return CollectStep::Recover(Recovery::BreakByte),
            ReadOutcome::Data(chunk) => {
                if !chunk.is_empty() {
                    self.buf.extend_from_slice(chunk);
                }
            }
        }
        if find_subslice(&self.buf, RC_OK.as_bytes()).is_some() {
            return CollectStep::MarkerHit(Marker::Ok);
        }
        if find_subslice(&self.buf, RC_FAIL.as_bytes()).is_some() {
            return CollectStep::MarkerHit(Marker::Fail);
        }
        CollectStep::Reading
    }

    /// Complete after a marker hit: append the post-marker drain bytes,
    /// decode, strip `\r`, and set `rc` per the marker.
    #[must_use]
    pub fn finish(mut self, marker: Marker, drained: &[u8]) -> CmdOutcome {
        self.buf.extend_from_slice(drained);
        let rc = match marker {
            Marker::Ok => 0,
            Marker::Fail => 1,
        };
        CmdOutcome {
            rc,
            output: render(&self.buf),
        }
    }

    /// Complete on deadline expiry: `rc = 2` with whatever arrived.
    #[must_use]
    pub fn expire(self) -> CmdOutcome {
        CmdOutcome {
            rc: 2,
            output: render(&self.buf),
        }
    }

    /// The raw undecoded buffer so far (diagnostics; also lets tests pin
    /// exactly which bytes were kept vs. discarded).
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }
}

/// Byte-substring search (`needle in haystack`, Python semantics — not
/// UTF-8-aware). The markers are ASCII, so boundaries are safe.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(chunk: &[u8]) -> ReadOutcome<'_> {
        ReadOutcome::Data(chunk)
    }

    #[test]
    fn rc_command_line_is_byte_exact() {
        assert_eq!(
            rc_command_line("true"),
            "true && echo __RC0__ || echo __RC1__"
        );
    }

    #[test]
    fn rc_ok_marker_hits() {
        let mut c = Collector::new();
        assert_eq!(
            c.feed(data(b"boot noise\r\n__RC0__\r\n")),
            CollectStep::MarkerHit(Marker::Ok)
        );
    }

    #[test]
    fn rc_fail_marker_hits() {
        let mut c = Collector::new();
        assert_eq!(
            c.feed(data(b"__RC1__\r\n")),
            CollectStep::MarkerHit(Marker::Fail)
        );
    }

    #[test]
    fn both_markers_success_wins() {
        // Python checks RC_OK first: a buffer holding both resolves as 0.
        let mut c = Collector::new();
        assert_eq!(
            c.feed(data(b"__RC1__ __RC0__")),
            CollectStep::MarkerHit(Marker::Ok)
        );
    }

    #[test]
    fn marker_split_across_chunks_is_found() {
        let mut c = Collector::new();
        assert_eq!(c.feed(data(b"__RC")), CollectStep::Reading);
        assert_eq!(
            c.feed(data(b"0__ tail")),
            CollectStep::MarkerHit(Marker::Ok)
        );
    }

    #[test]
    fn empty_chunk_keeps_reading() {
        let mut c = Collector::new();
        assert_eq!(c.feed(data(b"")), CollectStep::Reading);
        assert_eq!(c.feed(data(b"still no marker")), CollectStep::Reading);
    }

    #[test]
    fn break_byte_chunk_is_discarded_and_demands_recovery() {
        let mut c = Collector::new();
        c.feed(data(b"boot"));
        assert_eq!(
            c.feed(ReadOutcome::Break),
            CollectStep::Recover(Recovery::BreakByte)
        );
        // the break chunk carried a marker after the 0x00 — it is GONE
        // (Python drops the whole chunk; markers never see it)
        let mut c2 = Collector::new();
        assert_eq!(
            c2.feed(data(b"\x00__RC0__")),
            CollectStep::MarkerHit(Marker::Ok)
        );
        // ^ NB: this is the DRIVER's classification boundary — a chunk
        // starting with 0x00 is fed as Break, never as Data. This test
        // documents that when fed as Data, marker logic WOULD fire; the
        // driver-level tests pin the classification.
    }

    #[test]
    fn nul_at_nonzero_position_is_plain_data() {
        let mut c = Collector::new();
        assert_eq!(c.feed(data(b"a\x00b")), CollectStep::Reading);
        assert_eq!(c.buffer(), b"a\x00b");
    }

    #[test]
    fn io_error_demands_recovery_without_break_priority() {
        let mut c = Collector::new();
        assert_eq!(
            c.feed(ReadOutcome::Error),
            CollectStep::Recover(Recovery::IoError)
        );
    }

    #[test]
    fn break_recovery_preserves_buffered_output() {
        let mut c = Collector::new();
        c.feed(data(b"early output\r\n"));
        c.feed(ReadOutcome::Break);
        // post-recovery the buffer still carries pre-break bytes
        assert_eq!(c.buffer(), b"early output\r\n");
    }

    #[test]
    fn finish_appends_drain_and_strips_cr() {
        let mut c = Collector::new();
        c.feed(data(b"__RC0__"));
        let out = c.finish(Marker::Ok, b"\r\nmore\r\n");
        assert_eq!(out.rc, 0);
        assert_eq!(out.output, "__RC0__\nmore\n");
    }

    #[test]
    fn expire_returns_rc2_and_strips_cr() {
        let mut c = Collector::new();
        c.feed(data(b"partial\r\n"));
        let out = c.expire();
        assert_eq!(out.rc, 2);
        assert_eq!(out.output, "partial\n");
    }

    #[test]
    fn invalid_utf8_decodes_lossily() {
        let mut c = Collector::new();
        c.feed(data(b"\xff\xfe__RC0__"));
        let out = c.finish(Marker::Ok, b"");
        assert_eq!(out.rc, 0);
        assert!(
            out.output.contains('\u{fffd}'),
            "expected replacement char in {:?}",
            out.output
        );
        assert!(out.output.contains("__RC0__"));
    }

    #[test]
    fn marker_bytes_split_around_break_chunk_boundaries() {
        // "__RC" buffered, then a break chunk, then "0__": the break chunk
        // is dropped entirely — the split marker never completes from it.
        let mut c = Collector::new();
        c.feed(data(b"__RC"));
        assert_eq!(
            c.feed(ReadOutcome::Break),
            CollectStep::Recover(Recovery::BreakByte)
        );
        assert_eq!(c.feed(data(b"0__")), CollectStep::MarkerHit(Marker::Ok));
    }
}
