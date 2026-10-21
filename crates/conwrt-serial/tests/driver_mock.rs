//! Driver semantics over scripted mock ports — no hardware, no real
//! sleeps for the wire/cadence pins; REAL clock only where the deadline
//! reset behavior itself is under test.
//!
//! Pins, 1:1 with `tests/test_serial_transport.py` plus the mock-only
//! deadline distinctions the Python suite could not express:
//!
//! * wire bytes of `run`/`send_script` (byte-exact),
//! * sleep cadence (which waits fire, in order),
//! * break byte ⇒ close → wait → reopen → flush, deadline RESTARTED,
//! * read error ⇒ same recovery, deadline NOT restarted,
//! * failed reopen propagates (Python: exception out of `_reopen_after_break`),
//! * lint rejection happens before any write.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use conwrt_serial::collect::{CollectStep, ReadOutcome, Recovery};
use conwrt_serial::{
    CmdOutcome, Collector, ConsoleError, ConsoleIo, ConsoleTiming, Marker, PortOpener,
    SerialConsole, Sleeper,
};

/// One scripted read step for [`MockPort`]. `Sleep` advances the REAL
/// clock (deadline tests need actual time passage) without inventing data.
enum Step {
    Data(Vec<u8>),
    Err(io::Error),
    Sleep(Duration),
}

#[derive(Default)]
struct Log {
    writes: Vec<Vec<u8>>,
    resets: usize,
    closes: usize,
    opens: usize,
    sleeps: Vec<Duration>,
}

struct MockPort {
    log: Arc<Mutex<Log>>,
    steps: VecDeque<Step>,
}

impl ConsoleIo for MockPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.steps.pop_front() {
                None => return Ok(0), // script exhausted: silence
                Some(Step::Sleep(d)) => std::thread::sleep(d),
                Some(Step::Err(e)) => return Err(e),
                Some(Step::Data(v)) => {
                    let n = v.len().min(buf.len());
                    buf[..n].copy_from_slice(&v[..n]);
                    return Ok(n);
                }
            }
        }
    }

    fn write_all_bytes(&mut self, data: &[u8]) -> io::Result<()> {
        self.log.lock().unwrap().writes.push(data.to_vec());
        Ok(())
    }

    fn reset_input_buffer(&mut self) {
        self.log.lock().unwrap().resets += 1;
    }

    fn close(&mut self) {
        self.log.lock().unwrap().closes += 1;
    }
}

/// Opens the scripted ports in order; optionally fails once the scripts
/// run out (models a reopen against a vanished device).
struct MockOpener {
    log: Arc<Mutex<Log>>,
    scripts: Mutex<VecDeque<Vec<Step>>>,
    fail_when_exhausted: bool,
}

impl PortOpener for MockOpener {
    fn open(&mut self) -> Result<Box<dyn ConsoleIo>, ConsoleError> {
        self.log.lock().unwrap().opens += 1;
        let next = self.scripts.lock().unwrap().pop_front();
        match next {
            Some(steps) => Ok(Box::new(MockPort {
                log: Arc::clone(&self.log),
                steps: VecDeque::from(steps),
            })),
            None if self.fail_when_exhausted => Err(ConsoleError::Io(io::Error::other(
                "mock: device gone (reopen refused)",
            ))),
            None => Ok(Box::new(MockPort {
                log: Arc::clone(&self.log),
                steps: VecDeque::new(),
            })),
        }
    }
}

struct RecordSleeper(Arc<Mutex<Log>>);

impl Sleeper for RecordSleeper {
    fn sleep(&self, duration: Duration) {
        self.0.lock().unwrap().sleeps.push(duration);
    }
}

fn timing(tiny_wait: Duration) -> ConsoleTiming {
    ConsoleTiming {
        read_timeout: Duration::from_millis(1),
        break_recover_wait: Duration::from_millis(5),
        activate_wait: tiny_wait,
        pre_command_settle: Duration::from_millis(2),
        marker_drain_wait: Duration::from_millis(2),
        script_line_gap: Duration::from_millis(2),
        script_init_wait: Duration::from_millis(2),
    }
}

fn console(
    scripts: Vec<Vec<Step>>,
    fail_when_exhausted: bool,
) -> (SerialConsole<RecordSleeper, MockOpener>, Arc<Mutex<Log>>) {
    let log = Arc::new(Mutex::new(Log::default()));
    let opener = MockOpener {
        log: Arc::clone(&log),
        scripts: Mutex::new(VecDeque::from(scripts)),
        fail_when_exhausted,
    };
    let sleeper = RecordSleeper(Arc::clone(&log));
    let console = SerialConsole::new(opener, timing(Duration::from_millis(2)), sleeper).unwrap();
    (console, log)
}

fn data(bytes: &[u8]) -> Step {
    Step::Data(bytes.to_vec())
}

fn run_ok_marker() -> Vec<Step> {
    vec![data(b"__RC0__\r\n"), data(b"tail\r\n")]
}

#[test]
fn run_delivers_single_command_and_collects_rc_ok() {
    let (mut c, log) = console(vec![run_ok_marker()], false);
    let out = c.run("true", Duration::from_millis(500)).unwrap();
    assert_eq!(out.rc, 0);
    assert!(out.output.contains("__RC0__"));
    assert!(out.output.contains("tail"));
    let log = log.lock().unwrap();
    // byte-exact wire: activate Enter, then the RC-tailed command
    assert_eq!(log.writes[0], b"\n");
    assert_eq!(log.writes[1], b"true && echo __RC0__ || echo __RC1__\n");
    assert_eq!(log.writes.len(), 2);
    // command-FIFO gate: flush before Enter AND before the command
    assert_eq!(log.resets, 2);
    assert!(log.sleeps.contains(&Duration::from_millis(2)));
}

#[test]
fn run_collects_rc_fail() {
    let (mut c, _log) = console(vec![vec![data(b"__RC1__\r\n")]], false);
    let out = c.run("false", Duration::from_millis(500)).unwrap();
    assert_eq!(out.rc, 1);
    assert!(out.output.contains("__RC1__"));
}

#[test]
fn run_times_out_with_rc_2_when_device_silent() {
    let (mut c, _log) = console(vec![vec![]], false);
    let start = Instant::now();
    let out = c.run("true", Duration::from_millis(60)).unwrap();
    assert_eq!(out.rc, 2);
    assert_eq!(out.output, "");
    assert!(start.elapsed() >= Duration::from_millis(60));
}

#[test]
fn run_rejects_multiline_command_before_any_write() {
    let (mut c, log) = console(vec![vec![]], false);
    let err = c.run("a\nb", Duration::from_millis(50)).unwrap_err();
    assert!(matches!(err, ConsoleError::MultiLineCommand));
    assert!(log.lock().unwrap().writes.is_empty());
}

#[test]
fn activate_sends_newline_waits_and_reads_banner() {
    let (mut c, log) = console(
        vec![vec![data(b"BusyBox v1.36 built-in shell (ash)\r\n")]],
        false,
    );
    let banner = c.activate().unwrap();
    assert!(banner.contains("BusyBox v1.36"));
    let log = log.lock().unwrap();
    assert_eq!(log.writes, vec![b"\n".to_vec()]);
    assert!(log.sleeps.contains(&Duration::from_millis(2))); // activate_wait
}

#[test]
fn break_byte_triggers_close_wait_reopen_and_deadline_restart() {
    // Real clock: the initial port burns most of the budget, then breaks;
    // after recovery the marker arrives AFTER the original deadline would
    // have expired — only the documented deadline RESTART completes it.
    let (mut c, log) = console(
        vec![
            vec![
                Step::Sleep(Duration::from_millis(100)),
                data(b"\x00"), // UART break signature
            ],
            vec![
                Step::Sleep(Duration::from_millis(80)),
                data(b"partial boot output"), // forces a loop-top deadline check > t0+120ms
                data(b"__RC0__\r\n"),
                data(b""),
            ],
        ],
        false,
    );
    let out = c.run("true", Duration::from_millis(120)).unwrap();
    assert_eq!(out.rc, 0, "deadline must restart after a break byte");
    assert!(out.output.contains("__RC0__"));
    assert!(out.output.contains("partial boot output"));
    let log = log.lock().unwrap();
    assert_eq!(log.opens, 2, "reopen must have run");
    assert_eq!(log.closes, 1);
    assert!(log.sleeps.contains(&Duration::from_millis(5))); // break_recover_wait
}

#[test]
fn io_error_triggers_recovery_but_deadline_keeps_ticking() {
    // Symmetric to the break test: same post-recovery marker timing, but
    // the trigger is a read ERROR — no restart, so the SAME script that
    // completed above must now expire.
    let (mut c, log) = console(
        vec![
            vec![
                Step::Sleep(Duration::from_millis(100)),
                Step::Err(io::Error::other("EIO: master vanished")),
            ],
            vec![
                Step::Sleep(Duration::from_millis(80)),
                data(b"partial boot output"),
                data(b"__RC0__\r\n"),
            ],
        ],
        false,
    );
    let out = c.run("true", Duration::from_millis(120)).unwrap();
    assert_eq!(out.rc, 2, "io-error recovery must NOT restart the deadline");
    assert!(!out.output.contains("__RC0__"));
    let log = log.lock().unwrap();
    assert_eq!(log.opens, 2, "recovery must still have run");
}

#[test]
fn failed_reopen_propagates_out_of_run() {
    // Python parity: _reopen_after_break lets open_serial's exception
    // escape run(). Here: read error, then the device is GONE.
    let (mut c, _log) = console(vec![vec![Step::Err(io::Error::other("EIO"))]], true);
    let err = c.run("true", Duration::from_millis(500)).unwrap_err();
    assert!(
        err.to_string().contains("mock: device gone"),
        "reopen failure must propagate, got: {err}"
    );
}

#[test]
fn send_script_delivers_line_chunks_via_echo_append() {
    let (mut c, log) = console(vec![run_ok_marker()], false);
    let out = c
        .send_script(&["# a comment", "touch /tmp/x"], Duration::from_millis(500))
        .unwrap();
    assert_eq!(out.rc, 0);
    assert!(out.output.contains("__RC0__"));
    let log = log.lock().unwrap();
    assert_eq!(
        log.writes,
        vec![
            b"\n".to_vec(),
            b"rm -f /tmp/conwrt-deploy.sh\n".to_vec(),
            b"echo 'touch /tmp/x' >> /tmp/conwrt-deploy.sh\n".to_vec(),
            b"sh /tmp/conwrt-deploy.sh && echo __RC0__ || echo __RC1__\n".to_vec(),
        ]
    );
}

#[test]
fn send_script_lint_rejection_precedes_any_write() {
    let (mut c, log) = console(vec![vec![]], false);
    let err = c
        .send_script(&["echo '$HOME'"], Duration::from_millis(50))
        .unwrap_err();
    assert!(matches!(err, ConsoleError::Lint(_)));
    assert!(log.lock().unwrap().writes.is_empty());
}

#[test]
fn collector_classification_boundary_matches_python() {
    // The driver classifies "non-empty chunk starting with 0x00" as Break;
    // pin the equivalent Collector decision table the driver relies on.
    let mut c = Collector::new();
    assert_eq!(c.feed(ReadOutcome::Data(b"\x00")), CollectStep::Reading);
    let mut c = Collector::new();
    assert_eq!(
        c.feed(ReadOutcome::Break),
        CollectStep::Recover(Recovery::BreakByte)
    );
    let mut c = Collector::new();
    assert_eq!(
        c.feed(ReadOutcome::Error),
        CollectStep::Recover(Recovery::IoError)
    );
    let mut c = Collector::new();
    assert_eq!(
        c.feed(ReadOutcome::Data(b"ok __RC1__")),
        CollectStep::MarkerHit(Marker::Fail)
    );
    let finished: CmdOutcome = Collector::new().expire();
    assert_eq!(finished.rc, 2);
}
