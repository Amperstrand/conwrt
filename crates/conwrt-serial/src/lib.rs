//! # conwrt-serial
//!
//! Reliable command execution over OpenWrt serial consoles — the Rust port
//! of `scripts/serial_transport.py` (parity-matrix §5).
//!
//! Encodes the lessons from the 2026-09-22 switch recovery (AGENTS.md):
//!
//! * OpenWrt consoles use askfirst: send Enter to activate, then interact.
//! * Long single lines exceed the tty line buffer — deliver scripts
//!   line-by-line, assembled via `echo '...' >> file`, then `sh file`.
//! * Never carry shell variables through the serial channel: single-quoted
//!   payload lines turn `$N` into a literal. The [`lint::lint_script`]
//!   REFUSES scripts containing runtime variable references (generate
//!   literals on the controlling host instead).
//! * FT232R adapters wedge on the UART break when a device power-cycles:
//!   on reading `0x00`, close, wait for the device to boot, reopen fresh
//!   (AGENTS.md "UART Break Recovery" — the spec narrative).
//!
//! # Shape (and why this is its own crate)
//!
//! * The **pure core** — [`lint`] (script linting + wire-line assembly) and
//!   [`collect`] (the marker/break/error collection state machine) — has no
//!   I/O dependencies and is fully testable by injecting bytes and events,
//!   no hardware. Keep it separable: it is the Tier-A-shaped heart even
//!   though this crate is host-std.
//! * [`io`] is the transport seam ([`io::ConsoleIo`]) with two
//!   implementations: a local `/dev` port via `serialport-rs` and a
//!   `tcp://HOST:PORT` console bridge (the byte protocol of
//!   `scripts/conwrt_serial_bridge.py` / labgrid's `NetworkSerialPort`).
//!   A relayed break byte or a dropped bridge connection triggers the same
//!   close → wait → reopen recovery as a wedged local FT232R.
//! * [`console`] is the driver ([`console::SerialConsole`]): `activate`,
//!   `run` (RC-marker command execution), `send_script` (linted line-chunked
//!   delivery). Timing, sleeping, and port opening are injectable so the
//!   driver semantics are testable without hardware.
//!
//! This lives outside `conwrt-protocols` deliberately: that crate is
//! `no_std`-cross-compiled in CI (`--target thumbv7em-none-eabihf`), while
//! this driver is host-std by construction (`serialport-rs`, TCP sockets,
//! threads) — coupling them would contaminate the protocols crate's
//! cross-compile surface for zero shared code.
//!
//! # Tests (ADR-0011 rings)
//!
//! * `tests/lint_collect.rs` + unit tests: the pure core, Python scenarios
//!   ported 1:1 from `tests/test_serial_transport.py`.
//! * `tests/driver_mock.rs`: the driver over scripted mock ports — wire
//!   bytes, sleep cadence, break recovery, deadline reset semantics.
//! * `tests/pty_driver.rs`: the real `serialport-rs` path over a pty pair
//!   (chunked lines, simulated UART break, port-goes-away) — no
//!   `/dev/ttyUSB` needed, and the host's real serial ports are never
//!   touched.
//! * `tests/tcp_driver.rs`: the TCP bridge over a localhost echo server
//!   only (CI rule: no network beyond localhost).

pub mod collect;
pub mod console;
pub mod io;
pub mod lint;

pub use collect::{CmdOutcome, Collector, Marker, RC_FAIL, RC_OK, ReadOutcome};
pub use console::{ConsoleTiming, PortOpener, SerialConsole, Sleeper, SpecOpener, StdSleeper};
pub use io::{ConsoleError, ConsoleIo, open_port, parse_tcp_endpoint};
pub use lint::{LintError, MAX_LINE};
