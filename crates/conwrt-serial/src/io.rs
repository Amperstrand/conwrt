//! Transport seam: one trait over local serial ports and TCP console
//! bridges.
//!
//! [`ConsoleIo`] is the surface `scripts/serial_transport.py` actually used
//! from pyserial — read / write / `reset_input_buffer` / close — so the
//! break-recovery driver ([`crate::console`]) treats a local FT232R and a
//! remote bridge identically: both surface "wedged" as a read error and
//! both are reopened by re-running the opener.
//!
//! Two implementations:
//!
//! * [`SerialPortIo`] — a local `/dev` path via `serialport-rs` (8N1, read
//!   timeout; parity of pyserial's `serial.Serial`).
//! * [`TcpIo`] — `tcp://HOST:PORT` via a std socket to the serial-console
//!   bridge (`scripts/conwrt_serial_bridge.py` on the bench exporter, or
//!   labgrid's `NetworkSerialPort`): raw bidirectional relay, no
//!   negotiation. Baud is a property of the remote line and is ignored.
//!   EOF and socket errors surface as read errors so the recovery path
//!   treats a dropped bridge exactly like a wedged local adapter.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use serialport::{ClearBuffer, DataBits, FlowControl, Parity, StopBits};
use thiserror::Error;

use crate::lint::LintError;

/// `tcp://` port-spec prefix.
pub const TCP_PREFIX: &str = "tcp://";

/// Everything that can go wrong on the console path, typed. Messages are
/// safe to print to an operator (the Python module's rule: never a raw
/// traceback) — notably [`ConsoleError::Connect`] tells the operator how to
/// forward the bridge port.
#[derive(Debug, Error)]
pub enum ConsoleError {
    /// The script was refused by the serial-channel linter.
    #[error(transparent)]
    Lint(#[from] LintError),
    /// A `tcp://` endpoint could not be connected (refused / timeout /
    /// unreachable), or the local device could not be opened.
    #[error(
        "cannot connect to {endpoint}: {source} — is the serial bridge running and \
         forwarded? (Mac access: ssh -N -L {port}:127.0.0.1:{port} ai-legion)"
    )]
    Connect {
        /// The full `tcp://HOST:PORT` endpoint that failed.
        endpoint: String,
        /// The remote TCP port (for the operator's forward command).
        port: u16,
        /// The underlying connect failure.
        #[source]
        source: io::Error,
    },
    /// The endpoint has no `HOST:PORT` split (or an empty host).
    #[error("invalid endpoint {spec:?} — expected tcp://HOST:PORT")]
    InvalidEndpoint {
        /// The offending port spec.
        spec: String,
    },
    /// The port component is not a number.
    #[error("invalid port {port_str:?} in {spec:?} — expected tcp://HOST:PORT")]
    InvalidPort {
        /// The non-numeric port string.
        port_str: String,
        /// The offending port spec.
        spec: String,
    },
    /// The port number is outside `1..=65535`.
    #[error("port {port} out of range in {spec:?}")]
    PortOutOfRange {
        /// The parsed (but out-of-range) port number.
        port: i64,
        /// The offending port spec.
        spec: String,
    },
    /// The local `/dev` port could not be opened or configured.
    #[error("cannot open serial port {path}: {source}")]
    OpenDevice {
        /// The device path that failed.
        path: String,
        /// The underlying open/configure failure.
        #[source]
        source: serialport::Error,
    },
    /// A read/write against an open transport failed (outside the
    /// recovery-managed read loop — e.g. a command write, or the
    /// post-marker drain read).
    #[error(transparent)]
    Io(#[from] io::Error),
    /// `run` was given a multi-line command — the API takes exactly one.
    #[error("run() takes a single command (no newlines)")]
    MultiLineCommand,
    /// The script file could not be read.
    #[error("cannot read script file {path}: {source}")]
    ScriptFile {
        /// The file path that failed.
        path: String,
        /// The underlying read failure.
        #[source]
        source: io::Error,
    },
}

/// Split `tcp://HOST:PORT` into `(host, port)`; typed errors when
/// malformed (parity of Python's `parse_tcp_endpoint`). IPv6 hosts may be
/// bracketed: `tcp://[::1]:4002` → `("::1", 4002)`.
///
/// # Errors
/// [`ConsoleError::InvalidEndpoint`] / [`InvalidPort`] /
/// [`PortOutOfRange`] mirroring the Python messages.
pub fn parse_tcp_endpoint(spec: &str) -> Result<(String, u16), ConsoleError> {
    let endpoint = spec.strip_prefix(TCP_PREFIX).unwrap_or(spec);
    let Some((host, port_str)) = endpoint.rsplit_once(':') else {
        return Err(ConsoleError::InvalidEndpoint {
            spec: spec.to_string(),
        });
    };
    if host.is_empty() {
        return Err(ConsoleError::InvalidEndpoint {
            spec: spec.to_string(),
        });
    }
    let Ok(tcp_port) = port_str.parse::<i64>() else {
        return Err(ConsoleError::InvalidPort {
            port_str: port_str.to_string(),
            spec: spec.to_string(),
        });
    };
    if !(0 < tcp_port && tcp_port < 65536) {
        return Err(ConsoleError::PortOutOfRange {
            port: tcp_port,
            spec: spec.to_string(),
        });
    }
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    Ok((host.to_string(), tcp_port as u16))
}

/// The transport surface the console driver needs (the pyserial subset
/// `scripts/serial_transport.py` actually used).
///
/// `Ok(0)` from [`read`](ConsoleIo::read) means "no data within the read
/// timeout" — NOT end-of-stream. Serial lines have no EOF; a peer that
/// goes away surfaces as an `Err` (both implementations guarantee this).
pub trait ConsoleIo {
    /// Read up to `buf.len()` bytes, blocking at most the transport's read
    /// timeout.
    ///
    /// # Errors
    /// Transport failure — the driver's break-recovery trigger.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write all bytes or fail.
    ///
    /// # Errors
    /// Transport failure. Write errors are NOT recovery-managed by the
    /// collector (Python parity: only read errors trigger `_reopen_after_break`).
    fn write_all_bytes(&mut self, data: &[u8]) -> io::Result<()>;

    /// Drop any pending unread input (pyserial `reset_input_buffer`) —
    /// the "command FIFO" gate: stale replies from previous commands must
    /// never interleave with the next command's collection.
    fn reset_input_buffer(&mut self);

    /// Close the transport. Idempotent; reopening afterwards is the
    /// opener's job, not the transport's.
    fn close(&mut self);
}

/// Open a console transport by port spec (parity of Python's `open_serial`).
///
/// * `tcp://HOST:PORT` → [`TcpIo`] (baud is a property of the remote line
///   and is ignored),
/// * anything else → [`SerialPortIo`] on that `/dev` path, 8N1.
///
/// # Errors
/// [`ConsoleError::Connect`] for a malformed or unreachable `tcp://`
/// endpoint (clean operator-facing message, no traceback);
/// [`ConsoleError::OpenDevice`] when the local port cannot be opened.
/// Open a break-capable console (local serial only — TCP bridges cannot
/// assert a UART break). Recovery/sysrq path.
pub fn open_break_port(
    spec: &str,
    baud: u32,
    timeout: Duration,
) -> Result<Box<dyn crate::recovery::BreakIo>, ConsoleError> {
    if spec.starts_with(TCP_PREFIX) {
        return Err(ConsoleError::Connect {
            endpoint: spec.to_string(),
            port: 0,
            source: std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "sysrq-over-BREAK needs a local serial port; a TCP bridge cannot assert break",
            ),
        });
    }
    Ok(Box::new(SerialPortIo::open(spec, baud, timeout)?))
}

/// Open a break-capable console (local serial; sysrq/BREAK path).
pub fn open_port(
    spec: &str,
    baud: u32,
    timeout: Duration,
) -> Result<Box<dyn ConsoleIo>, ConsoleError> {
    if spec.starts_with(TCP_PREFIX) {
        let (host, port) = parse_tcp_endpoint(spec)?;
        Ok(Box::new(TcpIo::connect(
            &host,
            port,
            timeout,
            DEFAULT_CONNECT_TIMEOUT,
        )?))
    } else {
        Ok(Box::new(SerialPortIo::open(spec, baud, timeout)?))
    }
}

/// TCP connect bound (Python's `connect_timeout=5.0`).
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Local `/dev` serial port via `serialport-rs`, 8N1 with a read timeout
/// (pyserial `serial.Serial` parity). The port is held in an `Option` so
/// [`close`](ConsoleIo::close) releases the fd IMMEDIATELY — serialport
/// sets `TIOCEXCL`, and break recovery reopens the same path while the
/// old handle must already be gone (a lazy drop-on-reassign would reopen
/// into EBUSY).
pub struct SerialPortIo {
    port: Option<Box<dyn serialport::SerialPort>>,
}

impl SerialPortIo {
    /// Open `path` at `baud`, 8N1, no flow control, reads bounded by
    /// `timeout`.
    ///
    /// # Errors
    /// [`ConsoleError::OpenDevice`] when the device cannot be opened or
    /// configured.
    pub fn open(path: &str, baud: u32, timeout: Duration) -> Result<Self, ConsoleError> {
        let port = serialport::new(path, baud)
            .timeout(timeout)
            .data_bits(DataBits::Eight)
            .parity(Parity::None)
            .stop_bits(StopBits::One)
            .flow_control(FlowControl::None)
            .open()
            .map_err(|source| ConsoleError::OpenDevice {
                path: path.to_string(),
                source,
            })?;
        Ok(Self { port: Some(port) })
    }

    fn closed_err(path: &str) -> io::Error {
        io::Error::new(io::ErrorKind::NotConnected, format!("{path} is closed"))
    }
}

impl ConsoleIo for SerialPortIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let port = self
            .port
            .as_mut()
            .ok_or_else(|| Self::closed_err("serial port"))?;
        match port.read(buf) {
            // serialport-rs signals "read timeout, no data" as Ok(0); a
            // TimedOut error kind is translated too, so both semantics
            // land on the trait's Ok(0) contract.
            Ok(n) => Ok(n),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn write_all_bytes(&mut self, data: &[u8]) -> io::Result<()> {
        let port = self
            .port
            .as_mut()
            .ok_or_else(|| Self::closed_err("serial port"))?;
        port.write_all(data)
    }

    fn reset_input_buffer(&mut self) {
        // Best-effort drain (pyserial parity: reset_input_buffer does not
        // report errors); a genuinely wedged port surfaces on the next
        // read, which IS recovery-managed.
        if let Some(port) = self.port.as_mut() {
            let _ = port.clear(ClearBuffer::Input);
        }
    }

    fn close(&mut self) {
        // Drop the handle NOW: TIOCEXCL must be released before a reopen
        // of the same device path (the FT232R recovery depends on it).
        self.port = None;
    }
}

/// A raw TCP console-stream facade over the serial-bridge byte protocol
/// (Python `SerialTCP` parity): no negotiation, no control lines, reads
/// bounded by the read timeout, and — critically — **EOF and socket errors
/// surface as read errors**, so a dropped bridge triggers the same
/// close → 3 s wait → reopen (reconnect) recovery as a wedged FT232R.
pub struct TcpIo {
    stream: Option<TcpStream>,
    host: String,
    port: u16,
    read_timeout: Duration,
}

impl TcpIo {
    /// Connect to `host:port` within `connect_timeout`; `read_timeout`
    /// bounds each [`ConsoleIo::read`].
    ///
    /// # Errors
    /// [`ConsoleError::Connect`] with the operator-facing forward hint.
    pub fn connect(
        host: &str,
        port: u16,
        read_timeout: Duration,
        connect_timeout: Duration,
    ) -> Result<Self, ConsoleError> {
        let connect_err = |source: io::Error| ConsoleError::Connect {
            endpoint: format!("tcp://{host}:{port}"),
            port,
            source,
        };
        // Resolve first: connect_timeout needs SocketAddrs, and a hostname
        // (e.g. `tcp://ai-legion:4002`) must resolve like Python's
        // create_connection did.
        let addrs: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(connect_err)?
            .collect();
        let mut last_err: Option<io::Error> = None;
        let mut stream = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, connect_timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let stream = stream.ok_or_else(|| {
            connect_err(last_err.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved")
            }))
        })?;
        stream
            .set_read_timeout(Some(read_timeout))
            .map_err(connect_err)?;
        Ok(Self {
            stream: Some(stream),
            host: host.to_string(),
            port,
            read_timeout,
        })
    }

    /// `tcp://host:port` for error messages.
    pub fn endpoint(&self) -> String {
        format!("tcp://{}:{}", self.host, self.port)
    }

    fn closed_err(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::NotConnected,
            format!("{} is closed", self.endpoint()),
        )
    }

    fn stream(&self) -> io::Result<&TcpStream> {
        self.stream.as_ref().ok_or_else(|| self.closed_err())
    }
}

impl ConsoleIo for TcpIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut stream = self.stream()?;
        // Re-assert the read timeout each call: the input-buffer drain
        // toggles non-blocking mode, and the timeout must hold afterwards.
        stream.set_read_timeout(Some(self.read_timeout))?;
        match stream.read(buf) {
            // A bridge that closes the connection is a wedged transport,
            // not silence: surface as an error so recovery runs.
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("{}: connection closed by remote bridge", self.endpoint()),
            )),
            Ok(n) => Ok(n),
            // read-timeout expiry on std sockets: silence, not an error.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(0)
            }
            Err(e) => Err(e),
        }
    }

    fn write_all_bytes(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream()?.write_all(data)
    }

    fn reset_input_buffer(&mut self) {
        let Some(stream) = self.stream.as_mut() else {
            return;
        };
        // Best-effort non-blocking drain; a real connection failure
        // surfaces on the next read (Python parity).
        let _ = stream.set_nonblocking(true);
        let mut sink = [0u8; 4096];
        loop {
            match stream.read(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
        let _ = stream.set_nonblocking(false);
    }

    fn close(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl crate::recovery::BreakIo for SerialPortIo {
    fn send_break_for(&mut self, dur: Duration) -> io::Result<()> {
        // serialport-rs: set_break asserts the condition, clear_break ends it.
        // The port is Option<Box<dyn SerialPort>> because close() takes it.
        let port = self
            .port
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "port closed"))?;
        port.set_break().map_err(io::Error::other)?;
        std::thread::sleep(dur);
        port.clear_break().map_err(io::Error::other)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_endpoint_accepts_host_port() {
        assert_eq!(
            parse_tcp_endpoint("tcp://127.0.0.1:4002").unwrap(),
            ("127.0.0.1".to_string(), 4002)
        );
    }

    #[test]
    fn parse_endpoint_accepts_ipv6_brackets() {
        // 1:1 with test_serial_tcp.py::test_parse_tcp_endpoint_accepts_ipv6_brackets
        assert_eq!(
            parse_tcp_endpoint("tcp://[::1]:4002").unwrap(),
            ("::1".to_string(), 4002)
        );
    }

    #[test]
    fn parse_endpoint_rejects_malformed_specs() {
        // 1:1 with test_invalid_endpoints_raise_typed_error parametrize
        for bad in [
            "tcp://host-only",
            "tcp://host:notaport",
            "tcp://host:0",
            "tcp://host:70000",
        ] {
            assert!(parse_tcp_endpoint(bad).is_err(), "{bad} should be rejected");
        }
        assert!(matches!(
            parse_tcp_endpoint("tcp://host-only"),
            Err(ConsoleError::InvalidEndpoint { .. })
        ));
        assert!(matches!(
            parse_tcp_endpoint("tcp://host:notaport"),
            Err(ConsoleError::InvalidPort { .. })
        ));
        assert!(matches!(
            parse_tcp_endpoint("tcp://host:0"),
            Err(ConsoleError::PortOutOfRange { port: 0, .. })
        ));
        assert!(matches!(
            parse_tcp_endpoint("tcp://host:70000"),
            Err(ConsoleError::PortOutOfRange { port: 70000, .. })
        ));
    }

    #[test]
    fn connect_error_carries_forward_hint_and_source_text() {
        // 1:1 with test_refused_connection_raises_typed_error (message
        // shape) + test_connect_timeout_maps_to_typed_error (source text)
        let err = ConsoleError::Connect {
            endpoint: "tcp://127.0.0.1:4002".to_string(),
            port: 4002,
            source: io::Error::new(io::ErrorKind::TimedOut, "timed out"),
        };
        let msg = err.to_string();
        assert!(msg.contains("tcp://127.0.0.1:4002"), "msg: {msg}");
        assert!(msg.contains("ssh -N -L 4002:127.0.0.1:4002"), "msg: {msg}");
        assert!(msg.contains("timed out"), "msg: {msg}");
    }
}
