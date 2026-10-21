//! TCP transport integration over a localhost echo server only (CI rule:
//! no network beyond localhost) — the Rust twin of
//! `tests/test_serial_tcp.py`.
//!
//! Pins: round-trip line, bounded read silence, refused-connection typed
//! error fast (with the operator's forward hint), `run` over the mirrored
//! RC tail, and the stale-state rule — a dropped bridge surfaces as a
//! transport error, and a FRESH invocation opens a FRESH connection and
//! works (no session reuse, Python parity).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use conwrt_serial::{ConsoleError, ConsoleIo, SerialConsole};

/// Local TCP echo server: mirrors bytes back on every connection
/// (`close_after_first` models a bridge that drops its first client after
/// one exchange; later connections get a persistent echo).
struct EchoServer {
    /// Held only to keep the bound socket alive until drop; the accept
    /// loop runs on a cloned listener in a detached thread.
    _listener: TcpListener,
    port: u16,
    accepted: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl EchoServer {
    fn start(close_after_first: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo server");
        let port = listener.local_addr().expect("addr").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        {
            let listener = listener.try_clone().expect("clone listener");
            let accepted = Arc::clone(&accepted);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                listener
                    .set_nonblocking(true)
                    .expect("nonblocking listener");
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((conn, _)) => {
                            let n = accepted.fetch_add(1, Ordering::AcqRel) + 1;
                            let persistent = !(close_after_first && n == 1);
                            thread::spawn(move || serve(conn, persistent));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        Self {
            _listener: listener,
            port,
            accepted,
            stop,
        }
    }

    fn url(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.port)
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        // Flag out the accept loop (it polls non-blocking every 20 ms);
        // dropping the listener then closes the socket.
        self.stop.store(true, Ordering::Release);
    }
}

fn serve(conn: TcpStream, persistent: bool) {
    let mut conn = conn;
    let mut buf = [0u8; 4096];
    loop {
        match conn.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if conn.write_all(&buf[..n]).is_err() {
                    return;
                }
                if !persistent {
                    return; // one exchange, then the bridge drops us
                }
            }
        }
    }
}

/// An ephemeral localhost port with no listener (connection refused).
fn dead_port() -> u16 {
    let s = std::net::TcpListener::bind("127.0.0.1:0").expect("bind dead port");
    let port = s.local_addr().expect("addr").port();
    drop(s);
    port
}

fn tcp_read_until(io: &mut dyn ConsoleIo, needle: &[u8], timeout: Duration) -> Vec<u8> {
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while Instant::now() < deadline && !buf.windows(needle.len()).any(|w| w == needle) {
        match io.read(&mut chunk) {
            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            Err(e) => panic!("read error before {needle:?}: {e}"),
            _ => {}
        }
    }
    assert!(
        buf.windows(needle.len()).any(|w| w == needle),
        "expected {needle:?} over tcp, got {buf:?}"
    );
    buf
}

#[test]
fn connects_and_roundtrips_a_line() {
    let srv = EchoServer::start(false);
    let mut io = conwrt_serial::open_port(&srv.url(), 115_200, Duration::from_millis(200)).unwrap();
    io.write_all_bytes(b"ping\r\n").unwrap();
    let seen = tcp_read_until(io.as_mut(), b"ping\r\n", Duration::from_secs(3));
    assert_eq!(seen, b"ping\r\n");
    io.close();
}

#[test]
fn read_times_out_bounded_when_silent() {
    let srv = EchoServer::start(false);
    let mut io = conwrt_serial::open_port(&srv.url(), 115_200, Duration::from_millis(300)).unwrap();
    let mut buf = [0u8; 4096];
    let start = Instant::now();
    let n = io.read(&mut buf).expect("silent read must be Ok(0)");
    let elapsed = start.elapsed();
    assert_eq!(n, 0);
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(2),
        "read not bounded: {elapsed:?}"
    );
    io.close();
}

#[test]
fn refused_connection_raises_typed_error_fast() {
    let port = dead_port();
    let start = Instant::now();
    let err = conwrt_serial::open_port(
        &format!("tcp://127.0.0.1:{port}"),
        115_200,
        Duration::from_millis(200),
    )
    .map(|_| ())
    .expect_err("refused must error");
    assert!(start.elapsed() < Duration::from_secs(5), "not bounded");
    let msg = err.to_string();
    assert!(msg.contains(&format!("127.0.0.1:{port}")), "msg: {msg}");
    assert!(msg.contains("ssh -N -L"), "msg: {msg}");
    assert!(matches!(err, ConsoleError::Connect { .. }));
}

#[test]
fn run_roundtrips_through_line_chunked_delivery() {
    let srv = EchoServer::start(false);
    let mut console = SerialConsole::open(&srv.url()).unwrap();
    let out = console.run("echo hello", Duration::from_secs(5)).unwrap();
    // the echo server mirrors the command line, whose tail already
    // carries the RC marker — pins that the full round-trip works
    assert_eq!(out.rc, 0, "out: {:?}", out.output);
    assert!(out.output.contains("echo hello"));
    console.close();
}

#[test]
fn bridge_drop_surfaces_as_transport_error_then_fresh_invocation() {
    let srv = EchoServer::start(true);
    let mut io = conwrt_serial::open_port(&srv.url(), 115_200, Duration::from_millis(200)).unwrap();
    io.write_all_bytes(b"first\n").unwrap();
    tcp_read_until(io.as_mut(), b"first\n", Duration::from_secs(3));
    // the bridge drops us after one exchange: reads must surface an error
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_error = false;
    while Instant::now() < deadline {
        if io.read(&mut buf).is_err() {
            saw_error = true;
            break;
        }
    }
    assert!(saw_error, "dropped bridge must surface as read error");
    io.close();

    // stale-state rule: a NEW invocation opens a NEW connection and works
    let mut console = SerialConsole::open(&srv.url()).unwrap();
    let start = Instant::now();
    while Instant::now() - start < Duration::from_secs(3)
        && srv.accepted.load(Ordering::Acquire) < 2
    {
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(srv.accepted.load(Ordering::Acquire), 2);
    let out = console.run("echo again", Duration::from_secs(5)).unwrap();
    assert_eq!(out.rc, 0, "out: {:?}", out.output);
    assert!(out.output.contains("echo again"));
    console.close();
}
