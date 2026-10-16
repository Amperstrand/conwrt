//! Deterministic lossy localhost proxy for the ring-2 HIL experiments
//! (#226 resume-under-churn): sits between the executor pump (client)
//! and the one-request recovery mock (upstream), forwarding both
//! directions while dropping or delaying WRITE (client→mock) traffic
//! at configured points.
//!
//! Determinism rules:
//!
//! - the upstream is dialed **lazily**, on the first byte that would be
//!   forwarded — a connection killed at offset 0 never touches the mock,
//!   so the loss is provably invisible to the one-request window;
//! - a [`KillPoint`] aborts BOTH directions once exactly
//!   `after_client_bytes` client bytes have been forwarded upstream
//!   (the crossing chunk is partially forwarded, so the kill lands at
//!   the exact byte offset);
//! - `chunk_delay` sleeps before every forwarded WRITE chunk — fixed
//!   added latency, no randomness.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One deterministic loss: abort client connection number
/// `connection` (0-based accept order) once `after_client_bytes` bytes
/// have been forwarded toward the mock. `after_client_bytes: 0` kills
/// on accept — nothing is forwarded and the upstream is never dialed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillPoint {
    /// Which client connection (0-based accept order) gets killed.
    pub connection: usize,
    /// Forwarded client→mock byte count at which to abort.
    pub after_client_bytes: u64,
}

/// Loss profile: kills at chosen WRITE offsets plus a per-forwarded-
/// chunk delay.
#[derive(Debug, Clone)]
pub struct LossConfig {
    /// Connections to abort, at exact forwarded-byte offsets.
    pub kills: Vec<KillPoint>,
    /// Delay applied before forwarding every WRITE chunk.
    pub chunk_delay: Duration,
}

/// What the proxy observed for one client connection.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConnRecord {
    /// Whether the upstream mock was ever dialed for this connection.
    pub dialed: bool,
    /// Client→mock bytes actually forwarded.
    pub forwarded: u64,
    /// Forwarded-byte offset at which this connection was killed, if it
    /// was killed by a [`KillPoint`].
    pub killed_at: Option<u64>,
}

#[derive(Debug, Default)]
pub struct ProxyShared {
    /// One record per accepted client connection, in accept order.
    pub conns: Vec<ConnRecord>,
}

/// A running lossy proxy: dial `addr` from the client side.
pub struct LossyProxy {
    /// Listener address (clients connect here).
    pub addr: SocketAddr,
    /// Shared observation records.
    pub shared: Arc<Mutex<ProxyShared>>,
}

/// Spawn the proxy in front of `upstream` with the given loss profile.
pub fn spawn_lossy_proxy(upstream: SocketAddr, cfg: LossConfig) -> LossyProxy {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let addr = listener.local_addr().expect("proxy addr");
    let shared = Arc::new(Mutex::new(ProxyShared::default()));
    let shared2 = Arc::clone(&shared);
    std::thread::spawn(move || accept_loop(listener, upstream, cfg, shared2));
    LossyProxy { addr, shared }
}

fn accept_loop(
    listener: TcpListener,
    upstream: SocketAddr,
    cfg: LossConfig,
    shared: Arc<Mutex<ProxyShared>>,
) {
    let mut index = 0usize;
    for stream in listener.incoming() {
        let Ok(client) = stream else { continue };
        shared
            .lock()
            .expect("proxy lock")
            .conns
            .push(ConnRecord::default());
        let kill = cfg.kills.iter().find(|k| k.connection == index).copied();
        let conn = index;
        index += 1;
        let shared2 = Arc::clone(&shared);
        let delay = cfg.chunk_delay;
        std::thread::spawn(move || serve_conn(client, upstream, kill, delay, conn, shared2));
    }
}

fn serve_conn(
    client: TcpStream,
    upstream_addr: SocketAddr,
    kill: Option<KillPoint>,
    chunk_delay: Duration,
    conn: usize,
    shared: Arc<Mutex<ProxyShared>>,
) {
    // offset-0 kill fires on accept: nothing forwarded, no dial — the
    // mock must stay untouched (the pre-POST loss case).
    if let Some(k) = kill {
        if k.after_client_bytes == 0 {
            let _ = client.shutdown(Shutdown::Both);
            record_kill(&shared, conn, 0);
            return;
        }
    }

    // upstream→client relay: starts only once a first byte flowed and
    // the (lazily dialed) upstream socket is sent down the channel.
    let client_wr = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let (up_tx, up_rx) = mpsc::channel::<TcpStream>();
    std::thread::spawn(move || relay_upstream_to_client(up_rx, client_wr));

    let mut client = client;
    let mut upstream: Option<TcpStream> = None;
    let mut forwarded: u64 = 0;
    let mut buf = [0u8; 4096];
    loop {
        let n = match client.read(&mut buf) {
            Ok(0) | Err(_) => break, // client gone: end of WRITE stream
            Ok(n) => n,
        };
        let up = match upstream.as_mut() {
            Some(up) => up,
            None => match TcpStream::connect(upstream_addr) {
                Ok(s) => {
                    shared.lock().expect("proxy lock").conns[conn].dialed = true;
                    let read_side = match s.try_clone() {
                        Ok(rd) => rd,
                        Err(_) => break,
                    };
                    if up_tx.send(read_side).is_err() {
                        break;
                    }
                    if s.set_nodelay(true).is_err() {
                        break;
                    }
                    upstream.insert(s)
                }
                Err(_) => break, // mock unreachable: connection is dead
            },
        };
        if !chunk_delay.is_zero() {
            std::thread::sleep(chunk_delay);
        }
        // forward at most up to the kill offset — the crossing chunk is
        // partially forwarded so the kill lands at the exact byte.
        let budget = kill.map(|k| k.after_client_bytes.saturating_sub(forwarded));
        let take = budget.map_or(n, |b| n.min(usize::try_from(b).unwrap_or(usize::MAX)));
        if take > 0 && up.write_all(&buf[..take]).is_err() {
            break;
        }
        forwarded += take as u64;
        shared.lock().expect("proxy lock").conns[conn].forwarded = forwarded;
        if let Some(k) = kill {
            if forwarded >= k.after_client_bytes {
                // mid-stream abort: close BOTH directions at the offset
                let _ = up.shutdown(Shutdown::Both);
                let _ = client.shutdown(Shutdown::Both);
                record_kill(&shared, conn, forwarded);
                return;
            }
        }
    }
    // clean client EOF: half-close upstream so the mock can answer,
    // then the relay thread drains the verdict back to the client.
    if let Some(up) = upstream.as_ref() {
        let _ = up.shutdown(Shutdown::Write);
    }
    drop(up_tx);
}

fn relay_upstream_to_client(up_rx: mpsc::Receiver<TcpStream>, mut client: TcpStream) {
    let Ok(mut up) = up_rx.recv() else {
        return; // no byte ever flowed: nothing dialed, nothing to relay
    };
    let mut buf = [0u8; 4096];
    loop {
        match up.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if client.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = up.shutdown(Shutdown::Both);
    let _ = client.shutdown(Shutdown::Both);
}

fn record_kill(shared: &Arc<Mutex<ProxyShared>>, conn: usize, at: u64) {
    let mut shared = shared.lock().expect("proxy lock");
    shared.conns[conn].killed_at = Some(at);
    shared.conns[conn].forwarded = shared.conns[conn].forwarded.max(at);
}
