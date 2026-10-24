//! `conwrt watch` — live emission-window watcher for a dark target.
//!
//! The I/O half of `conwrt-probe-core::watch`: gentle active probes (ping,
//! TCP connects) plus a tcpdump passive stream, assembled into the event
//! timeline the core classifier turns into a verdict. The foreign-traffic
//! positive control follows the dark-device doctrine: silence is only
//! evidence if the capture path provably works.

use conwrt_probe_core::watch::{EventKind, WatchEvent, WatchVerdict, classify, recovery_hint};
use std::io::{BufRead, BufReader};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub struct WatchArgs {
    pub ip: String,
    pub interface: String,
    pub duration_s: u64,
    pub interval_s: u64,
}

const PROBE_PORTS: [u16; 3] = [22, 23, 80];

fn spawn_tcpdump(interface: &str, filter: &str) -> Option<std::process::Child> {
    Command::new("sudo")
        .args(["-n", "tcpdump", "-l", "-n", "-i", interface, filter])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

fn tcp_result(addr: &str) -> Option<EventKind> {
    let sock = addr.to_socket_addrs().ok()?.next()?;
    match TcpStream::connect_timeout(&sock, Duration::from_secs(2)) {
        Ok(_) => Some(EventKind::TcpOpen),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(EventKind::TcpRefused),
        Err(_) => None,
    }
}

fn label(k: EventKind) -> &'static str {
    match k {
        EventKind::TcpOpen => "OPEN",
        EventKind::TcpRefused => "REFUSED",
        EventKind::PingOk => "PING",
        EventKind::Passive => "FRAME",
    }
}

fn local_mac(interface: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/net/{interface}/address"))
        .unwrap_or_default()
        .trim()
        .to_lowercase()
}

pub fn run(args: WatchArgs) -> std::process::ExitCode {
    let code = watch(args);
    std::process::ExitCode::from(code)
}

/// tcpdump children are killed at watch end so the reader threads see EOF
/// and the joins below cannot deadlock on a capture that never ends.
fn kill(child: &Arc<Mutex<Option<std::process::Child>>>) {
    if let Some(mut c) = child.lock().unwrap().take() {
        let _ = c.kill();
    }
}

fn watch(args: WatchArgs) -> u8 {
    let start = Instant::now();
    let events: Arc<Mutex<Vec<WatchEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let control_ok = Arc::new(AtomicBool::new(false));

    let control_child: Arc<Mutex<Option<std::process::Child>>> = Arc::new(Mutex::new(None));
    let control = {
        let (ok, iface, ip, child) = (
            control_ok.clone(),
            args.interface.clone(),
            args.ip.clone(),
            control_child.clone(),
        );
        thread::spawn(move || {
            // Foreign traffic we actually RECEIVE: addressed to this host,
            // not involving the target. `not host` alone would match this
            // watcher's own outbound broadcasts and "prove" a dead path.
            let filter = format!("ether dst host {} and not host {ip}", local_mac(&iface));
            if let Some(mut c) = spawn_tcpdump(&iface, &filter) {
                if let Some(out) = c.stdout.take() {
                    *child.lock().unwrap() = Some(c);
                    if BufReader::new(out).lines().next().is_some() {
                        ok.store(true, Ordering::Relaxed);
                    }
                }
            }
        })
    };

    let passive_child: Arc<Mutex<Option<std::process::Child>>> = Arc::new(Mutex::new(None));
    let passive = {
        let (evs, iface, ip, child) = (
            events.clone(),
            args.interface.clone(),
            args.ip.clone(),
            passive_child.clone(),
        );
        thread::spawn(move || {
            // Only packets FROM the target: `host {ip}` would also capture
            // this watcher's own SYNs/ARPs toward the target and register
            // them as target life on a dead segment.
            let filter = format!("src host {ip}");
            let t0 = Instant::now();
            if let Some(mut c) = spawn_tcpdump(&iface, &filter) {
                if let Some(out) = c.stdout.take() {
                    *child.lock().unwrap() = Some(c);
                    for line in BufReader::new(out).lines().map_while(Result::ok) {
                        if !line.trim().is_empty() {
                            evs.lock().unwrap().push(WatchEvent {
                                t: t0.elapsed().as_secs_f64(),
                                kind: EventKind::Passive,
                            });
                        }
                    }
                }
            }
        })
    };

    println!(
        "watching {} on {} for {}s (probes every {}s; ports {:?})",
        args.ip, args.interface, args.duration_s, args.interval_s, PROBE_PORTS
    );
    loop {
        let t = start.elapsed().as_secs_f64();
        if t >= args.duration_s as f64 {
            break;
        }
        let mut marks = Vec::new();
        let ping_ok = Command::new("ping")
            .args(["-c", "1", "-W", "1", &args.ip])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        marks.push(format!("ping={}", if ping_ok { "PING" } else { ".." }));
        if ping_ok {
            events.lock().unwrap().push(WatchEvent {
                t,
                kind: EventKind::PingOk,
            });
        }
        for p in PROBE_PORTS {
            let kind = tcp_result(&format!("{}:{}", args.ip, p));
            marks.push(format!(":{p}={}", kind.map(label).unwrap_or("..")));
            if let Some(k) = kind {
                events.lock().unwrap().push(WatchEvent { t, kind: k });
            }
        }
        println!("[{:5.0}s] {}", t, marks.join(" "));
        thread::sleep(Duration::from_secs(args.interval_s));
    }

    let ctrl = control_ok.load(Ordering::Relaxed);
    let evs = events.lock().unwrap().clone();
    let watch_s = start.elapsed().as_secs_f64();
    let verdict = classify(&evs, watch_s, ctrl);
    println!("events: {} control_ok: {}", evs.len(), ctrl);
    println!("verdict: {verdict:?}");
    println!("hint: {}", recovery_hint(&verdict));
    kill(&passive_child);
    kill(&control_child);
    let _ = passive.join();
    let _ = control.join();
    match verdict {
        WatchVerdict::SteadyUp => 0,
        WatchVerdict::Inconclusive => 2,
        _ => 1,
    }
}
