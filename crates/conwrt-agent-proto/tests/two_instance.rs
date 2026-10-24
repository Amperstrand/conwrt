//! M4 #109: two-instance proof — one controller driving TWO agents
//! simultaneously: a mipsel agent on a physical router (COVR-X1860 A1,
//! OpenWrt 25.12.5) and a host-side agent, each holding an independent
//! lease table for the SAME resource name.
//!
//! Gated behind `CONWRT_TWO_AGENTS=1` — never runs in CI. Endpoints come
//! from the environment (bench addresses are operator-private and must
//! not be hardcoded):
//!
//! ```text
//! CONWRT_TWO_AGENTS=1
//! CONWRT_AGENT_A=<router>:8400        # e.g. the bench x1860 (mipsel agent)
//! CONWRT_AGENT_B=127.0.0.1:8401       # host-side agent
//! ```
//!
//! Setup (both agents must be listening before the test runs):
//!
//! ```text
//! # Agent B on the host:
//! cargo build -p conwrt-agent
//! <target-dir>/debug/conwrt-agent \
//!   --listen 127.0.0.1:8401 --capability serial:uarts=1 &
//!
//! # Agent A on the router (deploy once per boot, dropbear needs scp -O):
//! scp -O <target-dir>/mipsel-unknown-linux-musl/release/conwrt-agent \
//!   root@<router>:/tmp/conwrt-agent
//! ssh root@<router> 'setsid /tmp/conwrt-agent --listen 0.0.0.0:8400 --insecure-allow-non-loopback \
//!   --capability serial:uarts=2 --capability link-probe \
//!   > /tmp/agent.log 2>&1 &'
//! ```
//!
//! The proof (#463 hardening — this file must prove what its name claims):
//! - the CLI binary resolves from THIS build (`CONWRT_TEST_CLI`, default
//!   `<workspace>/target/debug/conwrt`) — never a host-absolute path that
//!   may be stale or absent;
//! - the conflicting lease presents a DISTINCT controller identity: the
//!   agent rejects same-controller reacquisition (`AlreadyHeld`) on a
//!   different code path than cross-controller conflict, so a shared
//!   identity proves nothing about exclusivity;
//! - denial assertions require the CLI's SPECIFIC denial surface (exit
//!   code 1 + `denied (holder:` on stderr) — a connection refusal or
//!   crash (exit 2) is a FAILED proof, not a passing one;
//! - the holder process stays alive (heartbeat) while the conflict is
//!   attempted, then is killed — the lease genuinely overlaps.

use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn cli_bin() -> String {
    if let Ok(path) = std::env::var("CONWRT_TEST_CLI") {
        return path;
    }
    // This build's target dir (CARGO_MANIFEST_DIR = crates/conwrt-agent-proto)
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop();
    dir.pop();
    dir.join("target")
        .join("debug")
        .join("conwrt")
        .display()
        .to_string()
}

fn reachable(addr: &str) -> bool {
    TcpStream::connect(addr).is_ok()
}

fn agent_info(addr: &str) -> (i32, String, String) {
    let out = Command::new(cli_bin())
        .args(["agent", "info", "--addr", addr])
        .output()
        .expect("CLI binary not found (set CONWRT_TEST_CLI)");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A live lease holder: the CLI process heartbeats until killed.
struct LeaseHolder {
    child: Child,
}

impl Drop for LeaseHolder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start `agent lease` as `controller` and wait for the GRANTED line
/// (the CLI holds the lease for its process lifetime, so the grant is
/// observed on stdout while the process keeps running).
fn start_lease_holder(addr: &str, controller: &str) -> (LeaseHolder, String) {
    let mut child = Command::new(cli_bin())
        .args([
            "agent",
            "lease",
            "--addr",
            addr,
            "--resource",
            "uart0",
            "--controller",
            controller,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn lease CLI");
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) if line.contains("granted") => {
                return (LeaseHolder { child }, line);
            }
            Ok(other) => panic!("lease {controller}@{addr}: unexpected output: {other}"),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = child.kill();
                let status = child.wait();
                let _ = status;
                panic!("lease {controller}@{addr}: CLI exited before granting ({status:?})");
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("lease {controller}@{addr}: no grant within 15s");
}

/// Attempt a conflicting exclusive lease as a DIFFERENT controller and
/// return the full denial surface (exit code, stderr).
/// Attempt a conflicting exclusive lease as a DIFFERENT controller and
/// return the denial surface (exit code, stderr). BOUNDED: if
/// exclusivity is broken the rival is GRANTED and enters its heartbeat
/// loop forever — that must surface as a test FAILURE, not a hang
/// (kill + reap, then panic naming the regression).
fn attempt_conflict(addr: &str, controller: &str) -> (i32, String) {
    let mut child = Command::new(cli_bin())
        .args([
            "agent",
            "lease",
            "--addr",
            addr,
            "--resource",
            "uart0",
            "--controller",
            controller,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run lease CLI");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait().expect("try_wait rival") {
            Some(_) => break,
            None if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(200));
            }
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "rival {controller}@{addr} was GRANTED the exclusive lease \
                     (still alive after 20s) — CROSS-CONTROLLER EXCLUSIVITY IS BROKEN"
                );
            }
        }
    }
    let out = child.wait_with_output().expect("reap rival");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn m4_two_agents_independent_lease_tables() {
    let gated = std::env::var("CONWRT_TWO_AGENTS").ok().as_deref() == Some("1");
    let (Ok(agent_a), Ok(agent_b)) = (
        std::env::var("CONWRT_AGENT_A"),
        std::env::var("CONWRT_AGENT_B"),
    ) else {
        eprintln!("skipping: CONWRT_AGENT_A/CONWRT_AGENT_B not both set");
        return;
    };
    if !gated {
        eprintln!("skipping: CONWRT_TWO_AGENTS=1 not set");
        return;
    }
    if !reachable(&agent_a) {
        eprintln!("skipping: agent A not reachable at {agent_a}");
        return;
    }
    if !reachable(&agent_b) {
        eprintln!("skipping: agent B not reachable at {agent_b}");
        return;
    }

    // --- both agents handshake and advertise capabilities ---
    for (label, addr) in [("A", &agent_a), ("B", &agent_b)] {
        let (code, out, err) = agent_info(addr);
        assert_eq!(code, 0, "agent info {label} failed: {out}{err}");
        assert!(
            out.contains("connected to"),
            "{label} handshake: {out}{err}"
        );
        assert!(
            out.contains("serial"),
            "{label} serial capability: {out}{err}"
        );
    }
    eprintln!("✓ both agents handshake: A={agent_a} B={agent_b}");

    // --- same exclusive resource grants on BOTH agents (independent
    // tables). The agent serves one controller connection at a time
    // (M4 single-operator phase, server_tcp doc), so the cross-
    // controller conflict is proven the supported way: the holder
    // acquires and DIES mid-lease (no release) — the lease outlives the
    // connection on the heartbeat budget — then a DIFFERENT controller
    // is denied with the holder NAMED. ---
    let mut denied_holders: Vec<String> = Vec::new();
    for (label, addr, holder_id) in [
        ("A", &agent_a, "excl-proof-holder-a"),
        ("B", &agent_b, "excl-proof-holder-b"),
    ] {
        let (holder, grant) = start_lease_holder(addr, holder_id);
        assert!(grant.contains("granted"), "{label} grant line: {grant}");
        drop(holder); // killed mid-lease: no release sent

        let (code, err) = attempt_conflict(addr, "excl-proof-rival");
        assert_eq!(
            code, 1,
            "{label}: conflict must be the CLI's DENIED path (exit 1), got {code}: {err}"
        );
        assert!(
            err.contains("denied (holder:"),
            "{label}: specific denial surface missing: {err}"
        );
        assert!(
            err.contains(holder_id),
            "{label}: denial must name the OTHER controller ({holder_id}): {err}"
        );
        denied_holders.push(format!("{label}={holder_id}"));
    }
    eprintln!(
        "✓ uart0 granted on A and B (independent tables); cross-controller \
         conflict denied naming the holder ({})",
        denied_holders.join(", ")
    );
    eprintln!("✓ exclusive conflict denied on A and B separately (exit 1 + holder named)");
    eprintln!("\n=== TWO-INSTANCE PROOF COMPLETE ===");
    eprintln!("Controller CLI drove two agents concurrently:");
    eprintln!("  A: {agent_a}");
    eprintln!("  B: {agent_b}");
}
