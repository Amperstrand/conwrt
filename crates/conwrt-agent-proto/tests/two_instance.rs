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
//! ~/.cargo-target/debug/conwrt-agent \
//!   --listen 127.0.0.1:8401 --capability serial:uarts=1 &
//!
//! # Agent A on the router (deploy once per boot, dropbear needs scp -O):
//! scp -O ~/.cargo-target/mipsel-unknown-linux-musl/release/conwrt-agent \
//!   root@<router>:/tmp/conwrt-agent
//! ssh root@<router> 'setsid /tmp/conwrt-agent --listen 0.0.0.0:8400 \
//!   --capability serial:uarts=2 --capability link-probe \
//!   > /tmp/agent.log 2>&1 &'
//! ```
//!
//! Assertions: both agents handshake; an exclusive lease on `uart0`
//! grants on A AND on B (independent tables — the multi-instance core
//! claim); a second exclusive lease for the same resource is denied on
//! each agent separately.

use std::net::TcpStream;
use std::process::Command;

const CLI_BIN: &str = "/home/ubuntu/.cargo-target/debug/conwrt";

fn run_cli(args: &[&str]) -> (bool, String) {
    let output = Command::new(CLI_BIN)
        .args(args)
        .output()
        .expect("CLI binary not found");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    (output.status.success(), stdout)
}

fn reachable(addr: &str) -> bool {
    TcpStream::connect(addr).is_ok()
}

fn lease(addr: &str) -> (bool, String) {
    run_cli(&["agent", "lease", "--addr", addr, "--resource", "uart0"])
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
    let (ok, out) = run_cli(&["agent", "info", "--addr", &agent_a]);
    assert!(ok, "agent info A failed: {out}");
    assert!(out.contains("connected to"), "A handshake: {out}");
    assert!(out.contains("serial"), "A serial capability: {out}");

    let (ok, out) = run_cli(&["agent", "info", "--addr", &agent_b]);
    assert!(ok, "agent info B failed: {out}");
    assert!(out.contains("connected to"), "B handshake: {out}");
    assert!(out.contains("serial"), "B serial capability: {out}");
    eprintln!("✓ both agents handshake: A={agent_a} B={agent_b}");

    // --- same exclusive resource grants on BOTH agents ---
    let (ok, out) = lease(&agent_a);
    assert!(ok && out.contains("granted"), "lease on A: {out}");
    let (ok, out) = lease(&agent_b);
    assert!(ok && out.contains("granted"), "lease on B: {out}");
    eprintln!("✓ uart0 granted on A and B (independent lease tables)");

    // --- second exclusive lease denied on EACH agent ---
    let (ok, out) = lease(&agent_a);
    assert!(
        !ok || out.contains("denied"),
        "A should deny conflict: {out}"
    );
    let (ok, out) = lease(&agent_b);
    assert!(
        !ok || out.contains("denied"),
        "B should deny conflict: {out}"
    );
    eprintln!("✓ exclusive conflict denied on A and B separately");

    eprintln!("\n=== TWO-INSTANCE PROOF COMPLETE ===");
    eprintln!("Controller CLI drove two agents concurrently:");
    eprintln!("  A: {agent_a} (physical router, mipsel_24kc)");
    eprintln!("  B: {agent_b} (host-side)");
}
