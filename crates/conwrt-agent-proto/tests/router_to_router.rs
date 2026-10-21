//! M4 #109: router-to-router proof — the `conwrt` CLI (controller) talking
//! to the `conwrt-agent` binary running on an OpenWrt VM, over a real
//! network boundary.
//!
//! Gated behind `CONWRT_QEMU_VM=1` — never runs in CI. Assumes:
//! - The OpenWrt 25.12.5 VM is up (SSH on 127.0.0.1:2222, agent port
//!   forwarded 127.0.0.1:18400 → VM:8400)
//! - The agent binary is cross-built (`cargo build --release -p conwrt-agent
//!   --target x86_64-unknown-linux-musl`)
//! - The `conwrt` CLI is built (`cargo build -p conwrt-cli`)
//!
//! The test exercises the full controller surface through the CLI:
//! `conwrt agent info` → `conwrt agent lease` → `conwrt agent status`.

use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

const AGENT_ADDR: &str = "127.0.0.1:18400";
const AGENT_BIN: &str = "/home/ubuntu/.cargo-target/x86_64-unknown-linux-musl/release/conwrt-agent";
const CLI_BIN: &str = "/home/ubuntu/.cargo-target/debug/conwrt";

fn deploy_and_start_agent() -> bool {
    // Kill any running instance first (scp fails with "text file busy" if
    // the binary is executing).
    let _ = Command::new("ssh")
        .args(["-p", "2222"])
        .args(["-o", "BatchMode=yes"])
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .arg("-i")
        .arg("tests/integration/.vm_ssh_key")
        .arg("root@127.0.0.1")
        .arg("kill $(pgrep conwrt-agent) 2>/dev/null; true")
        .output();
    std::thread::sleep(Duration::from_millis(500));

    // Deploy
    let scp = Command::new("scp")
        .args(["-O", "-q", "-P", "2222"])
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .arg("-i")
        .arg("tests/integration/.vm_ssh_key")
        .arg(AGENT_BIN)
        .arg("root@127.0.0.1:/tmp/conwrt-agent")
        .output()
        .expect("scp failed to start");
    if !scp.status.success() {
        eprintln!("deploy failed: {}", String::from_utf8_lossy(&scp.stderr));
        return false;
    }

    // Start (kill any stale instance first)
    let ssh = Command::new("ssh")
        .args(["-p", "2222"])
        .args(["-o", "BatchMode=yes"])
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .arg("-i")
        .arg("tests/integration/.vm_ssh_key")
        .arg("root@127.0.0.1")
        .arg(
            "kill $(pgrep conwrt-agent) 2>/dev/null; chmod +x /tmp/conwrt-agent && \
/tmp/conwrt-agent --listen 0.0.0.0:8400 --insecure-allow-non-loopback \
  --capability serial:uarts=2 \
  --capability link-probe \
  --capability tftp-server:port=69 \
  > /tmp/agent.log 2>&1 &",
        )
        .output()
        .expect("ssh failed to start");
    if !ssh.status.success() {
        eprintln!(
            "agent start failed: {}",
            String::from_utf8_lossy(&ssh.stderr)
        );
        return false;
    }
    std::thread::sleep(Duration::from_secs(1));
    TcpStream::connect("127.0.0.1:18400").is_ok()
}

fn run_cli(args: &[&str]) -> (bool, String) {
    let output = Command::new(CLI_BIN)
        .args(args)
        .output()
        .expect("CLI binary not found");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    (output.status.success(), stdout)
}

#[test]
fn m4_controller_cli_to_agent_on_openwrt_vm() {
    if std::env::var("CONWRT_QEMU_VM").ok().as_deref() != Some("1") {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set");
        return;
    }
    if !TcpStream::connect("127.0.0.1:2222").is_ok() {
        eprintln!("skipping: VM not reachable on 127.0.0.1:2222");
        return;
    }
    // Always restart the agent (fresh lease table — no stale state from
    // earlier manual tests).
    assert!(deploy_and_start_agent(), "deploy/start failed");

    // --- agent info: handshake + capabilities ---
    let (ok, out) = run_cli(&["agent", "info", "--addr", AGENT_ADDR]);
    assert!(ok, "agent info failed: {out}");
    assert!(
        out.contains("connected to"),
        "expected 'connected to': {out}"
    );
    assert!(out.contains("serial"), "expected serial capability: {out}");
    assert!(out.contains("uarts=2"), "expected uarts=2 detail: {out}");
    assert!(out.contains("tftp-server"), "expected tftp-server: {out}");
    eprintln!("✓ agent info: {out}");

    // --- agent lease: acquire uart0 ---
    let (ok, out) = run_cli(&[
        "agent",
        "lease",
        "--addr",
        AGENT_ADDR,
        "--resource",
        "uart0",
    ]);
    assert!(ok, "agent lease failed: {out}");
    assert!(out.contains("granted"), "expected 'granted': {out}");
    eprintln!("✓ agent lease: {out}");

    // --- agent status: query a (nonexistent) transfer ---
    let (ok, out) = run_cli(&[
        "agent",
        "status",
        "--addr",
        AGENT_ADDR,
        "--transfer-id",
        "999",
    ]);
    assert!(ok, "agent status failed: {out}");
    assert!(
        out.contains("transfer 999"),
        "expected transfer info: {out}"
    );
    eprintln!("✓ agent status: {out}");

    eprintln!("\n=== M4 PROOF COMPLETE ===");
    eprintln!("Controller CLI on host → agent binary on OpenWrt VM");
    eprintln!("Network boundary: QEMU user-mode (real TCP, not loopback-only)");
    eprintln!("Commands exercised: agent info, agent lease, agent status");
}
