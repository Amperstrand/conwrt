//! M4 #109: router-to-router proof — the `conwrt` CLI (controller) talking
//! to the `conwrt-agent` binary running on an OpenWrt VM, over a real
//! network boundary.
//!
//! Gated behind `CONWRT_QEMU_VM=1` — never runs in CI. Assumes:
//! - The OpenWrt 25.12.5 VM is up (SSH on 127.0.0.1:$CONWRT_VM_SESSION_PORT,
//!   default 2222 — the fixture's env-seam, never a hardcoded port)
//! - The agent binary is cross-built (`cargo build --release -p conwrt-agent
//!   --target x86_64-unknown-linux-musl`, resolved from $CARGO_TARGET_DIR /
//!   the workspace target dir; or CONWRT_AGENT_BIN)
//! - The `conwrt` CLI is built (`cargo build -p conwrt-cli`)
//! - The agent port is CLAIMED + tunneled by this test
//!   ($CONWRT_VM_TUNNEL_PORT, default 18400) — the session fixture only
//!   forwards SSH, so the agent leg is ours.
//!
//! Multi-agent host rules (AGENTS.md; #364): SSH/bins/keys resolve from
//! env + workspace (never author-home absolutes); the agent process is
//! killed by PIDFILE-scoped kill with cmdline validation (never
//! `pgrep conwrt-agent`, which would terminate every session's agent);
//! the tunnel child is dropped on success AND panic.
//!
//! The test exercises the full controller surface through the CLI:
//! `conwrt agent info` → `conwrt agent lease` → `conwrt agent status`.

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

const VM_PIDFILE: &str = "/tmp/conwrt-agent-r2r.pid";

fn vm_ssh_port() -> u16 {
    std::env::var("CONWRT_VM_SESSION_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(2222)
}

fn tunnel_port() -> u16 {
    std::env::var("CONWRT_VM_TUNNEL_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(18400)
}

/// #364 (r4272981979): workspace/CARGO_TARGET_DIR-resolved binaries —
/// the documented build commands produce these; author-home absolutes
/// made the test unperformable for anyone else.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn target_dir() -> PathBuf {
    std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("target"))
}

fn agent_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CONWRT_AGENT_BIN") {
        return PathBuf::from(p);
    }
    target_dir().join("x86_64-unknown-linux-musl/release/conwrt-agent")
}

fn cli_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CONWRT_CLI_BIN") {
        return PathBuf::from(p);
    }
    target_dir().join("debug/conwrt")
}

/// #364 (r4272981988): the fixture writes the key at the WORKSPACE root;
/// cargo runs tests from the crate dir — resolve from the manifest dir.
fn ssh_key() -> PathBuf {
    workspace_root().join("tests/integration/.vm_ssh_key")
}

fn vm_ssh_args() -> Vec<String> {
    [
        "-o".to_string(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=5".into(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-i".into(),
        ssh_key().to_string_lossy().into_owned(),
        "-p".into(),
        vm_ssh_port().to_string(),
        "root@127.0.0.1".into(),
    ]
    .to_vec()
}

fn ssh(cmd: &str) -> bool {
    Command::new("ssh")
        .args(vm_ssh_args())
        .arg(cmd)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn agent_addr() -> String {
    format!("127.0.0.1:{}", tunnel_port())
}

/// Owns the deployed agent + tunnel: PIDFILE-scoped kill and tunnel
/// teardown run on success AND panic (never a pgrep-wide kill).
struct AgentOnVm {
    tunnel: Option<Child>,
}

impl Drop for AgentOnVm {
    fn drop(&mut self) {
        // #364 (r4272981969): kill ONLY the PID this test launched
        // (pidfile + cmdline validation) — `pgrep conwrt-agent` on a
        // shared VM would kill other sessions' agents.
        let _ = ssh(&format!(
            "P=$(cat {VM_PIDFILE} 2>/dev/null); \
             if [ -n \"$P\" ] && grep -q conwrt-agent /proc/$P/cmdline 2>/dev/null; then \
             kill $P; fi; rm -f {VM_PIDFILE}; true"
        ));
        if let Some(t) = &mut self.tunnel {
            let _ = t.kill();
            let _ = t.wait();
        }
    }
}

fn deploy_and_start() -> Result<AgentOnVm, String> {
    let bin = agent_bin();
    if !bin.is_file() {
        return Err(format!(
            "agent binary not found at {} — build with `cargo build --release \
             -p conwrt-agent --target x86_64-unknown-linux-musl` or set CONWRT_AGENT_BIN",
            bin.display()
        ));
    }
    // Deploy ("text file busy" if a stale copy is executing — the scoped
    // kill below clears OUR instance; other sessions' instances own their
    // /tmp copies under their own pidfiles).
    let scp = Command::new("scp")
        .args(["-O", "-q"])
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .arg("-i")
        .arg(ssh_key().to_string_lossy().into_owned())
        .arg("-P")
        .arg(vm_ssh_port().to_string())
        .arg(&bin)
        .arg("root@127.0.0.1:/tmp/conwrt-agent-r2r")
        .output()
        .map_err(|e| format!("scp failed to spawn: {e}"))?;
    if !scp.status.success() {
        return Err(format!(
            "deploy failed: {}",
            String::from_utf8_lossy(&scp.stderr)
        ));
    }

    // Start with PID capture (#364 r4272981969): the pidfile scopes the
    // kill; the drop guard runs on success and panic alike.
    if !ssh("chmod +x /tmp/conwrt-agent-r2r && \
         /tmp/conwrt-agent-r2r --listen 0.0.0.0:8400 --insecure-allow-non-loopback \
         --capability serial:uarts=2 --capability link-probe \
         --capability tftp-server:port=69 \
         > /tmp/agent-r2r.log 2>&1 & echo $! > /tmp/conwrt-agent-r2r.pid")
    {
        return Err("agent start failed".into());
    }
    std::thread::sleep(Duration::from_secs(1));

    // #364 (r4272981961): the fixture only forwards SSH — claim + tunnel
    // the agent port ourselves; a held port is a REPORTED error (another
    // session's tunnel), not a silent collision.
    let tp = tunnel_port();
    if TcpStream::connect(("127.0.0.1", tp)).is_ok() {
        return Err(format!(
            "tunnel port {tp} already in use (another session's tunnel?) — \
             set CONWRT_VM_TUNNEL_PORT"
        ));
    }
    let tunnel = Command::new("ssh")
        .args(vm_ssh_args())
        .args([format!("-L{tp}:localhost:8400"), "-N".into()])
        .spawn()
        .map_err(|e| format!("tunnel spawn failed: {e}"))?;
    std::thread::sleep(Duration::from_secs(1));
    if TcpStream::connect(("127.0.0.1", tp)).is_err() {
        return Err("tunnel not reachable after start".into());
    }

    Ok(AgentOnVm {
        tunnel: Some(tunnel),
    })
}

fn run_cli(args: &[&str]) -> (bool, String) {
    let output = Command::new(cli_bin())
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
    if TcpStream::connect(("127.0.0.1", vm_ssh_port())).is_err() {
        eprintln!("skipping: VM not reachable on 127.0.0.1:{}", vm_ssh_port());
        return;
    }
    // Past the gate: setup failures FAIL the test (a green run that
    // exercised none of the protocol surface is the bug this guards).
    let addr = agent_addr();
    let _cleanup = deploy_and_start().expect("router-to-router setup failed");

    // --- agent info: handshake + capabilities ---
    let (ok, out) = run_cli(&["agent", "info", "--addr", &addr]);
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
    let (ok, out) = run_cli(&["agent", "lease", "--addr", &addr, "--resource", "uart0"]);
    assert!(ok, "agent lease failed: {out}");
    assert!(out.contains("granted"), "expected 'granted': {out}");
    eprintln!("✓ agent lease: {out}");

    // --- agent status: query a (nonexistent) transfer ---
    let (ok, out) = run_cli(&["agent", "status", "--addr", &addr, "--transfer-id", "999"]);
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
