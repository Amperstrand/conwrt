//! QEMU E2E: the conwrt-agent binary running on the OpenWrt VM, exercised
//! from this host through an SSH tunnel (#108 slice 3).
//!
//! Gated behind `CONWRT_QEMU_VM=1` — never runs in CI. Assumes:
//! - The OpenWrt 25.12.5 VM is up (SSH on 127.0.0.1:$CONWRT_VM_SESSION_PORT,
//!   default 2222 — read, never hardcoded: on this shared host another
//!   session's VM can sit on any port, AGENTS.md multi-agent rules)
//! - The agent binary is cross-built: `cargo build --release -p conwrt-agent
//!   --target x86_64-unknown-linux-musl` (resolved from $CARGO_TARGET_DIR /
//!   the workspace target dir, or overridden with $CONWRT_AGENT_BIN)
//!
//! The test handles the full lifecycle: deploy → start → tunnel → verify →
//! cleanup. Skips happen ONLY at the gate (env unset, VM port dead); any
//! failure AFTER the gate FAILS the test — a vacuously-green protocol run
//! is worse than a red one.

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

const VM_PIDFILE: &str = "/tmp/conwrt-agent-e2e.pid";

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

fn agent_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CONWRT_AGENT_BIN") {
        return PathBuf::from(p);
    }
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .to_string_lossy()
            .into_owned()
    });
    PathBuf::from(target_dir).join("x86_64-unknown-linux-musl/release/conwrt-agent")
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
        "tests/integration/.vm_ssh_key".into(),
        "-p".into(),
        vm_ssh_port().to_string(),
        "root@127.0.0.1".into(),
    ]
    .to_vec()
}

fn vm_reachable() -> bool {
    TcpStream::connect(("127.0.0.1", vm_ssh_port())).is_ok()
}

fn ssh(cmd: &str) -> bool {
    Command::new("ssh")
        .args(vm_ssh_args())
        .arg(cmd)
        .output()
        .is_ok_and(|o| o.status.success())
}

struct AgentOnVm {
    tunnel: Option<Child>,
}

impl Drop for AgentOnVm {
    fn drop(&mut self) {
        // Kill ONLY the PID this test launched (pidfile + cmdline
        // validation): `pgrep conwrt-agent` on a shared VM would kill
        // other sessions' agents (AGENTS.md multi-agent rules).
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

    // 1. Deploy
    let scp = Command::new("scp")
        .args(["-O", "-q"])
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .arg("-i")
        .arg("tests/integration/.vm_ssh_key")
        .arg("-P")
        .arg(vm_ssh_port().to_string())
        .arg(&bin)
        .arg("root@127.0.0.1:/tmp/conwrt-agent")
        .output()
        .map_err(|e| format!("scp failed to spawn: {e}"))?;
    if !scp.status.success() {
        return Err(format!(
            "deploy failed: {}",
            String::from_utf8_lossy(&scp.stderr)
        ));
    }

    // 2. Start the agent on the VM, recording its PID for scoped cleanup.
    if !ssh(&format!(
        "chmod +x /tmp/conwrt-agent && \
         /tmp/conwrt-agent --listen 0.0.0.0:8400 --insecure-allow-non-loopback \
         --capability serial:uarts=2 --capability link-probe \
         --capability tftp-server > /tmp/agent.log 2>&1 & echo $! > {VM_PIDFILE}"
    )) {
        return Err("agent start failed".into());
    }
    std::thread::sleep(Duration::from_secs(1));

    // 3. Tunnel: host:$tunnel_port → vm:8400. A port already held by
    // another listener (another session's tunnel) is a reported error,
    // not a silent collision.
    let tp = tunnel_port();
    if TcpStream::connect(("127.0.0.1", tp)).is_ok() {
        return Err(format!(
            "tunnel port {tp} is already in use (another session's tunnel?) — \
             set CONWRT_VM_TUNNEL_PORT"
        ));
    }
    let tunnel = Command::new("ssh")
        .args(vm_ssh_args())
        .args([format!("-L{tp}:localhost:8400"), "-N".into()])
        .spawn()
        .map_err(|e| format!("tunnel spawn failed: {e}"))?;
    std::thread::sleep(Duration::from_secs(1));

    // 4. Verify the tunnel reaches the agent
    if TcpStream::connect(("127.0.0.1", tp)).is_err() {
        return Err("tunnel not reachable after start".into());
    }

    Ok(AgentOnVm {
        tunnel: Some(tunnel),
    })
}

#[tokio::test]
async fn agent_on_openwrt_vm_full_protocol_surface() {
    if std::env::var("CONWRT_QEMU_VM").ok().as_deref() != Some("1") {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set");
        return;
    }
    if !vm_reachable() {
        eprintln!("skipping: VM not reachable on 127.0.0.1:{}", vm_ssh_port());
        return;
    }

    // Past the gate: setup failures FAIL the test (a green run that
    // exercised none of the protocol surface is the bug this guards).
    let _cleanup = deploy_and_start().expect("QEMU E2E setup failed");

    use conwrt_agent_proto::controller::AgentClient;
    use conwrt_agent_proto::protocol::{DisconnectPolicy, LeaseResponse};

    let mut client = AgentClient::connect(&format!("127.0.0.1:{}", tunnel_port()))
        .await
        .unwrap();

    // --- Handshake + capabilities ---
    let caps = client.handshake("host-controller").await.unwrap();
    assert!(caps.len() >= 3, "expected >=3 capabilities, got {caps:?}");
    assert!(caps.iter().any(|c| c.name == "serial"));
    assert!(caps.iter().any(|c| c.name == "link-probe"));
    assert!(caps.iter().any(|c| c.name == "tftp-server"));
    eprintln!("handshake OK: {} capabilities", caps.len());

    // --- Lease lifecycle ---
    let resp = client
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "uart0".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Abort,
        })
        .await
        .unwrap();
    assert!(matches!(resp, LeaseResponse::Granted { .. }));
    client.heartbeat(1).await.unwrap();
    client.release_lease(1).await.unwrap();
    eprintln!("lease lifecycle OK");

    // --- Streaming: upload, kill, reconnect, resume ---
    const CHUNK: usize = 1024;
    const TOTAL: usize = 16 * 1024;
    let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();

    client
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "flash/test".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Complete,
        })
        .await
        .unwrap();

    // Send half, kill, reconnect, resume.
    let half = TOTAL / 2;
    for offset in (0..half).step_by(CHUNK) {
        let ack = client
            .send_chunk(conwrt_agent_proto::protocol::StreamChunk {
                transfer_id: 1,
                offset: offset as u64,
                total: Some(TOTAL as u64),
                data: payload[offset..offset + CHUNK].to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(ack.contiguous as usize, offset + CHUNK);
    }
    drop(client);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Reconnect through the tunnel (agent survives: state is Arc<Mutex<>>).
    let mut c2 = AgentClient::connect(&format!("127.0.0.1:{}", tunnel_port()))
        .await
        .unwrap();
    c2.handshake("host-controller-resume").await.unwrap();

    let status = c2.stream_status(1).await.unwrap();
    assert_eq!(status.contiguous as usize, half);
    assert!(!status.done);

    for offset in (half..TOTAL).step_by(CHUNK) {
        let end = (offset + CHUNK).min(TOTAL);
        let ack = c2
            .send_chunk(conwrt_agent_proto::protocol::StreamChunk {
                transfer_id: 1,
                offset: offset as u64,
                total: Some(TOTAL as u64),
                data: payload[offset..end].to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(ack.contiguous as usize, end);
        if end == TOTAL {
            assert!(ack.done);
        }
    }

    let final_status = c2.stream_status(1).await.unwrap();
    assert!(final_status.done);
    eprintln!("streaming with kill+resume OK ({} bytes)", TOTAL);
}
