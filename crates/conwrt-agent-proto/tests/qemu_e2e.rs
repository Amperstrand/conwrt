//! QEMU E2E: the conwrt-agent binary running on the OpenWrt VM, exercised
//! from this host through an SSH tunnel (#108 slice 3).
//!
//! Gated behind `CONWRT_QEMU_VM=1` — never runs in CI. Assumes:
//! - The OpenWrt 25.12.5 VM is up (SSH on 127.0.0.1:2222)
//! - The agent binary is cross-built: `cargo build --release -p conwrt-agent
//!   --target x86_64-unknown-linux-musl`
//!
//! The test handles the full lifecycle: deploy → start → tunnel → verify →
//! cleanup. If any step fails, the cleanup still runs.

use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::Duration;

const VM_SSH: &[&str] = &[
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=5",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-i",
    "tests/integration/.vm_ssh_key",
    "-p",
    "2222",
    "root@127.0.0.1",
];

const AGENT_BIN: &str = "/home/ubuntu/.cargo-target/x86_64-unknown-linux-musl/release/conwrt-agent";

fn vm_reachable() -> bool {
    TcpStream::connect(("127.0.0.1", 2222)).is_ok()
}

fn ssh(cmd: &str) -> bool {
    Command::new("ssh")
        .args(VM_SSH)
        .arg(cmd)
        .output()
        .is_ok_and(|o| o.status.success())
}

struct AgentOnVm {
    tunnel: Option<Child>,
}

impl Drop for AgentOnVm {
    fn drop(&mut self) {
        let _ = ssh("kill $(pgrep conwrt-agent) 2>/dev/null; true");
        if let Some(t) = &mut self.tunnel {
            let _ = t.kill();
            let _ = t.wait();
        }
    }
}

fn deploy_and_start() -> Option<AgentOnVm> {
    // 1. Deploy
    let scp = Command::new("scp")
        .args(["-O", "-q"])
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .arg("-i")
        .arg("tests/integration/.vm_ssh_key")
        .arg("-P")
        .arg("2222")
        .arg(AGENT_BIN)
        .arg("root@127.0.0.1:/tmp/conwrt-agent")
        .output()
        .ok()?;
    if !scp.status.success() {
        eprintln!("deploy failed: {}", String::from_utf8_lossy(&scp.stderr));
        return None;
    }

    // 2. Start the agent on the VM
    if !ssh(
        "chmod +x /tmp/conwrt-agent && /tmp/conwrt-agent --listen 0.0.0.0:8400 --capability serial:uarts=2 --capability link-probe --capability tftp-server > /tmp/agent.log 2>&1 &",
    ) {
        eprintln!("agent start failed");
        return None;
    }
    std::thread::sleep(Duration::from_secs(1));

    // 3. Tunnel: host:18400 → vm:8400
    let tunnel = Command::new("ssh")
        .args(VM_SSH)
        .args(["-L", "18400:localhost:8400", "-N"])
        .spawn()
        .ok()?;
    std::thread::sleep(Duration::from_secs(1));

    // 4. Verify the tunnel reaches the agent
    if TcpStream::connect(("127.0.0.1", 18400)).is_err() {
        eprintln!("tunnel not reachable");
        return None;
    }

    Some(AgentOnVm {
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
        eprintln!("skipping: VM not reachable on 127.0.0.1:2222");
        return;
    }

    let _cleanup = match deploy_and_start() {
        Some(c) => c,
        None => {
            eprintln!("skipping: deploy/start/tunnel failed");
            return;
        }
    };

    use conwrt_agent_proto::controller::AgentClient;
    use conwrt_agent_proto::protocol::{DisconnectPolicy, LeaseResponse};

    let mut client = AgentClient::connect("127.0.0.1:18400").await.unwrap();

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
    let mut c2 = AgentClient::connect("127.0.0.1:18400").await.unwrap();
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
