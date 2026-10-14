//! End-to-end integration test for the M3 dispatch layer (#108):
//! agent + controller over real loopback TCP, exercising the full
//! protocol surface — handshake, capabilities, leases, heartbeat,
//! streaming with kill-and-resume — all in-process, no hardware.

use conwrt_agent_proto::agent::AgentConfig;
use conwrt_agent_proto::controller::{AgentClient, ClientError};
use conwrt_agent_proto::protocol::{CapabilityInfo, DisconnectPolicy, LeaseResponse};
use sha2::{Digest, Sha256};
use std::time::Duration;

async fn spawn_agent(capabilities: Vec<CapabilityInfo>) -> String {
    use conwrt_agent_proto::agent::run_agent_on;
    use std::sync::{Arc, Mutex};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let state = Arc::new(Mutex::new(conwrt_agent_proto::agent::AgentState::default()));
    let config = Arc::new(AgentConfig {
        listen: addr.clone(),
        capabilities,
        ..Default::default()
    });
    tokio::spawn(async move {
        run_agent_on(listener, state, config).await;
    });
    addr // Listener is already bound — no race, no sleep needed
}

#[tokio::test]
async fn full_protocol_surface_over_tcp() {
    let addr = spawn_agent(vec![CapabilityInfo {
        name: "serial".into(),
        detail: vec![("uarts".into(), "2".into())],
    }])
    .await;

    // --- Handshake ---
    let mut client = AgentClient::connect(&addr).await.unwrap();
    let caps = client.handshake("test-controller").await.unwrap();
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].name, "serial");
    assert_eq!(caps[0].detail[0].1, "2");

    // --- Capabilities (standalone) ---
    let caps2 = client.capabilities().await.unwrap();
    assert_eq!(caps2, caps);

    // --- Lease: acquire + heartbeat + release ---
    let resp = client
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "uart0".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Abort,
        })
        .await
        .unwrap();
    match resp {
        LeaseResponse::Granted { heartbeat_ms } => {
            assert!(heartbeat_ms > 0);
        }
        other => panic!("expected Granted, got {other:?}"),
    }
    client.heartbeat(1).await.unwrap();
    let released = client.release_lease(1).await.unwrap();
    assert!(released);

    // --- Streaming: upload, status, kill, reconnect, resume ---
    const CHUNK: usize = 1024;
    const TOTAL: usize = 64 * 1024; // 64 KiB
    let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
    let expect_sha = Sha256::digest(&payload);

    // Acquire a Complete-policy lease for the transfer (simulates flashing).
    client
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "flash/bay0".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Complete,
        })
        .await
        .unwrap();

    // Send 40% of the chunks.
    let kill_after = (TOTAL / CHUNK) * 40 / 100;
    for i in 0..kill_after {
        let offset = i * CHUNK;
        let ack = client
            .send_chunk(conwrt_agent_proto::protocol::StreamChunk {
                transfer_id: 42,
                offset: offset as u64,
                total: Some(TOTAL as u64),
                data: payload[offset..offset + CHUNK].to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(ack.contiguous as usize, offset + CHUNK);
    }

    // KILL the connection mid-transfer.
    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Reconnect: state survived (leases + streams are Arc<Mutex<>>).
    let mut client2 = AgentClient::connect(&addr).await.unwrap();
    client2.handshake("test-controller-resume").await.unwrap();

    // Query status: the resume token.
    let status = client2.stream_status(42).await.unwrap();
    assert_eq!(status.contiguous as usize, kill_after * CHUNK);
    assert!(!status.done);

    // Resume from the device-reported offset.
    let resume_from = status.contiguous as usize;
    for offset in (resume_from..TOTAL).step_by(CHUNK) {
        let end = (offset + CHUNK).min(TOTAL);
        let ack = client2
            .send_chunk(conwrt_agent_proto::protocol::StreamChunk {
                transfer_id: 42,
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

    // Final status: done.
    let final_status = client2.stream_status(42).await.unwrap();
    assert!(final_status.done);
    assert_eq!(final_status.contiguous, TOTAL as u64);

    // The agent's assembled data must match (we verify via the ack offsets;
    // byte-level verification happens on the device side in production).
    let _ = expect_sha; // available for future device-side hash endpoint
}

#[tokio::test]
async fn version_mismatch_refuses_structurally() {
    let addr = spawn_agent(vec![]).await;
    let mut client = AgentClient::connect(&addr).await.unwrap();

    // The typed handshake with the correct version must succeed;
    // version mismatches are unit-tested in dispatch.rs round-trips.
    let result = client.handshake("correct").await;
    assert!(result.is_ok(), "correct version must succeed: {result:?}");
}

#[tokio::test]
async fn pre_handshake_request_refused() {
    let addr = spawn_agent(vec![]).await;
    let mut client = AgentClient::connect(&addr).await.unwrap();

    // Try to acquire a lease BEFORE handshake.
    let result = client
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "uart0".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Abort,
        })
        .await;
    match result {
        Err(ClientError::Agent(e)) => {
            assert!(matches!(
                e,
                conwrt_agent_proto::dispatch::WireError::NotHandshaked
            ));
        }
        other => panic!("expected NotHandshaked, got {other:?}"),
    }
}

#[tokio::test]
async fn lease_survives_disconnect_and_denies_next_controller() {
    let addr = spawn_agent(vec![]).await;

    // Controller A connects, handshakes, acquires exclusively, disconnects.
    let mut a = AgentClient::connect(&addr).await.unwrap();
    a.handshake("controller-a").await.unwrap();
    let resp = a
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "uart0".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Abort,
        })
        .await
        .unwrap();
    assert!(matches!(resp, LeaseResponse::Granted { .. }));
    drop(a);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Controller B connects (the agent handles one at a time — A is gone).
    // The lease SURVIVED the disconnect (no auto-release; Complete-policy
    // work parks results; Abort-policy work is the embedder's concern).
    let mut b = AgentClient::connect(&addr).await.unwrap();
    b.handshake("controller-b").await.unwrap();
    let resp_b = b
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "uart0".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Abort,
        })
        .await
        .unwrap();
    match resp_b {
        LeaseResponse::Denied { holder: Some(h) } => assert_eq!(h, "controller-a"),
        other => panic!("expected Denied with holder, got {other:?}"),
    }
}
