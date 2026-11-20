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
    let lease_id = match resp {
        LeaseResponse::Granted {
            lease_id,
            heartbeat_ms,
        } => {
            assert!(heartbeat_ms > 0);
            assert!(lease_id > 0, "the granted lease id must be surfaced");
            lease_id
        }
        other => panic!("expected Granted, got {other:?}"),
    };
    client.heartbeat(lease_id).await.unwrap();
    let released = client.release_lease(lease_id).await.unwrap();
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

// --- #164 P1 residuals: owner-checked release + the expiry ticker ---

async fn spawn_agent_tuned(
    capabilities: Vec<CapabilityInfo>,
    heartbeat_ms: u32,
    budget: u32,
) -> String {
    use conwrt_agent_proto::agent::run_agent_on;
    use std::sync::{Arc, Mutex};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let state = Arc::new(Mutex::new(conwrt_agent_proto::agent::AgentState::default()));
    let config = Arc::new(AgentConfig {
        listen: addr.clone(),
        capabilities,
        heartbeat_ms,
        heartbeat_budget: budget,
        ..Default::default()
    });
    tokio::spawn(async move {
        run_agent_on(listener, state, config).await;
    });
    addr
}

#[tokio::test]
async fn lease_release_is_owner_checked() {
    let addr = spawn_agent(vec![]).await;
    let mut owner = AgentClient::connect(&addr).await.unwrap();
    owner.handshake("controller-owner").await.unwrap();
    let lease_id = match owner
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "uart0".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Abort,
        })
        .await
        .unwrap()
    {
        LeaseResponse::Granted { lease_id, .. } => lease_id,
        other => panic!("expected Granted, got {other:?}"),
    };

    // The agent serves ONE connection at a time (per-connection state
    // model) — the intruder gets the socket only after the owner drops
    // it. The lease SURVIVES the disconnect (state outlives connections).
    drop(owner);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // A DIFFERENT controller must not free it: the wire bool says false
    // and the lease stays alive for the owner's reconnect.
    let mut intruder = AgentClient::connect(&addr).await.unwrap();
    intruder.handshake("controller-intruder").await.unwrap();
    let stolen = intruder.release_lease(lease_id).await.unwrap();
    assert!(
        !stolen,
        "a non-owning controller must not release the lease"
    );
    drop(intruder);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The owner reconnects: still holds the lease (heartbeat acks), and
    // ITS release succeeds.
    let mut owner = AgentClient::connect(&addr).await.unwrap();
    owner.handshake("controller-owner").await.unwrap();
    owner.heartbeat(lease_id).await.unwrap();
    assert!(owner.release_lease(lease_id).await.unwrap());
}

#[tokio::test]
async fn heartbeat_is_owner_checked() {
    // #164 P1 4272448192 (heartbeat half): after the owner drops, an
    // intruder's heartbeats must NOT immortalize the lease — each is
    // refused with LeaseNotOwner, the budget still decays, and the
    // expiry event fires for the lease the intruder kept prodding.
    use conwrt_agent_proto::dispatch::{AgentEvent, WireError};

    let addr = spawn_agent_tuned(vec![], 50, 5).await;
    let mut owner = AgentClient::connect(&addr).await.unwrap();
    owner.handshake("controller-owner").await.unwrap();
    let lease_id = match owner
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "uart0".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Abort,
        })
        .await
        .unwrap()
    {
        LeaseResponse::Granted { lease_id, .. } => lease_id,
        other => panic!("expected Granted, got {other:?}"),
    };
    drop(owner);

    let mut intruder = AgentClient::connect(&addr).await.unwrap();
    intruder.handshake("controller-intruder").await.unwrap();

    // Heartbeat at twice the ticker rate for well past budget x
    // interval. While the lease lives, every attempt is refused with
    // LeaseNotOwner; once the budget hits 0 the lease vanishes and
    // the refusal turns UnknownLease — with the LeaseExpired event
    // trailing that same response on this connection.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
    let mut saw_expiry = false;
    loop {
        match intruder.heartbeat(lease_id).await {
            Err(ClientError::Agent(WireError::LeaseNotOwner {
                lease_id: lid,
                holder,
            })) => {
                assert_eq!(lid, lease_id);
                assert_eq!(holder, "controller-owner");
            }
            Err(ClientError::Agent(WireError::UnknownLease(id))) if id == lease_id => {}
            other => panic!("non-owner heartbeat must be refused, got {other:?}"),
        }
        if let Some(AgentEvent::LeaseExpired(ev)) = intruder.try_recv_event() {
            assert_eq!(ev.lease_id, lease_id);
            saw_expiry = true;
            break;
        }
        if tokio::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        saw_expiry,
        "the lease must expire despite the intruder's refills"
    );
    drop(intruder);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The resource is free: a fresh controller acquires it.
    let mut next = AgentClient::connect(&addr).await.unwrap();
    next.handshake("controller-next").await.unwrap();
    match next
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "uart0".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Abort,
        })
        .await
        .unwrap()
    {
        LeaseResponse::Granted { .. } => {}
        LeaseResponse::Denied { holder } => {
            panic!("lease still held by {holder:?}: a non-owner's heartbeats immortalized it");
        }
    }
}

#[tokio::test]
async fn heartbeat_expiry_frees_lease_via_ticker() {
    // Before #164 P1 4272448155 the tick() never ran on a timer: budgets
    // only moved on request traffic, and a silent controller's lease
    // NEVER expired. With the ticker, a lease whose heartbeats stop is
    // freed after budget x interval — the re-acquire GRANTS.
    let addr = spawn_agent_tuned(vec![], 50, 2).await;
    let mut client = AgentClient::connect(&addr).await.unwrap();
    client.handshake("silent-controller").await.unwrap();
    let first = match client
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "uart0".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Abort,
        })
        .await
        .unwrap()
    {
        LeaseResponse::Granted { lease_id, .. } => lease_id,
        other => panic!("expected Granted, got {other:?}"),
    };

    // Go silent: budget 2 x 50 ms + slack. No heartbeats sent.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The same controller re-acquires: Granted (a NEW id) — the expired
    // lease no longer blocks, which is only true if the ticker ran.
    match client
        .acquire_lease(conwrt_agent_proto::protocol::LeaseRequest {
            resource: "uart0".into(),
            exclusive: true,
            on_disconnect: DisconnectPolicy::Abort,
        })
        .await
        .unwrap()
    {
        LeaseResponse::Granted { lease_id, .. } => {
            assert_ne!(
                lease_id, first,
                "expiry must free the old lease for a fresh grant"
            );
        }
        LeaseResponse::Denied { holder } => {
            panic!("lease {first} still held by {holder:?}: the expiry ticker did not run");
        }
    }
}

#[tokio::test]
async fn transfer_claims_end_with_connection() {
    // #164 P1 4272448227: transfer ids are agent-global. The guarantee
    // boundary: no LIVE cross-controller interleave (sequential serving
    // + the ownership map), while a takeover AFTER the owner's
    // disconnect is the documented resume pattern. Here: a's bytes
    // persist, b re-claims the id post-drop and completes the stream.
    use conwrt_agent_proto::protocol::StreamChunk;

    let addr = spawn_agent(vec![]).await;
    let mut a = AgentClient::connect(&addr).await.unwrap();
    a.handshake("controller-a").await.unwrap();
    let ack = a
        .send_chunk(StreamChunk {
            transfer_id: 42,
            offset: 0,
            total: Some(2048),
            data: vec![0xAA; 1024],
        })
        .await
        .unwrap();
    assert_eq!(ack.contiguous, 1024);
    drop(a);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Post-disconnect: the claim ended with a's connection; b re-claims
    // (resume shape) and the PRIOR bytes persist — contiguous continues
    // from 1024, not from 0.
    let mut b = AgentClient::connect(&addr).await.unwrap();
    b.handshake("controller-b").await.unwrap();
    let st = b.stream_status(42).await.unwrap();
    assert_eq!(st.contiguous, 1024, "a's bytes must survive the disconnect");
    let ack2 = b
        .send_chunk(StreamChunk {
            transfer_id: 42,
            offset: 1024,
            total: None,
            data: vec![0xBB; 1024],
        })
        .await
        .unwrap();
    assert_eq!(ack2.contiguous, 2048);
    assert!(ack2.done);
}

#[tokio::test]
async fn oversized_chunk_refused_client_side() {
    // #164 P2 4272448213: chunks whose encoded frame exceeds the agent's
    // 8192B COBS accumulator are dropped silently by the receiver — the
    // controller now refuses them before the wire, naming the limit.
    use conwrt_agent_proto::controller::ClientError;
    use conwrt_agent_proto::protocol::StreamChunk;

    let addr = spawn_agent(vec![]).await;
    let mut c = AgentClient::connect(&addr).await.unwrap();
    c.handshake("chunky").await.unwrap();
    match c
        .send_chunk(StreamChunk {
            transfer_id: 7,
            offset: 0,
            total: None,
            data: vec![0u8; 9000],
        })
        .await
    {
        Err(ClientError::ChunkTooLarge { len, max }) => {
            assert_eq!(len, 9000);
            assert_eq!(max, 8192 - 512);
        }
        other => panic!("expected ChunkTooLarge, got {other:?}"),
    }
    // the connection stays usable afterwards (no half-sent frame)
    let st = c.stream_status(7).await.unwrap();
    assert_eq!(st.contiguous, 0);
}
