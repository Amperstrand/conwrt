//! Round-trip integration tests for the M3 first slice (#108): the shared
//! COBS pump over real loopback TCP sockets, the version handshake message
//! set, and the lease table's controller-loss semantics — all in-process,
//! no hardware.

use conwrt_agent_proto::leases::{LeaseDenied, LeaseError, LeaseTable};
use conwrt_agent_proto::protocol::{
    CapabilityInfo, DisconnectPolicy, HandshakeError, HandshakeOk, HandshakeRequest, LeaseRequest,
    LeaseResponse, PROTOCOL_VERSION,
};
use conwrt_agent_proto::wire::{CobsReceiver, CobsSender};
use std::time::Duration;

#[tokio::test]
async fn cobs_pump_round_trips_frames_over_tcp() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut rx, tx) = socket.into_split();
        let mut recv = CobsReceiver::new();
        let frame = recv.receive(&mut rx).await.unwrap().expect("frame");
        // Echo it back through the sender.
        let mut sender = CobsSender::new(tx);
        sender.send(&frame).await.unwrap();
    });

    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut rx, tx) = socket.into_split();
    let mut sender = CobsSender::new(tx);
    // COBS-hostile payload: zero bytes and 0xff runs — the codec must
    // survive exactly the garbage a half-flashed device can emit.
    let payload: Vec<u8> = [0x00u8, 0xff, 0x00, 0x01, 0x02, 0xff, 0xff]
        .iter()
        .cycle()
        .take(4096)
        .copied()
        .collect();
    sender.send(&payload).await.unwrap();
    let mut recv = CobsReceiver::new();
    let echoed = recv.receive(&mut rx).await.unwrap().expect("echoed frame");
    assert_eq!(echoed, payload);
    server.await.unwrap();
}

#[test]
fn handshake_messages_round_trip_through_postcard() {
    let req = HandshakeRequest {
        protocol_version: PROTOCOL_VERSION,
        controller_id: "laptop-test".into(),
    };
    let bytes = postcard::to_stdvec(&req).unwrap();
    let back: HandshakeRequest = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(back, req);

    let ok = HandshakeOk {
        protocol_version: PROTOCOL_VERSION,
        agent_version: "0.1.0-test".into(),
        capabilities: vec![CapabilityInfo {
            name: "serial".into(),
            detail: vec![("uarts".into(), "2".into())],
        }],
    };
    let bytes = postcard::to_stdvec(&ok).unwrap();
    let back: HandshakeOk = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(back, ok);

    let err = HandshakeError::VersionMismatch {
        agent: 1,
        requested: 2,
    };
    let bytes = postcard::to_stdvec(&err).unwrap();
    let back: HandshakeError = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(back, err);
}

#[test]
fn lease_messages_round_trip() {
    let req = LeaseRequest {
        resource: "uart0".into(),
        exclusive: true,
        on_disconnect: DisconnectPolicy::Complete,
    };
    let back: LeaseRequest = postcard::from_bytes(&postcard::to_stdvec(&req).unwrap()).unwrap();
    assert_eq!(back, req);

    let granted = LeaseResponse::Granted { heartbeat_ms: 1000 };
    let back: LeaseResponse =
        postcard::from_bytes(&postcard::to_stdvec(&granted).unwrap()).unwrap();
    assert_eq!(back, granted);

    let denied = LeaseResponse::Denied {
        holder: Some("other-laptop".into()),
    };
    let back: LeaseResponse = postcard::from_bytes(&postcard::to_stdvec(&denied).unwrap()).unwrap();
    assert_eq!(back, denied);
}

#[test]
fn controller_death_policy_is_per_lease() {
    // The table must expose the policy so the agent's work manager knows
    // whether to abort or complete when the holder's lease expires.
    let mut t = LeaseTable::new();
    let abort_id = t
        .acquire("link-probe", "laptop", false, DisconnectPolicy::Abort, 1)
        .unwrap();
    let complete_id = t
        .acquire("flash/bay1", "laptop", true, DisconnectPolicy::Complete, 99)
        .unwrap();
    assert_eq!(
        t.get(abort_id).unwrap().on_disconnect,
        DisconnectPolicy::Abort
    );
    assert_eq!(
        t.get(complete_id).unwrap().on_disconnect,
        DisconnectPolicy::Complete
    );
    // probe lease dies on heartbeat timeout; flash lease survives.
    let expired = t.tick();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].lease_id, abort_id);
    assert!(t.get(complete_id).is_some());
}

#[test]
fn second_controller_sees_denial_path() {
    let mut t = LeaseTable::new();
    t.acquire("eth0", "controller-a", true, DisconnectPolicy::Abort, 5)
        .unwrap();
    match t.acquire("eth0", "controller-b", false, DisconnectPolicy::Abort, 5) {
        Err(LeaseError::Denied(LeaseDenied::HeldBy(h))) => assert_eq!(h, "controller-a"),
        other => panic!("expected HeldBy, got {other:?}"),
    }
}

#[tokio::test]
async fn pump_reports_clean_eof() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        // peer closes immediately
    });
    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut rx, _tx) = socket.into_split();
    let mut recv = CobsReceiver::new();
    let got = recv.receive(&mut rx).await.unwrap();
    assert!(got.is_none(), "clean EOF must surface as Ok(None)");
    let _ = server.await;
}

/// Framing self-synchronization check: garbage before a valid frame must
/// not destroy the following frame (COBS resync, ADR-0004 §2 rationale).
#[tokio::test]
async fn garbage_before_frame_resynchronizes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let (mut socket, _) = listener.accept().await.unwrap();
        // Realistic boot garbage: NOT COBS-encoded, but CONTAINS 0x00
        // delimiter bytes (real boot noise does — it is how COBS resyncs).
        // Known edge (documented): a zero-free garbage run would merge with
        // the following frame and lose BOTH — resync happens at the NEXT
        // delimiter, which zero-free noise delays.
        socket
            .write_all(&[0xde, 0x00, 0xad, 0xbe, 0x00, 0xef, 0x42, 0x00])
            .await
            .unwrap();
        // Then a proper COBS frame.
        let mut frame = cobs::encode_vec(b"survivor");
        frame.push(0);
        socket.write_all(&frame).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    });
    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut rx, _tx) = socket.into_split();
    let mut recv = CobsReceiver::new();
    // Keep receiving until EOF; the survivor frame must come through intact.
    let mut survivor = None;
    while let Some(frame) = recv.receive(&mut rx).await.unwrap() {
        if frame == b"survivor".to_vec() {
            survivor = Some(frame);
        }
    }
    assert_eq!(survivor, Some(b"survivor".to_vec()));
    let _ = server.await;
}
