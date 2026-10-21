//! HIL-style suite for the [`ExecutorTransfer`] bridge (#226 slice 3):
//! stream frames driven through the **real** `ServerCore` dispatch —
//! handshake → exclusive executor lease → `StreamChunk`/`StreamStatus`
//! — exactly the path the F746 firmware wires up, asserted on the
//! controller-visible results (acks, errors, lease gating).

use conwrt_agent_proto::dispatch::{WireEndpoint, WireError, WireFrame, WireResult};
use conwrt_agent_proto::protocol::{
    CapabilityInfo, DisconnectPolicy, HandshakeRequest, LeaseRequest, PROTOCOL_VERSION, StreamAck,
    StreamChunk,
};
use conwrt_agent_proto::server::{ServerCore, TransferSink};
use conwrt_executor::ExecutorTransfer;

fn core(capacity: usize) -> ServerCore {
    ServerCore::with_transfer(
        "executor-bridge-test 0.1",
        Vec::from([CapabilityInfo {
            name: String::from("executor"),
            detail: Vec::new(),
        }]),
        Box::new(ExecutorTransfer::new(capacity)),
    )
}

fn handshake(core: &mut ServerCore) -> WireResult {
    request(
        core,
        1,
        WireEndpoint::Handshake(HandshakeRequest {
            protocol_version: PROTOCOL_VERSION,
            controller_id: String::from("laptop"),
        }),
    )
}

fn request(core: &mut ServerCore, id: u32, endpoint: WireEndpoint) -> WireResult {
    core.handle_frame(WireFrame::Request { id, endpoint })
        .map(|f| match f {
            WireFrame::Response { result, .. } => result,
            _ => unreachable!("requests must answer with a Response"),
        })
        .unwrap()
}

fn lease_executor(core: &mut ServerCore, exclusive: bool, policy: DisconnectPolicy) -> WireResult {
    request(
        core,
        2,
        WireEndpoint::LeaseAcquire(LeaseRequest {
            resource: String::from("executor"),
            exclusive,
            on_disconnect: policy,
        }),
    )
}

fn chunk(core: &mut ServerCore, id: u32, c: StreamChunk) -> Result<StreamAck, WireError> {
    match request(core, id, WireEndpoint::StreamChunk(c)) {
        WireResult::StreamAck(ack) => Ok(ack),
        WireResult::Error(e) => Err(e),
        other => panic!("expected stream ack or error, got {other:?}"),
    }
}

fn sample_chunk(transfer_id: u64, offset: u64, data: Vec<u8>, total: u64) -> StreamChunk {
    StreamChunk {
        transfer_id,
        offset,
        total: Some(total),
        data,
    }
}

#[test]
fn chunks_flow_through_dispatch_with_resume_acks() {
    let mut c = core(8192);
    handshake(&mut c);
    assert!(matches!(
        lease_executor(&mut c, true, DisconnectPolicy::Complete),
        WireResult::Lease(conwrt_agent_proto::protocol::LeaseResponse::Granted { .. })
    ));

    let ack = chunk(&mut c, 3, sample_chunk(1, 0, vec![0xAA; 4096], 8192)).expect("accept");
    assert_eq!(ack.transfer_id, 1);
    assert_eq!(ack.contiguous, 4096);
    assert!(!ack.done);

    // stale-ack replay trimmed, then the tail: done
    let ack = chunk(&mut c, 4, sample_chunk(1, 0, vec![0xAA; 4096], 8192)).expect("replay accept");
    assert_eq!(ack.contiguous, 4096, "replay adds nothing");
    let ack = chunk(&mut c, 5, sample_chunk(1, 4096, vec![0xBB; 4096], 8192)).expect("tail accept");
    assert_eq!(ack.contiguous, 8192);
    assert!(ack.done);

    // status mirrors the resume token through dispatch
    match request(&mut c, 6, WireEndpoint::StreamStatus { transfer_id: 1 }) {
        WireResult::StreamAck(ack) => {
            assert_eq!(ack.contiguous, 8192);
            assert!(ack.done);
        }
        other => panic!("status must ack, got {other:?}"),
    }
}

#[test]
fn stream_endpoints_are_lease_gated_through_dispatch() {
    let mut c = core(64);
    handshake(&mut c);
    assert_eq!(
        chunk(&mut c, 3, sample_chunk(1, 0, vec![1, 2, 3], 3)),
        Err(WireError::LeaseRequired(String::from("executor"))),
        "no lease: refused"
    );
    match request(&mut c, 4, WireEndpoint::StreamStatus { transfer_id: 1 }) {
        WireResult::Error(WireError::LeaseRequired(res)) => assert_eq!(res, "executor"),
        other => panic!("status gated too, got {other:?}"),
    }
}

#[test]
fn wrong_transfer_resets_the_window_through_dispatch() {
    let mut c = core(64);
    handshake(&mut c);
    lease_executor(&mut c, true, DisconnectPolicy::Complete);

    // first transfer partially received
    chunk(&mut c, 3, sample_chunk(7, 0, vec![1, 2, 3], 5)).unwrap();
    // a NEW controller/transfer id: fresh window, old id unknown
    let ack = chunk(&mut c, 4, sample_chunk(2, 0, vec![9, 9], 4)).expect("reset accept");
    assert_eq!(ack.transfer_id, 2);
    assert_eq!(ack.contiguous, 2);

    match request(&mut c, 5, WireEndpoint::StreamStatus { transfer_id: 7 }) {
        WireResult::Error(WireError::UnknownTransfer(7)) => {}
        other => panic!("old transfer gone after reset, got {other:?}"),
    }
    match request(&mut c, 6, WireEndpoint::StreamStatus { transfer_id: 2 }) {
        WireResult::StreamAck(ack) => assert_eq!(ack.contiguous, 2),
        other => panic!("new transfer live, got {other:?}"),
    }
}

#[test]
fn window_backpressure_and_errors_surface_through_dispatch() {
    let mut c = core(4);
    handshake(&mut c);
    lease_executor(&mut c, true, DisconnectPolicy::Complete);

    chunk(&mut c, 3, sample_chunk(1, 0, vec![0; 4], 8)).unwrap();
    let err = chunk(&mut c, 4, sample_chunk(1, 4, vec![0; 4], 8)).unwrap_err();
    match &err {
        WireError::Internal(msg) => assert!(msg.contains("window full"), "got {msg}"),
        other => panic!("backpressure surfaced as Internal, got {other:?}"),
    }

    // gap: reconnecting controller replaying beyond the window point
    let err = chunk(&mut c, 5, sample_chunk(1, 6, vec![0; 2], 8)).unwrap_err();
    match &err {
        WireError::Internal(msg) => assert!(msg.contains("gap"), "got {msg}"),
        other => panic!("gap surfaced as Internal, got {other:?}"),
    }
}

#[test]
fn reset_session_frees_the_executor_lease_for_the_next_controller() {
    // lease semantics with the sink attached: disconnect drops the
    // lease (Abort is not legal for executor, Complete survives only
    // in-flight work) — the next controller re-leases and re-streams
    // from scratch (fresh window via the WrongTransfer reset).
    let mut c = core(64);
    handshake(&mut c);
    lease_executor(&mut c, true, DisconnectPolicy::Complete);
    chunk(&mut c, 3, sample_chunk(1, 0, vec![1, 2, 3], 10)).unwrap();

    c.reset_session();
    assert_eq!(
        chunk(&mut c, 4, sample_chunk(1, 3, vec![4], 10)),
        Err(WireError::NotHandshaked),
        "session reset closes the gate"
    );

    handshake(&mut c);
    assert!(
        matches!(
            lease_executor(&mut c, true, DisconnectPolicy::Complete),
            WireResult::Lease(conwrt_agent_proto::protocol::LeaseResponse::Granted { .. })
        ),
        "lease is free again after disconnect"
    );
    // the WINDOW survived the disconnect (the resume-token contract):
    // the reconnecting controller continues at its ack point
    let ack = chunk(&mut c, 5, sample_chunk(1, 3, vec![4], 10)).expect("resume");
    assert_eq!(ack.transfer_id, 1);
    assert_eq!(ack.contiguous, 4);
    // a NEW controller's fresh transfer id gets the WrongTransfer reset
    let ack = chunk(&mut c, 6, sample_chunk(2, 0, vec![7, 7], 4)).expect("fresh window");
    assert_eq!(ack.transfer_id, 2);
    assert_eq!(ack.contiguous, 2);
}

// TransferSink is object-safe and Send through the Box the firmware
// hands to ServerCore (compile-time check mirroring the app wiring).
#[test]
fn sink_boxes_into_server_core() {
    let sink: Box<dyn TransferSink> = Box::new(ExecutorTransfer::new(8));
    let _core = ServerCore::with_transfer("boxed", Vec::new(), sink);
}
