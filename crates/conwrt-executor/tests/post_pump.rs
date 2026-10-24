//! HIL for the [`PostPump`] orchestrator (#226 slice 4a): the
//! sink-window → wire composition the F746 task loop will run. Rings
//! reuse the shared one-request mock and the ring-2 lossy proxy:
//!
//! - lock-step feeding through [`ExecutorTransfer::window`] drives
//!   exactly one accepted POST with the verdict in the pump;
//! - an uncommitted pump re-targets a reset window (new controller,
//!   no wire bytes yet); a committed one answers [`PumpStep::Superseded`];
//! - the pre-device connection loss (ring-2's kill-at-accept) burns
//!   nothing: a fresh pump over a fresh transfer id completes the POST
//!   on the still-unburned window;
//! - the full `ServerCore` dispatch composition — the verbatim recipe
//!   for the future `main.rs` wiring.

mod common;
#[path = "common/lossy_proxy.rs"]
mod lossy_proxy;

use std::time::Duration;

use common::{RequestRecord, await_records, connect, framing, image, spawn_mock};
use conwrt_agent_proto::protocol::StreamChunk;
use conwrt_agent_proto::server::TransferSink;
use conwrt_executor::{ExecutorTransfer, PostPump, PumpStep, Verdict};
use lossy_proxy::{KillPoint, LossConfig, spawn_lossy_proxy};

const WINDOW: usize = 8 * 1024;

/// The mock validates framing byte-for-byte: the pump must speak the
/// exact boundary `framing()` built the expectation with.
fn pump(boundary: &str) -> PostPump<'_> {
    PostPump::new("192.168.0.1", "/upload", boundary)
}

fn chunk(transfer_id: u64, offset: u64, data: &[u8], total: u64) -> StreamChunk {
    StreamChunk {
        transfer_id,
        offset,
        total: Some(total),
        data: data.to_vec(),
    }
}

#[tokio::test]
async fn full_image_pumps_in_lockstep_to_one_post() {
    let img = image(16 * 1024);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let (addr, shared) = spawn_mock(expected);

    let mut sink = ExecutorTransfer::new(WINDOW);
    let mut io = connect(addr).await;
    let mut pump = pump(mp.boundary);
    assert!(!pump.committed());

    let mut off = 0usize;
    loop {
        let end = (off + 4096).min(img.len());
        sink.stream_chunk(&chunk(1, off as u64, &img[off..end], img.len() as u64))
            .expect("accept");
        let step = pump.step(&mut io, sink.window()).await.expect("step");
        off = end;
        match step {
            PumpStep::Streaming { drained } => {
                assert!(drained > 0);
                assert_eq!(sink.window().expect("bound").buffered(), 0);
                assert!(pump.committed(), "head went out with the first step");
            }
            PumpStep::Posted(outcome) => {
                assert_eq!(off, img.len());
                assert_eq!(outcome.verdict, Verdict::Accepted);
                assert_eq!(outcome.uploaded, img.len() as u64);
                assert_eq!(pump.verdict(), Some(&outcome));
                break;
            }
            other => panic!("unexpected step: {other:?}"),
        }
    }

    // terminal: further steps replay the verdict, wire stays quiet
    let again = pump.step(&mut io, sink.window()).await.expect("step");
    assert_eq!(
        again,
        pump.verdict()
            .cloned()
            .map(PumpStep::Posted)
            .expect("verdict")
    );

    await_records(&shared, 1).await;
    let rec = shared.lock().expect("mock lock");
    assert_eq!(
        rec.requests,
        vec![RequestRecord::PostAccepted {
            payload_bytes: img.len()
        }]
    );
    assert!(rec.burned);
}

#[tokio::test]
async fn step_without_a_window_is_idle() {
    let img = image(2048);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let (addr, shared) = spawn_mock(expected);

    let mut sink = ExecutorTransfer::new(WINDOW);
    let mut io = connect(addr).await;
    let mut pump = pump(mp.boundary);

    assert_eq!(
        pump.step(&mut io, sink.window()).await.expect("idle"),
        PumpStep::Idle
    );
    assert!(!pump.committed());

    // the pump sent nothing: while the connection stays open the mock
    // is deterministically blocked in its header read with zero bytes,
    // so nothing is recorded. (Asserting AFTER a drop raced the mock
    // thread's close-handling — which records a Violation burn for an
    // empty connection per the one-request contract — and lost under
    // parallel workspace load.)
    {
        let rec = shared.lock().expect("mock lock");
        assert!(rec.requests.is_empty() && !rec.burned);
    }
    drop(io);
}

#[tokio::test]
async fn uncommitted_pump_retargets_a_reset_window() {
    let img = image(4096);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let (addr, shared) = spawn_mock(expected);

    let mut sink = ExecutorTransfer::new(WINDOW);
    // a first controller binds id 7 with a partial chunk — NEVER stepped,
    // so nothing touched the wire
    sink.stream_chunk(&chunk(7, 0, &img[..1024], 8192))
        .expect("accept");
    // new controller, new id: fresh window at 0 (the WrongTransfer reset)
    sink.stream_chunk(&chunk(2, 0, &img, img.len() as u64))
        .expect("reset accepts");

    let mut io = connect(addr).await;
    let mut pump = pump(mp.boundary);
    let step = pump.step(&mut io, sink.window()).await.expect("step");
    let PumpStep::Posted(outcome) = step else {
        panic!("complete transfer finishes in one step: {step:?}")
    };
    assert_eq!(outcome.verdict, Verdict::Accepted);

    await_records(&shared, 1).await;
    let rec = shared.lock().expect("mock lock");
    assert_eq!(
        rec.requests,
        vec![RequestRecord::PostAccepted {
            payload_bytes: img.len()
        }],
        "the abandoned id-7 bytes never reached the wire"
    );
}

#[tokio::test]
async fn committed_pump_answers_superseded_on_reset() {
    let img = image(16 * 1024);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let (addr, shared) = spawn_mock(expected);

    let mut sink = ExecutorTransfer::new(WINDOW);
    let mut io = connect(addr).await;
    let mut pump = pump(mp.boundary);

    sink.stream_chunk(&chunk(7, 0, &img[..4096], img.len() as u64))
        .expect("accept");
    let step = pump.step(&mut io, sink.window()).await.expect("started");
    assert!(matches!(step, PumpStep::Streaming { .. }));
    assert!(pump.committed());

    // the window resets under the committed pump (new controller/id)
    sink.stream_chunk(&chunk(2, 0, &img[..2048], 2048))
        .expect("reset accepts");
    let step = pump.step(&mut io, sink.window()).await.expect("step");
    assert_eq!(step, PumpStep::Superseded);

    // the started POST is abandoned mid-body: the mock burns on EOF
    drop(io);
    for _ in 0..200 {
        if shared.lock().expect("mock lock").burned {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let rec = shared.lock().expect("mock lock");
    assert!(rec.burned);
    assert!(matches!(
        &rec.requests[0],
        RequestRecord::PartialBurn { got, wanted } if *got < *wanted
    ));
}

#[tokio::test]
async fn pre_device_connection_loss_composes_with_a_fresh_pump() {
    let img = image(4096);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let (addr, shared) = spawn_mock(expected);
    let proxy = spawn_lossy_proxy(
        addr,
        LossConfig {
            kills: vec![KillPoint {
                connection: 0,
                after_client_bytes: 0,
            }],
            chunk_delay: Duration::from_millis(0),
        },
    );

    let mut sink = ExecutorTransfer::new(WINDOW);
    sink.stream_chunk(&chunk(1, 0, &img, img.len() as u64))
        .expect("accept");

    // attempt 1 dies on accept: the device is never dialed. The dead
    // attempt surfaces as either shape (ring-2's race): a wire write
    // error, or locally-buffered writes + EOF read = `NoResponse` —
    // both mean the same thing, and NEITHER burned the device.
    let mut io1 = connect(proxy.addr).await;
    let mut pump1 = pump(mp.boundary);
    match pump1.step(&mut io1, sink.window()).await {
        Err(conwrt_executor::PostError::Write { .. }) => {}
        Ok(PumpStep::Posted(outcome)) => {
            assert_eq!(outcome.verdict, Verdict::NoResponse, "got {outcome:?}");
        }
        other => panic!("dead connection must write-fail or NoResponse: {other:?}"),
    }
    drop(io1);
    drop(pump1);
    {
        let proxy_shared = proxy.shared.lock().expect("proxy lock");
        assert!(!proxy_shared.conns[0].dialed, "upstream never dialed");
    }
    {
        let rec = shared.lock().expect("mock lock");
        assert!(
            !rec.burned && rec.requests.is_empty(),
            "device window intact"
        );
    }

    // attempt 2: the controller re-feeds from 0 under a FRESH transfer
    // id (the WrongTransfer reset) and a fresh pump completes the POST
    sink.stream_chunk(&chunk(2, 0, &img, img.len() as u64))
        .expect("reset accepts");
    let mut io2 = connect(addr).await;
    let mut pump2 = pump(mp.boundary);
    let step = pump2.step(&mut io2, sink.window()).await.expect("step");
    let PumpStep::Posted(outcome) = step else {
        panic!("fresh attempt completes: {step:?}")
    };
    assert_eq!(outcome.verdict, Verdict::Accepted);

    await_records(&shared, 1).await;
    let rec = shared.lock().expect("mock lock");
    assert_eq!(
        rec.requests,
        vec![RequestRecord::PostAccepted {
            payload_bytes: img.len()
        }],
        "exactly one POST — the killed attempt never reached the device"
    );
}

mod dispatch {
    use conwrt_agent_proto::dispatch::WireError;
    use conwrt_agent_proto::dispatch::{WireEndpoint, WireFrame, WireResult};
    use conwrt_agent_proto::protocol::{
        CapabilityInfo, DisconnectPolicy, HandshakeRequest, LeaseRequest, PROTOCOL_VERSION,
        StreamAck, StreamChunk,
    };
    use conwrt_agent_proto::server::{ServerCore, TransferSink};
    use conwrt_executor::{ExecutorTransfer, PostPump, PumpStep, Verdict};

    use std::sync::{Arc, Mutex};

    use crate::common::{RequestRecord, await_records, connect, framing, image, spawn_mock};

    const WINDOW: usize = 8 * 1024;

    /// The one window shared by dispatch and pump — the composition
    /// the F746 task loop runs (there as a single-task borrow; here as
    /// an Arc<Mutex>, the same mutual exclusion).
    #[derive(Clone)]
    struct SharedSink(Arc<Mutex<ExecutorTransfer>>);

    impl TransferSink for SharedSink {
        fn stream_chunk(&mut self, chunk: &StreamChunk) -> Result<StreamAck, WireError> {
            self.0.lock().expect("sink").stream_chunk(chunk)
        }
        fn stream_status(&mut self, transfer_id: u64) -> Result<StreamAck, WireError> {
            self.0.lock().expect("sink").stream_status(transfer_id)
        }
    }

    /// The verbatim firmware composition: real `ServerCore` dispatch
    /// lands chunks in the sink; the pump drains the same window to
    /// the wire. This is the recipe the F746 `main.rs` will run.
    ///
    /// The std `Mutex` guard rides across the await deliberately: it
    /// models the F746's single-task exclusive borrow of the window,
    /// on a current-thread runtime with no other task to deadlock.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn chunks_through_dispatch_pump_through_the_window() {
        let img = image(8 * 1024);
        let (mp, mut expected) = framing(img.len());
        expected.image = img.clone();
        let (addr, shared) = spawn_mock(expected);

        let sink = SharedSink(Arc::new(Mutex::new(ExecutorTransfer::new(WINDOW))));
        let mut core = ServerCore::with_transfer(
            "pump-hil 0.1",
            Vec::from([CapabilityInfo {
                name: String::from("executor"),
                detail: Vec::new(),
            }]),
            Box::new(sink.clone()),
        );
        let (ack, lease, chunk_id) = (1, 2, 3u32);
        request(
            &mut core,
            ack,
            WireEndpoint::Handshake(HandshakeRequest {
                protocol_version: PROTOCOL_VERSION,
                controller_id: String::from("laptop"),
            }),
        );
        request(
            &mut core,
            lease,
            WireEndpoint::LeaseAcquire(LeaseRequest {
                resource: String::from("executor"),
                exclusive: true,
                on_disconnect: DisconnectPolicy::Complete,
            }),
        );

        let mut io = connect(addr).await;
        let mut pump = PostPump::new("192.168.0.1", "/upload", mp.boundary);

        let mut off = 0usize;
        loop {
            let end = (off + 2048).min(img.len());
            let WireResult::StreamAck(ack) = request(
                &mut core,
                chunk_id + (off / 2048) as u32,
                WireEndpoint::StreamChunk(StreamChunk {
                    transfer_id: 1,
                    offset: off as u64,
                    total: Some(img.len() as u64),
                    data: img[off..end].to_vec(),
                }),
            ) else {
                panic!("chunk must ack");
            };
            let _: StreamAck = ack;
            let step = pump
                .step(&mut io, sink.0.lock().expect("sink").window())
                .await
                .expect("step");
            off = end;
            match step {
                PumpStep::Streaming { .. } => {}
                PumpStep::Posted(outcome) => {
                    assert_eq!(outcome.verdict, Verdict::Accepted);
                    assert_eq!(outcome.uploaded, img.len() as u64);
                    break;
                }
                other => panic!("unexpected step: {other:?}"),
            }
        }

        await_records(&shared, 1).await;
        let rec = shared.lock().expect("mock lock");
        assert_eq!(
            rec.requests,
            vec![RequestRecord::PostAccepted {
                payload_bytes: img.len()
            }]
        );
    }

    fn request(core: &mut ServerCore, id: u32, endpoint: WireEndpoint) -> WireResult {
        core.handle_frame(WireFrame::Request { id, endpoint })
            .map(|f| match f {
                WireFrame::Response { result, .. } => result,
                _ => unreachable!("requests must answer with a Response"),
            })
            .unwrap()
    }
}
