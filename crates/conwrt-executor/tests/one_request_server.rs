//! HIL ring-1 suite (#226 slice 1): the executor pump against a
//! **one-request U-Boot recovery mock** over real localhost TCP.
//!
//! The mock lives in `common` (shared with the ring-2 lossy-resume
//! experiments in `lossy_resume.rs`); its one-request contract is
//! documented there.

mod common;

use common::{RequestRecord, await_records, connect, framing, image, spawn_mock, verdict_page};
use conwrt_agent_proto::protocol::StreamChunk;
use conwrt_executor::transfer::TransferState;
use conwrt_executor::{RecoveryPost, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Drive one full POST (start → pump → finish) against the mock and
/// return the outcome — shared by the bounded-retention regressions.
async fn run_one_post(addr: std::net::SocketAddr, img: &[u8]) -> conwrt_executor::PostOutcome {
    let (mp, _) = framing(img.len());
    let mut xfer = TransferState::new(1, 8 * 1024);
    let mut io = connect(addr).await;
    let mut post = RecoveryPost::new(mp, "192.168.0.1", "/upload");
    let mut sent = 0usize;
    while sent < img.len() {
        let end = (sent + 4096).min(img.len());
        xfer.accept(&StreamChunk {
            transfer_id: 1,
            offset: sent as u64,
            total: Some(img.len() as u64),
            data: img[sent..end].to_vec(),
        })
        .expect("accept");
        if !post.committed() {
            post.start(&mut io, &xfer).await.expect("start");
        }
        post.pump(&mut io, &mut xfer).await.expect("pump");
        sent = end;
    }
    post.finish(&mut io, &xfer).await.expect("finish")
}

#[tokio::test]
async fn full_image_streams_through_bounded_window_to_one_post() {
    let img = image(1024 * 1024);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let (addr, shared) = spawn_mock(expected);

    // executor side: 8 KiB window, lock-step chunks of 4 KiB
    let mut xfer = TransferState::new(1, 8 * 1024);
    let mut io = connect(addr).await;
    let mut post = RecoveryPost::new(mp, "192.168.0.1", "/upload");

    let mut sent = 0usize;
    let mut started = false;
    while sent < img.len() {
        let end = (sent + 4096).min(img.len());
        xfer.accept(&StreamChunk {
            transfer_id: 1,
            offset: sent as u64,
            total: Some(img.len() as u64),
            data: img[sent..end].to_vec(),
        })
        .expect("accept");
        if !started {
            post.start(&mut io, &xfer).await.expect("start");
            started = true;
        }
        post.pump(&mut io, &mut xfer).await.expect("pump");
        sent = end;
    }
    let outcome = post.finish(&mut io, &xfer).await.expect("finish");

    assert_eq!(outcome.uploaded, img.len() as u64);
    assert_eq!(outcome.verdict, Verdict::Accepted);

    await_records(&shared, 1).await;
    {
        let rec = shared.lock().expect("mock lock");
        assert_eq!(
            rec.requests,
            vec![RequestRecord::PostAccepted {
                payload_bytes: img.len()
            }]
        );
        assert!(rec.burned, "the good POST consumed the one-request window");
    }

    // a second connection finds the window closed: dropped before any
    // request can be served
    let mut second = connect(addr).await;
    let mut sink = Vec::new();
    second.0.read_to_end(&mut sink).await.expect("EOF");
    assert!(sink.is_empty(), "no second serving");
}

#[tokio::test]
async fn get_before_post_burns_the_window() {
    let img = image(2048);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let (addr, shared) = spawn_mock(expected);

    // the sinner: GET first (exactly what AGENTS.md forbids)
    let mut sinner = connect(addr).await;
    AsyncWriteExt::write_all(
        &mut sinner.0,
        b"GET / HTTP/1.1\r\nHost: 192.168.0.1\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect("send GET");
    let mut response = Vec::new();
    sinner.0.read_to_end(&mut response).await.expect("read EOF");
    assert!(
        response.is_empty(),
        "one-request server never answers a GET"
    );

    // the subsequent correct POST finds a burned window: the server
    // drops the connection before the request head can even land
    let mut xfer = TransferState::new(1, 4096);
    xfer.accept(&StreamChunk {
        transfer_id: 1,
        offset: 0,
        total: Some(img.len() as u64),
        data: img.clone(),
    })
    .expect("accept");
    let mut io = connect(addr).await;
    let mut post = RecoveryPost::new(mp, "192.168.0.1", "/upload");
    // Transport-level outcome races with the server's RST: the head
    // write may fail outright, or land in the socket buffer and only
    // the response read reveals the burn. Both mean the same thing.
    match post.start(&mut io, &xfer).await {
        Err(conwrt_executor::PostError::Write { op: "head" }) => {}
        Ok(()) => {
            post.pump(&mut io, &mut xfer).await.expect("pump");
            let outcome = post.finish(&mut io, &xfer).await.expect("finish");
            assert_eq!(outcome.verdict, Verdict::NoResponse, "burned window");
        }
        other => panic!("unexpected start outcome: {other:?}"),
    }

    let rec = shared.lock().expect("mock lock");
    assert!(rec.burned);
    assert_eq!(rec.requests.len(), 1);
    assert!(matches!(
        &rec.requests[0],
        RequestRecord::Violation { method } if method.starts_with("GET ")
    ));
}

#[tokio::test]
async fn dropped_mid_post_body_burns_the_window() {
    let img = image(64 * 1024);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let (addr, shared) = spawn_mock(expected);

    let mut xfer = TransferState::new(1, 8 * 1024);
    let mut io = connect(addr).await;
    let mut post = RecoveryPost::new(mp, "192.168.0.1", "/upload");

    // feed and pump only half the image, then drop the connection
    // mid-body (the documented unrecoverable case, #226)
    let half = img.len() / 2;
    let mut sent = 0usize;
    while sent < half {
        let end = (sent + 4096).min(half);
        xfer.accept(&StreamChunk {
            transfer_id: 1,
            offset: sent as u64,
            total: Some(img.len() as u64),
            data: img[sent..end].to_vec(),
        })
        .expect("accept");
        if !post.committed() {
            post.start(&mut io, &xfer).await.expect("start");
        }
        post.pump(&mut io, &mut xfer).await.expect("pump");
        sent = end;
    }
    drop(io); // controller/stream loss mid-body
    drop(post);

    // give the mock thread a moment to observe EOF
    for _ in 0..50 {
        if shared.lock().expect("mock lock").burned {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let rec = shared.lock().expect("mock lock");
    assert!(rec.burned);
    assert!(matches!(
        &rec.requests[0],
        RequestRecord::PartialBurn { got, wanted } if *got < *wanted && *wanted > img.len() / 2
    ));
}

#[tokio::test]
async fn replay_from_stale_ack_before_post_is_clean() {
    let img = image(32 * 1024);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let (addr, shared) = spawn_mock(expected);

    // pre-drop phase: a 4 KiB prefix received (window holds it whole,
    // no wire bytes — the POST has not started), then the controller
    // drops. On reconnect it replays from its STALE ack point 0 (full
    // overlap that must be trimmed), the POST starts, and the rest
    // streams through the bounded window as usual.
    let mut xfer = TransferState::new(1, 8 * 1024);
    let ack_point = {
        let ack = xfer
            .accept(&StreamChunk {
                transfer_id: 1,
                offset: 0,
                total: Some(img.len() as u64),
                data: img[..4096].to_vec(),
            })
            .expect("prefix accept");
        ack.contiguous
    };
    assert_eq!(ack_point, 4096);

    // "drop + reconnect": replay from 0 (stale ack), then the rest,
    // starting and pumping the POST as chunks arrive
    let mut io = connect(addr).await;
    let mut post = RecoveryPost::new(mp, "192.168.0.1", "/upload");
    let mut offset = 0usize;
    while offset < img.len() {
        let end = (offset + 4096).min(img.len());
        xfer.accept(&StreamChunk {
            transfer_id: 1,
            offset: offset as u64,
            total: Some(img.len() as u64),
            data: img[offset..end].to_vec(),
        })
        .expect("replay accept");
        if !post.committed() {
            post.start(&mut io, &xfer).await.expect("start");
        }
        post.pump(&mut io, &mut xfer).await.expect("pump");
        offset = end;
    }
    let outcome = post.finish(&mut io, &xfer).await.expect("finish");
    assert_eq!(outcome.verdict, Verdict::Accepted);

    await_records(&shared, 1).await;
    let rec = shared.lock().expect("mock lock");
    assert_eq!(
        rec.requests,
        vec![RequestRecord::PostAccepted {
            payload_bytes: img.len()
        }],
        "the replay cost exactly one POST of the full image"
    );
}

#[tokio::test]
async fn oversized_response_with_early_pattern_accepts_with_bounded_retention() {
    // review round 2: a wrong-scale response (64 KiB) with the verdict
    // at its head must not grow the verdict buffer unbounded — drain
    // to EOF, retain the first MAX_VERDICT_BYTES, classify Accepted.
    let img = image(2048);
    let (_, mut expected) = framing(img.len());
    expected.image = img.clone();
    let mut body = b"<html><body>Upgrade successfully!</body></html>".to_vec();
    body.extend_from_slice(&vec![b'x'; 64 * 1024]);
    expected.response = verdict_page(&body);
    let (addr, shared) = spawn_mock(expected);

    let outcome = run_one_post(addr, &img).await;
    assert_eq!(outcome.verdict, Verdict::Accepted);

    await_records(&shared, 1).await;
    let rec = shared.lock().expect("mock lock");
    assert!(matches!(
        rec.requests[0],
        RequestRecord::PostAccepted { .. }
    ));
}

#[tokio::test]
async fn oversized_response_with_pattern_beyond_cap_degrades_to_rejected() {
    // the accept pattern lands PAST the retention cap (the
    // unexpected-HTTP-server shape): the retained prefix classifies
    // Rejected with a snippet — the reader never hunts for the
    // pattern by growing past the bound.
    let img = image(2048);
    let (_, mut expected) = framing(img.len());
    expected.image = img.clone();
    let mut body = vec![b'x'; 64 * 1024];
    body.extend_from_slice(b"<html>Upgrade successfully!</html>");
    expected.response = verdict_page(&body);
    let (addr, _shared) = spawn_mock(expected);

    let outcome = run_one_post(addr, &img).await;
    match outcome.verdict {
        Verdict::Rejected { snippet } => assert!(snippet.starts_with('x')),
        other => panic!("pattern beyond the cap must not be hunted: {other:?}"),
    }
}
