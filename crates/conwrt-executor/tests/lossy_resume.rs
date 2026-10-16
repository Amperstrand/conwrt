//! HIL ring-2 (#226 resume-under-churn): the executor pump against the
//! one-request mock **through a lossy localhost proxy** — the
//! executable design for the M6 validation ladder's second ring.
//!
//! The proxy (`lossy_proxy`) deterministically aborts connections at
//! chosen forwarded-WRITE byte offsets (and can delay every forwarded
//! chunk), so each loss point below is reproducible, not raced:
//!
//! | scenario | loss point (client→mock bytes forwarded) | controller answer | mock record | outcome |
//! |---|---|---|---|---|
//! | pre-POST loss | 0 — connection dead before any POST byte; upstream never dialed | reconnect, resume feeding from its last ack, fresh POST | exactly one `PostAccepted` (full image) | `Accepted` — the loss is invisible to the one-request window |
//! | post-head loss | 4096 — head landed, ~3.8 KiB of body landed, then both directions aborted | wire error mid-pump (or a failed/`NoResponse` finish); a retry POST is probed once | exactly one `PartialBurn` (`0 < got < wanted`) | window burned **for good** — retry never accepted |
//! | control | none, every forwarded chunk delayed 1 ms | normal lock-step | exactly one `PostAccepted` | `Accepted` — the proxy itself is faithful |
//!
//! The dividing line the experiments pin down: a connection loss is
//! recoverable by replay **only while no POST byte has reached the
//! device** (`start` not yet attempted — the window still holds every
//! received byte from offset 0). Once the request head has landed, the
//! one-request window is burned and no controller-side replay can save
//! the attempt — re-arm (power-cycle into recovery) is the only path.

mod common;
// The proxy is a sibling of the shared mock under tests/common/ so it
// can never be picked up by cargo as its own integration-test target.
#[path = "common/lossy_proxy.rs"]
mod lossy_proxy;

use std::sync::Mutex;
use std::time::Duration;

use common::{RequestRecord, Shared, await_records, connect, framing, image, spawn_mock};
use conwrt_agent_proto::protocol::StreamChunk;
use conwrt_executor::transfer::TransferState;
use conwrt_executor::{RecoveryPost, Verdict};
use lossy_proxy::{KillPoint, LossConfig, LossyProxy, spawn_lossy_proxy};

/// Deterministic barrier: wait until the proxy has killed `conn`.
async fn await_conn_killed(proxy: &LossyProxy, conn: usize) {
    for _ in 0..200 {
        let killed = proxy
            .shared
            .lock()
            .expect("proxy lock")
            .conns
            .get(conn)
            .is_some_and(|c| c.killed_at.is_some());
        if killed {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("proxy never killed connection {conn}");
}

/// Deterministic barrier: wait until the mock has burned its window.
async fn await_burned(shared: &Mutex<Shared>) {
    for _ in 0..200 {
        if shared.lock().expect("mock lock").burned {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("mock never burned its window");
}

#[tokio::test]
async fn pre_post_loss_replays_from_last_ack_into_exactly_one_accepted_post() {
    let img = image(32 * 1024);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let body_len = expected.content_len as u64;
    let (mock_addr, shared) = spawn_mock(expected);

    // connection 0 dies on accept (0 bytes forwarded, upstream never
    // dialed); connection 1 is clean but every forwarded WRITE chunk
    // pays a 2 ms delay — one configuration, both loss knobs exercised.
    let proxy = spawn_lossy_proxy(
        mock_addr,
        LossConfig {
            kills: vec![KillPoint {
                connection: 0,
                after_client_bytes: 0,
            }],
            chunk_delay: Duration::from_millis(2),
        },
    );

    // stream mid-flight into the window: a 4 KiB prefix is received and
    // acked, the POST has NOT started — no head bytes exist anywhere.
    let mut xfer = TransferState::new(1, 8 * 1024);
    let ack = xfer
        .accept(&StreamChunk {
            transfer_id: 1,
            offset: 0,
            total: Some(img.len() as u64),
            data: img[..4096].to_vec(),
        })
        .expect("prefix accept");
    let last_ack = ack.contiguous;
    assert_eq!(last_ack, 4096);

    // the controller holds a connection while the stream is in flight;
    // the proxy kills it mid-stream. Nothing was ever written on it.
    let io0 = connect(proxy.addr).await;
    await_conn_killed(&proxy, 0).await;
    drop(io0);

    // proof the loss is invisible to the device-side contract: the mock
    // still has its one request window fully armed.
    {
        let rec = shared.lock().expect("mock lock");
        assert!(!rec.burned, "a pre-POST loss must not burn the window");
        assert!(rec.requests.is_empty());
    }

    // reconnect and replay from the controller's LAST ACK: feeding
    // resumes at the acked offset (the window still holds 0..4096
    // undrained, so the fresh POST carries the full body from offset 0),
    // start + pump proceed as on any clean connection.
    let mut io1 = connect(proxy.addr).await;
    let mut post = RecoveryPost::new(mp, "192.168.0.1", "/upload");
    let mut offset = last_ack as usize;
    while offset < img.len() {
        let end = (offset + 4096).min(img.len());
        xfer.accept(&StreamChunk {
            transfer_id: 1,
            offset: offset as u64,
            total: Some(img.len() as u64),
            data: img[offset..end].to_vec(),
        })
        .expect("resume accept");
        if !post.committed() {
            post.start(&mut io1, &xfer)
                .await
                .expect("start after reconnect");
        }
        post.pump(&mut io1, &mut xfer).await.expect("pump");
        offset = end;
    }
    let outcome = post.finish(&mut io1, &xfer).await.expect("finish");
    assert_eq!(outcome.verdict, Verdict::Accepted);
    assert_eq!(outcome.uploaded, img.len() as u64);

    // exactly ONE accepted POST — the replay cost nothing at the device
    await_records(&shared, 1).await;
    {
        let rec = shared.lock().expect("mock lock");
        assert_eq!(
            rec.requests,
            vec![RequestRecord::PostAccepted {
                payload_bytes: img.len()
            }],
            "the pre-POST loss plus replay completed with exactly one accepted POST"
        );
        assert!(rec.burned, "the good POST consumed the window");
    }
    let conns = &proxy.shared.lock().expect("proxy lock").conns;
    assert_eq!(conns.len(), 2);
    assert!(
        !conns[0].dialed,
        "the killed connection never reached the mock"
    );
    assert_eq!(conns[0].killed_at, Some(0));
    assert_eq!(conns[0].forwarded, 0);
    assert!(conns[1].dialed);
    assert_eq!(conns[1].killed_at, None);
    assert!(
        conns[1].forwarded >= body_len,
        "the replayed POST carried the full body"
    );
}

#[tokio::test]
async fn post_head_loss_under_proxy_burns_window_for_good() {
    let img = image(64 * 1024);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let (mock_addr, shared) = spawn_mock(expected);

    // kill connection 0 after 4096 forwarded client bytes — past the
    // request head (~310 B) and into the body. Both directions abort at
    // exactly that offset: the mock has a landed head + a partial body.
    let proxy = spawn_lossy_proxy(
        mock_addr,
        LossConfig {
            kills: vec![KillPoint {
                connection: 0,
                after_client_bytes: 4096,
            }],
            chunk_delay: Duration::ZERO,
        },
    );

    let mut xfer = TransferState::new(1, 8 * 1024);
    let mut io0 = connect(proxy.addr).await;
    let mut post = RecoveryPost::new(mp, "192.168.0.1", "/upload");
    let mut lost = false;
    let mut offset = 0usize;
    while offset < img.len() {
        let end = (offset + 4096).min(img.len());
        xfer.accept(&StreamChunk {
            transfer_id: 1,
            offset: offset as u64,
            total: Some(img.len() as u64),
            data: img[offset..end].to_vec(),
        })
        .expect("accept");
        if !post.committed() {
            post.start(&mut io0, &xfer).await.expect("start");
        }
        if post.pump(&mut io0, &mut xfer).await.is_err() {
            // the abort surfaces as a WRITE error mid-body
            lost = true;
            break;
        }
        offset = end;
    }
    if !lost {
        // or every write buffered locally and the loss only surfaces at
        // the verdict — either way the mock never saw a complete body
        if let Ok(outcome) = post.finish(&mut io0, &xfer).await {
            assert_ne!(
                outcome.verdict,
                Verdict::Accepted,
                "a killed body must never be accepted"
            );
        }
    }
    drop(io0);

    await_burned(&shared).await;
    {
        let rec = shared.lock().expect("mock lock");
        assert!(rec.burned, "the landed head burned the one-request window");
        assert_eq!(rec.requests.len(), 1);
        // got > 0 proves the head parsed and body bytes arrived — this
        // is the "AFTER the POST head" class, not the pre-POST one
        assert!(matches!(
            &rec.requests[0],
            RequestRecord::PartialBurn { got, wanted }
                if *got > 0 && *got < *wanted
        ));
    }
    {
        let conns = &proxy.shared.lock().expect("proxy lock").conns;
        assert_eq!(
            conns[0].killed_at,
            Some(4096),
            "kill landed at the exact offset"
        );
        assert_eq!(conns[0].forwarded, 4096);
        assert!(conns[0].dialed);
    }

    // the controller's retry POST — from the transfer's point of view
    // it still holds buffered bytes and may try again. The burned
    // window refuses it: no stage of the retry ever reaches Accepted.
    let (mp2, _) = framing(img.len());
    let mut io1 = connect(proxy.addr).await;
    let mut post2 = RecoveryPost::new(mp2, "192.168.0.1", "/upload");
    let accepted = post2.start(&mut io1, &xfer).await.is_ok()
        && post2.pump(&mut io1, &mut xfer).await.is_ok()
        && matches!(
            post2.finish(&mut io1, &xfer).await,
            Ok(outcome) if outcome.verdict == Verdict::Accepted
        );
    assert!(
        !accepted,
        "a retry after a landed head must never be accepted"
    );
}

#[tokio::test]
async fn clean_delayed_proxy_still_completes_one_accepted_post() {
    let img = image(128 * 1024);
    let (mp, mut expected) = framing(img.len());
    expected.image = img.clone();
    let body_len = expected.content_len as u64;
    let (mock_addr, shared) = spawn_mock(expected);

    // control configuration: no kills, but every forwarded WRITE chunk
    // is delayed 1 ms — the proxy must stay faithful under added
    // latency, or the two experiments above prove nothing.
    let proxy = spawn_lossy_proxy(
        mock_addr,
        LossConfig {
            kills: vec![],
            chunk_delay: Duration::from_millis(1),
        },
    );

    let mut xfer = TransferState::new(1, 8 * 1024);
    let mut io = connect(proxy.addr).await;
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
        .expect("accept");
        if !post.committed() {
            post.start(&mut io, &xfer).await.expect("start");
        }
        post.pump(&mut io, &mut xfer).await.expect("pump");
        offset = end;
    }
    let outcome = post.finish(&mut io, &xfer).await.expect("finish");
    assert_eq!(outcome.verdict, Verdict::Accepted);

    await_records(&shared, 1).await;
    {
        let rec = shared.lock().expect("mock lock");
        assert_eq!(
            rec.requests,
            vec![RequestRecord::PostAccepted {
                payload_bytes: img.len()
            }],
            "the proxy forwards a full image byte-exactly"
        );
    }
    let conns = &proxy.shared.lock().expect("proxy lock").conns;
    assert_eq!(conns.len(), 1);
    assert!(conns[0].dialed);
    assert_eq!(conns[0].killed_at, None);
    assert!(conns[0].forwarded >= body_len);
}
