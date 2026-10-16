//! HIL ring-1 suite (#226 slice 1): the executor pump against a
//! **one-request U-Boot recovery mock** over real localhost TCP.
//!
//! The mock encodes the field-documented recovery-server contract
//! (AGENTS.md + model JSONs):
//!
//! - exactly one HTTP request is served, and it must be the POST —
//!   a GET (or anything non-POST) closes the connection with no
//!   response and burns the window;
//! - after serving (or burning) its one request, every further
//!   connection is dropped immediately;
//! - the body must be the exact WebKit-shaped multipart framing with
//!   the exact `Content-Length` (no chunked encoding, no `Expect:`);
//! - the verdict is an HTML page containing "Upgrade successfully!"
//!   followed by FIN.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use conwrt_agent_proto::protocol::StreamChunk;
use conwrt_executor::multipart::{Multipart, UPLOAD_FIELD};
use conwrt_executor::transfer::TransferState;
use conwrt_executor::{HttpIo, RecoveryPost, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What the mock observed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestRecord {
    /// The one good POST: full body matched the expected image.
    PostAccepted {
        /// Image bytes that arrived inside the multipart part.
        payload_bytes: usize,
    },
    /// A non-POST first request: connection closed, window burned.
    Violation {
        /// The request line that sinned.
        method: String,
    },
    /// A POST that did not deliver `Content-Length` bytes (client
    /// dropped mid-body): window burned.
    PartialBurn {
        /// Body bytes that did arrive.
        got: usize,
        /// Body bytes promised.
        wanted: usize,
    },
}

#[derive(Debug, Default)]
struct Shared {
    requests: Vec<RequestRecord>,
    /// Whether the one request window has been consumed — by the good
    /// POST or by a violation/burn. Further connections are dropped.
    burned: bool,
}

struct Expected {
    image: Vec<u8>,
    content_len: usize,
    header: Vec<u8>,
    footer: Vec<u8>,
}

/// Spawn the one-request mock; returns `(address, shared)`.
fn spawn_mock(expected: Expected) -> (std::net::SocketAddr, Arc<Mutex<Shared>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let shared = Arc::new(Mutex::new(Shared::default()));
    let shared2 = Arc::clone(&shared);
    std::thread::spawn(move || serve_forever(listener, expected, shared2));
    (addr, shared)
}

fn serve_forever(listener: TcpListener, expected: Expected, shared: Arc<Mutex<Shared>>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let already = shared.lock().expect("mock lock").burned;
        if already {
            // window burned/served: drop without reading
            let _ = stream.shutdown(std::net::Shutdown::Both);
            continue;
        }
        let outcome = serve_one(&mut stream, &expected);
        let mut shared = shared.lock().expect("mock lock");
        match outcome {
            Ok(()) => shared.requests.push(RequestRecord::PostAccepted {
                payload_bytes: expected.image.len(),
            }),
            Err(rec) => shared.requests.push(rec),
        }
        // the one request window is consumed either way
        shared.burned = true;
    }
}

/// Serve the single request on `stream`; `Err(record)` means burned.
fn serve_one(stream: &mut TcpStream, expected: &Expected) -> Result<(), RequestRecord> {
    let head = read_head(stream);
    let first_line = head.lines().next().unwrap_or_default().to_string();
    if !first_line.starts_with("POST ") {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(RequestRecord::Violation { method: first_line });
    }
    // no Expect: (100-continue) — U-Boot can't speak it
    if head.to_ascii_lowercase().contains("expect:") {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(RequestRecord::Violation {
            method: String::from("Expect-header"),
        });
    }
    let content_len: usize = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    if content_len != expected.content_len {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(RequestRecord::Violation {
            method: format!("content-length {content_len} != {}", expected.content_len),
        });
    }

    // stream the body, validating framing and hashing the payload
    let mut body = Vec::with_capacity(content_len.min(512 * 1024));
    body.resize(content_len, 0);
    let mut got = 0;
    while got < content_len {
        match stream.read(&mut body[got..]) {
            Ok(0) | Err(_) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Err(RequestRecord::PartialBurn {
                    got,
                    wanted: content_len,
                });
            }
            Ok(n) => got += n,
        }
    }

    let hdr = &expected.header;
    let ftr = &expected.footer;
    let framing_ok = body.starts_with(hdr)
        && body.ends_with(ftr)
        && body[hdr.len()..body.len() - ftr.len()] == expected.image[..];
    if !framing_ok {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Err(RequestRecord::Violation {
            method: String::from("multipart framing mismatch"),
        });
    }

    let resp = b"HTTP/1.0 200 OK\r\n\
                 Content-Type: text/html\r\n\
                 Connection: close\r\n\
                 \r\n\
                 <html><body>Upgrade successfully!</body></html>";
    let _ = stream.write_all(resp);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    Ok(())
}

fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => head.push(byte[0]),
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// HttpIo over tokio TCP (the pump's host-side transport).
struct TokioIo(tokio::net::TcpStream);

impl HttpIo for TokioIo {
    type Error = std::io::Error;
    async fn write_all(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        AsyncWriteExt::write_all(&mut self.0, data).await
    }
    async fn read_response(&mut self, out: &mut Vec<u8>) -> Result<(), std::io::Error> {
        self.0.read_to_end(out).await.map(|_| ())
    }
}

/// Deterministic 1 MiB-ish image (xorshift, no deps).
fn image(len: usize) -> Vec<u8> {
    let mut s = 0x1234_5678u32;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            (s >> 24) as u8
        })
        .collect()
}

const BOUNDARY: &str = "----WebKitFormBoundarye3b0c44298fc1c14";

fn framing(image_len: usize) -> (Multipart<'static>, Expected) {
    let mp = Multipart {
        boundary: BOUNDARY,
        field: UPLOAD_FIELD,
        filename: "recovery.bin",
        image_len: image_len as u64,
    };
    let expected = Expected {
        image: Vec::new(), // filled by caller
        content_len: mp.content_len().expect("sane test sizes") as usize,
        header: mp.header(),
        footer: mp.footer(),
    };
    (mp, expected)
}

/// Wait until the mock thread has recorded `n` requests (the record is
/// pushed after the response write — a deliberate barrier for tests).
async fn await_records(shared: &Arc<Mutex<Shared>>, n: usize) {
    for _ in 0..200 {
        if shared.lock().expect("mock lock").requests.len() >= n {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn connect(addr: std::net::SocketAddr) -> TokioIo {
    TokioIo(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect mock"),
    )
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
