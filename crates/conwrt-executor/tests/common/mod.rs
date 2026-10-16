//! Shared HIL fixtures: the one-request U-Boot recovery mock and the
//! controller-side helpers used by both the ring-1 suite
//! (`one_request_server.rs`) and the ring-2 lossy-resume experiments
//! (`lossy_resume.rs`).
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

use conwrt_executor::HttpIo;
use conwrt_executor::multipart::{Multipart, UPLOAD_FIELD};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What the mock observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestRecord {
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
pub struct Shared {
    /// Requests the mock served (or refused) so far.
    pub requests: Vec<RequestRecord>,
    /// Whether the one request window has been consumed — by the good
    /// POST or by a violation/burn. Further connections are dropped.
    pub burned: bool,
}

pub struct Expected {
    /// Full expected image.
    pub image: Vec<u8>,
    /// Exact multipart body size (the POST's `Content-Length`).
    pub content_len: usize,
    /// Expected multipart part header bytes.
    pub header: Vec<u8>,
    /// Expected multipart footer bytes.
    pub footer: Vec<u8>,
    /// The exact response bytes served after the good POST (default:
    /// the standard verdict page; oversized variants for the
    /// bounded-retention regression).
    pub response: Vec<u8>,
}

/// Spawn the one-request mock; returns `(address, shared)`.
pub fn spawn_mock(expected: Expected) -> (std::net::SocketAddr, Arc<Mutex<Shared>>) {
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

    let _ = stream.write_all(&expected.response);
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
pub struct TokioIo(pub tokio::net::TcpStream);

impl HttpIo for TokioIo {
    type Error = std::io::Error;
    async fn write_all(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        AsyncWriteExt::write_all(&mut self.0, data).await
    }
    async fn read_response(&mut self, out: &mut Vec<u8>) -> Result<(), std::io::Error> {
        // bounded retention like the firmware socket (review round 2):
        // drain to EOF, keep only the first MAX_VERDICT_BYTES
        let mut buf = [0u8; 512];
        loop {
            match self.0.read(&mut buf).await {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    conwrt_executor::post::retain_verdict_bytes(out, &buf[..n]);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Deterministic 1 MiB-ish image (xorshift, no deps).
pub fn image(len: usize) -> Vec<u8> {
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

/// Multipart framing + the mock's expectation for an image of
/// `image_len` bytes; callers fill `expected.image`.
pub fn framing(image_len: usize) -> (Multipart<'static>, Expected) {
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
        response: verdict_page(b"<html><body>Upgrade successfully!</body></html>"),
    };
    (mp, expected)
}

/// A standard U-Boot-style response page wrapping `body`.
pub fn verdict_page(body: &[u8]) -> Vec<u8> {
    let mut page = b"HTTP/1.0 200 OK\r\n\
                     Content-Type: text/html\r\n\
                     Connection: close\r\n\
                     \r\n"
        .to_vec();
    page.extend_from_slice(body);
    page
}

/// Wait until the mock thread has recorded `n` requests (the record is
/// pushed after the response write — a deliberate barrier for tests).
pub async fn await_records(shared: &Arc<Mutex<Shared>>, n: usize) {
    for _ in 0..200 {
        if shared.lock().expect("mock lock").requests.len() >= n {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Connect a tokio transport to a listening address.
pub async fn connect(addr: std::net::SocketAddr) -> TokioIo {
    TokioIo(
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect mock"),
    )
}
