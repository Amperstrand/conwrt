//! The recovery HTTP POST pump (#226 slice 1).
//!
//! Staged on purpose — the firmware drives it from its session loop
//! (accept a chunk, drain into the request body, repeat), so nothing
//! here owns an executor or a socket lifecycle:
//!
//! 1. [`RecoveryPost::start`] writes the request head — only after the
//!    first chunk announced `total` (`Content-Length` is exact; U-Boot's
//!    uIP httpd has no chunked encoding).
//! 2. [`RecoveryPost::pump`] moves buffered window bytes into the body.
//!    Backpressure is structural: the window is bounded, and the
//!    controller is lock-step, so the body advances only as fast as the
//!    agent drains.
//! 3. [`RecoveryPost::finish`] requires the transfer complete, writes
//!    the multipart footer, then reads the server's verdict to EOF
//!    (U-Boot FINs after the response body).
//!
//! One-request contract (AGENTS.md): there is no GET/probe path in this
//! API at all. The POST is the first and only request; once
//! [`RecoveryPost::start`] has written, a mid-body failure is a burned
//! recovery window (re-arm = power-cycle into recovery) — the caller's
//! lease policy owns that fact (ADR-0004 §5 `Complete` semantics).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::multipart::Multipart;
use crate::transfer::TransferState;

/// Async byte transport to the recovery server (AFIT per ADR-0002 —
/// firmware monomorphizes over its embassy-net socket; host tests over
/// tokio TCP). Connected when handed to the pump.
#[allow(async_fn_in_trait)]
pub trait HttpIo {
    /// Transport error type.
    type Error;

    /// Write the whole buffer or fail.
    ///
    /// # Errors
    /// Transport failure mid-body — a burned window (see module docs).
    async fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Read the response body to EOF (the server FINs when done).
    ///
    /// # Errors
    /// Transport failure before EOF.
    async fn read_response(&mut self, out: &mut Vec<u8>) -> Result<(), Self::Error>;
}

/// Why a post did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostError {
    /// Transport failure while writing (`op` names the stage).
    Write {
        /// Stage that failed: `"head"`, `"body"` or `"footer"`.
        op: &'static str,
    },
    /// Transport failure reading the verdict.
    Read,
    /// [`finish`] called before the transfer was complete — nothing
    /// was committed; drain the rest first.
    Incomplete {
        /// Bytes received so far.
        received: u64,
        /// Announced total.
        total: u64,
    },
    /// [`start`] called before the first chunk arrived (no `total`,
    /// no `Content-Length`).
    NoTotal,
    /// [`start`] called twice.
    AlreadyStarted,
}

/// The server's verdict on a completed upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The model's `upload_response_pattern` matched (D-Link:
    /// "Upgrade successfully!").
    Accepted,
    /// The response was HTML (1.x treats any HTML reply as accepted).
    AcceptedHtml,
    /// Server responded, but the body matched no acceptance shape.
    Rejected {
        /// First bytes of the response, for logs.
        snippet: String,
    },
    /// Connection closed with no response (the burned-window shape:
    /// a one-request server that already served — or refused — its
    /// one request).
    NoResponse,
}

/// Result of a finished post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostOutcome {
    /// Image bytes that reached the body.
    pub uploaded: u64,
    /// The verdict.
    pub verdict: Verdict,
}

/// Response text the model JSONs mark as acceptance
/// (`upload_response_pattern`, dlink-covr-x1860-a1).
pub const ACCEPT_PATTERN: &str = "Upgrade successfully!";

/// The staged recovery POST.
pub struct RecoveryPost<'a> {
    mp: Multipart<'a>,
    host: String,
    endpoint: String,
    started: bool,
    written: u64,
}

impl<'a> RecoveryPost<'a> {
    /// New post over a prepared [`Multipart`] framing.
    ///
    /// `host` is used for the `Host:` header (U-Boot's uIP stack does
    /// not parse it, but browsers send it and 1.x parity is free).
    /// `endpoint` is the model's `upload_endpoint` (`"/upload"`).
    #[must_use]
    pub fn new(mp: Multipart<'a>, host: &str, endpoint: &str) -> Self {
        Self {
            mp,
            host: String::from(host),
            endpoint: String::from(endpoint),
            started: false,
            written: 0,
        }
    }

    /// Write the request head. Requires the transfer to know its
    /// `total` (first chunk received) — nothing goes on the wire
    /// before the exact `Content-Length` is known.
    ///
    /// Headers mirror the proven 1.x curl invocation: no `Expect:`
    /// (U-Boot does not speak 100-continue) and `Connection: close`.
    pub async fn start(
        &mut self,
        io: &mut impl HttpIo,
        xfer: &TransferState,
    ) -> Result<(), PostError> {
        if self.started {
            return Err(PostError::AlreadyStarted);
        }
        let Some(total) = xfer.total() else {
            return Err(PostError::NoTotal);
        };
        let head = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            self.endpoint,
            self.host,
            self.mp.content_type(),
            self.mp.content_len(),
        );
        io.write_all(head.as_bytes())
            .await
            .map_err(|_| PostError::Write { op: "head" })?;
        io.write_all(&self.mp.header())
            .await
            .map_err(|_| PostError::Write { op: "head" })?;
        self.written += self.mp.header().len() as u64;
        self.started = true;
        let _ = total;
        Ok(())
    }

    /// Whether [`start`](Self::start) has written the head (the
    /// point of no return for the one-request window).
    pub fn committed(&self) -> bool {
        self.started
    }

    /// Move buffered window bytes into the request body. Call after
    /// each accepted chunk; backpressure ends when the window empties.
    pub async fn pump(
        &mut self,
        io: &mut impl HttpIo,
        xfer: &mut TransferState,
    ) -> Result<u64, PostError> {
        let mut buf = [0u8; 1024];
        let mut moved = 0u64;
        loop {
            let n = xfer.drain(&mut buf);
            if n == 0 {
                return Ok(moved);
            }
            io.write_all(&buf[..n])
                .await
                .map_err(|_| PostError::Write { op: "body" })?;
            self.written += n as u64;
            moved += n as u64;
        }
    }

    /// Write the footer and read the verdict. Requires the transfer
    /// complete (fully drained) — an incomplete body would desync the
    /// one-request server, so it is refused before any wire bytes.
    pub async fn finish(
        &mut self,
        io: &mut impl HttpIo,
        xfer: &TransferState,
    ) -> Result<PostOutcome, PostError> {
        let Some(total) = xfer.total() else {
            return Err(PostError::NoTotal);
        };
        if !xfer.is_complete() {
            return Err(PostError::Incomplete {
                received: xfer.ack().contiguous,
                total,
            });
        }
        io.write_all(&self.mp.footer())
            .await
            .map_err(|_| PostError::Write { op: "footer" })?;
        self.written += self.mp.footer().len() as u64;

        let mut response = Vec::new();
        match io.read_response(&mut response).await {
            Ok(()) => {
                let text = String::from_utf8_lossy(&response).into_owned();
                let verdict = if text.contains(ACCEPT_PATTERN) {
                    Verdict::Accepted
                } else if text
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("<!doctype")
                    || text.trim_start().to_ascii_lowercase().starts_with("<html")
                {
                    Verdict::AcceptedHtml
                } else {
                    Verdict::Rejected {
                        snippet: text.chars().take(80).collect(),
                    }
                };
                Ok(PostOutcome {
                    uploaded: total,
                    verdict,
                })
            }
            // Distinguish "closed with nothing" (burned window) from a
            // read error after partial data: read_response only errors
            // on transport failure; an empty-but-Ok body means the
            // server hung up silently — same burned-window shape.
            Err(_) if response.is_empty() => Ok(PostOutcome {
                uploaded: total,
                verdict: Verdict::NoResponse,
            }),
            Err(_) => Err(PostError::Read),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory IO: records writes, replays a canned response.
    struct MemIo {
        written: Vec<u8>,
        response: Vec<u8>,
        fail_writes: bool,
    }

    impl HttpIo for MemIo {
        type Error = ();
        async fn write_all(&mut self, data: &[u8]) -> Result<(), ()> {
            if self.fail_writes {
                return Err(());
            }
            self.written.extend_from_slice(data);
            Ok(())
        }
        async fn read_response(&mut self, out: &mut Vec<u8>) -> Result<(), ()> {
            if self.response.is_empty() {
                return Err(());
            }
            out.extend_from_slice(&self.response);
            Ok(())
        }
    }

    fn mp() -> Multipart<'static> {
        Multipart {
            boundary: "----WebKitFormBoundary0123456789abcdef",
            field: "firmware",
            filename: "recovery.bin",
            image_len: 6,
        }
    }

    fn fed_transfer() -> TransferState {
        let mut t = TransferState::new(1, 64);
        t.accept(&conwrt_agent_proto::protocol::StreamChunk {
            transfer_id: 1,
            offset: 0,
            total: Some(6),
            data: alloc::vec![0xAA; 6],
        })
        .unwrap();
        t
    }

    #[tokio::test]
    async fn head_shape_matches_1x_curl_semantics() {
        let mut io = MemIo {
            written: Vec::new(),
            response: b"Upgrade successfully!".to_vec(),
            fail_writes: false,
        };
        let mut t = fed_transfer();
        let mut post = RecoveryPost::new(mp(), "192.168.0.1", "/upload");
        post.start(&mut io, &t).await.unwrap();
        let head = String::from_utf8_lossy(&io.written).into_owned();
        assert!(head.starts_with("POST /upload HTTP/1.1\r\n"));
        assert!(head.contains("Host: 192.168.0.1\r\n"));
        assert!(head.contains(
            "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary0123456789abcdef\r\n"
        ));
        assert!(head.contains(&format!("Content-Length: {}\r\n", mp().content_len())));
        assert!(head.contains("Connection: close\r\n"));
        assert!(!head.to_ascii_lowercase().contains("expect:")); // no 100-continue
        assert!(head.ends_with("\r\n\r\n"));
        // head write includes the multipart part header after the blank line
        assert!(io.written.ends_with(b"application/octet-stream\r\n\r\n"));
        let _ = &mut t;
    }

    #[tokio::test]
    async fn full_post_body_and_verdict() {
        let mut io = MemIo {
            written: Vec::new(),
            response: b"<html>Upgrade successfully!</html>".to_vec(),
            fail_writes: false,
        };
        let mut t = fed_transfer();
        let mut post = RecoveryPost::new(mp(), "192.168.0.1", "/upload");
        post.start(&mut io, &t).await.unwrap();
        assert!(post.committed());
        assert_eq!(post.pump(&mut io, &mut t).await.unwrap(), 6);
        let outcome = post.finish(&mut io, &t).await.unwrap();
        assert_eq!(outcome.uploaded, 6);
        assert_eq!(outcome.verdict, Verdict::Accepted);

        // body assembled on the wire: header + 6 bytes + footer, tail-aligned
        let mp = mp();
        let hdr = mp.header();
        let ftr = mp.footer();
        let w = &io.written;
        assert!(w.ends_with(&ftr));
        let payload_start = w.len() - ftr.len() - 6;
        let hdr_start = payload_start - hdr.len();
        assert_eq!(&w[hdr_start..payload_start], &hdr[..]);
        assert_eq!(&w[payload_start..payload_start + 6], &[0xAA; 6]);
    }

    #[tokio::test]
    async fn finish_refuses_incomplete_transfer_before_wire() {
        let mut io = MemIo {
            written: Vec::new(),
            response: Vec::new(),
            fail_writes: false,
        };
        let mut t = TransferState::new(1, 64);
        t.accept(&conwrt_agent_proto::protocol::StreamChunk {
            transfer_id: 1,
            offset: 0,
            total: Some(10),
            data: alloc::vec![1, 2, 3],
        })
        .unwrap();
        let mut post = RecoveryPost::new(
            Multipart {
                image_len: 10,
                ..mp()
            },
            "192.168.0.1",
            "/upload",
        );
        post.start(&mut io, &t).await.unwrap();
        post.pump(&mut io, &mut t).await.unwrap();
        let before = io.written.len();
        assert_eq!(
            post.finish(&mut io, &t).await,
            Err(PostError::Incomplete {
                received: 3,
                total: 10
            })
        );
        assert_eq!(io.written.len(), before, "no footer bytes on refusal");
    }

    #[tokio::test]
    async fn start_requires_total_and_once_only() {
        let mut io = MemIo {
            written: Vec::new(),
            response: Vec::new(),
            fail_writes: false,
        };
        let t = TransferState::new(1, 64); // no chunk yet
        let mut post = RecoveryPost::new(mp(), "h", "/upload");
        assert_eq!(post.start(&mut io, &t).await, Err(PostError::NoTotal));

        let t2 = fed_transfer();
        post.start(&mut io, &t2).await.unwrap();
        assert_eq!(
            post.start(&mut io, &t2).await,
            Err(PostError::AlreadyStarted)
        );
    }

    #[tokio::test]
    async fn empty_response_is_burned_window_verdict() {
        let mut io = MemIo {
            written: Vec::new(),
            response: Vec::new(),
            fail_writes: false,
        };
        let mut t = fed_transfer();
        let mut post = RecoveryPost::new(mp(), "h", "/upload");
        post.start(&mut io, &t).await.unwrap();
        post.pump(&mut io, &mut t).await.unwrap();
        let outcome = post.finish(&mut io, &t).await.unwrap();
        assert_eq!(outcome.verdict, Verdict::NoResponse);
    }
}
