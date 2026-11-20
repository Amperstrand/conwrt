//! The flash-trigger request — stage two of the GL.iNet recovery flow
//! (#232 P1 4298093559).
//!
//! Some U-Boot recovery httpds split flashing into two requests: the
//! multipart POST merely STORES the image (its `<size> <md5>` body is
//! what [`post`](crate::post) classifies as `Verdict::Accepted`), and
//! flashing only starts when a follow-up GET hits the model's
//! `trigger_flash_endpoint` — for GL.iNet MT3000 that is `/result`
//! (models/glinet-mt3000.json: `trigger_flash_endpoint`,
//! `trigger_response_pattern: "success"`,
//! `trigger_blocks_until_done: true`,
//! `flash_duration_seconds: 360`). The trigger request BLOCKS until
//! the flash completes, then answers `success`; an interim answer is
//! the `Update in progress` page.
//!
//! The proven semantics are the 1.x Python twin's
//! (scripts/flash/upload.py::trigger_flash): GET the trigger endpoint,
//! bound by `flash_time_seconds + 60`; `success` (case-insensitive)
//! and `Update in progress` both count as flashing; an empty response
//! is the "may have been consumed already" shape; only a transport
//! failure is an error. This module is the wire half of that, staged
//! over [`HttpIo`](crate::post::HttpIo) exactly like
//! [`RecoveryPost`](crate::post::RecoveryPost) — no socket ownership,
//! so firmware and the host twin run the same bytes.
//!
//! One-request rule scope: the trigger is NOT a probe — it is the
//! documented second request of a two-stage flow, sent only AFTER an
//! accepted upload verdict. One-request servers (D-Link uIP) never see
//! it: their profiles carry no trigger endpoint.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::post::{HttpIo, PostError, body_after_headers, retain_verdict_bytes};
/// The trigger endpoint's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerVerdict {
    /// Body contains `success` (case-insensitive) — flash completed.
    Success,
    /// The `Update in progress` page — flash started, answer early.
    InProgress,
    /// Body carried no content — either a bare close or HTTP headers
    /// with an empty body (`Content-Length: 0`): ambiguous — the
    /// trigger may already have been consumed (the lenient 1.x shape:
    /// warn and verify on the wire afterwards, do not fail the run).
    NoResponse,
    /// Server responded, but the body matched no trigger shape.
    Rejected {
        /// First bytes of the response, for logs.
        snippet: String,
    },
}

/// The staged flash-trigger GET.
pub struct TriggerRequest {
    host: String,
    endpoint: String,
}

/// Classify a trigger response BODY (headers already stripped via
/// [`body_after_headers`]). Public so host twins can classify a
/// partial body captured before a transport failure — the wire order
/// is [`TriggerRequest::trigger`]'s and must not drift from it:
/// upload.py::trigger_flash checks "success" first (exact, then
/// substring case-insensitive), then the in-progress page, then the
/// lenient empty (the STRIPPED body — a headers-only response is
/// empty too, #673 codex P2), else rejection.
#[must_use]
pub fn classify_trigger_body(text: &str) -> TriggerVerdict {
    if text.to_ascii_lowercase().contains("success") {
        TriggerVerdict::Success
    } else if text.contains("Update in progress") {
        TriggerVerdict::InProgress
    } else if text.trim().is_empty() {
        TriggerVerdict::NoResponse
    } else {
        TriggerVerdict::Rejected {
            snippet: text.chars().take(80).collect(),
        }
    }
}

impl TriggerRequest {
    /// New trigger request for `endpoint` (the model's
    /// `trigger_flash_endpoint`, e.g. `/result`). `host` feeds the
    /// `Host:` header, mirroring [`RecoveryPost`](crate::post::RecoveryPost).
    #[must_use]
    pub fn new(host: &str, endpoint: &str) -> Self {
        Self {
            host: String::from(host),
            endpoint: String::from(endpoint),
        }
    }

    /// Send the trigger GET and read the verdict. The caller owns the
    /// connection: a two-stage server FINs the upload connection after
    /// its verdict, so the trigger rides a FRESH connection with a
    /// read deadline that spans the model's `flash_duration_seconds`
    /// (the request blocks until the flash completes — a 30 s
    /// upload-verdict budget would fire mid-flash).
    ///
    /// # Errors
    /// [`PostError::Write`] on the request head, [`PostError::Read`]
    /// on the response read (a deadline expiry surfaces here — the
    /// caller decides whether that is failure or the lenient
    /// "flash may still be in progress" shape).
    pub async fn trigger(&mut self, io: &mut impl HttpIo) -> Result<TriggerVerdict, PostError> {
        let head = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             \r\n",
            self.endpoint, self.host,
        );
        io.write_all(head.as_bytes())
            .await
            .map_err(|_| PostError::Write { op: "trigger" })?;

        let mut response = Vec::new();
        match io.read_response(&mut response).await {
            Ok(()) => {
                let raw = String::from_utf8_lossy(&response).into_owned();
                Ok(classify_trigger_body(body_after_headers(&raw)))
            }
            Err(_) => Err(PostError::Read),
        }
    }
}

/// Bounded retention for the trigger response — same rule as the
/// upload verdict (kept here so trigger-only IO impls share it).
#[must_use]
pub fn retain_trigger_bytes(out: &mut Vec<u8>, segment: &[u8]) -> usize {
    retain_verdict_bytes(out, segment)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory IO: records writes, replays a canned response
    /// (post.rs test shape — trigger tests need the same two knobs).
    struct MemIo {
        written: Vec<u8>,
        response: Vec<u8>,
        fail_writes: bool,
        fail_read: bool,
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
            if self.fail_read {
                return Err(());
            }
            out.extend_from_slice(&self.response);
            Ok(())
        }
    }

    fn io_with(response: &[u8]) -> MemIo {
        MemIo {
            written: Vec::new(),
            response: response.to_vec(),
            fail_writes: false,
            fail_read: false,
        }
    }

    #[tokio::test]
    async fn head_shape_is_a_get_with_host_and_close() {
        let mut io = io_with(b"success");
        let mut req = TriggerRequest::new("192.168.1.1", "/result");
        req.trigger(&mut io).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&io.written),
            "GET /result HTTP/1.1\r\nHost: 192.168.1.1\r\nConnection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn success_body_after_http_headers() {
        // U-Boot sends real status headers before the body (post.rs
        // verdict tests pin the same skip) — the trigger must skip
        // them too, or "HTTP/1.0 200" would never classify.
        let mut io = io_with(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nsuccess");
        let mut req = TriggerRequest::new("h", "/result");
        assert_eq!(req.trigger(&mut io).await.unwrap(), TriggerVerdict::Success);
    }

    #[tokio::test]
    async fn success_matches_case_insensitively() {
        // upload.py falls back to `"success" in response.lower()` when
        // the exact-match misses — pin the same leniency.
        let mut io = io_with(b"Flash SUCCESS\r\n");
        let mut req = TriggerRequest::new("h", "/result");
        assert_eq!(req.trigger(&mut io).await.unwrap(), TriggerVerdict::Success);
    }

    #[tokio::test]
    async fn empty_response_is_the_lenient_no_response() {
        let mut io = io_with(b"");
        let mut req = TriggerRequest::new("h", "/result");
        assert_eq!(
            req.trigger(&mut io).await.unwrap(),
            TriggerVerdict::NoResponse
        );
    }

    /// #673 codex P2: a headers-only response (empty body after the
    /// header strip) is the same lenient shape — NOT a rejection.
    #[tokio::test]
    async fn headers_only_response_is_still_no_response() {
        let mut io = io_with(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
        let mut req = TriggerRequest::new("h", "/result");
        assert_eq!(
            req.trigger(&mut io).await.unwrap(),
            TriggerVerdict::NoResponse
        );
    }

    #[tokio::test]
    async fn update_in_progress_page_is_in_progress() {
        let mut io = io_with(b"<html>Update in progress</html>");
        let mut req = TriggerRequest::new("h", "/result");
        assert_eq!(
            req.trigger(&mut io).await.unwrap(),
            TriggerVerdict::InProgress
        );
    }

    #[tokio::test]
    async fn unknown_body_is_rejected_with_snippet() {
        let mut io = io_with(b"404 not found");
        let mut req = TriggerRequest::new("h", "/result");
        match req.trigger(&mut io).await.unwrap() {
            TriggerVerdict::Rejected { snippet } => assert_eq!(snippet, "404 not found"),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_failure_is_post_error_write_trigger() {
        let mut io = MemIo {
            written: Vec::new(),
            response: Vec::new(),
            fail_writes: true,
            fail_read: false,
        };
        let mut req = TriggerRequest::new("h", "/result");
        assert_eq!(
            req.trigger(&mut io).await,
            Err(PostError::Write { op: "trigger" })
        );
    }

    #[tokio::test]
    async fn read_failure_is_post_error_read() {
        let mut io = MemIo {
            written: Vec::new(),
            response: Vec::new(),
            fail_writes: false,
            fail_read: true,
        };
        let mut req = TriggerRequest::new("h", "/result");
        assert_eq!(req.trigger(&mut io).await, Err(PostError::Read));
    }
}
