//! The U-Boot recovery multipart body shape (#226 slice 1).
//!
//! Byte-compatible with conwrt 1.x `build_webkit_multipart`
//! (`scripts/flash/upload.py`): some U-Boot recovery servers mishandle
//! curl-shaped framing while accepting browser uploads, so the executor
//! emits the exact WebKit layout — a `----WebKitFormBoundary` token,
//! CRLF framing, one octet-stream part.
//!
//! `Content-Length` is the full body size (header + image + footer):
//! U-Boot's uIP httpd has no chunked-encoding support, so the length
//! must be known before the first byte goes on the wire — which is why
//! [`crate::transfer::TransferState`] requires the first chunk to
//! carry `total`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Default multipart field name (model JSON `upload_field`).
pub const UPLOAD_FIELD: &str = "firmware";

/// The boundary layout: prefix + caller-supplied token (16 hex chars in
/// the 1.x reference; any token the server hasn't seen works — the
/// firmware supplies one from its RNG).
pub const BOUNDARY_PREFIX: &str = "----WebKitFormBoundary";

/// The multipart framing for one recovery upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multipart<'a> {
    /// Full boundary token (prefix included), e.g.
    /// `----WebKitFormBoundary0123456789abcdef`.
    pub boundary: &'a str,
    /// Form field name (model JSON `upload_field`, default `firmware`).
    pub field: &'a str,
    /// Filename the server sees (basename of the image).
    pub filename: &'a str,
    /// Exact image size in bytes.
    pub image_len: u64,
}

impl Multipart<'_> {
    /// Header bytes: first boundary marker + part headers + blank line.
    pub fn header(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.boundary.len() + 96);
        out.extend_from_slice(b"--");
        out.extend_from_slice(self.boundary.as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                self.field, self.filename
            )
            .as_bytes(),
        );
        out.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        out
    }

    /// Footer bytes: CRLF + closing boundary marker.
    pub fn footer(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.boundary.len() + 8);
        out.extend_from_slice(b"\r\n--");
        out.extend_from_slice(self.boundary.as_bytes());
        out.extend_from_slice(b"--\r\n");
        out
    }

    /// Exact `Content-Length` for the whole body.
    pub fn content_len(&self) -> u64 {
        self.header().len() as u64 + self.image_len + self.footer().len() as u64
    }

    /// The `Content-Type` header value.
    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-exact reference: the 1.x `build_webkit_multipart` output for
    /// a 3-byte payload (scripts/flash/upload.py, verified 2026-10-16).
    #[test]
    fn matches_1x_webkit_layout() {
        let mp = Multipart {
            boundary: "----WebKitFormBoundary0123456789abcdef",
            field: "firmware",
            filename: "recovery.bin",
            image_len: 3,
        };
        let header = mp.header();
        assert_eq!(
            header,
            b"------WebKitFormBoundary0123456789abcdef\r\n\
              Content-Disposition: form-data; name=\"firmware\"; filename=\"recovery.bin\"\r\n\
              Content-Type: application/octet-stream\r\n\r\n"[..]
        );
        assert_eq!(
            mp.footer(),
            b"\r\n------WebKitFormBoundary0123456789abcdef--\r\n"[..]
        );
        // content_len = header + payload + footer
        assert_eq!(
            mp.content_len(),
            header.len() as u64 + 3 + mp.footer().len() as u64
        );
        assert_eq!(
            mp.content_type(),
            "multipart/form-data; boundary=----WebKitFormBoundary0123456789abcdef"
        );
    }

    #[test]
    fn default_field_is_firmware() {
        assert_eq!(UPLOAD_FIELD, "firmware");
    }
}
