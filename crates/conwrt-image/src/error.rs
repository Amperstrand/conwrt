//! Error type for the ASU firmware-image client.

use std::time::Duration;

/// Errors produced while requesting, polling, downloading, or caching ASU
/// firmware images.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    /// A transport-level HTTP failure (connection error, timeout, or a
    /// non-success status on a request that requires success).
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// A request succeeded at the transport level but returned a non-success
    /// HTTP status. Carries the response body for diagnostics, mirroring
    /// firmware-manager.py's `ASU build request failed (HTTP %d): %s` log.
    #[error("HTTP {status} from {url}: {body}")]
    HttpStatus {
        /// HTTP status code.
        status: u16,
        /// Request URL.
        url: String,
        /// Response body (best effort).
        body: String,
    },
    /// The build submission response did not contain a `request_hash`.
    #[error("ASU did not return a request_hash: {0}")]
    MissingRequestHash(String),
    /// The build reached a terminal, non-done status.
    #[error("build failed: status={status} detail={detail} message={message}")]
    BuildFailed {
        /// Raw status value reported by ASU (e.g. `failed`, `500`).
        status: String,
        /// `detail` field from the ASU response, if any.
        detail: String,
        /// `message` field from the ASU response, if any.
        message: String,
    },
    /// The build did not reach a terminal status before the poll deadline.
    #[error("build timed out after {}s", .0.as_secs())]
    PollTimeout(Duration),
    /// The completed build manifest contained no image entries.
    #[error("ASU response contains no images")]
    NoImages,
    /// A downloaded image did not match the SHA-256 recorded in the manifest.
    #[error("SHA-256 mismatch for {filename}: expected {expected}, got {actual}")]
    ShaMismatch {
        /// Image file name that failed verification.
        filename: String,
        /// Expected digest from the ASU manifest.
        expected: String,
        /// Digest computed over the downloaded bytes.
        actual: String,
    },
    /// A filesystem operation on the image cache failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A response body could not be parsed as the expected JSON shape.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
