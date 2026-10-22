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
    /// A vanilla-image release string was not a full `X.Y.Z` version
    /// (mirrors the `ValueError` from `image_source.resolve_release`).
    #[error(
        "invalid OpenWrt release '{0}': expected a full version like 24.10.2 (the model's openwrt.version is the ASU major, not a download release)"
    )]
    InvalidRelease(String),
    /// The model's `openwrt.target` lacked the `<target>/<subtarget>`
    /// shape needed to build a downloads URL.
    #[error(
        "model '{model}' has invalid openwrt.target '{target}': expected '<target>/<subtarget>'"
    )]
    InvalidTarget {
        /// Model identifier, for error context.
        model: String,
        /// The malformed target value.
        target: String,
    },
    /// The model has no `openwrt.profile`.
    #[error("model '{0}' is missing openwrt.profile")]
    MissingProfile(String),
    /// A defaults script set a static `network.<section>.ipaddr` without a
    /// paired netmask. OpenWrt 25.12 netifd defaults the missing netmask
    /// to /32, leaving the device v4-dead at L2 (2026-10-14 x1860
    /// postmortem); the Python profile builder always emits the pair.
    #[error(
        "defaults script sets network.{section}.ipaddr without network.{section}.netmask — \
         a static LAN address must carry its netmask (2026-10-14 /32 postmortem)"
    )]
    DefaultsMissingNetmask {
        /// The UCI network section with the unpaired address.
        section: String,
    },
    /// The image file name was absent from the target directory's
    /// `sha256sums` index.
    #[error(
        "{filename} not found in checksum index at {url} — the model's openwrt target/profile may not match release"
    )]
    NotInChecksumIndex {
        /// Image file name that was looked up.
        filename: String,
        /// URL of the `sha256sums` index that was searched.
        url: String,
    },
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
