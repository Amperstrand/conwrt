//! The mockable ASU client seam plus endpoint and polling configuration.

use std::future::Future;
use std::time::Duration;

use crate::error::ImageError;
use crate::types::{BuildRequest, BuildStatus, SubmitResponse};

/// Default ASU base URL (`ASU_BASE` in firmware-manager.py).
pub const DEFAULT_ASU_BASE: &str = "https://sysupgrade.openwrt.org";

/// User-Agent sent on every request — parity with firmware-manager.py.
pub const USER_AGENT: &str = "conwrt-firmware-manager/1.0";

/// ASU endpoint URLs, derived from one base URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsuEndpoints {
    /// Build endpoint (`POST` to submit, `GET {build_url}/{hash}` to poll).
    pub build_url: String,
    /// Image store base; image files live at `{store_url}/{bin_dir}/{name}`.
    pub store_url: String,
}

impl AsuEndpoints {
    /// Derives both endpoints from a base URL (no trailing slash).
    pub fn from_base(base: &str) -> Self {
        Self {
            build_url: format!("{base}/api/v1/build"),
            store_url: format!("{base}/store"),
        }
    }

    /// Status URL for one request hash.
    pub fn status_url(&self, request_hash: &str) -> String {
        format!("{}/{}", self.build_url, request_hash)
    }
}

impl Default for AsuEndpoints {
    fn default() -> Self {
        Self::from_base(DEFAULT_ASU_BASE)
    }
}

/// Build-polling behaviour.
///
/// Defaults are firmware-manager.py parity: a fixed 10 s interval
/// (`POLL_INTERVAL`) and a 600 s overall deadline (`POLL_TIMEOUT`). Setting
/// `backoff_multiplier` above 1.0 grows the interval exponentially (capped
/// at `max_interval`) for callers that want backoff; the default of 1.0
/// keeps the interval flat, exactly like Python.
#[derive(Debug, Clone)]
pub struct PollConfig {
    /// Delay before the first re-poll.
    pub initial_interval: Duration,
    /// Upper bound for the grown interval.
    pub max_interval: Duration,
    /// Multiplier applied after every non-terminal poll (`1.0` = fixed).
    pub backoff_multiplier: f64,
    /// Overall deadline for reaching a terminal status.
    pub timeout: Duration,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            initial_interval: Duration::from_secs(10),
            max_interval: Duration::from_secs(10),
            backoff_multiplier: 1.0,
            timeout: Duration::from_secs(600),
        }
    }
}

impl PollConfig {
    /// One backoff step: grows `interval` by the multiplier, capped at
    /// `max_interval`; non-finite multipliers clamp to the cap.
    pub(crate) fn next_interval(&self, interval: Duration) -> Duration {
        let grown = interval.as_secs_f64() * self.backoff_multiplier;
        let capped = if grown.is_finite() {
            grown.min(self.max_interval.as_secs_f64())
        } else {
            self.max_interval.as_secs_f64()
        };
        Duration::from_secs_f64(capped.max(0.0))
    }
}

/// The ASU client seam.
///
/// [`ReqwestAsuClient`](crate::ReqwestAsuClient) is the production
/// implementation. Tests (and future providers — offline caches,
/// record/replay) implement this trait instead of patching HTTP, which is
/// what makes the polling workflow unit-testable without network access.
///
/// Methods return `impl Future + Send` (rather than `async fn`) so the
/// futures stay usable from multi-threaded executors; implementations can
/// still be written as `async fn`.
pub trait AsuClient: Send + Sync {
    /// Submits a build request to `POST /api/v1/build`.
    ///
    /// Implementations should return
    /// [`ImageError::MissingRequestHash`](crate::ImageError::MissingRequestHash)
    /// when the response carries no `request_hash`.
    fn submit_build(
        &self,
        request: &BuildRequest,
    ) -> impl Future<Output = Result<SubmitResponse, ImageError>> + Send;

    /// Fetches the current status of a build (`GET /api/v1/build/{hash}`).
    fn build_status(
        &self,
        request_hash: &str,
    ) -> impl Future<Output = Result<BuildStatus, ImageError>> + Send;

    /// Downloads one image from the store, returning its bytes.
    fn download_image(
        &self,
        bin_dir: &str,
        filename: &str,
    ) -> impl Future<Output = Result<Vec<u8>, ImageError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_default_to_public_asu() {
        let endpoints = AsuEndpoints::default();
        assert_eq!(
            endpoints.build_url,
            "https://sysupgrade.openwrt.org/api/v1/build"
        );
        assert_eq!(endpoints.store_url, "https://sysupgrade.openwrt.org/store");
    }

    #[test]
    fn status_url_appends_hash() {
        let endpoints = AsuEndpoints::from_base("http://localhost:1234");
        assert_eq!(
            endpoints.status_url("abc"),
            "http://localhost:1234/api/v1/build/abc"
        );
    }

    #[test]
    fn poll_config_defaults_match_python() {
        let config = PollConfig::default();
        assert_eq!(config.initial_interval, Duration::from_secs(10));
        assert_eq!(config.timeout, Duration::from_secs(600));
        assert_eq!(config.backoff_multiplier, 1.0);
    }

    #[test]
    fn poll_config_backoff_is_fixed_at_one_and_caps_growth() {
        let fixed = PollConfig::default();
        assert_eq!(
            fixed.next_interval(Duration::from_secs(10)),
            Duration::from_secs(10)
        );

        let backoff = PollConfig {
            initial_interval: Duration::from_secs(1),
            max_interval: Duration::from_secs(4),
            backoff_multiplier: 2.0,
            timeout: Duration::from_secs(60),
        };
        assert_eq!(
            backoff.next_interval(Duration::from_secs(1)),
            Duration::from_secs(2)
        );
        assert_eq!(
            backoff.next_interval(Duration::from_secs(3)),
            Duration::from_secs(4),
            "growth caps at max_interval"
        );
    }
}
