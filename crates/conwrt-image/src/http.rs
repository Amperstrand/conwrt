//! `reqwest`-backed [`AsuClient`] — the production HTTP path.

use std::time::Duration;

use crate::cache::store_url;
use crate::client::{AsuClient, AsuEndpoints, USER_AGENT};
use crate::error::ImageError;
use crate::types::{BuildManifest, BuildRequest, BuildStatus, SubmitResponse};

/// Submission timeout (`timeout=30` on the POST in firmware-manager.py).
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);
/// Status-poll timeout (`timeout=15` on the GET in firmware-manager.py).
const STATUS_TIMEOUT: Duration = Duration::from_secs(15);
/// Download timeout (`timeout=120` in firmware-manager.py).
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// ASU client over `reqwest` (rustls TLS, no default features).
///
/// Clone-safe: the underlying HTTP client is pooled and shared.
#[derive(Debug, Clone)]
pub struct ReqwestAsuClient {
    endpoints: AsuEndpoints,
    http: reqwest::Client,
}

impl ReqwestAsuClient {
    /// Client for the public ASU instance
    /// (`https://sysupgrade.openwrt.org`).
    pub fn new() -> Result<Self, ImageError> {
        Self::with_endpoints(AsuEndpoints::default())
    }

    /// Client for explicit endpoints — tests point this at a local mock
    /// server.
    pub fn with_endpoints(endpoints: AsuEndpoints) -> Result<Self, ImageError> {
        let http = reqwest::Client::builder().user_agent(USER_AGENT).build()?;
        Ok(Self { endpoints, http })
    }

    /// The endpoints this client talks to.
    pub fn endpoints(&self) -> &AsuEndpoints {
        &self.endpoints
    }
}

impl AsuClient for ReqwestAsuClient {
    async fn submit_build(&self, request: &BuildRequest) -> Result<SubmitResponse, ImageError> {
        let response = self
            .http
            .post(&self.endpoints.build_url)
            .timeout(SUBMIT_TIMEOUT)
            .json(request)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(ImageError::HttpStatus {
                status: status.as_u16(),
                url: self.endpoints.build_url.clone(),
                body,
            });
        }
        let submit: SubmitResponse = serde_json::from_str(&body)?;
        if submit.request_hash.is_empty() {
            // firmware-manager.py: "ASU did not return a request_hash: %s".
            return Err(ImageError::MissingRequestHash(body));
        }
        Ok(submit)
    }

    async fn build_status(&self, request_hash: &str) -> Result<BuildStatus, ImageError> {
        let url = self.endpoints.status_url(request_hash);
        let response = self
            .http
            .get(&url)
            .timeout(STATUS_TIMEOUT)
            .send()
            .await?
            .error_for_status()?;
        let manifest: BuildManifest = response.json().await?;
        Ok(BuildStatus::classify(manifest))
    }

    async fn download_image(&self, bin_dir: &str, filename: &str) -> Result<Vec<u8>, ImageError> {
        let url = store_url(&self.endpoints.store_url, bin_dir, filename);
        let response = self.http.get(&url).timeout(DOWNLOAD_TIMEOUT).send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(ImageError::HttpStatus {
                status: status.as_u16(),
                url,
                body: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        Ok(bytes.to_vec())
    }
}
