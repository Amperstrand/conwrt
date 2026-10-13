//! End-to-end parity for firmware-manager.py `cmd_request`:
//! submit → poll → download → verify → cache, plus metadata writing.

use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::client::{AsuClient, PollConfig};
use crate::error::ImageError;
use crate::metadata::{CachedImage, CachedMetadata, write_metadata};
use crate::timestamp;
use crate::types::{BuildManifest, BuildRequest, BuildStatus, ImageType};

/// Request-scoped extras threaded into the written metadata that come from
/// the profile planner (still Python-side today), not from the ASU API.
#[derive(Debug, Clone, Default)]
pub struct RequestExtras<'a> {
    /// Where the embedded SSH key came from, if one was baked into the
    /// defaults script (`ssh_key_source` in firmware-manager.py).
    pub ssh_key_source: Option<&'a str>,
}

/// Outcome of [`request_and_cache`].
#[derive(Debug, Clone)]
pub struct RequestOutcome {
    /// Cache directory holding the images and metadata.
    pub cache_dir: PathBuf,
    /// `true` when the build was already cached and no ASU round-trips
    /// were made (firmware-manager.py logs and prints the existing path).
    pub already_cached: bool,
    /// Metadata as written to `build.metadata.json`.
    pub metadata: CachedMetadata,
}

/// Requests a firmware build from ASU and caches the verified result under
/// `<images_root>/<profile>/<cache_key>/` — the library core of
/// firmware-manager.py's `request` subcommand.
///
/// Steps, in order:
///
/// 1. Compute the cache key and short-circuit when a verified build is
///    already cached.
/// 2. Submit the build; fail on a missing `request_hash`.
/// 3. Poll `GET /api/v1/build/{hash}` with backoff until a terminal
///    status, tolerating transient poll errors (network hiccups, HTTP
///    errors, unparseable bodies) until the deadline — like Python.
/// 4. Download every image from the store, verify its SHA-256 against the
///    manifest (deleting the file on mismatch), and classify its type from
///    the file name.
/// 5. Write `build.metadata.json` and return the outcome.
pub async fn request_and_cache<C: AsuClient>(
    client: &C,
    images_root: &Path,
    request: &BuildRequest,
    poll: &PollConfig,
    extras: &RequestExtras<'_>,
) -> Result<RequestOutcome, ImageError> {
    let cache_key = crate::cache::request_cache_key(request);

    if let Some(metadata) =
        crate::metadata::find_cached_build(images_root, &request.profile, &cache_key)
    {
        return Ok(RequestOutcome {
            cache_dir: crate::cache::hash_dir(images_root, &request.profile, &cache_key),
            already_cached: true,
            metadata,
        });
    }

    let submit = client.submit_build(request).await?;
    if submit.request_hash.is_empty() {
        return Err(ImageError::MissingRequestHash(String::new()));
    }
    let request_hash = submit.request_hash;

    let manifest = poll_until_done(client, &request_hash, poll).await?;
    if manifest.images.is_empty() {
        // firmware-manager.py: "ASU response contains no images".
        return Err(ImageError::NoImages);
    }
    let bin_dir = if manifest.bin_dir.is_empty() {
        request_hash.clone()
    } else {
        manifest.bin_dir.clone()
    };

    let cache_dir = crate::cache::hash_dir(images_root, &request.profile, &cache_key);
    std::fs::create_dir_all(&cache_dir)?;

    let mut images = Vec::new();
    for image in &manifest.images {
        if image.name.is_empty() {
            // firmware-manager.py warns and skips entries without a name.
            continue;
        }
        let bytes = client.download_image(&bin_dir, &image.name).await?;
        let dest = cache_dir.join(&image.name);
        std::fs::write(&dest, &bytes)?;
        let actual = crate::cache::sha256_file(&dest)?;
        if let Some(expected) = image.sha256.as_deref().filter(|sha| !sha.is_empty()) {
            if actual != expected {
                let _ = std::fs::remove_file(&dest);
                return Err(ImageError::ShaMismatch {
                    filename: image.name.clone(),
                    expected: expected.to_string(),
                    actual,
                });
            }
        }
        images.push(CachedImage {
            image_type: ImageType::from_filename(&image.name),
            name: image.name.clone(),
            sha256: actual,
            size_bytes: bytes.len() as u64,
            verified: true,
        });
    }

    let metadata = CachedMetadata {
        cache_key: cache_key.clone(),
        request_hash,
        // status_data.get(key, fallback) in Python — empty means absent here.
        distro: fallback(&manifest.distro, "openwrt"),
        version: fallback(&manifest.version, &request.version),
        version_code: manifest.version_code.clone(),
        target: fallback(&manifest.target, &request.target),
        profile: fallback(&manifest.profile, &request.profile),
        packages: request.packages.clone().unwrap_or_default(),
        packages_all: manifest.packages.clone(),
        defaults: request.defaults.clone(),
        ssh_key_source: extras.ssh_key_source.map(str::to_string),
        images,
        linux_kernel: manifest.linux_kernel.clone(),
        build_at: manifest.build_at.clone(),
        enqueued_at: manifest.enqueued_at.clone(),
        downloaded_at: timestamp::utc_now(),
    };
    write_metadata(images_root, &metadata)?;
    Ok(RequestOutcome {
        cache_dir,
        already_cached: false,
        metadata,
    })
}

/// Polls until the build reaches a terminal status.
///
/// Semantics mirror firmware-manager.py's poll loop: the deadline is
/// checked before each poll, in-progress statuses (`pending`, `building`,
/// `202`) sleep and continue, transient errors are logged-and-tolerated
/// until the deadline, and a terminal non-done status fails with the
/// response's `detail`/`message`.
async fn poll_until_done<C: AsuClient>(
    client: &C,
    request_hash: &str,
    poll: &PollConfig,
) -> Result<BuildManifest, ImageError> {
    let deadline = Instant::now() + poll.timeout;
    let mut interval = poll.initial_interval;
    loop {
        if Instant::now() >= deadline {
            return Err(ImageError::PollTimeout(poll.timeout));
        }
        match client.build_status(request_hash).await {
            Ok(BuildStatus::InProgress) => {}
            Ok(BuildStatus::Done(manifest)) => return Ok(*manifest),
            Ok(BuildStatus::Failed(manifest)) => {
                let status = manifest
                    .status
                    .map(|value| value.label())
                    .unwrap_or_default();
                return Err(ImageError::BuildFailed {
                    status,
                    detail: manifest.detail,
                    message: manifest.message,
                });
            }
            Err(_) => { /* transient poll error — tolerated */ }
        }
        tokio::time::sleep(interval).await;
        interval = poll.next_interval(interval);
    }
}

fn fallback(value: &str, alternative: &str) -> String {
    if value.is_empty() {
        alternative.to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SubmitResponse;
    use std::sync::Mutex;
    use std::time::Duration;

    /// One scripted poll result (errors are re-created per call because
    /// `ImageError` is not `Clone`).
    #[derive(Clone)]
    enum Scripted {
        InProgress,
        Done(BuildManifest),
        Failed(BuildManifest),
        TransientError,
    }

    /// Scripted fake implementing the [`AsuClient`] seam — proves the
    /// polling workflow is testable without HTTP.
    struct FakeAsuClient {
        submit: SubmitResponse,
        statuses: Mutex<Vec<Scripted>>,
        downloads: Mutex<Vec<(String, String)>>,
    }

    impl FakeAsuClient {
        fn with_statuses(submit: SubmitResponse, statuses: Vec<Scripted>) -> Self {
            Self {
                submit,
                statuses: Mutex::new(statuses),
                downloads: Mutex::new(Vec::new()),
            }
        }
    }

    impl AsuClient for FakeAsuClient {
        async fn submit_build(
            &self,
            _request: &BuildRequest,
        ) -> Result<SubmitResponse, ImageError> {
            Ok(self.submit.clone())
        }

        async fn build_status(&self, _request_hash: &str) -> Result<BuildStatus, ImageError> {
            let mut queue = self.statuses.lock().expect("lock");
            let Some(step) = queue.first().cloned() else {
                return Ok(BuildStatus::InProgress);
            };
            // Consume scripted steps, but repeat the last one so a lone
            // `InProgress` fills the whole poll window.
            if queue.len() > 1 {
                queue.remove(0);
            }
            match step {
                Scripted::InProgress => Ok(BuildStatus::InProgress),
                Scripted::Done(manifest) => Ok(BuildStatus::Done(Box::new(manifest))),
                Scripted::Failed(manifest) => Ok(BuildStatus::Failed(Box::new(manifest))),
                Scripted::TransientError => Err(ImageError::HttpStatus {
                    status: 502,
                    url: "http://mock/status".into(),
                    body: "transient".into(),
                }),
            }
        }

        async fn download_image(
            &self,
            bin_dir: &str,
            filename: &str,
        ) -> Result<Vec<u8>, ImageError> {
            self.downloads
                .lock()
                .expect("lock")
                .push((bin_dir.to_string(), filename.to_string()));
            Ok(b"firmware-bytes".to_vec())
        }
    }

    fn fast_poll() -> PollConfig {
        PollConfig {
            initial_interval: Duration::from_millis(1),
            max_interval: Duration::from_millis(1),
            backoff_multiplier: 1.0,
            timeout: Duration::from_millis(500),
        }
    }

    fn submit_ok() -> SubmitResponse {
        SubmitResponse {
            request_hash: "hash123".into(),
            status: Some(crate::types::StatusValue::Number(202)),
        }
    }

    fn done_manifest() -> BuildManifest {
        BuildManifest {
            request_hash: "hash123".into(),
            status: Some(crate::types::StatusValue::Number(200)),
            distro: String::new(),
            version: String::new(),
            version_code: "r2782".into(),
            target: String::new(),
            profile: String::new(),
            packages: [("curl".to_string(), serde_json::json!("8.9.1"))]
                .into_iter()
                .collect(),
            images: vec![crate::types::ManifestImage {
                name: "fw-squashfs-sysupgrade.bin".into(),
                sha256: Some(sha256_hex(b"firmware-bytes")),
                size: Some(14),
            }],
            bin_dir: "07/ab".into(),
            linux_kernel: serde_json::json!({"version": "5.15"}),
            build_at: "2026-10-12T10:00:00".into(),
            enqueued_at: "2026-10-12T09:59:00".into(),
            detail: String::new(),
            message: String::new(),
        }
    }

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(data);
        let mut out = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    fn request() -> BuildRequest {
        BuildRequest::openwrt("24.10.2", "ramips/mt7621", "dlink_covr_x1860_a1")
    }

    #[tokio::test]
    async fn polls_through_queued_and_building_until_done() {
        let client = FakeAsuClient::with_statuses(
            submit_ok(),
            vec![
                Scripted::InProgress, // pending
                Scripted::InProgress, // building / 202
                Scripted::Done(done_manifest()),
            ],
        );
        let root = tempfile::tempdir().expect("tempdir");
        let outcome = request_and_cache(
            &client,
            root.path(),
            &request(),
            &fast_poll(),
            &RequestExtras {
                ssh_key_source: Some("config.toml"),
            },
        )
        .await
        .expect("cached");

        assert!(!outcome.already_cached);
        let expected_key = crate::cache::request_cache_key(&request());
        assert_eq!(
            outcome.cache_dir,
            root.path().join("dlink_covr_x1860_a1").join(&expected_key)
        );

        // Image downloaded from the manifest bin_dir, verified, classified.
        assert_eq!(
            client.downloads.lock().expect("lock").as_slice(),
            [(
                "07/ab".to_string(),
                "fw-squashfs-sysupgrade.bin".to_string()
            )]
        );
        let fw = outcome.cache_dir.join("fw-squashfs-sysupgrade.bin");
        assert_eq!(std::fs::read(&fw).expect("fw"), b"firmware-bytes");

        // Metadata fields: manifest values with request fallbacks.
        assert_eq!(outcome.metadata.request_hash, "hash123");
        assert_eq!(outcome.metadata.distro, "openwrt");
        assert_eq!(outcome.metadata.version, "24.10.2");
        assert_eq!(outcome.metadata.version_code, "r2782");
        assert_eq!(outcome.metadata.target, "ramips/mt7621");
        assert_eq!(outcome.metadata.profile, "dlink_covr_x1860_a1");
        assert_eq!(
            outcome.metadata.packages_all["curl"],
            serde_json::json!("8.9.1")
        );
        assert_eq!(
            outcome.metadata.ssh_key_source.as_deref(),
            Some("config.toml")
        );
        assert_eq!(outcome.metadata.images.len(), 1);
        assert_eq!(outcome.metadata.images[0].image_type, ImageType::Sysupgrade);
        assert!(outcome.metadata.images[0].verified);
        assert_eq!(outcome.metadata.build_at, "2026-10-12T10:00:00");
        assert_eq!(outcome.metadata.downloaded_at.len(), 19);

        // The metadata file is on disk at the canonical path.
        assert!(
            crate::metadata::metadata_path(root.path(), "dlink_covr_x1860_a1", &expected_key)
                .exists()
        );
    }

    #[tokio::test]
    async fn already_cached_build_short_circuits_without_submit() {
        let root = tempfile::tempdir().expect("tempdir");
        let client =
            FakeAsuClient::with_statuses(submit_ok(), vec![Scripted::Done(done_manifest())]);
        // First run populates the cache.
        request_and_cache(
            &client,
            root.path(),
            &request(),
            &fast_poll(),
            &RequestExtras::default(),
        )
        .await
        .expect("first run");

        let second = FakeAsuClient::with_statuses(submit_ok(), vec![Scripted::InProgress]);
        let outcome = request_and_cache(
            &second,
            root.path(),
            &request(),
            &fast_poll(),
            &RequestExtras::default(),
        )
        .await
        .expect("cached second run");
        assert!(outcome.already_cached);
        assert!(second.downloads.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn transient_poll_errors_are_tolerated_until_done() {
        let client = FakeAsuClient::with_statuses(
            submit_ok(),
            vec![
                Scripted::TransientError, // HTTP 502
                Scripted::TransientError, // unparseable body
                Scripted::Done(done_manifest()),
            ],
        );
        let root = tempfile::tempdir().expect("tempdir");
        let outcome = request_and_cache(
            &client,
            root.path(),
            &request(),
            &fast_poll(),
            &RequestExtras::default(),
        )
        .await
        .expect("transient errors tolerated");
        assert!(!outcome.already_cached);
    }

    #[tokio::test]
    async fn poll_deadline_times_out() {
        let client = FakeAsuClient::with_statuses(submit_ok(), vec![Scripted::InProgress]);
        let root = tempfile::tempdir().expect("tempdir");
        let err = request_and_cache(
            &client,
            root.path(),
            &request(),
            &fast_poll(),
            &RequestExtras::default(),
        )
        .await
        .expect_err("must time out");
        assert!(matches!(err, ImageError::PollTimeout(d) if d == Duration::from_millis(500)));
    }

    #[tokio::test]
    async fn terminal_failure_maps_to_build_failed() {
        let manifest = BuildManifest {
            status: Some(crate::types::StatusValue::Text("failed".into())),
            detail: "no space left on builder".into(),
            message: "build error".into(),
            ..BuildManifest::default()
        };
        let client = FakeAsuClient::with_statuses(submit_ok(), vec![Scripted::Failed(manifest)]);
        let root = tempfile::tempdir().expect("tempdir");
        let err = request_and_cache(
            &client,
            root.path(),
            &request(),
            &fast_poll(),
            &RequestExtras::default(),
        )
        .await
        .expect_err("failed build");
        match err {
            ImageError::BuildFailed {
                status,
                detail,
                message,
            } => {
                assert_eq!(status, "failed");
                assert_eq!(detail, "no space left on builder");
                assert_eq!(message, "build error");
            }
            other => panic!("expected BuildFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_request_hash_fails() {
        let client = FakeAsuClient::with_statuses(
            SubmitResponse {
                request_hash: String::new(),
                status: None,
            },
            vec![],
        );
        let root = tempfile::tempdir().expect("tempdir");
        let err = request_and_cache(
            &client,
            root.path(),
            &request(),
            &fast_poll(),
            &RequestExtras::default(),
        )
        .await
        .expect_err("no hash");
        assert!(matches!(err, ImageError::MissingRequestHash(_)));
    }

    #[tokio::test]
    async fn sha_mismatch_deletes_file_and_fails() {
        let mut manifest = done_manifest();
        manifest.images[0].sha256 = Some("0000".into());
        let client = FakeAsuClient::with_statuses(submit_ok(), vec![Scripted::Done(manifest)]);
        let root = tempfile::tempdir().expect("tempdir");
        let err = request_and_cache(
            &client,
            root.path(),
            &request(),
            &fast_poll(),
            &RequestExtras::default(),
        )
        .await
        .expect_err("mismatch");
        assert!(matches!(err, ImageError::ShaMismatch { .. }));

        let key = crate::cache::request_cache_key(&request());
        let dir = root.path().join("dlink_covr_x1860_a1").join(&key);
        assert!(
            !dir.join("fw-squashfs-sysupgrade.bin").exists(),
            "mismatched file must be deleted"
        );
        assert!(
            !dir.join(crate::metadata::METADATA_FILENAME).exists(),
            "metadata must not be written for a failed download"
        );
    }

    #[tokio::test]
    async fn bin_dir_falls_back_to_request_hash() {
        let mut manifest = done_manifest();
        manifest.bin_dir = String::new();
        let client = FakeAsuClient::with_statuses(submit_ok(), vec![Scripted::Done(manifest)]);
        let root = tempfile::tempdir().expect("tempdir");
        request_and_cache(
            &client,
            root.path(),
            &request(),
            &fast_poll(),
            &RequestExtras::default(),
        )
        .await
        .expect("cached");
        assert_eq!(
            client.downloads.lock().expect("lock").as_slice(),
            [(
                "hash123".to_string(),
                "fw-squashfs-sysupgrade.bin".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn empty_image_names_are_skipped() {
        let mut manifest = done_manifest();
        manifest.images.insert(
            0,
            crate::types::ManifestImage {
                name: String::new(),
                sha256: None,
                size: None,
            },
        );
        let client = FakeAsuClient::with_statuses(submit_ok(), vec![Scripted::Done(manifest)]);
        let root = tempfile::tempdir().expect("tempdir");
        let outcome = request_and_cache(
            &client,
            root.path(),
            &request(),
            &fast_poll(),
            &RequestExtras::default(),
        )
        .await
        .expect("cached");
        assert_eq!(outcome.metadata.images.len(), 1);
    }

    #[tokio::test]
    async fn empty_image_list_is_rejected() {
        let client = FakeAsuClient::with_statuses(
            submit_ok(),
            vec![Scripted::Done(BuildManifest::default())],
        );
        let root = tempfile::tempdir().expect("tempdir");
        let err = request_and_cache(
            &client,
            root.path(),
            &request(),
            &fast_poll(),
            &RequestExtras::default(),
        )
        .await
        .expect_err("no images");
        assert!(matches!(err, ImageError::NoImages));
    }
}
