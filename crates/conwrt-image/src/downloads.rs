//! Downloading vanilla OpenWrt images — parity for `fetch_image` in
//! `scripts/conwrt/image_source.py`.
//!
//! [`DownloadsClient`] is the mockable seam for `downloads.openwrt.org`
//! (or a mirror); [`fetch_image`] resolves the artefact, verifies it
//! against the target directory's `sha256sums` index, and caches it in
//! the flat `images/` directory like Python does.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::ImageError;
use crate::vanilla::{
    DEFAULT_DOWNLOADS_BASE, ReleaseOverrides, SuffixOverrides, VanillaModel, image_filename,
    image_url, parse_sha256sums, resolve_image_suffix, resolve_release, target_dir_url,
};

/// User-Agent for downloads.openwrt.org (`image_source.py` sends
/// `conwrt/1.0` — a different UA from the ASU client, preserved as-is).
pub const DOWNLOADS_USER_AGENT: &str = "conwrt/1.0";

/// Timeout for the `sha256sums` text fetch (Python: 30 s).
const TEXT_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout for the image download (Python: 300 s).
const IMAGE_TIMEOUT: Duration = Duration::from_secs(300);

/// The `downloads.openwrt.org` seam.
pub trait DownloadsClient: Send + Sync {
    /// Base URL every fetched resource is rooted at (a mirror or local
    /// mock server in tests).
    fn base_url(&self) -> String;

    /// GETs a text resource (the `sha256sums` index).
    fn fetch_text(&self, url: &str) -> impl Future<Output = Result<String, ImageError>> + Send;

    /// GETs a binary resource (the image), buffered in memory.
    fn fetch_bytes(&self, url: &str) -> impl Future<Output = Result<Vec<u8>, ImageError>> + Send;
}

/// `reqwest`-backed [`DownloadsClient`] (rustls TLS, no default
/// features). Construct with a mirror base URL for tests.
#[derive(Debug, Clone)]
pub struct ReqwestDownloadsClient {
    base_url: String,
    http: reqwest::Client,
}

impl ReqwestDownloadsClient {
    /// Client for `https://downloads.openwrt.org`.
    pub fn new() -> Result<Self, ImageError> {
        Self::with_base(DEFAULT_DOWNLOADS_BASE)
    }

    /// Client for an explicit base URL (`CONWRT_OPENWRT_BASE` mirrors or a
    /// local mock server).
    pub fn with_base(base_url: impl Into<String>) -> Result<Self, ImageError> {
        let mut base = base_url.into();
        // image_source.py rstrips "/" off the configured base.
        while base.ends_with('/') {
            base.pop();
        }
        let http = reqwest::Client::builder()
            .user_agent(DOWNLOADS_USER_AGENT)
            .build()?;
        Ok(Self {
            base_url: base,
            http,
        })
    }

    async fn get(&self, url: &str, timeout: Duration) -> Result<Vec<u8>, ImageError> {
        let response = self.http.get(url).timeout(timeout).send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(ImageError::HttpStatus {
                status: status.as_u16(),
                url: url.to_string(),
                body: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        Ok(bytes.to_vec())
    }
}

impl DownloadsClient for ReqwestDownloadsClient {
    fn base_url(&self) -> String {
        self.base_url.clone()
    }

    async fn fetch_text(&self, url: &str) -> Result<String, ImageError> {
        let bytes = self.get(url, TEXT_TIMEOUT).await?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, ImageError> {
        self.get(url, IMAGE_TIMEOUT).await
    }
}

/// Options for [`fetch_image`].
#[derive(Debug, Clone, Default)]
pub struct FetchOptions<'a> {
    /// Release precedence inputs (`--release` / env vars).
    pub release: ReleaseOverrides<'a>,
    /// Suffix precedence inputs (`--image-suffix` / env var).
    pub suffix: SuffixOverrides<'a>,
    /// Verify against the `sha256sums` index (default `true` at the CLI;
    /// the library requires explicit opt-out like Python's kwarg).
    pub verify: bool,
    /// Re-download even when a matching cached image exists.
    pub force: bool,
}

/// Outcome of [`fetch_image`].
#[derive(Debug, Clone)]
pub struct FetchedImage {
    /// Local path of the cached image.
    pub path: PathBuf,
    /// Resolved release the image belongs to.
    pub release: String,
    /// Image file name.
    pub filename: String,
    /// Source URL the image was (or would be) downloaded from.
    pub url: String,
    /// Verified digest, when verification ran.
    pub sha256: Option<String>,
    /// `true` when an existing cached file satisfied the request and no
    /// download happened.
    pub already_cached: bool,
}

/// Downloads (or reuses) the vanilla OpenWrt image for a model —
/// parity for `fetch_image` in image_source.py:
///
/// 1. Resolve release and suffix through the precedence chains.
/// 2. When verifying, fetch `<target_dir>/sha256sums` and look up the
///    expected digest (absent entry → [`ImageError::NotInChecksumIndex`]).
/// 3. Reuse a cached `images/<filename>` whose digest matches, unless
///    `force` is set.
/// 4. Download, verify the bytes against the index, and write the file
///    atomically (`.part` then rename). A mismatch removes any stale
///    cached file, exactly like Python's `dest.unlink()` path.
pub async fn fetch_image<C: DownloadsClient>(
    client: &C,
    images_root: &Path,
    model: &VanillaModel,
    options: &FetchOptions<'_>,
) -> Result<FetchedImage, ImageError> {
    let release = resolve_release(model, &options.release)?;
    let suffix = resolve_image_suffix(model, &options.suffix);
    let filename = image_filename(model, &release, &suffix)?;
    let base = client.base_url();
    let url = image_url(&base, model, &release, &suffix)?;
    let sums_url = format!(
        "{}/sha256sums",
        target_dir_url(&base, &model.target, &release)
    );

    let expected = if options.verify {
        let index = client.fetch_text(&sums_url).await?;
        parse_sha256sums(&index, &filename).ok_or(ImageError::NotInChecksumIndex {
            filename: filename.clone(),
            url: sums_url.clone(),
        })?
    } else {
        String::new()
    };

    std::fs::create_dir_all(images_root)?;
    let dest = images_root.join(&filename);

    if dest.is_file() && !options.force {
        let matches = !options.verify || crate::cache::sha256_file(&dest)? == expected;
        if matches {
            return Ok(FetchedImage {
                path: dest,
                release,
                filename,
                url,
                sha256: options.verify.then_some(expected),
                already_cached: true,
            });
        }
    }

    let bytes = client.fetch_bytes(&url).await?;
    let actual = hex(&Sha256::digest(&bytes));
    if options.verify && actual != expected {
        let _ = std::fs::remove_file(&dest);
        return Err(ImageError::ShaMismatch {
            filename: filename.clone(),
            expected,
            actual,
        });
    }

    let part = dest.with_extension("bin.part");
    std::fs::write(&part, &bytes)?;
    std::fs::rename(&part, &dest)?;

    Ok(FetchedImage {
        path: dest,
        release,
        filename,
        url,
        sha256: options.verify.then_some(actual),
        already_cached: false,
    })
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vanilla::{DEFAULT_IMAGE_SUFFIX, DEFAULT_RELEASE};
    use std::sync::Mutex;

    const IMAGE_BYTES: &[u8] = b"vanilla-openwrt-image";

    fn sha256_hex(data: &[u8]) -> String {
        hex(&Sha256::digest(data))
    }

    fn model() -> VanillaModel {
        VanillaModel {
            id: "dlink_covr-x1860-a1".into(),
            target: "ramips/mt7621".into(),
            profile: "dlink_covr_x1860-a1".into(),
            release: None,
            image_suffix: None,
        }
    }

    fn filename() -> String {
        image_filename(&model(), DEFAULT_RELEASE, DEFAULT_IMAGE_SUFFIX).expect("filename")
    }

    /// In-memory fake: serves the right digest from its sums index and
    /// counts fetches so cache behaviour is observable.
    struct FakeDownloads {
        image_bytes: Vec<u8>,
        sums_entries: Vec<String>,
        text_fetches: Mutex<usize>,
        byte_fetches: Mutex<usize>,
    }

    impl FakeDownloads {
        fn with_image(bytes: &[u8]) -> Self {
            Self {
                image_bytes: bytes.to_vec(),
                sums_entries: vec![format!("{} *{}", sha256_hex(bytes), filename())],
                text_fetches: Mutex::new(0),
                byte_fetches: Mutex::new(0),
            }
        }

        fn fetches(&self) -> (usize, usize) {
            (
                *self.text_fetches.lock().expect("lock"),
                *self.byte_fetches.lock().expect("lock"),
            )
        }
    }

    impl DownloadsClient for FakeDownloads {
        fn base_url(&self) -> String {
            "https://downloads.example.org".into()
        }

        async fn fetch_text(&self, url: &str) -> Result<String, ImageError> {
            *self.text_fetches.lock().expect("lock") += 1;
            assert!(
                url.ends_with("/sha256sums"),
                "text fetches are the sums index"
            );
            Ok(self.sums_entries.join("\n"))
        }

        async fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, ImageError> {
            *self.byte_fetches.lock().expect("lock") += 1;
            assert!(url.contains("/releases/"), "byte fetches are images");
            Ok(self.image_bytes.clone())
        }
    }

    fn verifying() -> FetchOptions<'static> {
        FetchOptions {
            verify: true,
            ..FetchOptions::default()
        }
    }

    #[tokio::test]
    async fn downloads_verifies_and_caches_flat_in_images_dir() {
        let client = FakeDownloads::with_image(IMAGE_BYTES);
        let root = tempfile::tempdir().expect("tempdir");

        let fetched = fetch_image(&client, root.path(), &model(), &verifying())
            .await
            .expect("fetched");

        assert!(!fetched.already_cached);
        assert_eq!(fetched.release, DEFAULT_RELEASE);
        assert_eq!(fetched.filename, filename());
        assert_eq!(
            fetched.url,
            format!(
                "https://downloads.example.org/releases/{DEFAULT_RELEASE}/targets/ramips/mt7621/{}",
                filename()
            )
        );
        assert_eq!(
            fetched.sha256.as_deref(),
            Some(sha256_hex(IMAGE_BYTES).as_str())
        );
        assert_eq!(fetched.path, root.path().join(filename()));
        assert_eq!(std::fs::read(&fetched.path).expect("image"), IMAGE_BYTES);
        assert!(!root.path().join(format!("{}.part", filename())).exists());
    }

    #[tokio::test]
    async fn matching_cache_hit_skips_the_download() {
        let client = FakeDownloads::with_image(IMAGE_BYTES);
        let root = tempfile::tempdir().expect("tempdir");
        fetch_image(&client, root.path(), &model(), &verifying())
            .await
            .expect("first");

        let cached = fetch_image(&client, root.path(), &model(), &verifying())
            .await
            .expect("second");
        assert!(cached.already_cached);
        assert_eq!(
            client.fetches(),
            (2, 1),
            "sums re-checked, image not re-downloaded"
        );
    }

    #[tokio::test]
    async fn force_redownloads_despite_matching_cache() {
        let client = FakeDownloads::with_image(IMAGE_BYTES);
        let root = tempfile::tempdir().expect("tempdir");
        let forced = FetchOptions {
            force: true,
            ..verifying()
        };
        fetch_image(&client, root.path(), &model(), &forced)
            .await
            .expect("first");
        fetch_image(&client, root.path(), &model(), &forced)
            .await
            .expect("second");
        assert_eq!(client.fetches(), (2, 2));
    }

    #[tokio::test]
    async fn stale_cache_with_wrong_digest_is_replaced() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(root.path().join(filename()), b"stale bytes").expect("stale");

        let client = FakeDownloads::with_image(IMAGE_BYTES);
        let fetched = fetch_image(&client, root.path(), &model(), &verifying())
            .await
            .expect("replaced");
        assert!(!fetched.already_cached);
        assert_eq!(std::fs::read(&fetched.path).expect("image"), IMAGE_BYTES);
    }

    #[tokio::test]
    async fn sha_mismatch_errors_and_clears_the_stale_file() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(root.path().join(filename()), b"stale bytes").expect("stale");

        // Index advertises a digest that does not match the served bytes.
        let mut client = FakeDownloads::with_image(IMAGE_BYTES);
        client.sums_entries = vec![format!("{} *{}", "0".repeat(64), filename())];

        let err = fetch_image(&client, root.path(), &model(), &verifying())
            .await
            .expect_err("mismatch");
        assert!(matches!(err, ImageError::ShaMismatch { .. }));
        assert!(
            !root.path().join(filename()).exists(),
            "mismatch must leave no file behind"
        );
    }

    #[tokio::test]
    async fn missing_sums_entry_is_reported_with_the_index_url() {
        let mut client = FakeDownloads::with_image(IMAGE_BYTES);
        client.sums_entries = vec![format!("{} *other-image.bin", "a".repeat(64))];

        let root = tempfile::tempdir().expect("tempdir");
        let err = fetch_image(&client, root.path(), &model(), &verifying())
            .await
            .expect_err("not indexed");
        match err {
            ImageError::NotInChecksumIndex {
                filename: listed,
                url,
            } => {
                assert_eq!(listed, filename());
                assert!(url.ends_with("/sha256sums"));
            }
            other => panic!("expected NotInChecksumIndex, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_false_skips_the_index_and_caches_blindly() {
        let client = FakeDownloads::with_image(IMAGE_BYTES);
        let root = tempfile::tempdir().expect("tempdir");
        let opts = FetchOptions::default();

        let fetched = fetch_image(&client, root.path(), &model(), &opts)
            .await
            .expect("fetched");
        assert_eq!(fetched.sha256, None);
        assert_eq!(client.fetches(), (0, 1), "no sums fetch without verify");

        let cached = fetch_image(&client, root.path(), &model(), &opts)
            .await
            .expect("cached");
        assert!(cached.already_cached);
    }
}
