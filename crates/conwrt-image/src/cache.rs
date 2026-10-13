//! Pure cache-layout helpers: cache-key computation, directory layout,
//! store URLs, and SHA-256 verification.
//!
//! Everything here works on values and paths the caller supplies — no HTTP,
//! no global state — so the parity-critical logic (especially the cache key)
//! is unit-testable in isolation.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::types::BuildRequest;

/// Lowercase hex encoding.
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// SHA-256 of a file as lowercase hex, computed in 1 MiB chunks (matching
/// firmware-manager.py's streaming `flash.context.sha256_file`).
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Cache key for a build request — byte-for-byte parity with
/// `_compute_cache_key` in `scripts/firmware-manager.py`:
///
/// ```text
/// sha256("{distro}\n{version}\n{target}\n{profile}\n{':'.join(sorted(packages))}\n{defaults}")
/// ```
///
/// `packages` is sorted (lexicographically) and joined with `:` before
/// hashing; `None` and an empty list produce the same payload, exactly like
/// Python's `packages or []`.
pub fn cache_key(
    distro: &str,
    version: &str,
    target: &str,
    profile: &str,
    packages: Option<&[String]>,
    defaults: Option<&str>,
) -> String {
    let joined = match packages {
        Some(pkgs) => {
            let mut sorted = pkgs.to_vec();
            sorted.sort();
            sorted.join(":")
        }
        None => String::new(),
    };
    let payload = format!(
        "{distro}\n{version}\n{target}\n{profile}\n{joined}\n{}",
        defaults.unwrap_or("")
    );
    hex(&Sha256::digest(payload.as_bytes()))
}

/// Cache key for a [`BuildRequest`] (see [`cache_key`]).
pub fn request_cache_key(request: &BuildRequest) -> String {
    cache_key(
        &request.distro,
        &request.version,
        &request.target,
        &request.profile,
        request.packages.as_deref(),
        request.defaults.as_deref(),
    )
}

/// Directory caching one build: `<images_root>/<profile>/<cache_key>/`
/// (the `IMAGES_DIR / profile / request_hash` layout of
/// firmware-manager.py, keyed by the local cache key).
pub fn hash_dir(images_root: &Path, profile: &str, cache_key: &str) -> PathBuf {
    images_root.join(profile).join(cache_key)
}

/// Download URL for one image under the ASU store:
/// `<store_base>/<bin_dir>/<filename>` — parity with the `download_url`
/// construction in firmware-manager.py.
pub fn store_url(store_base: &str, bin_dir: &str, filename: &str) -> String {
    format!("{store_base}/{bin_dir}/{filename}")
}

/// Sorted subdirectories of `dir` (by name). Returns an empty vector when
/// `dir` does not exist, mirroring `sorted(IMAGES_DIR.iterdir())` guards in
/// firmware-manager.py.
pub(crate) fn sorted_subdirs(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut subdirs = Vec::new();
    if !dir.is_dir() {
        return Ok(subdirs);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            subdirs.push(entry.path());
        }
    }
    subdirs.sort();
    Ok(subdirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ImageType;

    // Goldens generated with the actual `_compute_cache_key` from
    // scripts/firmware-manager.py (python3 hashlib) — the parity oracle.
    const GOLDEN_NO_EXTRAS: &str =
        "4e9ae68b1e78461030303b982364a8fac7098b7c5c7d71574f42c30ed48ca8ec";
    const GOLDEN_PACKAGES: &str =
        "5952abbdba234b5b758a220bcb58286f63457fa3fe62515b5366ad549ead1dfd";
    const GOLDEN_PACKAGES_DEFAULTS: &str =
        "2f0c737524fdaf4c86f425b425ece1689deedf072325bae3be0109f2a22637fe";
    const GOLDEN_EMPTY_PACKAGES: &str =
        "5bb515475ea21d1b6f73c03331838615102359f8e95cb15dc3cb4ea2b4575090";

    #[test]
    fn cache_key_matches_python_golden() {
        assert_eq!(
            cache_key(
                "openwrt",
                "24.10.2",
                "ramips/mt7621",
                "dlink_covr_x1860_a1",
                None,
                None
            ),
            GOLDEN_NO_EXTRAS
        );
        assert_eq!(
            cache_key(
                "openwrt",
                "24.10.2",
                "ramips/mt7621",
                "dlink_covr_x1860_a1",
                Some(&[
                    "curl".to_string(),
                    "htop".to_string(),
                    "wireguard-tools".to_string()
                ]),
                None
            ),
            GOLDEN_PACKAGES
        );
        assert_eq!(
            cache_key(
                "openwrt",
                "25.12.4",
                "mediatek/filogic",
                "glinet_mt3000",
                Some(&["b".to_string(), "a".to_string(), "c".to_string()]),
                Some("echo hello")
            ),
            GOLDEN_PACKAGES_DEFAULTS
        );
    }

    #[test]
    fn cache_key_sorts_packages_and_treats_none_like_empty() {
        let unsorted = cache_key(
            "openwrt",
            "25.12.4",
            "mediatek/filogic",
            "glinet_mt3000",
            Some(&["c".to_string(), "a".to_string(), "b".to_string()]),
            Some("echo hello"),
        );
        assert_eq!(unsorted, GOLDEN_PACKAGES_DEFAULTS);

        assert_eq!(
            cache_key(
                "openwrt",
                "24.10.2",
                "ramips/mt7621",
                "p",
                Some(&[]),
                Some("")
            ),
            GOLDEN_EMPTY_PACKAGES
        );
    }

    #[test]
    fn request_cache_key_uses_request_fields() {
        let mut request = BuildRequest::openwrt("24.10.2", "ramips/mt7621", "dlink_covr_x1860_a1");
        assert_eq!(request_cache_key(&request), GOLDEN_NO_EXTRAS);
        request.packages = Some(vec!["wireguard-tools".into(), "curl".into(), "htop".into()]);
        assert_eq!(request_cache_key(&request), GOLDEN_PACKAGES);
    }

    #[test]
    fn hash_dir_layout_matches_images_profile_key() {
        let dir = hash_dir(Path::new("/tmp/images"), "dlink_covr_x1860_a1", "abc123");
        assert_eq!(dir, PathBuf::from("/tmp/images/dlink_covr_x1860_a1/abc123"));
    }

    #[test]
    fn store_url_joins_store_bin_dir_and_filename() {
        assert_eq!(
            store_url("https://sysupgrade.openwrt.org/store", "07/ab", "fw.bin"),
            "https://sysupgrade.openwrt.org/store/07/ab/fw.bin"
        );
    }

    #[test]
    fn sha256_file_streams_known_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("payload.bin");
        // ~2.5 MiB so the 1 MiB chunked read loops at least twice.
        let mut data = vec![0u8; (2 << 20) + 123];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        std::fs::write(&path, &data).expect("write");
        let digest = sha256_file(&path).expect("digest");
        assert_eq!(
            digest,
            hex(&Sha256::digest(&data)),
            "chunked file hashing must equal whole-buffer hashing"
        );
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn image_type_ordering_allows_sorted_dedup() {
        // The `list` types column is sorted by label (alphabetical), not by
        // enum declaration order.
        let mut labels = [
            ImageType::Sysupgrade.as_str(),
            ImageType::Factory.as_str(),
            ImageType::Recovery.as_str(),
        ];
        labels.sort_unstable();
        assert_eq!(labels, ["factory", "recovery", "sysupgrade"]);
    }
}
