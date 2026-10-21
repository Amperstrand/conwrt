//! On-disk cache metadata (`build.metadata.json`) and the query operations
//! behind firmware-manager.py's `list`, `show`, and `find` subcommands.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::cache::{hash_dir, sorted_subdirs};
use crate::types::ImageType;

/// Name of the canonical metadata file inside a cache directory.
pub const METADATA_FILENAME: &str = "build.metadata.json";

fn empty_object() -> Value {
    Value::Object(Map::new())
}

/// Metadata for one cached build, written as `build.metadata.json` inside
/// `<images_root>/<profile>/<cache_key>/`. Shape-compatible with the dict
/// firmware-manager.py writes at the end of `cmd_request`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CachedMetadata {
    /// Local cache key (see [`crate::cache::cache_key`]).
    #[serde(default)]
    pub cache_key: String,
    /// Server-side ASU request hash.
    #[serde(default)]
    pub request_hash: String,
    /// Distro (`openwrt`).
    #[serde(default)]
    pub distro: String,
    /// OpenWrt release of the build.
    #[serde(default)]
    pub version: String,
    /// Release commit code (`r…`).
    #[serde(default)]
    pub version_code: String,
    /// Target of the build.
    #[serde(default)]
    pub target: String,
    /// Profile of the build.
    #[serde(default)]
    pub profile: String,
    /// Requested packages (what was sent to ASU, not the full set).
    #[serde(default)]
    pub packages: Vec<String>,
    /// Full resolved package set (name → version) from the manifest.
    #[serde(default)]
    pub packages_all: Map<String, Value>,
    /// First-boot defaults script, when one was baked in.
    #[serde(default)]
    pub defaults: Option<String>,
    /// Where the embedded SSH key came from, when one was baked in.
    #[serde(default)]
    pub ssh_key_source: Option<String>,
    /// Downloaded (and verified) images.
    #[serde(default)]
    pub images: Vec<CachedImage>,
    /// Kernel version info from the manifest (`{}` when absent).
    #[serde(default = "empty_object")]
    pub linux_kernel: Value,
    /// Build completion timestamp (server format).
    #[serde(default)]
    pub build_at: String,
    /// Enqueue timestamp (server format) — the `find` ordering key.
    #[serde(default)]
    pub enqueued_at: String,
    /// When this build was downloaded and cached (UTC).
    #[serde(default)]
    pub downloaded_at: String,
}

/// One downloaded image recorded in [`CachedMetadata`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedImage {
    /// Flavour derived from the file name (`"type"` in the JSON).
    #[serde(rename = "type")]
    pub image_type: ImageType,
    /// Image file name.
    pub name: String,
    /// SHA-256 hex digest of the downloaded file.
    pub sha256: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// `true` once the SHA-256 check has passed (or was not required —
    /// same convention as firmware-manager.py).
    pub verified: bool,
}

/// One row of the `list` view (firmware-manager.py `cmd_list`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    /// Profile directory name.
    pub profile: String,
    /// First 12 characters of the cache key.
    pub hash: String,
    /// Version, or `"?"` when metadata is missing.
    pub version: String,
    /// `build_at` truncated to 19 chars, or `"?"` when missing.
    pub build_date: String,
    /// Comma-joined image types (sorted, deduplicated), `"none"` for an
    /// empty image list, `"?"` when metadata is missing.
    pub types: String,
}

/// Path of the canonical metadata file for a cached build.
pub fn metadata_path(images_root: &Path, profile: &str, cache_key: &str) -> PathBuf {
    hash_dir(images_root, profile, cache_key).join(METADATA_FILENAME)
}

/// Reads metadata for a cached build.
///
/// Falls back to the legacy `<cache_key>.metadata.json` file name used by
/// older firmware-manager versions, and returns `None` on any read or parse
/// error — parity with `_read_metadata` in firmware-manager.py.
pub fn read_metadata(images_root: &Path, profile: &str, cache_key: &str) -> Option<CachedMetadata> {
    let canonical = metadata_path(images_root, profile, cache_key);
    let path = if canonical.exists() {
        canonical
    } else {
        let legacy =
            hash_dir(images_root, profile, cache_key).join(format!("{cache_key}.metadata.json"));
        if legacy.exists() { legacy } else { return None }
    };
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// firmware-manager.py `_find_cached_firmware`: metadata present, every
/// image marked verified, and the directory present. Returns the metadata
/// of the cached build.
pub fn find_cached_build(
    images_root: &Path,
    profile: &str,
    cache_key: &str,
) -> Option<CachedMetadata> {
    let metadata = read_metadata(images_root, profile, cache_key)?;
    if !metadata.images.iter().all(|image| image.verified) {
        return None;
    }
    hash_dir(images_root, profile, cache_key)
        .exists()
        .then_some(metadata)
}

/// Directory of a cached-and-verified build, when present.
pub fn find_cached(images_root: &Path, profile: &str, cache_key: &str) -> Option<PathBuf> {
    find_cached_build(images_root, profile, cache_key)
        .map(|_| hash_dir(images_root, profile, cache_key))
}

/// Writes metadata as pretty JSON with a trailing newline to
/// `<images_root>/<profile>/<cache_key>/build.metadata.json`, creating the
/// directory as needed. Parity with the `meta_path.write_text(json.dumps(
/// metadata, indent=2) + "\n")` in firmware-manager.py.
pub fn write_metadata(images_root: &Path, metadata: &CachedMetadata) -> std::io::Result<PathBuf> {
    let dir = hash_dir(images_root, &metadata.profile, &metadata.cache_key);
    fs::create_dir_all(&dir)?;
    let mut json = serde_json::to_string_pretty(metadata)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    json.push('\n');
    let path = dir.join(METADATA_FILENAME);
    fs::write(&path, json)?;
    Ok(path)
}

/// Lists cached builds (firmware-manager.py `cmd_list`), sorted by profile
/// then cache key. An empty vector when `images_root` does not exist.
pub fn list_entries(
    images_root: &Path,
    profile_filter: Option<&str>,
) -> std::io::Result<Vec<ListEntry>> {
    let mut entries = Vec::new();
    for profile_dir in sorted_subdirs(images_root)? {
        let profile = file_name(&profile_dir);
        if let Some(filter) = profile_filter {
            if profile != filter {
                continue;
            }
        }
        for hash_dir in sorted_subdirs(&profile_dir)? {
            let cache_key = file_name(&hash_dir);
            let Some(metadata) = read_metadata(images_root, &profile, &cache_key) else {
                entries.push(ListEntry {
                    profile: profile.clone(),
                    hash: cache_key.chars().take(12).collect(),
                    version: "?".into(),
                    build_date: "?".into(),
                    types: "?".into(),
                });
                continue;
            };
            entries.push(ListEntry {
                profile: profile.clone(),
                hash: cache_key.chars().take(12).collect(),
                version: non_empty_or(&metadata.version, "?"),
                build_date: metadata.build_at.chars().take(19).collect(),
                types: image_types_label(&metadata),
            });
        }
    }
    Ok(entries)
}

/// `show` (firmware-manager.py `cmd_show`): exact cache key first, then a
/// unique-prefix match against the profile's cache directories. Returns the
/// resolved full cache key and the metadata.
pub fn show_metadata(
    images_root: &Path,
    profile: &str,
    hash_or_prefix: &str,
) -> Option<(String, CachedMetadata)> {
    if let Some(metadata) = read_metadata(images_root, profile, hash_or_prefix) {
        return Some((hash_or_prefix.to_string(), metadata));
    }
    let profile_dir = images_root.join(profile);
    for hash_dir in sorted_subdirs(&profile_dir).ok()? {
        let cache_key = file_name(&hash_dir);
        if cache_key.starts_with(hash_or_prefix) {
            if let Some(metadata) = read_metadata(images_root, profile, &cache_key) {
                return Some((cache_key, metadata));
            }
        }
    }
    None
}

/// `find` (firmware-manager.py `cmd_find`): newest build for a profile —
/// ordered by `enqueued_at` (descending), then cache key (descending), the
/// same tuple ordering Python's `candidates.sort(reverse=True)` produces.
///
/// Returns the newest existing image file matching `image_type` (any image
/// when `None`), falling back to the cache directory when files are gone.
pub fn find_latest(
    images_root: &Path,
    profile: &str,
    image_type: Option<ImageType>,
) -> Option<PathBuf> {
    let profile_dir = images_root.join(profile);
    let mut candidates: Vec<(String, String, CachedMetadata)> = Vec::new();
    for hash_dir in sorted_subdirs(&profile_dir).ok()? {
        let cache_key = file_name(&hash_dir);
        let Some(metadata) = read_metadata(images_root, profile, &cache_key) else {
            continue;
        };
        let matches = metadata
            .images
            .iter()
            .filter(|image| image_type.is_none_or(|wanted| image.image_type == wanted))
            .count();
        if matches == 0 {
            continue;
        }
        candidates.push((metadata.enqueued_at.clone(), cache_key, metadata));
    }
    candidates.sort_by(|a, b| (&b.0, &b.1).cmp(&(&a.0, &a.1)));
    let (_, newest_key, metadata) = candidates.into_iter().next()?;
    let dir = hash_dir(images_root, profile, &newest_key);
    for image in &metadata.images {
        if let Some(wanted) = image_type {
            if image.image_type != wanted {
                continue;
            }
        }
        let path = dir.join(&image.name);
        if path.exists() {
            return Some(path);
        }
    }
    dir.exists().then_some(dir)
}

fn image_types_label(metadata: &CachedMetadata) -> String {
    if metadata.images.is_empty() {
        return "none".into();
    }
    let mut labels: Vec<&str> = metadata
        .images
        .iter()
        .map(|image| image.image_type.as_str())
        .collect();
    labels.sort_unstable();
    labels.dedup();
    labels.join(", ")
}

fn non_empty_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.into()
    } else {
        value.to_string()
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ImageType;

    fn sample_metadata(profile: &str, cache_key: &str, enqueued_at: &str) -> CachedMetadata {
        CachedMetadata {
            cache_key: cache_key.into(),
            request_hash: "reqhash".into(),
            distro: "openwrt".into(),
            version: "24.10.2".into(),
            version_code: "r1234".into(),
            target: "ramips/mt7621".into(),
            profile: profile.into(),
            packages: vec!["curl".into()],
            packages_all: Map::new(),
            defaults: None,
            ssh_key_source: None,
            images: vec![CachedImage {
                image_type: ImageType::Sysupgrade,
                name: "fw-squashfs-sysupgrade.bin".into(),
                sha256: "abc".into(),
                size_bytes: 42,
                verified: true,
            }],
            linux_kernel: Value::Object(Map::new()),
            build_at: "2026-10-12T10:00:00+00:00".into(),
            enqueued_at: enqueued_at.into(),
            downloaded_at: "2026-10-12T10:05:00".into(),
        }
    }

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn write_then_read_metadata_roundtrips() {
        let root = temp_root();
        let metadata = sample_metadata("p_one", "key1111", "2026-10-12T09:00:00");
        let path = write_metadata(root.path(), &metadata).expect("write");
        assert_eq!(path, metadata_path(root.path(), "p_one", "key1111"));

        let text = fs::read_to_string(&path).expect("text");
        assert!(text.ends_with('\n'), "parity: trailing newline");
        assert!(text.contains("\"type\": \"sysupgrade\""));

        let read = read_metadata(root.path(), "p_one", "key1111").expect("read");
        assert_eq!(read, metadata);
    }

    #[test]
    fn read_metadata_falls_back_to_legacy_file_name() {
        let root = temp_root();
        let dir = hash_dir(root.path(), "p_one", "key1111");
        fs::create_dir_all(&dir).expect("mkdir");
        let legacy = dir.join("key1111.metadata.json");
        fs::write(
            &legacy,
            serde_json::to_string(&sample_metadata("p_one", "key1111", "t")).expect("json"),
        )
        .expect("write");
        assert!(read_metadata(root.path(), "p_one", "key1111").is_some());
    }

    #[test]
    fn read_metadata_returns_none_for_garbage() {
        let root = temp_root();
        let dir = hash_dir(root.path(), "p_one", "key1111");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(dir.join(METADATA_FILENAME), "{not json").expect("write");
        assert!(read_metadata(root.path(), "p_one", "key1111").is_none());
    }

    #[test]
    fn find_cached_requires_verified_images_and_directory() {
        let root = temp_root();
        let mut metadata = sample_metadata("p_one", "key1111", "2026-10-12T09:00:00");
        write_metadata(root.path(), &metadata).expect("write");
        assert!(find_cached(root.path(), "p_one", "key1111").is_some());

        metadata.images[0].verified = false;
        write_metadata(root.path(), &metadata).expect("write");
        assert!(
            find_cached(root.path(), "p_one", "key1111").is_none(),
            "unverified images must not count as cached"
        );
    }

    #[test]
    fn list_entries_covers_metadata_and_missing_metadata_dirs() {
        let root = temp_root();
        write_metadata(root.path(), &sample_metadata("a_prof", "aaaa1111", "t")).expect("write");
        write_metadata(root.path(), &sample_metadata("b_prof", "bbbb2222", "t")).expect("write");
        // A cache directory with unreadable metadata.
        fs::create_dir_all(hash_dir(root.path(), "a_prof", "zzzz3333")).expect("mkdir");

        let entries = list_entries(root.path(), None).expect("list");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].profile, "a_prof");
        assert_eq!(entries[0].hash, "aaaa1111");
        assert_eq!(entries[0].version, "24.10.2");
        assert_eq!(entries[0].build_date, "2026-10-12T10:00:00");
        assert_eq!(entries[0].types, "sysupgrade");
        // The unreadable-metadata directory still lists, with placeholders.
        assert_eq!(entries[1].profile, "a_prof");
        assert_eq!(entries[1].hash, "zzzz3333");
        assert_eq!(entries[1].version, "?");
        assert_eq!(entries[1].types, "?");
        assert_eq!(entries[2].profile, "b_prof");
        assert_eq!(entries[2].hash, "bbbb2222");

        let filtered = list_entries(root.path(), Some("b_prof")).expect("list");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].profile, "b_prof");
    }

    #[test]
    fn list_entries_empty_types_render_none() {
        let root = temp_root();
        let mut metadata = sample_metadata("p_one", "key1111", "t");
        metadata.images.clear();
        write_metadata(root.path(), &metadata).expect("write");
        let entries = list_entries(root.path(), None).expect("list");
        assert_eq!(entries[0].types, "none");
    }

    #[test]
    fn show_metadata_matches_exact_then_prefix() {
        let root = temp_root();
        write_metadata(root.path(), &sample_metadata("p_one", "abcdef1234", "t")).expect("write");

        let (key, meta) = show_metadata(root.path(), "p_one", "abcdef1234").expect("exact");
        assert_eq!(key, "abcdef1234");
        assert_eq!(meta.cache_key, "abcdef1234");

        let (key, _) = show_metadata(root.path(), "p_one", "abc").expect("prefix");
        assert_eq!(key, "abcdef1234");

        assert!(show_metadata(root.path(), "p_one", "zzz").is_none());
    }

    #[test]
    fn find_latest_prefers_newest_enqueued_and_honors_type_filter() {
        let root = temp_root();
        for (key, enqueued) in [
            ("old1111", "2026-10-01T00:00:00"),
            ("new2222", "2026-10-12T00:00:00"),
        ] {
            let mut metadata = sample_metadata("p_one", key, enqueued);
            metadata.images.push(CachedImage {
                image_type: ImageType::Factory,
                name: "fw-factory.bin".into(),
                sha256: "def".into(),
                size_bytes: 7,
                verified: true,
            });
            write_metadata(root.path(), &metadata).expect("write");
            // Create the image files so `find` can return them.
            for name in ["fw-squashfs-sysupgrade.bin", "fw-factory.bin"] {
                fs::write(hash_dir(root.path(), "p_one", key).join(name), b"fw").expect("write");
            }
        }

        let sysupgrade = find_latest(root.path(), "p_one", Some(ImageType::Sysupgrade))
            .expect("sysupgrade found");
        assert!(sysupgrade.ends_with("new2222/fw-squashfs-sysupgrade.bin"));

        let factory =
            find_latest(root.path(), "p_one", Some(ImageType::Factory)).expect("factory found");
        assert!(factory.ends_with("new2222/fw-factory.bin"));

        let any = find_latest(root.path(), "p_one", None).expect("any found");
        assert!(any.ends_with("new2222/fw-squashfs-sysupgrade.bin"));

        assert!(find_latest(root.path(), "p_one", Some(ImageType::Recovery)).is_none());
        assert!(find_latest(root.path(), "missing", None).is_none());
    }

    #[test]
    fn find_latest_falls_back_to_directory_when_files_missing() {
        let root = temp_root();
        write_metadata(root.path(), &sample_metadata("p_one", "key1111", "t")).expect("write");
        let found = find_latest(root.path(), "p_one", None).expect("dir fallback");
        assert_eq!(found, hash_dir(root.path(), "p_one", "key1111"));
    }

    #[test]
    fn list_entries_empty_when_root_missing() {
        let root = temp_root();
        let entries = list_entries(root.path().join("nope").as_path(), None).expect("list");
        assert!(entries.is_empty());
    }
}
