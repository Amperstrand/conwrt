//! Flash-method-aware image selection — parity for the selection logic in
//! `scripts/conwrt/firmware.py` (`_request_custom_image`'s candidate
//! resolution, minus the CLI glue).
//!
//! Given a profile and a flash method, pick the cached image to flash:
//!
//! 1. Try the method's preferred image types in order
//!    ([`preferred_image_types`]), taking the first type for which the
//!    newest build has an existing image **file** (directory-only fallbacks
//!    from `find` are skipped, like Python's `os.path.isfile` check).
//! 2. Fall back to the newest build with any image type.
//! 3. Last resort: scan the profile's cache directories newest-name-first
//!    for any `.bin`/`.img`/`.tar` file (the `sorted(..., reverse=True)`
//!    scan in firmware.py).
//!
//! The selected image's `build.metadata.json` is loaded alongside it, and
//! for initramfs-based flash methods the companion initramfs image is
//! located (firmware.py's `initramfs_path`).

use std::path::{Path, PathBuf};

use crate::metadata::{CachedMetadata, find_latest, read_metadata};
use crate::types::ImageType;

/// Flash methods that boot a recovery artefact and therefore prefer
/// recovery/factory images over sysupgrade (the `recovery_methods` set in
/// firmware.py).
pub const RECOVERY_FLASH_METHODS: &[&str] = &[
    "recovery-http",
    "uboot-http",
    "uboot-tftp",
    "zycast",
    "dlink-hnap",
    "mtd-write",
    "extreme-rdwr-tftp-initramfs",
    "oem-http",
];

/// Flash methods that additionally want the companion initramfs image
/// (the set in firmware.py that sets `metadata["initramfs_path"]`).
pub const INITRAMFS_FLASH_METHODS: &[&str] = &[
    "edgeos-kernel-swap",
    "extreme-rdwr-tftp-initramfs",
    "oem-http",
];

/// Image types a flash method should use, in preference order.
///
/// firmware.py lists `["recovery", "factory", "initramfs"]` for recovery
/// methods, but `firmware-manager.py find --type` only accepts
/// `recovery|factory|sysupgrade` — the third entry would abort the Python
/// process with argparse's `SystemExit(2)`. This port treats the effective
/// preference as `[recovery, factory]` and falls through to the untyped
/// lookup instead of dying (deliberate deviation, see the PR parity
/// table).
pub fn preferred_image_types(flash_method: &str) -> &'static [ImageType] {
    const RECOVERY: &[ImageType] = &[ImageType::Recovery, ImageType::Factory];
    const SYSUPGRADE: &[ImageType] = &[ImageType::Sysupgrade];
    if RECOVERY_FLASH_METHODS.contains(&flash_method) {
        RECOVERY
    } else {
        SYSUPGRADE
    }
}

/// The image firmware.py would flash for `profile` under `flash_method`,
/// with its metadata and provenance.
#[derive(Debug, Clone)]
pub struct SelectedImage {
    /// Image file to flash.
    pub path: PathBuf,
    /// Matched preference when found via the typed lookup; `None` when
    /// selected by the untyped or directory-scan fallbacks.
    pub image_type: Option<ImageType>,
    /// `true` when a non-first preference (or a fallback) was used —
    /// firmware.py logs a boot-failure warning for this case
    /// (factory.bin into recovery-http bricks COVR-class devices).
    pub fell_back: bool,
    /// Metadata of the build the image belongs to, when present and
    /// parseable (firmware.py tolerates missing/garbage metadata).
    pub metadata: Option<CachedMetadata>,
    /// Companion initramfs image for [`INITRAMFS_FLASH_METHODS`]; `None`
    /// for other methods or when absent (firmware.py warns and stores an
    /// empty string — modelled as `None` here).
    pub initramfs_path: Option<PathBuf>,
}

/// Selects the cached image to flash for `profile` under `flash_method`.
///
/// Returns `Ok(None)` when nothing flashable is cached (firmware.py's
/// "No firmware image file found after ASU request").
pub fn select_image(
    images_root: &Path,
    profile: &str,
    flash_method: &str,
) -> std::io::Result<Option<SelectedImage>> {
    let preferences = preferred_image_types(flash_method);
    for image_type in preferences {
        let path =
            find_latest(images_root, profile, Some(*image_type)).filter(|path| path.is_file());
        if let Some(path) = path {
            return Ok(Some(with_context(
                images_root,
                profile,
                path,
                Some(*image_type),
                image_type != &preferences[0],
                flash_method,
            )?));
        }
    }

    // Untyped fallback: newest build with any image type.
    if let Some(path) = find_latest(images_root, profile, None).filter(|path| path.is_file()) {
        return Ok(Some(with_context(
            images_root,
            profile,
            path,
            None,
            true,
            flash_method,
        )?));
    }

    // Last resort: newest-named cache directory containing any image file.
    if let Some(path) = scan_for_any_image(images_root, profile)? {
        return Ok(Some(with_context(
            images_root,
            profile,
            path,
            None,
            true,
            flash_method,
        )?));
    }
    Ok(None)
}

fn scan_for_any_image(images_root: &Path, profile: &str) -> std::io::Result<Option<PathBuf>> {
    let profile_dir = images_root.join(profile);
    // firmware.py: sorted(profile_dir.iterdir(), reverse=True) — newest
    // cache-key name first, not mtime or enqueued_at.
    let mut hash_dirs = crate::cache::sorted_subdirs(&profile_dir)?;
    hash_dirs.reverse();
    for hash_dir in hash_dirs {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&hash_dir)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_file())
            .collect();
        files.sort();
        if let Some(found) = files.into_iter().find(|path| {
            matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("bin" | "img" | "tar")
            )
        }) {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

fn with_context(
    images_root: &Path,
    profile: &str,
    path: PathBuf,
    image_type: Option<ImageType>,
    fell_back: bool,
    flash_method: &str,
) -> std::io::Result<SelectedImage> {
    let cache_key = path
        .parent()
        .and_then(|parent| parent.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let metadata = read_metadata(images_root, profile, &cache_key);
    let initramfs_path = if INITRAMFS_FLASH_METHODS.contains(&flash_method) {
        scan_for_initramfs(path.parent())
    } else {
        None
    };
    Ok(SelectedImage {
        path,
        image_type,
        fell_back,
        metadata,
        initramfs_path,
    })
}

/// First sorted file in `dir` whose name contains `initramfs`
/// (firmware.py's companion lookup).
fn scan_for_initramfs(dir: Option<&Path>) -> Option<PathBuf> {
    let dir = dir?;
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    files.into_iter().find(|path| {
        path.file_name()
            .is_some_and(|name| name.to_string_lossy().contains("initramfs"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{CachedImage, CachedMetadata, write_metadata};
    use serde_json::{Map, Value};

    fn build_metadata(
        profile: &str,
        cache_key: &str,
        enqueued_at: &str,
        images: &[(&str, ImageType)],
    ) -> CachedMetadata {
        CachedMetadata {
            cache_key: cache_key.into(),
            request_hash: format!("hash-{cache_key}"),
            distro: "openwrt".into(),
            version: "24.10.2".into(),
            version_code: "r1".into(),
            target: "ramips/mt7621".into(),
            profile: profile.into(),
            packages: vec![],
            packages_all: Map::new(),
            defaults: None,
            ssh_key_source: None,
            images: images
                .iter()
                .map(|(name, image_type)| CachedImage {
                    image_type: *image_type,
                    name: name.to_string(),
                    sha256: "abc".into(),
                    size_bytes: 10,
                    verified: true,
                })
                .collect(),
            linux_kernel: Value::Object(Map::new()),
            build_at: format!("{enqueued_at}Z"),
            enqueued_at: enqueued_at.into(),
            downloaded_at: "2026-10-12T10:00:00".into(),
        }
    }

    fn cache_build(
        root: &Path,
        profile: &str,
        cache_key: &str,
        enqueued_at: &str,
        images: &[(&str, ImageType)],
    ) {
        write_metadata(
            root,
            &build_metadata(profile, cache_key, enqueued_at, images),
        )
        .expect("write metadata");
        let dir = root.join(profile).join(cache_key);
        std::fs::create_dir_all(&dir).expect("mkdir");
        for (name, _) in images {
            std::fs::write(dir.join(name), b"fw").expect("write image");
        }
    }

    #[test]
    fn preference_lists_match_firmware_py() {
        assert_eq!(
            preferred_image_types("recovery-http"),
            &[ImageType::Recovery, ImageType::Factory]
        );
        assert_eq!(
            preferred_image_types("extreme-rdwr-tftp-initramfs"),
            &[ImageType::Recovery, ImageType::Factory]
        );
        assert_eq!(
            preferred_image_types("sysupgrade"),
            &[ImageType::Sysupgrade]
        );
        assert_eq!(
            preferred_image_types("dlink-hnap"),
            &[ImageType::Recovery, ImageType::Factory]
        );
        assert_eq!(
            preferred_image_types("some-unknown-method"),
            &[ImageType::Sysupgrade]
        );
    }

    #[test]
    fn recovery_method_prefers_recovery_then_factory_over_sysupgrade() {
        let root = tempfile::tempdir().expect("tempdir");
        cache_build(
            root.path(),
            "p",
            "aaaa",
            "2026-10-12T10:00:00",
            &[("fw-sysupgrade.bin", ImageType::Sysupgrade)],
        );
        cache_build(
            root.path(),
            "p",
            "bbbb",
            "2026-10-12T09:00:00",
            &[("fw-factory.bin", ImageType::Factory)],
        );

        let selected = select_image(root.path(), "p", "recovery-http")
            .expect("select")
            .expect("an image");
        assert!(selected.path.ends_with("bbbb/fw-factory.bin"));
        assert_eq!(selected.image_type, Some(ImageType::Factory));
        assert!(
            selected.fell_back,
            "factory is the second preference — firmware.py warns here"
        );
        assert_eq!(
            selected.metadata.as_ref().map(|m| m.cache_key.as_str()),
            Some("bbbb")
        );
    }

    #[test]
    fn first_preference_hit_is_not_a_fallback() {
        let root = tempfile::tempdir().expect("tempdir");
        cache_build(
            root.path(),
            "p",
            "aaaa",
            "2026-10-12T10:00:00",
            &[
                ("fw-sysupgrade.bin", ImageType::Sysupgrade),
                ("fw-recovery.bin", ImageType::Recovery),
            ],
        );

        let selected = select_image(root.path(), "p", "recovery-http")
            .expect("select")
            .expect("an image");
        assert!(selected.path.ends_with("fw-recovery.bin"));
        assert!(!selected.fell_back);

        let sysupgrade = select_image(root.path(), "p", "sysupgrade")
            .expect("select")
            .expect("an image");
        assert!(sysupgrade.path.ends_with("fw-sysupgrade.bin"));
        assert_eq!(sysupgrade.image_type, Some(ImageType::Sysupgrade));
        assert!(!sysupgrade.fell_back);
    }

    #[test]
    fn untyped_fallback_uses_newest_build_with_any_image() {
        let root = tempfile::tempdir().expect("tempdir");
        cache_build(
            root.path(),
            "p",
            "older",
            "2026-10-01T00:00:00",
            &[("fw-sysupgrade.bin", ImageType::Sysupgrade)],
        );
        // Newer build's only image is of an unpreferred type. For a
        // recovery method (recovery/factory preferences both miss) the
        // untyped fallback must pick the newest build with any image.
        cache_build(
            root.path(),
            "p",
            "newer",
            "2026-10-12T00:00:00",
            &[("fw-mystery.bin", ImageType::Unknown)],
        );

        let selected = select_image(root.path(), "p", "recovery-http")
            .expect("select")
            .expect("an image");
        assert!(selected.path.ends_with("newer/fw-mystery.bin"));
        assert!(selected.fell_back);
        assert_eq!(selected.image_type, None);
    }

    #[test]
    fn dir_scan_last_resort_picks_newest_named_dir_with_image_file() {
        let root = tempfile::tempdir().expect("tempdir");
        let old = root.path().join("p").join("aaaa");
        let new = root.path().join("p").join("zzzz");
        std::fs::create_dir_all(&old).expect("mkdir");
        std::fs::create_dir_all(&new).expect("mkdir");
        std::fs::write(old.join("notes.txt"), b"x").expect("write");
        std::fs::write(old.join("fw.img"), b"fw").expect("write");
        std::fs::write(new.join("fw.tar"), b"fw").expect("write");

        // No metadata anywhere → typed and untyped find miss; the reverse-
        // sorted directory scan must take zzzz (firmware.py parity).
        let selected = select_image(root.path(), "p", "recovery-http")
            .expect("select")
            .expect("an image");
        assert!(selected.path.ends_with("zzzz/fw.tar"));
        assert_eq!(selected.image_type, None);
        assert_eq!(selected.metadata, None);
    }

    #[test]
    fn initramfs_companion_for_oem_methods_only() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("p").join("aaaa");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("a-initramfs-kernel.bin"), b"initramfs").expect("write");
        std::fs::write(dir.join("b-squashfs-sysupgrade.bin"), b"fw").expect("write");
        write_metadata(
            root.path(),
            &build_metadata(
                "p",
                "aaaa",
                "2026-10-12T00:00:00",
                &[("b-squashfs-sysupgrade.bin", ImageType::Sysupgrade)],
            ),
        )
        .expect("write");

        let oem = select_image(root.path(), "p", "oem-http")
            .expect("select")
            .expect("an image");
        assert!(oem.initramfs_path.is_some());
        assert!(
            oem.initramfs_path
                .as_deref()
                .unwrap()
                .ends_with("a-initramfs-kernel.bin")
        );

        let plain = select_image(root.path(), "p", "sysupgrade")
            .expect("select")
            .expect("an image");
        assert!(plain.initramfs_path.is_none());
    }

    #[test]
    fn nothing_cached_yields_none() {
        let root = tempfile::tempdir().expect("tempdir");
        assert!(
            select_image(root.path(), "p", "sysupgrade")
                .expect("select")
                .is_none()
        );
    }
}
