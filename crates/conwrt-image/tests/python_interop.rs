//! Python-interop tests: the `build.metadata.json` written by
//! `scripts/firmware-manager.py` (the fixture is byte-identical —
//! `json.dumps(metadata, indent=2) + "\n"` with the exact field set
//! `cmd_request` assembles) must be consumable by every Rust cache
//! operation. This pins the shared on-disk seam of the strangler
//! migration: Python writes, Rust reads.

use conwrt_image::{
    find_cached_build, list_entries, read_metadata, select_image, show_metadata, types::ImageType,
};
use std::path::Path;

const PROFILE: &str = "dlink_covr-x1860-a1";
const CACHE_KEY: &str = "9b25a3336bb3a22fc5e0712b7223e89023a6f549d90b801d8197bd04227c2d7c";

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dlink-example/build.metadata.json")
}

/// Copies the fixture into an images/<profile>/<cache_key>/ layout and
/// materializes the image files it references.
fn python_written_cache() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path().join(PROFILE).join(CACHE_KEY);
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::copy(fixture(), dir.join("build.metadata.json")).expect("copy fixture");
    std::fs::write(
        dir.join("openwrt-24.10.2-ramips-mt7621-dlink_covr-x1860-a1-squashfs-sysupgrade.bin"),
        b"sysupgrade-payload",
    )
    .expect("write sysupgrade");
    std::fs::write(
        dir.join("openwrt-24.10.2-ramips-mt7621-dlink_covr_x1860_a1-squashfs-factory.bin"),
        b"factory-payload",
    )
    .expect("write factory");
    root
}

#[test]
fn python_metadata_parses_with_all_fields() {
    let root = python_written_cache();
    let metadata = read_metadata(root.path(), PROFILE, CACHE_KEY).expect("parses");

    assert_eq!(metadata.request_hash, "6ae4a03c491df54e4e2a6b28b93c4e08");
    assert_eq!(metadata.version, "24.10.2");
    assert_eq!(metadata.version_code, "r2782-9gef7f5a");
    assert_eq!(metadata.packages, ["curl", "htop", "wireguard-tools"]);
    assert_eq!(
        metadata.packages_all["wireguard-tools"],
        serde_json::json!("1.0.20210914-r1")
    );
    assert_eq!(
        metadata.ssh_key_source.as_deref(),
        Some("~/.ssh/id_ed25519.pub")
    );
    assert_eq!(metadata.defaults, None);
    assert_eq!(
        metadata.linux_kernel["version"],
        serde_json::json!("5.15.167")
    );
    assert_eq!(metadata.images.len(), 2);
    assert_eq!(metadata.images[0].image_type, ImageType::Sysupgrade);
    assert_eq!(metadata.images[1].image_type, ImageType::Factory);
    assert!(metadata.images.iter().all(|image| image.verified));
    assert_eq!(metadata.enqueued_at, "2026-10-12T09:59:00+00:00");
}

#[test]
fn python_cache_counts_as_cached_build() {
    let root = python_written_cache();
    let cached = find_cached_build(root.path(), PROFILE, CACHE_KEY).expect("verified build");
    assert_eq!(cached.cache_key, CACHE_KEY);
}

#[test]
fn python_cache_lists_and_shows() {
    let root = python_written_cache();
    let entries = list_entries(root.path(), None).expect("list");
    assert_eq!(entries.len(), 1);
    // Sorted type labels, 12-char hash, build_at truncated to 19 chars —
    // the cmd_list row Python prints for this cache.
    assert_eq!(entries[0].profile, PROFILE);
    assert_eq!(entries[0].hash, "9b25a3336bb3");
    assert_eq!(entries[0].version, "24.10.2");
    assert_eq!(entries[0].build_date, "2026-10-12T10:00:00");
    assert_eq!(entries[0].types, "factory, sysupgrade");

    let (key, meta) = show_metadata(root.path(), PROFILE, "9b25a333").expect("prefix show");
    assert_eq!(key, CACHE_KEY);
    assert_eq!(meta.images.len(), 2);
}

#[test]
fn selector_picks_images_from_a_python_written_cache() {
    let root = python_written_cache();

    let sysupgrade = select_image(root.path(), PROFILE, "sysupgrade")
        .expect("select")
        .expect("image");
    assert_eq!(
        sysupgrade.path.file_name().and_then(|n| n.to_str()),
        Some("openwrt-24.10.2-ramips-mt7621-dlink_covr-x1860-a1-squashfs-sysupgrade.bin")
    );
    assert!(!sysupgrade.fell_back);
    assert_eq!(
        sysupgrade.metadata.as_ref().map(|m| m.version.as_str()),
        Some("24.10.2")
    );

    // recovery-http prefers recovery (absent) then factory.
    let recovery = select_image(root.path(), PROFILE, "recovery-http")
        .expect("select")
        .expect("image");
    assert_eq!(
        recovery.path.file_name().and_then(|n| n.to_str()),
        Some("openwrt-24.10.2-ramips-mt7621-dlink_covr_x1860_a1-squashfs-factory.bin")
    );
    assert!(recovery.fell_back, "factory is the second preference");
}

#[test]
fn fixture_is_json_dumps_formatted_like_python() {
    let text = std::fs::read_to_string(fixture()).expect("read");
    assert!(text.ends_with('\n'), "trailing newline from write_text");
    // json.dumps(indent=2) puts a space after the colon.
    assert!(text.contains("\"cache_key\": \"9b25a333"));
    // Round-trip through serde must preserve every field.
    let metadata: conwrt_image::CachedMetadata = serde_json::from_str(&text).expect("parse");
    assert_eq!(metadata.cache_key, CACHE_KEY);
}
