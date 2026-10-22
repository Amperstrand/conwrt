//! Binary integration tests for `conwrt cache` — the CLI twin of the
//! retired Python `conwrt.py cache list/clean` (parity-matrix §3,
//! retirement queue #3). Real CLI against a synthetic images root:
//! list walks the ASU layout with the 1.x table shape; clean honors
//! --keep-latest / --model-id / --yes with the hyphen/underscore
//! profile spelling.

use std::path::PathBuf;
use std::process::Command;

fn conwrt() -> Command {
    Command::new(env!("CARGO_BIN_EXE_conwrt"))
}

fn run(args: &[&str]) -> std::process::Output {
    conwrt()
        .arg("cache")
        .args(args)
        .output()
        .expect("run conwrt cache")
}

fn make_build(root: &std::path::Path, profile: &str, key: &str, bins: &[&str]) -> PathBuf {
    let dir = root.join(profile).join(key);
    std::fs::create_dir_all(&dir).expect("mkdir");
    for bin in bins {
        std::fs::write(dir.join(bin), vec![0u8; 1024]).expect("write bin");
    }
    dir
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn list_shows_the_asu_layout_table() {
    let root = tempfile::tempdir().expect("root");
    let build = make_build(
        root.path(),
        "dlink_covr-x1860-a1",
        "abcdef1234567890",
        &[
            "openwrt-25.12.6-x-squashfs-sysupgrade.bin",
            "openwrt-25.12.6-x-squashfs-factory.bin",
        ],
    );
    std::fs::write(
        build.join("build.metadata.json"),
        r#"{"version": "25.12.6", "version_code": "r33311-981c978eff"}"#,
    )
    .expect("metadata");
    // A vanilla flat file at the root: the 1.x list walks ONLY the
    // model/hash directories — parity keeps that behavior.
    std::fs::write(root.path().join("openwrt-flat-sysupgrade.bin"), b"x").expect("flat");

    let out = run(&["list", "--images-root", root.path().to_str().expect("path")]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = stdout(&out);
    assert!(text.contains("dlink_covr-x1860-a1"), "model row: {text}");
    assert!(text.contains("abcdef1234"), "hash prefix: {text}");
    assert!(text.contains("25.12.6"), "version: {text}");
    assert!(text.contains("factory, sysupgrade"), "types: {text}");
    assert!(text.contains("Total: 1 cached build"), "total: {text}");
    assert!(!text.contains("openwrt-flat"), "flat files stay unlisted");
}

#[test]
fn list_on_an_empty_root_is_success() {
    let root = tempfile::tempdir().expect("root");
    let out = run(&["list", "--images-root", root.path().to_str().expect("path")]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("No cached firmware images found."));
}

#[test]
fn clean_keep_latest_drops_all_but_newest_with_yes() {
    let root = tempfile::tempdir().expect("root");
    // Name order + stable mtime sort make 'aaa' the dropped one even on
    // mtime ties (the same tie-break the 1.x sorted()+mtime uses).
    let old = make_build(root.path(), "testmodel_a", "aaa-old", &["fw.bin"]);
    let keep = make_build(root.path(), "testmodel_a", "zzz-new", &["fw.bin"]);
    let other = make_build(root.path(), "othermodel_b", "only", &["fw.bin"]);

    let out = run(&[
        "clean",
        "--keep-latest",
        "--yes",
        "--images-root",
        root.path().to_str().expect("path"),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!old.exists(), "older build removed");
    assert!(keep.exists(), "newest build kept");
    assert!(
        other.exists(),
        "keep-latest keeps a single-build model's only build"
    );
}

#[test]
fn clean_without_yes_only_plans() {
    let root = tempfile::tempdir().expect("root");
    let build = make_build(root.path(), "testmodel_a", "only", &["fw.bin"]);
    let out = run(&[
        "clean",
        "--images-root",
        root.path().to_str().expect("path"),
    ]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("Would remove"), "preview: {text}");
    assert!(build.exists(), "nothing deleted without --yes");
}

#[test]
fn clean_model_id_matches_both_spellings() {
    let root = tempfile::tempdir().expect("root");
    let mine = make_build(root.path(), "dlink_covr-x1860-a1", "only", &["fw.bin"]);
    let theirs = make_build(root.path(), "othermodel_b", "only", &["fw.bin"]);
    let out = run(&[
        "clean",
        "--model-id",
        "dlink-covr-x1860-a1",
        "--yes",
        "--images-root",
        root.path().to_str().expect("path"),
    ]);
    assert!(out.status.success());
    assert!(!mine.exists(), "hyphenated selector matches underscore dir");
    assert!(theirs.exists(), "other models untouched");
}
