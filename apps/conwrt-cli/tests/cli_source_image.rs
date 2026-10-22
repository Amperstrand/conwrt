//! Binary integration tests for `conwrt source-image` (#117 §3 vanilla
//! slice): the REAL CLI against an httpmock downloads server —
//! resolve → fetch sha256sums → verify → cache, then the cache
//! short-circuit. Mirrors the `conwrt image` ASU-slice test pattern:
//! model coordinates come from the real corpus at runtime.

use std::path::PathBuf;
use std::process::Command;

use httpmock::prelude::*;
use sha2::{Digest, Sha256};

const IMAGE_BYTES: &[u8] = b"conwrt source-image vanilla parity payload";

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn conwrt() -> Command {
    Command::new(env!("CARGO_BIN_EXE_conwrt"))
}

fn coords() -> (String, String) {
    let model: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo("../../models/dlink-covr-x1860-a1.json")).expect("model"),
    )
    .expect("parse model");
    (
        model["openwrt"]["target"].as_str().expect("target").into(),
        model["openwrt"]["profile"]
            .as_str()
            .expect("profile")
            .into(),
    )
}

fn expected_filename(release: &str) -> String {
    let (target, profile) = coords();
    format!(
        "openwrt-{release}-{}-{profile}-squashfs-sysupgrade.bin",
        target.replace('/', "-")
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn run(server: &MockServer, args: &[&str]) -> std::process::Output {
    conwrt()
        .arg("source-image")
        .arg("--model-id")
        .arg("dlink-covr-x1860-a1")
        .arg("--images-root")
        .arg(args[0])
        .arg("--downloads-base")
        .arg(server.url(""))
        .arg("--dir")
        .arg(repo("../../models"))
        .args(&args[1..])
        .env("CONWRT_CONFIG", "/nonexistent-config.toml")
        .output()
        .expect("run conwrt source-image")
}

fn mock_downloads<'a>(
    server: &'a MockServer,
    release: &str,
) -> (httpmock::Mock<'a>, httpmock::Mock<'a>) {
    let (target, _profile) = coords();
    let filename = expected_filename(release);
    let sums = format!("{}  {}\n", sha256_hex(IMAGE_BYTES), filename);
    let sums_path = format!("/releases/{release}/targets/{target}/sha256sums");
    let image_path = format!("/releases/{release}/targets/{target}/{filename}");
    let sums_mock = server.mock(|when, then| {
        when.method(GET).path(sums_path);
        then.status(200).body(sums);
    });
    let image_mock = server.mock(|when, then| {
        when.method(GET).path(image_path);
        then.status(200).body(IMAGE_BYTES);
    });
    (sums_mock, image_mock)
}

#[test]
fn sources_verifies_and_caches_then_short_circuits() {
    let server = MockServer::start();
    let (_sums, image_mock) = mock_downloads(&server, "25.12.6");
    let root = tempfile::tempdir().expect("images root");

    let out = run(
        &server,
        &[
            root.path().to_str().expect("path"),
            "--release",
            "25.12.6",
            "--image-suffix",
            "squashfs-sysupgrade.bin",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "exit {:?}\nstdout: {stdout}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("SHA-256 verified"), "stdout: {stdout}");
    let cached = root.path().join(expected_filename("25.12.6"));
    assert!(cached.exists(), "{} missing", cached.display());
    assert_eq!(
        sha256_hex(&std::fs::read(&cached).expect("read cached")),
        sha256_hex(IMAGE_BYTES)
    );

    let out2 = run(
        &server,
        &[
            root.path().to_str().expect("path"),
            "--release",
            "25.12.6",
            "--image-suffix",
            "squashfs-sysupgrade.bin",
        ],
    );
    assert!(out2.status.success());
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(stdout2.contains("cached"), "second run: {stdout2}");
    assert_eq!(
        image_mock.hits(),
        1,
        "the image endpoint must be fetched exactly once"
    );
}

#[test]
fn release_defaults_to_the_model_and_suffix_overrides() {
    let server = MockServer::start();
    // The model pins release 25.12.6 and image_suffix squashfs-factory.bin
    // (since the 2026-10-22 bump) — no --release needed; the suffix
    // override selects the sysupgrade flavour.
    let (_sums, _image) = mock_downloads(&server, "25.12.6");
    let root = tempfile::tempdir().expect("images root");
    let out = run(
        &server,
        &[
            root.path().to_str().expect("path"),
            "--image-suffix",
            "squashfs-sysupgrade.bin",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(root.path().join(expected_filename("25.12.6")).exists());
}
