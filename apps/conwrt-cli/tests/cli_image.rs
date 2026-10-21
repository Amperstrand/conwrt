//! Binary integration tests for `conwrt image` (#117 parity slice for
//! firmware-manager.py `request`): the REAL CLI against an httpmock ASU —
//! submit → poll → download → verify → cache, then the cache
//! short-circuit. Model coordinates are mirrored from the real corpus at
//! runtime so the test tracks corpus drift instead of pinning copies.

use std::path::PathBuf;
use std::process::Command;

use httpmock::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

const FIRMWARE_BYTES: &[u8] = b"conwrt image parity slice stand-in firmware bytes";

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn conwrt() -> Command {
    Command::new(env!("CARGO_BIN_EXE_conwrt"))
}

struct ModelCoords {
    target: String,
    profile: String,
    version: String,
}

fn model_coords() -> ModelCoords {
    let model: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo("../../models/dlink-covr-x1860-a1.json")).expect("model"),
    )
    .expect("parse model");
    ModelCoords {
        target: model["openwrt"]["target"].as_str().expect("target").into(),
        profile: model["openwrt"]["profile"]
            .as_str()
            .expect("profile")
            .into(),
        version: model["openwrt"]["version"]
            .as_str()
            .expect("version")
            .into(),
    }
}

fn mount_asu(server: &MockServer) -> httpmock::Mock<'_> {
    let m = model_coords();
    // The submit mock counts hits across BOTH runs: the cache
    // short-circuit must never resubmit.
    let submit = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/build")
            .body_contains(format!("\"profile\":\"{}\"", m.profile))
            .body_contains("\"packages\":[\"curl\"]");
        then.status(200).json_body(json!({
            "request_hash": "hash123",
            "status": 202,
        }));
    });
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/build/hash123");
        then.status(200).json_body(json!({
            "request_hash": "hash123",
            "status": 200,
            "distro": "openwrt",
            "version": m.version,
            "version_code": "r2782-9gef7f5a",
            "target": m.target,
            "profile": m.profile,
            "packages": {"curl": "8.9.1-r1"},
            "images": [{
                "name": "fw-squashfs-sysupgrade.bin",
                "sha256": sha256_hex(FIRMWARE_BYTES),
                "size": FIRMWARE_BYTES.len(),
                "type": "sysupgrade",
            }],
            "bin_dir": "07/ab",
            "build_at": "2026-10-16T10:00:00",
            "enqueued_at": "2026-10-16T09:59:00",
            "id": 42,
        }));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/store/07/ab/fw-squashfs-sysupgrade.bin");
        then.status(200).body(FIRMWARE_BYTES);
    });
    submit
}

fn sha256_hex(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn run_image(server: &MockServer, images_root: &std::path::Path) -> std::process::Output {
    conwrt()
        .env("CONWRT_ASU_BASE", server.base_url())
        .env("CONWRT_ASU_POLL_MS", "10")
        .args([
            "image",
            "--model-id",
            "dlink-covr-x1860-a1",
            "--packages",
            "curl",
            "--images-root",
            images_root.to_str().unwrap(),
            "--dir",
            repo("../../models").to_str().unwrap(),
        ])
        .output()
        .expect("run conwrt image")
}

#[test]
fn image_requests_builds_and_caches_then_short_circuits() {
    let server = MockServer::start();
    let submit = mount_asu(&server);
    let root = tempfile::tempdir().expect("tempdir");

    // Run 1: submit → poll → download → verify → cache.
    let out = run_image(&server, root.path());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("built:"), "stdout: {stdout}");
    assert!(stdout.contains("packages (1)"), "stdout: {stdout}");

    // Files land in images/<ASU profile>/<cache_key>/ with metadata — the
    // profile field (mixed dash/underscore form, per the #198 lesson), not
    // the model id.
    let profile_dir = root.path().join(model_coords().profile);
    let cache_dir = std::fs::read_dir(&profile_dir)
        .expect("profile dir")
        .next()
        .expect("one cache dir")
        .expect("entry")
        .path();
    assert_eq!(
        std::fs::read(cache_dir.join("fw-squashfs-sysupgrade.bin")).expect("fw"),
        FIRMWARE_BYTES
    );
    assert!(cache_dir.join("build.metadata.json").exists());

    // Run 2: same request — cache short-circuit, no second submit.
    let out2 = run_image(&server, root.path());
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(
        out2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    assert!(stdout2.contains("cached:"), "stdout: {stdout2}");
    submit.assert_hits(1); // the short-circuit never resubmits
}

#[test]
fn unknown_model_is_a_usage_error() {
    let out = conwrt()
        .env("CONWRT_ASU_BASE", "http://127.0.0.1:1")
        .args([
            "image",
            "--model-id",
            "no-such-model",
            "--dir",
            repo("../../models").to_str().unwrap(),
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown model id"));
}
