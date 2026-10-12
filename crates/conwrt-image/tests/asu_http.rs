//! Integration tests for [`conwrt_image::ReqwestAsuClient`] against a
//! local `httpmock` server — no real network calls.
//!
//! These exercise the production HTTP path (URL construction, headers,
//! JSON payload shape, status handling, download bytes); poll *sequencing*
//! (pending → building → done, transient-error tolerance) is covered by
//! the scripted-fake unit tests in `workflow.rs`.

use conwrt_image::{
    AsuClient, AsuEndpoints, BuildRequest, ImageError, PollConfig, RequestExtras, ReqwestAsuClient,
    request_and_cache,
};
use httpmock::Method::{GET, POST};
use httpmock::{Mock, MockServer};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;

const FIRMWARE_BYTES: &[u8] = b"openwrt-firmware-image-payload";

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn fast_poll() -> PollConfig {
    PollConfig {
        initial_interval: Duration::from_millis(1),
        max_interval: Duration::from_millis(1),
        backoff_multiplier: 1.0,
        timeout: Duration::from_millis(2_000),
    }
}

struct AsuMock<'a> {
    submit: Mock<'a>,
    status: Mock<'a>,
    download: Mock<'a>,
}

fn asu_mocks<'a>(server: &'a MockServer, status_body: serde_json::Value) -> AsuMock<'a> {
    let submit = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/build")
            .header("Content-Type", "application/json")
            .body_contains("\"profile\":\"dlink_covr_x1860_a1\"");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(json!({"request_hash": "hash123", "status": 202}));
    });
    let status = server.mock(|when, then| {
        when.method(GET).path("/api/v1/build/hash123");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(status_body);
    });
    let download = server.mock(|when, then| {
        when.method(GET)
            .path("/store/07/ab/fw-squashfs-sysupgrade.bin");
        then.status(200).body(FIRMWARE_BYTES);
    });
    AsuMock {
        submit,
        status,
        download,
    }
}

fn done_status_body() -> serde_json::Value {
    json!({
        "request_hash": "hash123",
        "status": 200,
        "distro": "openwrt",
        "version": "24.10.2",
        "version_code": "r2782-9gef7f5a",
        "target": "ramips/mt7621",
        "profile": "dlink_covr_x1860_a1",
        "packages": {"curl": "8.9.1-r1"},
        "images": [
            {
                "name": "fw-squashfs-sysupgrade.bin",
                "sha256": sha256_hex(FIRMWARE_BYTES),
                "size": FIRMWARE_BYTES.len(),
                "type": "sysupgrade"
            }
        ],
        "bin_dir": "07/ab",
        "build_at": "2026-10-12T10:00:00",
        "enqueued_at": "2026-10-12T09:59:00",
        "id": 42
    })
}

fn request() -> BuildRequest {
    let mut request = BuildRequest::openwrt("24.10.2", "ramips/mt7621", "dlink_covr_x1860_a1");
    request.packages = Some(vec!["curl".into()]);
    request
}

fn client_for(server: &MockServer) -> ReqwestAsuClient {
    ReqwestAsuClient::with_endpoints(AsuEndpoints::from_base(&server.base_url())).expect("client")
}

#[tokio::test]
async fn submit_poll_download_and_cache_through_real_http() {
    let server = MockServer::start();
    let mocks = asu_mocks(&server, done_status_body());
    let root = tempfile::tempdir().expect("tempdir");

    let outcome = request_and_cache(
        &client_for(&server),
        root.path(),
        &request(),
        &fast_poll(),
        &RequestExtras::default(),
    )
    .await
    .expect("cached");

    assert!(!outcome.already_cached);
    mocks.submit.assert();
    mocks.status.assert();
    mocks.download.assert();

    // Files land in the images/<profile>/<cache_key>/ layout.
    let expected_key = conwrt_image::request_cache_key(&request());
    let dir = root.path().join("dlink_covr_x1860_a1").join(&expected_key);
    assert_eq!(outcome.cache_dir, dir);
    let fw = dir.join("fw-squashfs-sysupgrade.bin");
    assert_eq!(std::fs::read(&fw).expect("fw"), FIRMWARE_BYTES);

    // Metadata matches the Python-written shape.
    let metadata_path = dir.join("build.metadata.json");
    let text = std::fs::read_to_string(&metadata_path).expect("metadata");
    assert!(text.ends_with('\n'));
    let metadata: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(metadata["cache_key"], json!(expected_key));
    assert_eq!(metadata["request_hash"], json!("hash123"));
    assert_eq!(metadata["version_code"], json!("r2782-9gef7f5a"));
    assert_eq!(metadata["packages_all"], json!({"curl": "8.9.1-r1"}));
    assert_eq!(
        metadata["images"],
        json!([{
            "type": "sysupgrade",
            "name": "fw-squashfs-sysupgrade.bin",
            "sha256": sha256_hex(FIRMWARE_BYTES),
            "size_bytes": FIRMWARE_BYTES.len(),
            "verified": true,
        }])
    );
}

#[tokio::test]
async fn submit_payload_carries_parity_fields() {
    let server = MockServer::start();
    // Strict full-payload matcher: proves the POSTed JSON is exactly the
    // firmware-manager.py shape (packages present, defaults omitted).
    let submit = server.mock(|when, then| {
        when.method(POST).path("/api/v1/build").json_body(json!({
            "distro": "openwrt",
            "version": "24.10.2",
            "target": "ramips/mt7621",
            "profile": "dlink_covr_x1860_a1",
            "packages": ["curl"],
        }));
        then.status(200).json_body(json!({
            "request_hash": "hash123",
            "status": 202,
        }));
    });
    let mut mocks = asu_mocks(&server, done_status_body());
    // Replace the loose submit matcher with the strict one.
    mocks.submit.delete();
    let root = tempfile::tempdir().expect("tempdir");

    request_and_cache(
        &client_for(&server),
        root.path(),
        &request(),
        &fast_poll(),
        &RequestExtras::default(),
    )
    .await
    .expect("cached");
    submit.assert();
}

#[tokio::test]
async fn already_cached_never_touches_the_network() {
    let server = MockServer::start();
    let mocks = asu_mocks(&server, done_status_body());
    let root = tempfile::tempdir().expect("tempdir");

    // First run caches the build.
    request_and_cache(
        &client_for(&server),
        root.path(),
        &request(),
        &fast_poll(),
        &RequestExtras::default(),
    )
    .await
    .expect("first run");

    let hits_after_first = (
        mocks.submit.hits(),
        mocks.status.hits(),
        mocks.download.hits(),
    );
    let outcome = request_and_cache(
        &client_for(&server),
        root.path(),
        &request(),
        &fast_poll(),
        &RequestExtras::default(),
    )
    .await
    .expect("second run");
    assert!(outcome.already_cached);
    assert_eq!(
        (
            mocks.submit.hits(),
            mocks.status.hits(),
            mocks.download.hits()
        ),
        hits_after_first,
        "cache hit must not re-submit, re-poll, or re-download"
    );
}

#[tokio::test]
async fn sha_mismatch_is_detected_and_cleaned_up() {
    let server = MockServer::start();
    let mut bad = done_status_body();
    bad["images"][0]["sha256"] = json!("deadbeef");
    let _mocks = asu_mocks(&server, bad);
    let root = tempfile::tempdir().expect("tempdir");

    let err = request_and_cache(
        &client_for(&server),
        root.path(),
        &request(),
        &fast_poll(),
        &RequestExtras::default(),
    )
    .await
    .expect_err("mismatch");
    assert!(matches!(err, ImageError::ShaMismatch { .. }));

    let key = conwrt_image::request_cache_key(&request());
    let dir = root.path().join("dlink_covr_x1860_a1").join(key);
    assert!(!dir.join("fw-squashfs-sysupgrade.bin").exists());
    assert!(!dir.join("build.metadata.json").exists());
}

#[tokio::test]
async fn http_error_on_submit_reports_status_and_body() {
    let server = MockServer::start();
    let _submit = server.mock(|when, then| {
        when.method(POST).path("/api/v1/build");
        then.status(500).body("boom: worker died");
    });
    let root = tempfile::tempdir().expect("tempdir");

    let err = request_and_cache(
        &client_for(&server),
        root.path(),
        &request(),
        &fast_poll(),
        &RequestExtras::default(),
    )
    .await
    .expect_err("server error");
    match err {
        ImageError::HttpStatus { status, body, .. } => {
            assert_eq!(status, 500);
            assert_eq!(body, "boom: worker died");
        }
        other => panic!("expected HttpStatus, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_request_hash_is_an_error() {
    let server = MockServer::start();
    let _submit = server.mock(|when, then| {
        when.method(POST).path("/api/v1/build");
        then.status(200).json_body(json!({"status": 202}));
    });
    let root = tempfile::tempdir().expect("tempdir");

    let err = request_and_cache(
        &client_for(&server),
        root.path(),
        &request(),
        &fast_poll(),
        &RequestExtras::default(),
    )
    .await
    .expect_err("no hash");
    assert!(matches!(err, ImageError::MissingRequestHash(body) if body.contains("status")));
}

#[tokio::test]
async fn failed_build_status_surfaces_detail_and_message() {
    let server = MockServer::start();
    let _submit = server.mock(|when, then| {
        when.method(POST).path("/api/v1/build");
        then.status(200)
            .json_body(json!({"request_hash": "hash123"}));
    });
    let _status = server.mock(|when, then| {
        when.method(GET).path("/api/v1/build/hash123");
        then.status(200).json_body(json!({
            "status": "failed",
            "detail": "package foo not found",
            "message": "imagebuilder failure"
        }));
    });
    let root = tempfile::tempdir().expect("tempdir");

    let err = request_and_cache(
        &client_for(&server),
        root.path(),
        &request(),
        &fast_poll(),
        &RequestExtras::default(),
    )
    .await
    .expect_err("failed");
    match err {
        ImageError::BuildFailed {
            status,
            detail,
            message,
        } => {
            assert_eq!(status, "failed");
            assert_eq!(detail, "package foo not found");
            assert_eq!(message, "imagebuilder failure");
        }
        other => panic!("expected BuildFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn numeric_202_status_keeps_polling_then_succeeds() {
    let server = MockServer::start();
    let _submit = server.mock(|when, then| {
        when.method(POST).path("/api/v1/build");
        then.status(200)
            .json_body(json!({"request_hash": "hash123"}));
    });
    // httpmock matches the first-created mock first: the queued mock
    // (created first) intercepts polls until deleted, then the done mock
    // takes over.
    let mut queued = server.mock(|when, then| {
        when.method(GET).path("/api/v1/build/hash123");
        then.status(202).json_body(json!({
            "request_hash": "hash123",
            "status": 202,
            "message": "build in progress"
        }));
    });
    let done = server.mock(|when, then| {
        when.method(GET).path("/api/v1/build/hash123");
        then.status(200).json_body(done_status_body());
    });
    let download = server.mock(|when, then| {
        when.method(GET)
            .path("/store/07/ab/fw-squashfs-sysupgrade.bin");
        then.status(200).body(FIRMWARE_BYTES);
    });
    let root = tempfile::tempdir().expect("tempdir");

    // Poll once in-progress, then let the done mock answer.
    let client = client_for(&server);
    let status = client.build_status("hash123").await.expect("queued");
    assert!(matches!(status, conwrt_image::BuildStatus::InProgress));
    queued.delete();

    let outcome = request_and_cache(
        &client,
        root.path(),
        &request(),
        &fast_poll(),
        &RequestExtras::default(),
    )
    .await
    .expect("cached");
    assert!(!outcome.already_cached);
    done.assert();
    download.assert();
}

#[tokio::test]
async fn download_error_leaves_no_partial_cache() {
    let server = MockServer::start();
    let _submit = server.mock(|when, then| {
        when.method(POST).path("/api/v1/build");
        then.status(200)
            .json_body(json!({"request_hash": "hash123"}));
    });
    let _status = server.mock(|when, then| {
        when.method(GET).path("/api/v1/build/hash123");
        then.status(200).json_body(done_status_body());
    });
    let _download = server.mock(|when, then| {
        when.method(GET)
            .path("/store/07/ab/fw-squashfs-sysupgrade.bin");
        then.status(404).body("not found");
    });
    let root = tempfile::tempdir().expect("tempdir");

    let err = request_and_cache(
        &client_for(&server),
        root.path(),
        &request(),
        &fast_poll(),
        &RequestExtras::default(),
    )
    .await
    .expect_err("download failure");
    assert!(matches!(err, ImageError::HttpStatus { status: 404, .. }));

    let key = conwrt_image::request_cache_key(&request());
    let dir = root.path().join("dlink_covr_x1860_a1").join(key);
    assert!(!dir.join("fw-squashfs-sysupgrade.bin").exists());
    assert!(!dir.join("build.metadata.json").exists());
}

#[tokio::test]
async fn user_agent_matches_firmware_manager() {
    let server = MockServer::start();
    let submit = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/build")
            .header("User-Agent", "conwrt-firmware-manager/1.0");
        then.status(500).body("stop");
    });
    let root = tempfile::tempdir().expect("tempdir");

    let _ = request_and_cache(
        &client_for(&server),
        root.path(),
        &request(),
        &fast_poll(),
        &RequestExtras::default(),
    )
    .await;
    submit.assert();
}
