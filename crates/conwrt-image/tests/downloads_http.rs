//! Integration tests for the vanilla-image download path
//! ([`conwrt_image::ReqwestDownloadsClient`]) against a local `httpmock`
//! server — no real network calls, `downloads.openwrt.org` is never
//! contacted.

use conwrt_image::{
    DownloadsClient, FetchOptions, ImageError, ReqwestDownloadsClient, VanillaModel, fetch_image,
};
use httpmock::Method::GET;
use httpmock::MockServer;
use sha2::{Digest, Sha256};

const IMAGE_BYTES: &[u8] = b"vanilla-openwrt-image-payload";

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn model() -> VanillaModel {
    VanillaModel {
        id: "dlink_covr_x1860-a1".into(),
        target: "ramips/mt7621".into(),
        profile: "dlink_covr-x1860-a1".into(),
        release: None,
        image_suffix: None,
    }
}

fn filename() -> String {
    "openwrt-24.10.2-ramips-mt7621-dlink_covr-x1860-a1-squashfs-sysupgrade.bin".into()
}

fn mock_downloads(server: &MockServer, sums_body: String) -> Vec<httpmock::Mock<'_>> {
    vec![
        server.mock(|when, then| {
            when.method(GET)
                .path("/releases/24.10.2/targets/ramips/mt7621/sha256sums");
            then.status(200).body(sums_body);
        }),
        server.mock(|when, then| {
            when.method(GET)
                .path("/releases/24.10.2/targets/ramips/mt7621/fw-factory.bin");
            then.status(200).body(IMAGE_BYTES);
        }),
        server.mock(|when, then| {
            when.method(GET).path(format!(
                "/releases/24.10.2/targets/ramips/mt7621/{}",
                filename()
            ));
            then.status(200).body(IMAGE_BYTES);
        }),
    ]
}

fn client_for(server: &MockServer) -> ReqwestDownloadsClient {
    ReqwestDownloadsClient::with_base(server.base_url()).expect("client")
}

fn verifying() -> FetchOptions<'static> {
    FetchOptions {
        verify: true,
        ..FetchOptions::default()
    }
}

#[tokio::test]
async fn fetches_verifies_and_caches_a_vanilla_image() {
    let server = MockServer::start();
    let sums = format!("{} *{}\n", sha256_hex(IMAGE_BYTES), filename());
    let mocks = mock_downloads(&server, sums);
    let root = tempfile::tempdir().expect("tempdir");

    let fetched = fetch_image(&client_for(&server), root.path(), &model(), &verifying())
        .await
        .expect("fetched");

    assert!(!fetched.already_cached);
    assert_eq!(fetched.release, "24.10.2");
    assert_eq!(fetched.filename, filename());
    assert_eq!(
        fetched.sha256.as_deref(),
        Some(sha256_hex(IMAGE_BYTES).as_str())
    );
    assert_eq!(fetched.path, root.path().join(filename()));
    assert_eq!(std::fs::read(&fetched.path).expect("image"), IMAGE_BYTES);
    mocks[0].assert();
    mocks[2].assert();
}

#[tokio::test]
async fn image_suffix_override_selects_the_factory_artefact() {
    let server = MockServer::start();
    let factory = "openwrt-24.10.2-ramips-mt7621-dlink_covr-x1860-a1-squashfs-factory.bin";
    let _sums = server.mock(|when, then| {
        when.method(GET)
            .path("/releases/24.10.2/targets/ramips/mt7621/sha256sums");
        then.status(200)
            .body(format!("{} *{factory}\n", sha256_hex(IMAGE_BYTES)));
    });
    // Exact-artefact matcher proves the suffix drove the URL.
    let factory_mock = server.mock(|when, then| {
        when.method(GET)
            .path(format!("/releases/24.10.2/targets/ramips/mt7621/{factory}"));
        then.status(200).body(IMAGE_BYTES);
    });

    let root = tempfile::tempdir().expect("tempdir");
    let opts = FetchOptions {
        verify: true,
        suffix: conwrt_image::SuffixOverrides {
            cli: Some("squashfs-factory.bin"),
            env: None,
        },
        ..FetchOptions::default()
    };
    let fetched = fetch_image(&client_for(&server), root.path(), &model(), &opts)
        .await
        .expect("fetched");
    assert_eq!(fetched.filename, factory);
    assert_eq!(std::fs::read(&fetched.path).expect("image"), IMAGE_BYTES);
    factory_mock.assert();
}

#[tokio::test]
async fn cached_image_short_circuits_the_download() {
    let server = MockServer::start();
    let sums = format!("{} *{}\n", sha256_hex(IMAGE_BYTES), filename());
    let mocks = mock_downloads(&server, sums);
    let root = tempfile::tempdir().expect("tempdir");

    fetch_image(&client_for(&server), root.path(), &model(), &verifying())
        .await
        .expect("first");
    let (sums_hits, image_hits) = (mocks[0].hits(), mocks[2].hits());

    let cached = fetch_image(&client_for(&server), root.path(), &model(), &verifying())
        .await
        .expect("second");
    assert!(cached.already_cached);
    assert_eq!(
        (mocks[0].hits(), mocks[2].hits()),
        (sums_hits + 1, image_hits)
    );
}

#[tokio::test]
async fn checksum_index_miss_reports_the_url() {
    let server = MockServer::start();
    let _sums = server.mock(|when, then| {
        when.method(GET)
            .path("/releases/24.10.2/targets/ramips/mt7621/sha256sums");
        then.status(200).body("deadbeef *some-other-image.bin\n");
    });
    let root = tempfile::tempdir().expect("tempdir");

    let err = fetch_image(&client_for(&server), root.path(), &model(), &verifying())
        .await
        .expect_err("not indexed");
    match err {
        ImageError::NotInChecksumIndex {
            filename: listed,
            url,
        } => {
            assert_eq!(listed, filename());
            assert!(url.contains("/releases/24.10.2/targets/ramips/mt7621/sha256sums"));
        }
        other => panic!("expected NotInChecksumIndex, got {other:?}"),
    }
}

#[tokio::test]
async fn sha_mismatch_clears_the_file() {
    let server = MockServer::start();
    let sums = format!("{} *{}\n", "0".repeat(64), filename());
    let _mocks = mock_downloads(&server, sums);
    let root = tempfile::tempdir().expect("tempdir");

    let err = fetch_image(&client_for(&server), root.path(), &model(), &verifying())
        .await
        .expect_err("mismatch");
    assert!(matches!(err, ImageError::ShaMismatch { .. }));
    assert!(!root.path().join(filename()).exists());
}

#[tokio::test]
async fn sums_fetch_failure_surfaces_status_and_body() {
    let server = MockServer::start();
    let _sums = server.mock(|when, then| {
        when.method(GET)
            .path("/releases/24.10.2/targets/ramips/mt7621/sha256sums");
        then.status(503).body("mirror maintenance");
    });
    let root = tempfile::tempdir().expect("tempdir");

    let err = fetch_image(&client_for(&server), root.path(), &model(), &verifying())
        .await
        .expect_err("mirror down");
    match err {
        ImageError::HttpStatus { status, body, .. } => {
            assert_eq!(status, 503);
            assert_eq!(body, "mirror maintenance");
        }
        other => panic!("expected HttpStatus, got {other:?}"),
    }
}

#[tokio::test]
async fn user_agent_matches_image_source() {
    let server = MockServer::start();
    let sums = server.mock(|when, then| {
        when.method(GET)
            .path("/releases/24.10.2/targets/ramips/mt7621/sha256sums")
            .header("User-Agent", "conwrt/1.0");
        then.status(500).body("stop");
    });
    let root = tempfile::tempdir().expect("tempdir");

    let _ = fetch_image(&client_for(&server), root.path(), &model(), &verifying()).await;
    sums.assert();
}

#[tokio::test]
async fn base_url_trailing_slashes_are_trimmed_like_python() {
    let server = MockServer::start();
    let sums = format!("{} *{}\n", sha256_hex(IMAGE_BYTES), filename());
    let mocks = mock_downloads(&server, sums);
    let root = tempfile::tempdir().expect("tempdir");

    let client =
        ReqwestDownloadsClient::with_base(format!("{}/", server.base_url())).expect("client");
    assert_eq!(client.base_url(), server.base_url());
    fetch_image(&client, root.path(), &model(), &verifying())
        .await
        .expect("fetched");
    mocks[2].assert();
}

#[tokio::test]
async fn fetch_text_and_fetch_bytes_are_usable_directly() {
    let server = MockServer::start();
    let _text = server.mock(|when, then| {
        when.method(GET).path("/some.txt");
        then.status(200).body("plain text");
    });
    let client = client_for(&server);
    assert_eq!(
        client
            .fetch_text(&format!("{}/some.txt", server.base_url()))
            .await
            .expect("text"),
        "plain text"
    );
}
