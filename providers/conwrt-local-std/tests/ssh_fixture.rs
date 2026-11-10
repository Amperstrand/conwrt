//! SSH provider tests against an **in-process russh server** — the
//! fixture-sshd pattern from ADR-0011 ring 1: a real SSH wire protocol
//! (key exchange, host keys, auth, exec channels) with scripted behavior,
//! no external binaries and no leaving the machine.

#[path = "common/mod.rs"]
mod common;

use common::{FIXTURE_PASSWORD, Fixture};
use conwrt_core::ssh::{MemoryTrustStore, RefusalReason, TrustMode};
use conwrt_local_std::ssh::{SshAuth, SshError, SshOptions, SshTarget, connect};

fn target(addr: &str) -> SshTarget {
    SshTarget {
        addr: addr.to_string(),
        user: "root".to_string(),
        auth: SshAuth::Password(FIXTURE_PASSWORD.to_string()),
    }
}

#[tokio::test]
async fn exec_collects_stdout_and_exit_status() {
    let fixture = Fixture::start().await;
    let mut store = MemoryTrustStore::new();
    let options = SshOptions {
        mode: TrustMode::TrustOnFirstUse,
        ..Default::default()
    };
    let session = connect(&target(&fixture.addr), &mut store, &options)
        .await
        .expect("connect");

    let out = session.exec("echo hello fixture").await.expect("exec");
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(out.stdout, b"hello fixture\n");

    let out = session.exec("false").await.expect("exec false");
    assert_eq!(out.exit_code, Some(1));
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let fixture = Fixture::start().await;
    let mut store = MemoryTrustStore::new();
    let mut bad = target(&fixture.addr);
    bad.auth = SshAuth::Password("wrong".to_string());
    let err = connect(
        &bad,
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, SshError::AuthRejected), "got {err:?}");
}

#[tokio::test]
async fn strict_mode_refuses_unknown_host_with_pin_hint() {
    let fixture = Fixture::start().await;
    let mut store = MemoryTrustStore::new();
    let err = connect(&target(&fixture.addr), &mut store, &SshOptions::default())
        .await
        .unwrap_err();
    match err {
        SshError::HostKeyRefused(refusal) => {
            assert_eq!(refusal.reason, RefusalReason::FirstUse);
            assert!(refusal.hint.contains("--trust-host-key SHA256:"));
            assert!(refusal.presented.fingerprint.starts_with("SHA256:"));
            assert_eq!(refusal.presented.key_algo, "ssh-ed25519");
        }
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn tofu_remembers_then_second_connect_uses_store() {
    let fixture = Fixture::start().await;
    let mut store = MemoryTrustStore::new();
    let options = SshOptions {
        mode: TrustMode::TrustOnFirstUse,
        ..Default::default()
    };
    let session = connect(&target(&fixture.addr), &mut store, &options)
        .await
        .expect("first connect");
    assert_eq!(store.entries(&fixture.addr).len(), 1);

    // Strict mode now succeeds purely from the store.
    let session2 = connect(&target(&fixture.addr), &mut store, &SshOptions::default())
        .await
        .expect("second connect from store");
    assert_eq!(
        session2.presented_key.fingerprint,
        session.presented_key.fingerprint
    );
}

#[tokio::test]
async fn pin_match_connects_and_pin_mismatch_refuses() {
    let fixture = Fixture::start().await;
    let mut store = MemoryTrustStore::new();
    let tofu = SshOptions {
        mode: TrustMode::TrustOnFirstUse,
        ..Default::default()
    };
    let session = connect(&target(&fixture.addr), &mut store, &tofu)
        .await
        .expect("learn fingerprint");
    let pin = session.presented_key.fingerprint.clone();

    let pinned = SshOptions {
        pin: Some(pin),
        ..Default::default()
    };
    let mut empty = MemoryTrustStore::new();
    connect(&target(&fixture.addr), &mut empty, &pinned)
        .await
        .expect("pin match connects");

    let wrong_pin = SshOptions {
        pin: Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
        ..Default::default()
    };
    let err = connect(&target(&fixture.addr), &mut empty, &wrong_pin)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, SshError::HostKeyRefused(r) if r.reason == RefusalReason::PinMismatch),
        "got {err:?}"
    );
}

#[tokio::test]
async fn changed_server_key_is_refused_from_store() {
    // Seed the store with a stale ed25519 fingerprint for this host: the
    // presented key (same algorithm, different key) must read as ChangedKey
    // — the MITM/reimage signature.
    let fixture = Fixture::start().await;
    let mut store = MemoryTrustStore::new();
    store.remember(
        &fixture.addr,
        &conwrt_core::ssh::HostKeyView {
            key_algo: "ssh-ed25519".to_string(),
            fingerprint: "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".to_string(),
        },
    );

    let err = connect(&target(&fixture.addr), &mut store, &SshOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, SshError::HostKeyRefused(r) if r.reason == RefusalReason::ChangedKey),
        "got {err:?}"
    );
}

#[tokio::test]
async fn scp_roundtrip_through_sink_and_source() {
    let fixture = Fixture::start().await;
    let mut store = MemoryTrustStore::new();
    let session = connect(
        &target(&fixture.addr),
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("connect");

    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    session
        .scp_upload(&payload, "/tmp/firmware.bin")
        .await
        .expect("upload");

    let stored = fixture
        .files
        .lock()
        .expect("files")
        .get("/tmp/firmware.bin")
        .cloned()
        .expect("file landed in fixture fs");
    assert_eq!(stored, payload);

    let downloaded = session
        .scp_download("/tmp/firmware.bin")
        .await
        .expect("download");
    assert_eq!(downloaded, payload);

    let err = session.scp_download("/tmp/missing.bin").await.unwrap_err();
    assert!(matches!(err, SshError::Scp(_)), "got {err:?}");
}
