//! SSH provider tests against an **in-process russh server** — the
//! fixture-sshd pattern from ADR-0011 ring 1: a real SSH wire protocol
//! (key exchange, host keys, auth, exec channels) with scripted behavior,
//! no external binaries and no leaving the machine.

#[path = "common/mod.rs"]
mod common;

use common::{FIXTURE_PASSWORD, Fixture};
use conwrt_core::ssh::{MemoryTrustStore, Refusal, RefusalReason, TrustMode, TrustStore};
use conwrt_local_std::ssh::{SshAuth, SshError, SshOptions, SshTarget, connect, resolve_auth};
use std::path::Path;

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
async fn first_use_refusal_sends_zero_auth_attempts() {
    // #125 regression: the structural guarantee — on a FirstUse refusal
    // (Strict), authentication must NEVER have been attempted. The
    // fixture counts every auth callback; a regression that reorders the
    // ladder after the handshake would send credentials first.
    let fixture = Fixture::start().await;
    let mut store = MemoryTrustStore::new();
    let err = connect(&target(&fixture.addr), &mut store, &SshOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        SshError::HostKeyRefused(Refusal {
            reason: RefusalReason::FirstUse,
            ..
        })
    ));
    assert_eq!(
        fixture.auth_attempts(),
        0,
        "credentials must not be sent before host-key approval"
    );
}

#[tokio::test]
async fn changed_key_refusal_sends_zero_auth_attempts() {
    // #125 regression: ChangedKey (MITM/reimage signature) must refuse
    // with zero auth attempts — a stored same-algorithm key differs, so
    // the ladder stops at the handshake.
    let fixture = Fixture::start().await;
    let mut store = MemoryTrustStore::new();
    // Seed the store with a DIFFERENT ed25519 key for this exact host:
    // the fixture's freshly generated key then presents as ChangedKey.
    store.remember(
        &fixture.addr,
        &conwrt_core::ssh::HostKeyView {
            key_algo: "ssh-ed25519".into(),
            fingerprint: "SHA256:0000000000000000000000000000000000000000000".into(),
        },
    );
    let err = connect(&target(&fixture.addr), &mut store, &SshOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        SshError::HostKeyRefused(Refusal {
            reason: RefusalReason::ChangedKey,
            ..
        })
    ));
    assert_eq!(
        fixture.auth_attempts(),
        0,
        "credentials must not be sent to a host whose key changed"
    );
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

#[tokio::test]
async fn relearn_forget_then_tofu_relearns_the_new_key() {
    // The reflash escape hatch (#125): a ChangedKey refusal is resolved
    // ONLY by the explicit forget — never silently — after which TOFU
    // trusts the new key and authentication proceeds exactly once.
    use conwrt_core::ssh::HostKeyView;

    let fixture = Fixture::start().await;
    let mut store = MemoryTrustStore::new();
    // Simulate a pre-reflash key: same algo, different fingerprint.
    store.remember(
        &fixture.addr,
        &HostKeyView {
            key_algo: "ssh-ed25519".into(),
            fingerprint: "SHA256:0000000000000000000000000000000000000000000".into(),
        },
    );

    // Without relearn: refused, zero auth attempts.
    let err = connect(&target(&fixture.addr), &mut store, &SshOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        SshError::HostKeyRefused(Refusal {
            reason: RefusalReason::ChangedKey,
            ..
        })
    ));
    assert_eq!(fixture.auth_attempts(), 0);

    // The explicit escape hatch: forget → TOFU re-learns (the CLI's
    // relearn flag pairs with its TOFU connect mode).
    store.forget(&fixture.addr);
    assert!(store.entries(&fixture.addr).is_empty());
    let tofu = SshOptions {
        mode: TrustMode::TrustOnFirstUse,
        ..SshOptions::default()
    };
    let session = connect(&target(&fixture.addr), &mut store, &tofu)
        .await
        .expect("connect after relearn");
    assert_eq!(fixture.auth_attempts(), 1);
    assert_eq!(store.entries(&fixture.addr).len(), 1);
    assert_eq!(
        store.entries(&fixture.addr)[0].fingerprint,
        session.presented_key.fingerprint
    );
}

#[test]
fn ssh_auth_debug_redacts_secrets() {
    let password = SshAuth::Password("super-secret".into());
    let dbg = format!("{password:?}");
    assert!(!dbg.contains("super-secret"), "leak: {dbg}");
    assert!(dbg.contains("<redacted>"));

    let key = SshAuth::KeyFile {
        path: "/tmp/id_ed25519".into(),
        passphrase: Some("pass-phrase".into()),
    };
    let dbg = format!("{key:?}");
    assert!(!dbg.contains("pass-phrase"), "leak: {dbg}");
    assert!(dbg.contains("/tmp/id_ed25519"), "path should stay: {dbg}");
}

#[test]
fn resolve_auth_precedence_flags_then_env_then_error() {
    use conwrt_local_std::ssh::resolve_auth_with;

    let env = |key: &str| match key {
        "CONWRT_SSH_KEY" => Some("/env/key".to_string()),
        "CONWRT_SSH_PASSWORD" => Some("env-pass".to_string()),
        _ => None,
    };
    let no_env = |_: &str| None;

    // Explicit flags beat env; key beats password at equal levels.
    match resolve_auth_with(&env, Some(Path::new("/flag/key")), Some("flag-pass")).unwrap() {
        SshAuth::KeyFile { path, .. } => assert_eq!(path, Path::new("/flag/key")),
        other => panic!("key flag must win, got {other:?}"),
    }
    match resolve_auth_with(&env, None, Some("flag-pass")).unwrap() {
        SshAuth::Password(p) => assert_eq!(p, "flag-pass"),
        other => panic!("password flag must beat env key, got {other:?}"),
    }
    // Env fallbacks.
    match resolve_auth_with(&env, None, None).unwrap() {
        SshAuth::KeyFile { path, .. } => assert_eq!(path, Path::new("/env/key")),
        other => panic!("env key fallback, got {other:?}"),
    }
    let password_only = |k: &str| (k == "CONWRT_SSH_PASSWORD").then(|| "env-pass".to_string());
    match resolve_auth_with(&password_only, None, None).unwrap() {
        SshAuth::Password(p) => assert_eq!(p, "env-pass"),
        other => panic!("env password fallback, got {other:?}"),
    }
    // Nothing → usage error naming the env vars.
    let err = resolve_auth_with(&no_env, None, None).unwrap_err();
    assert!(
        err.contains("CONWRT_SSH_KEY"),
        "must name the env vars: {err}"
    );
    // Empty env values are ignored (no insecure empty-password default).
    let empty = |k: &str| (k == "CONWRT_SSH_PASSWORD").then(|| String::new());
    assert!(resolve_auth_with(&empty, None, None).is_err());
}
