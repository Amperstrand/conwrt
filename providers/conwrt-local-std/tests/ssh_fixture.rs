//! SSH provider tests against an **in-process russh server** — the
//! fixture-sshd pattern from ADR-0011 ring 1: a real SSH wire protocol
//! (key exchange, host keys, auth, exec channels) with scripted behavior,
//! no external binaries and no leaving the machine.
//!
//! The fixture implements exactly what conwrt's targets implement:
//! password auth, exec with exit statuses, and the `scp -t`/`scp -f`
//! transfer protocol against an in-memory filesystem.

use conwrt_core::ssh::{MemoryTrustStore, RefusalReason, TrustMode};
use conwrt_local_std::ssh::{SshAuth, SshError, SshOptions, SshTarget, connect};
use russh::ChannelId;
use russh::server::{self, Auth, Session};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const FIXTURE_PASSWORD: &str = "bench-password";

/// Per-channel scp state for the fixture.
#[derive(Debug)]
enum SinkState {
    AwaitHeader {
        dir: String,
    },
    AwaitPayload {
        path: String,
        len: usize,
        got: usize,
        buf: Vec<u8>,
    },
}

#[derive(Debug)]
enum SourceState {
    /// Header sent; waiting for the client's zero to send the payload.
    AwaitZero {
        payload: Vec<u8>,
    },
    /// Payload + trailing zero sent; the next client zero ends the transfer.
    AwaitFinalZero,
    Done,
}

#[derive(Debug, Default)]
struct ChannelRole {
    sink: Option<SinkState>,
    source: Option<(String, SourceState)>,
}

/// The scripted fixture server.
struct FixtureServer {
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    roles: HashMap<ChannelId, ChannelRole>,
}

impl russh::server::Handler for FixtureServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        if password == FIXTURE_PASSWORD {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        request: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let request = String::from_utf8_lossy(request).into_owned();
        if let Some(dir) = request.strip_prefix("scp -t ") {
            session.channel_success(channel)?;
            session.data(channel, &[0u8][..])?;
            self.roles.insert(
                channel,
                ChannelRole {
                    sink: Some(SinkState::AwaitHeader {
                        dir: dir.trim().to_string(),
                    }),
                    source: None,
                },
            );
        } else if let Some(path) = request.strip_prefix("scp -f ") {
            session.channel_success(channel)?;
            let path = path.trim().to_string();
            let files = self.files.lock().expect("files");
            if let Some(content) = files.get(&path).cloned() {
                let header = format!("C0644 {} {}\n", content.len(), file_name(&path));
                session.data(channel, header.into_bytes())?;
                self.roles.insert(
                    channel,
                    ChannelRole {
                        sink: None,
                        source: Some((path.clone(), SourceState::AwaitZero { payload: content })),
                    },
                );
            } else {
                eprintln!("[fixture] -f NOT FOUND {:?}", path);
                session.extended_data(channel, 1, format!("scp: {path}: not found\n"))?;
                session.exit_status_request(channel, 1)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
        } else if request == "true" {
            session.channel_success(channel)?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        } else if request == "false" {
            session.channel_success(channel)?;
            session.exit_status_request(channel, 1)?;
            session.eof(channel)?;
            session.close(channel)?;
        } else if let Some(text) = request.strip_prefix("echo ") {
            session.channel_success(channel)?;
            session.data(channel, format!("{text}\n").into_bytes())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        } else {
            session.channel_success(channel)?;
            session.exit_status_request(channel, 127)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let role = self.roles.entry(channel).or_default();
        if let Some(sink) = &mut role.sink {
            match sink {
                SinkState::AwaitHeader { dir } => {
                    if data == [0u8] {
                        // Trailing end-of-transfer byte: ack and close.
                        session.exit_status_request(channel, 0)?;
                        session.eof(channel)?;
                        session.close(channel)?;
                        return Ok(());
                    }
                    let header = String::from_utf8_lossy(data).into_owned();
                    let mut parts = header.split_whitespace();
                    if parts.next().is_some_and(|m| m.starts_with('C'))
                        && let (Some(size), Some(name)) = (parts.next(), parts.next())
                    {
                        let len: usize = size.parse().map_err(|_| russh::Error::Inconsistent)?;
                        let path = format!("{dir}/{name}");
                        *sink = SinkState::AwaitPayload {
                            path,
                            len,
                            got: 0,
                            buf: Vec::new(),
                        };
                        session.data(channel, &[0u8][..])?;
                    }
                }
                SinkState::AwaitPayload {
                    path,
                    len,
                    got,
                    buf,
                } => {
                    buf.extend_from_slice(data);
                    *got = buf.len();
                    if *got >= *len {
                        self.files
                            .lock()
                            .expect("files")
                            .insert(path.clone(), std::mem::take(buf));
                        *sink = SinkState::AwaitHeader {
                            dir: parent_dir(path),
                        };
                        session.data(channel, &[0u8][..])?;
                    }
                }
            }
            return Ok(());
        }
        if let Some((_path, source)) = &mut role.source {
            match source {
                SourceState::AwaitZero { .. } => {
                    if data == [0u8] {
                        let SourceState::AwaitZero { payload } =
                            std::mem::replace(source, SourceState::AwaitFinalZero)
                        else {
                            unreachable!()
                        };
                        session.data(channel, payload)?;
                        session.data(channel, &[0u8][..])?;
                    }
                }
                SourceState::AwaitFinalZero => {
                    if data == [0u8] {
                        session.exit_status_request(channel, 0)?;
                        session.eof(channel)?;
                        session.close(channel)?;
                        *source = SourceState::Done;
                    }
                }
                SourceState::Done => {}
            }
        }
        Ok(())
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(idx) => path[..idx].to_string(),
        None => ".".to_string(),
    }
}

/// One fixture instance bound to an ephemeral loopback port.
struct Fixture {
    addr: String,
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Fixture {
    async fn start() -> Self {
        let files: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
        let config = Arc::new(server::Config {
            auth_rejection_time: std::time::Duration::ZERO,
            keys: vec![
                russh::keys::PrivateKey::random(
                    &mut rand::rng(),
                    russh::keys::ssh_key::Algorithm::Ed25519,
                )
                .expect("host key"),
            ],
            ..Default::default()
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let server_files = Arc::clone(&files);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let handler = FixtureServer {
                    files: Arc::clone(&server_files),
                    roles: HashMap::new(),
                };
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    let _ = server::run_stream(config, socket, handler).await;
                });
            }
        });
        Self { addr, files }
    }
}

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
