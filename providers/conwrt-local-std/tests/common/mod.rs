//! Shared in-process russh fixture server for integration tests
//! (ADR-0011 ring 1). Served-file semantics: `cat <path>`, `echo`, `true`,
//! `false`, and the `scp -t`/`scp -f` protocol against an in-memory
//! filesystem. Include from a sibling test binary with:
//! `#[path = "../common/mod.rs"] mod common;`

#![allow(dead_code)]

use russh::ChannelId;
use russh::server::{self, Auth, Session};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

pub const FIXTURE_PASSWORD: &str = "bench-password";

/// Per-channel scp state for the fixture.
#[derive(Debug)]
pub enum SinkState {
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
pub enum SourceState {
    /// Header sent; waiting for the client's zero to send the payload.
    AwaitZero {
        payload: Vec<u8>,
    },
    /// Payload + trailing zero sent; the next client zero ends the transfer.
    AwaitFinalZero,
    Done,
}

#[derive(Debug, Default)]
pub struct ChannelRole {
    sink: Option<SinkState>,
    source: Option<(String, SourceState)>,
}

/// The scripted fixture server.
pub struct FixtureServer {
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
        } else if let Some(path) = request.strip_prefix("cat ") {
            session.channel_success(channel)?;
            let files = self.files.lock().expect("files");
            let found = files.get(path.trim()).cloned();
            drop(files);
            match found {
                Some(content) => {
                    session.data(channel, content)?;
                    session.exit_status_request(channel, 0)?;
                }
                None => {
                    session.extended_data(
                        channel,
                        1,
                        format!("cat: {path}: No such file or directory\n"),
                    )?;
                    session.exit_status_request(channel, 1)?;
                }
            }
            session.eof(channel)?;
            session.close(channel)?;
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
pub struct Fixture {
    pub addr: String,
    pub files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Fixture {
    pub async fn start() -> Self {
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

    pub fn put_file(&self, path: &str, contents: &str) {
        self.files
            .lock()
            .expect("files")
            .insert(path.to_string(), contents.as_bytes().to_vec());
    }
}
