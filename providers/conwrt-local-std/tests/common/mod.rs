//! Shared in-process russh fixture server for integration tests
//! (ADR-0011 ring 1). Served-file semantics: `cat <path>`, `echo`, `true`,
//! `false`, and the `scp -t`/`scp -f` protocol against an in-memory
//! filesystem. Include from a sibling test binary with:
//! `#[path = "../common/mod.rs"] mod common;`

#![allow(dead_code)]

use russh::ChannelId;
use russh::server::{self, Auth, Session};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    /// `sh -s` exec: buffers stdin until EOF, then answers from
    /// exec_responses keyed by the fed script (mirrors how the real
    /// apply path transports plans).
    stdin_exec: Option<String>,
}

/// The scripted fixture server.
pub struct FixtureServer {
    pub files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    pub exec_responses: Arc<Mutex<HashMap<String, (u32, String)>>>,
    /// Total authentication attempts seen (any method) — the #125
    /// regression probe: a host-key refusal must leave this at zero.
    pub auth_attempts: Arc<AtomicUsize>,
    /// `sh -s` scripts whose channel closes WITHOUT an exit status —
    /// the #555 "channel died mid-script" class (fate unknown).
    pub drop_scripts: Arc<Mutex<Vec<String>>>,
    roles: HashMap<ChannelId, ChannelRole>,
}

impl russh::server::Handler for FixtureServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.auth_attempts.fetch_add(1, Ordering::SeqCst);
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
        {
            let scripted = self
                .exec_responses
                .lock()
                .expect("exec_responses")
                .get(&request)
                .cloned();
            if let Some((exit_code, stdout)) = scripted {
                session.channel_success(channel)?;
                session.data(channel, stdout.into_bytes())?;
                session.exit_status_request(channel, exit_code)?;
                session.eof(channel)?;
                session.close(channel)?;
                return Ok(());
            }
        }
        if request.trim() == "sh -s" {
            session.channel_success(channel)?;
            self.roles.insert(
                channel,
                ChannelRole {
                    sink: None,
                    source: None,
                    stdin_exec: Some(String::new()),
                },
            );
            return Ok(());
        }
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
                    stdin_exec: None,
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
                        stdin_exec: None,
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

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // a `sh -s` exec just finished feeding its script: answer from
        // the scripted responses keyed by the fed text
        if let Some(role) = self.roles.get_mut(&channel)
            && let Some(script) = role.stdin_exec.take()
        {
            let dropped = self
                .drop_scripts
                .lock()
                .expect("drop_scripts")
                .iter()
                .any(|s| s == &script);
            if dropped {
                // close with NO data and NO exit status — the client sees
                // a channel that vanished mid-script (fate unknown)
                session.close(channel)?;
                return Ok(());
            }
            let scripted = self
                .exec_responses
                .lock()
                .expect("exec_responses")
                .get(&script)
                .cloned();
            if let Some((exit_code, stdout)) = scripted {
                session.data(channel, stdout.into_bytes())?;
                session.exit_status_request(channel, exit_code)?;
            } else {
                session.exit_status_request(channel, 127)?;
            }
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
        if let Some(buf) = &mut role.stdin_exec {
            buf.push_str(&String::from_utf8_lossy(data));
            return Ok(());
        }
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
    pub exec_responses: Arc<Mutex<HashMap<String, (u32, String)>>>,
    pub auth_attempts: Arc<AtomicUsize>,
    pub drop_scripts: Arc<Mutex<Vec<String>>>,
}

impl Fixture {
    pub async fn start() -> Self {
        let files: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
        let exec_responses: Arc<Mutex<HashMap<String, (u32, String)>>> = Arc::default();
        let auth_attempts: Arc<AtomicUsize> = Arc::default();
        let drop_scripts: Arc<Mutex<Vec<String>>> = Arc::default();
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
        let server_exec = Arc::clone(&exec_responses);
        let server_auth = Arc::clone(&auth_attempts);
        let server_drop = Arc::clone(&drop_scripts);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let handler = FixtureServer {
                    files: Arc::clone(&server_files),
                    exec_responses: Arc::clone(&server_exec),
                    auth_attempts: Arc::clone(&server_auth),
                    drop_scripts: Arc::clone(&server_drop),
                    roles: HashMap::new(),
                };
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    let _ = server::run_stream(config, socket, handler).await;
                });
            }
        });
        Self {
            addr,
            files,
            exec_responses,
            auth_attempts,
            drop_scripts,
        }
    }

    /// Make the NEXT `sh -s` carrying exactly `script` close without an
    /// exit status (the #555 mid-script channel-death class).
    pub fn set_exec_drop(&self, script: &str) {
        self.drop_scripts
            .lock()
            .expect("drop_scripts")
            .push(script.to_string());
    }

    /// Authentication attempts the server has seen (any method).
    pub fn auth_attempts(&self) -> usize {
        self.auth_attempts.load(Ordering::SeqCst)
    }

    pub fn set_exec_response(&self, command: &str, exit_code: u32, stdout: &str) {
        self.exec_responses
            .lock()
            .expect("exec_responses")
            .insert(command.to_string(), (exit_code, stdout.to_string()));
    }

    pub fn put_file(&self, path: &str, contents: &str) {
        self.files
            .lock()
            .expect("files")
            .insert(path.to_string(), contents.as_bytes().to_vec());
    }
}
