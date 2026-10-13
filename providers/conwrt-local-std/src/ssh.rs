//! SSH client provider over russh (ADR-0005): connection, exec channels,
//! scp-over-exec file transfer, and the host-key trust ladder wired into
//! `conwrt-core::ssh`.
//!
//! Algorithm floor (never negotiated below): curve25519-sha256 kex,
//! chacha20-poly1305/aes-ctr ciphers, ssh-ed25519/rsa-sha2 host keys —
//! russh's defaults already match; SSH-1 and ssh-rsa(SHA-1) are never
//! offered. File transfer uses the scp exec protocol (`scp -t`/`-f`),
//! which every OpenWrt Dropbear serves without extra packages.

use std::path::PathBuf;
use std::sync::Arc;

use conwrt_core::ssh::{
    HostKeyView, MemoryTrustStore, Refusal, TrustDecision, TrustMode, TrustedHow, evaluate_host_key,
};
use russh::client::{self, Handle};
use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::ssh_key::HashAlg;
use russh::{Channel, ChannelMsg};

/// How to authenticate.
#[derive(Debug, Clone)]
pub enum SshAuth {
    /// Password authentication.
    Password(String),
    /// Public-key authentication from an OpenSSH private-key file.
    KeyFile {
        /// Path to the private key.
        path: PathBuf,
        /// Passphrase for encrypted keys.
        passphrase: Option<String>,
    },
}

/// Where and how to connect.
#[derive(Debug, Clone)]
pub struct SshTarget {
    /// `host` or `host:port`.
    pub addr: String,
    /// User name (usually `root` on OpenWrt).
    pub user: String,
    /// Authentication method.
    pub auth: SshAuth,
}

/// Connection-time policy.
#[derive(Debug, Clone)]
pub struct SshOptions {
    /// Explicit host-key fingerprint pin (`SHA256:...`) — overrides the
    /// store when present.
    pub pin: Option<String>,
    /// Unknown-host policy.
    pub mode: TrustMode,
    /// TCP connect timeout.
    pub connect_timeout: std::time::Duration,
}

impl Default for SshOptions {
    fn default() -> Self {
        Self {
            pin: None,
            mode: TrustMode::Strict,
            connect_timeout: std::time::Duration::from_secs(10),
        }
    }
}

/// Result of one exec command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// Exit status reported by the remote, when the channel delivered one.
    pub exit_code: Option<u32>,
    /// stdout bytes.
    pub stdout: Vec<u8>,
    /// stderr bytes.
    pub stderr: Vec<u8>,
}

/// SSH failures, refusal-as-data included.
#[derive(Debug)]
pub enum SshError {
    /// TCP/SSH transport failure during connect.
    Connect(String),
    /// Authentication rejected.
    AuthRejected,
    /// Host key refused by the trust ladder — carries the full refusal
    /// (reason + remediation hint) for the UI to render.
    HostKeyRefused(Refusal),
    /// russh-level transport error mid-session.
    Transport(String),
    /// Key material could not be loaded.
    Key(String),
    /// scp protocol violation.
    Scp(String),
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshError::Connect(msg) => write!(f, "ssh connect failed: {msg}"),
            SshError::AuthRejected => write!(f, "ssh authentication rejected"),
            SshError::HostKeyRefused(refusal) => write!(f, "{refusal}"),
            SshError::Transport(msg) => write!(f, "ssh transport error: {msg}"),
            SshError::Key(msg) => write!(f, "ssh key error: {msg}"),
            SshError::Scp(msg) => write!(f, "scp failed: {msg}"),
        }
    }
}

impl std::error::Error for SshError {}

/// Inputs the in-connection handler needs to evaluate the ladder.
struct LadderInputs {
    host: String,
    pin: Option<String>,
    mode: TrustMode,
    stored: Vec<HostKeyView>,
}

/// Client-side handler whose only job is the host-key ladder.
struct LadderHandler {
    policy: Arc<LadderInputs>,
    seen: Arc<std::sync::Mutex<Option<HostKeyView>>>,
}

impl client::Handler for LadderHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = server_public_key.public_key();
        // ssh-key's Fingerprint Display already renders `SHA256:<base64>`.
        let view = HostKeyView {
            key_algo: key.algorithm().to_string(),
            fingerprint: format!("{}", key.fingerprint(HashAlg::Sha256)),
        };
        let decision = evaluate_host_key(
            &self.policy.host,
            &view,
            self.policy.pin.as_deref(),
            &self.policy.stored,
            self.policy.mode,
        );
        *self.seen.lock().expect("ladder slot") = Some(view);
        match decision {
            TrustDecision::Trusted(_) => Ok(true),
            TrustDecision::Refused(refusal) => Err(SshError::HostKeyRefused(refusal)),
        }
    }
}

impl From<russh::Error> for SshError {
    fn from(e: russh::Error) -> Self {
        SshError::Transport(format!("{e}"))
    }
}

/// An authenticated SSH session.
pub struct SshSession {
    handle: Handle<LadderHandler>,
    /// The key the server presented (available for later inspection).
    pub presented_key: HostKeyView,
}

impl std::fmt::Debug for SshSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshSession")
            .field("presented_key", &self.presented_key)
            .finish_non_exhaustive()
    }
}

/// Connect, evaluate the host-key ladder, authenticate, and return the
/// session. On [`TrustMode::TrustOnFirstUse`] first use, the key is
/// remembered in `store` only after authentication succeeds.
pub async fn connect(
    target: &SshTarget,
    store: &mut MemoryTrustStore,
    options: &SshOptions,
) -> Result<SshSession, SshError> {
    let stored = store.entries(&target.addr);
    let policy = Arc::new(LadderInputs {
        host: target.addr.clone(),
        pin: options.pin.clone(),
        mode: options.mode,
        stored,
    });
    let seen = Arc::new(std::sync::Mutex::new(None));
    let handler = LadderHandler {
        policy: Arc::clone(&policy),
        seen: Arc::clone(&seen),
    };

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(60)),
        ..Default::default()
    });

    let socket = tokio::time::timeout(
        options.connect_timeout,
        tokio::net::TcpStream::connect(&target.addr),
    )
    .await
    .map_err(|_| SshError::Connect(format!("{}: connect timeout", target.addr)))?
    .map_err(|e| SshError::Connect(format!("{}: {e}", target.addr)))?;

    let mut handle = client::connect_stream(config, socket, handler)
        .await
        .map_err(|e| {
            match e {
                // Refusal-as-data must survive the connect phase untouched
                // (ADR-0005: the UI renders the refusal, not a transport error).
                SshError::HostKeyRefused(_) => e,
                SshError::Transport(msg) => SshError::Connect(msg),
                other => SshError::Connect(format!("{other}")),
            }
        })?;

    let authenticated = match &target.auth {
        SshAuth::Password(password) => handle
            .authenticate_password(target.user.clone(), password.clone())
            .await
            .map_err(|e| SshError::Transport(format!("auth: {e}")))?,
        SshAuth::KeyFile { path, passphrase } => {
            let key = russh::keys::load_secret_key(path, passphrase.as_deref())
                .map_err(|e| SshError::Key(format!("{}: {e}", path.display())))?;
            let rsa_hash = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|e| SshError::Transport(format!("rsa hash probe: {e}")))?
                .flatten();
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash);
            handle
                .authenticate_publickey(target.user.clone(), key)
                .await
                .map_err(|e| SshError::Transport(format!("auth: {e}")))?
        }
    };
    if !authenticated.success() {
        return Err(SshError::AuthRejected);
    }

    let presented = seen
        .lock()
        .expect("ladder slot")
        .clone()
        .ok_or_else(|| SshError::Connect("server key never checked".into()))?;

    match evaluate_host_key(
        &policy.host,
        &presented,
        policy.pin.as_deref(),
        &policy.stored,
        policy.mode,
    ) {
        TrustDecision::Trusted(TrustedHow::FirstUse) => store.remember(&target.addr, &presented),
        TrustDecision::Trusted(_) => {}
        TrustDecision::Refused(refusal) => return Err(SshError::HostKeyRefused(refusal)),
    }

    Ok(SshSession {
        handle,
        presented_key: presented,
    })
}

impl SshSession {
    /// Run one command, collecting stdout/stderr/exit status.
    pub async fn exec(&self, command: &str) -> Result<ExecOutput, SshError> {
        let channel = self.exec_channel(command).await?;
        let output = collect_exec_output(channel).await?;
        Ok(output)
    }

    /// Upload `data` to `remote_path` via the scp sink protocol
    /// (`scp -t`). Works against Dropbear without sftp-server.
    pub async fn scp_upload(&self, data: &[u8], remote_path: &str) -> Result<(), SshError> {
        let (dir, name) = split_remote_path(remote_path);
        let mut channel = self.exec_channel(&format!("scp -t {dir}")).await?;

        // Sink protocol: header `C<mode> <size> <name>\n`, zero-byte acks
        // around the payload, final zero ack.
        let header = format!("C0644 {} {name}\n", data.len());
        expect_zero(&mut channel, "initial sink ack").await?;
        channel
            .data(header.as_bytes())
            .await
            .map_err(|e| SshError::Transport(format!("scp header: {e}")))?;
        expect_zero(&mut channel, "header ack").await?;
        channel
            .data(data)
            .await
            .map_err(|e| SshError::Transport(format!("scp payload: {e}")))?;
        channel
            .data(&[0u8][..])
            .await
            .map_err(|e| SshError::Transport(format!("scp trailing byte: {e}")))?;
        expect_zero(&mut channel, "payload ack").await?;
        // The sink waits for EOF (or a next header) after the final ack —
        // half-close so real scp implementations exit instead of idling.
        channel
            .eof()
            .await
            .map_err(|e| SshError::Transport(format!("scp eof: {e}")))?;

        let output = collect_exec_output(channel).await?;
        finish_ok(&output, "scp upload")
    }

    /// Download `remote_path` via the scp source protocol (`scp -f`).
    pub async fn scp_download(&self, remote_path: &str) -> Result<Vec<u8>, SshError> {
        let mut channel = self.exec_channel(&format!("scp -f {remote_path}")).await?;

        // Source protocol: the receiver speaks first with a zero byte.
        channel
            .data(&[0u8][..])
            .await
            .map_err(|e| SshError::Transport(format!("scp start ack: {e}")))?;
        let header = read_line(&mut channel).await?;
        let (size, _) = parse_scp_header(&header)?;
        channel
            .data(&[0u8][..])
            .await
            .map_err(|e| SshError::Transport(format!("scp header ack: {e}")))?;
        let mut payload = Vec::with_capacity(size);
        let mut surplus_zero = false;
        while payload.len() < size {
            let chunk = read_chunk(&mut channel, size - payload.len()).await?;
            let take = (size - payload.len()).min(chunk.len());
            payload.extend_from_slice(&chunk[..take]);
            if chunk.len() > take && chunk[take] == 0 {
                // The trailing zero rode along in the payload's final
                // message — already consumed.
                surplus_zero = true;
            }
        }
        if !surplus_zero {
            // Tolerate sources that fold (or omit) the trailing zero.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                read_chunk(&mut channel, 1),
            )
            .await;
        }
        channel
            .data(&[0u8][..])
            .await
            .map_err(|e| SshError::Transport(format!("scp final ack: {e}")))?;
        channel
            .eof()
            .await
            .map_err(|e| SshError::Transport(format!("scp eof: {e}")))?;

        let output = collect_exec_output(channel).await?;
        finish_ok(&output, "scp download")?;
        Ok(payload)
    }

    async fn exec_channel(&self, command: &str) -> Result<Channel<client::Msg>, SshError> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| SshError::Transport(format!("open channel: {e}")))?;
        channel
            .exec(true, command.to_string())
            .await
            .map_err(|e| SshError::Transport(format!("exec: {e}")))?;
        Ok(channel)
    }
}

fn split_remote_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(idx) => (&path[..idx], &path[idx + 1..]),
        None => (".", path),
    }
}

fn parse_scp_header(line: &str) -> Result<(usize, String), SshError> {
    // `C0644 <size> <name>`
    let mut parts = line.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some(mode), Some(size), Some(name)) if mode.starts_with('C') => size
            .parse::<usize>()
            .map(|size| (size, name.to_string()))
            .map_err(|_| SshError::Scp(format!("bad size in header {line:?}"))),
        _ => Err(SshError::Scp(format!(
            "error or unsupported header from source: {line:?}"
        ))),
    }
}

fn finish_ok(output: &ExecOutput, what: &str) -> Result<(), SshError> {
    match output.exit_code {
        Some(0) => Ok(()),
        code => Err(SshError::Scp(format!(
            "{what}: remote scp exited with {code:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        ))),
    }
}

/// Wait for one zero-byte ack, tolerating a missing initial ack from
/// minimal sinks.
async fn expect_zero(channel: &mut Channel<client::Msg>, what: &str) -> Result<(), SshError> {
    match tokio::time::timeout(std::time::Duration::from_secs(10), read_chunk(channel, 1)).await {
        Ok(Ok(byte)) if byte == [0] => Ok(()),
        Ok(Ok(other)) => Err(SshError::Scp(format!(
            "{what}: expected 0x00 ack, got {other:?}"
        ))),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(SshError::Scp(format!("{what}: timed out"))),
    }
}

/// Read exactly `n` bytes of channel data (accumulating across `Data`
/// messages).
async fn read_chunk(channel: &mut Channel<client::Msg>, n: usize) -> Result<Vec<u8>, SshError> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => out.extend_from_slice(&data),
            Some(ChannelMsg::ExtendedData { data, .. }) => {
                // stderr during scp is an error worth surfacing
                if String::from_utf8_lossy(&data).trim().contains("scp:") {
                    return Err(SshError::Scp(
                        String::from_utf8_lossy(&data).trim().to_string(),
                    ));
                }
            }
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => {
                return Err(SshError::Scp(format!(
                    "channel closed with {} of {n} bytes",
                    out.len()
                )));
            }
            Some(_) => {}
        }
    }
    Ok(out)
}

/// Read one `\n`-terminated line (header) from the channel.
///
/// `read_chunk` returns whole channel messages (possibly more bytes than
/// requested); every returned byte is consumed here.
async fn read_line(channel: &mut Channel<client::Msg>) -> Result<String, SshError> {
    let mut line = Vec::new();
    loop {
        let chunk = read_chunk(channel, 1).await?;
        for &byte in &chunk {
            line.push(byte);
            if byte == b'\n' {
                return Ok(String::from_utf8_lossy(&line).into_owned());
            }
        }
        if line.len() > 512 {
            return Err(SshError::Scp("header line too long".into()));
        }
    }
}

/// Drain a channel to completion, returning the exec output.
async fn collect_exec_output(mut channel: Channel<client::Msg>) -> Result<ExecOutput, SshError> {
    let mut output = ExecOutput {
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => output.stdout.extend_from_slice(&data),
            Some(ChannelMsg::ExtendedData { data, .. }) => {
                output.stderr.extend_from_slice(&data);
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                output.exit_code = Some(exit_status);
            }
            Some(ChannelMsg::Close) | None => break,
            Some(_) => {}
        }
    }
    Ok(output)
}
