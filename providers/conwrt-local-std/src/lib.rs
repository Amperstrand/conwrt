//! # conwrt-local-std
//!
//! Local Linux/macOS implementation of the conwrt capability traits
//! (ADR-0003): read-only link probing over real interfaces — TCP probes
//! (HTTP GET, SSH banner), ICMP ping via the system binary, neighbor-table
//! MAC lookup, and link carrier state.
//!
//! Everything here is **read-only toward the target** by construction; the
//! mutating capabilities arrive in later milestones behind explicit
//! authorization.
//!
//! Platform notes:
//! - Linux: carrier via `/sys/class/net/<iface>/carrier`, ARP via
//!   `/proc/net/arp`.
//! - macOS: carrier + ARP via `ifconfig`/`arp` subprocesses.
//! - Other OSes: those probes return `Ok(None)` (unknown), TCP probes work
//!   everywhere std does.

pub mod execute;
pub mod fingerprint;
pub mod ssh;
pub mod v6;

use conwrt_core::capability::{HttpProbeResult, LinkProbe, ProbeError, SshBanner};
use conwrt_types::MacAddress;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// TCP connect timeout for HTTP/SSH probes.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// Read timeout for banner/header reads.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Maximum response bytes parsed (headers + a title window).
const RESPONSE_LIMIT: usize = 16 * 1024;
/// Body bytes kept in `HttpProbeResult::body_snippet` (recovery markers).
const BODY_SNIPPET_LIMIT: usize = 256;

/// Local-std `LinkProbe`/`Time` provider over a concrete network interface.
#[derive(Debug, Clone)]
pub struct LocalProber {
    /// Interface used for carrier/ARP queries (e.g. `enp5s0`, `en0`);
    /// `None` = not applicable / unknown.
    pub interface: Option<String>,
    /// TCP port probed for HTTP (80 by default; override for OEM/recovery
    /// servers on alternate ports).
    pub http_port: u16,
    /// TCP port probed for the SSH banner (22 by default).
    pub ssh_port: u16,
}

impl LocalProber {
    /// Provider scoped to a named interface.
    #[must_use]
    pub fn on_interface(interface: impl Into<String>) -> Self {
        Self {
            interface: Some(interface.into()),
            http_port: 80,
            ssh_port: 22,
        }
    }

    /// Provider without interface scope (carrier/ARP report unknown).
    #[must_use]
    pub fn global() -> Self {
        Self {
            interface: None,
            http_port: 80,
            ssh_port: 22,
        }
    }

    /// Override the probed ports (tests, alternate OEM ports).
    #[must_use]
    pub fn with_ports(mut self, http_port: u16, ssh_port: u16) -> Self {
        self.http_port = http_port;
        self.ssh_port = ssh_port;
        self
    }
}

impl Default for LocalProber {
    fn default() -> Self {
        Self::global()
    }
}

impl LinkProbe for LocalProber {
    async fn link_up(&mut self) -> Result<Option<bool>, ProbeError> {
        let Some(iface) = self.interface.clone() else {
            return Ok(None);
        };
        #[cfg(target_os = "linux")]
        {
            let path = format!("/sys/class/net/{iface}/carrier");
            match tokio::fs::read_to_string(&path).await {
                Ok(content) => Ok(Some(content.trim() == "1")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(ProbeError::Unavailable(format!("carrier read {path}: {e}"))),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let output = run_command("ifconfig", [&iface]).await?;
            Ok(Some(output.stdout.contains("status: active")))
        }
    }

    async fn ping(&mut self, ip: IpAddr) -> Result<bool, ProbeError> {
        // macOS `ping -t` takes seconds; Linux `-W` takes seconds. Both
        // accept `-c`.
        #[cfg(target_os = "macos")]
        const TIMEOUT_FLAG: &str = "-t";
        #[cfg(not(target_os = "macos"))]
        const TIMEOUT_FLAG: &str = "-W";

        let args = ["-c", "1", TIMEOUT_FLAG, "1", &ip.to_string()];
        let output = run_command("ping", args).await?;
        Ok(output.status.success())
    }

    async fn http_get(
        &mut self,
        ip: IpAddr,
        path: &str,
    ) -> Result<Option<HttpProbeResult>, ProbeError> {
        let stream = tcp_connect(SocketAddr::new(ip, self.http_port)).await?;
        let Some(mut stream) = stream else {
            return Ok(None);
        };
        let request = format!(
            "GET {path} HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: conwrt/{} probe\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );
        if let Err(e) = stream.write_all(request.as_bytes()).await {
            return Err(ProbeError::Unavailable(format!("http send: {e}")));
        }
        let mut raw = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            let read = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut chunk)).await;
            let n = match read {
                Ok(Ok(n)) => n,
                // A reset after the peer finished writing is how abrupt OEM
                // servers (and test stubs) end the response.
                Ok(Err(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    break;
                }
                Ok(Err(e)) => {
                    return Err(ProbeError::Unavailable(format!("http read: {e}")));
                }
                Err(_) => return Err(ProbeError::Unavailable("http read timed out".into())),
            };
            if n == 0 || raw.len() + n > RESPONSE_LIMIT {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
        }
        Ok(Some(parse_http_response(&raw)))
    }

    async fn ssh_banner(&mut self, ip: IpAddr) -> Result<Option<SshBanner>, ProbeError> {
        let stream = tcp_connect(SocketAddr::new(ip, self.ssh_port)).await?;
        let Some(mut stream) = stream else {
            return Ok(None);
        };
        let mut line = Vec::with_capacity(64);
        let mut byte = [0u8; 1];
        loop {
            let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut byte))
                .await
                .map_err(|_| ProbeError::Unavailable("ssh banner read timed out".into()))?
                .map_err(|e| ProbeError::Unavailable(format!("ssh banner read: {e}")))?;
            if n == 0 || byte[0] == b'\n' || line.len() > 255 {
                break;
            }
            if byte[0] != b'\r' {
                line.push(byte[0]);
            }
        }
        let text = String::from_utf8_lossy(&line).into_owned();
        Ok(SshBanner::parse(&text))
    }

    async fn arp_mac(&mut self, ip: IpAddr) -> Result<Option<MacAddress>, ProbeError> {
        #[cfg(target_os = "linux")]
        {
            let table = tokio::fs::read_to_string("/proc/net/arp")
                .await
                .map_err(|e| ProbeError::Unavailable(format!("/proc/net/arp: {e}")))?;
            Ok(lookup_arp_table(&table, ip))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let ip = ip.to_string();
            let output = run_command("arp", ["-n".as_ref(), ip.as_str()]).await?;
            Ok(parse_arp_command_output(&output.stdout, ip.as_str()))
        }
    }
}

impl conwrt_core::capability::Time for LocalProber {
    async fn sleep_ms(&mut self, ms: u64) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}

/// Connect with a timeout; `Ok(None)` = refused/timeout (nothing there).
async fn tcp_connect(addr: SocketAddr) -> Result<Option<TcpStream>, ProbeError> {
    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(Some(stream)),
        Ok(Err(_)) | Err(_) => Ok(None),
    }
}

/// Run a system command, capturing stdout (and status for `ping`).
async fn run_command<'a, I>(program: &str, args: I) -> Result<CommandOutput, ProbeError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    match cmd.output().await {
        Ok(output) => Ok(CommandOutput {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(ProbeError::Unavailable(format!("{program} not on PATH")))
        }
        Err(e) => Err(ProbeError::Unavailable(format!("{program}: {e}"))),
    }
}

/// Captured command result (status + stdout).
#[cfg_attr(target_os = "linux", allow(dead_code))]
struct CommandOutput {
    status: std::process::ExitStatus,
    stdout: String,
}

/// Parse a raw HTTP response into the probe result shape using `httparse`
/// (the parser hyper builds on — battle-tested against the ancient,
/// malformed responses OEM recovery servers emit).
///
/// Unparseable input yields a status of 0 with whatever title fragment was
/// findable; probing must never fail hard on a weird server.
#[must_use]
pub fn parse_http_response(raw: &[u8]) -> HttpProbeResult {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut response = httparse::Response::new(&mut headers);
    let (status, body) = match response.parse(raw) {
        Ok(httparse::Status::Complete(head_len)) => (response.code.unwrap_or(0), &raw[head_len..]),
        Ok(httparse::Status::Partial) | Err(_) => (0, raw),
    };
    let server_header = response
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("server"))
        .map(|h| String::from_utf8_lossy(h.value).trim().to_string());
    let title = extract_title(&String::from_utf8_lossy(body)).map(str::to_string);
    let body_snippet = if body.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&body[..body.len().min(BODY_SNIPPET_LIMIT)]).into_owned())
    };
    HttpProbeResult {
        status,
        server_header,
        title,
        body_snippet,
    }
}

/// Extract `<title>` contents (case-insensitive tags, first occurrence).
#[must_use]
fn extract_title(body: &str) -> Option<&str> {
    let lowered = body.to_ascii_lowercase();
    let start = lowered.find("<title")?;
    let after_open = lowered[start..].find('>')? + start + 1;
    let end = lowered[after_open..].find("</title")? + after_open;
    Some(body[after_open..end].trim())
}

/// Look up an IP in Linux `/proc/net/arp` content.
#[must_use]
pub fn lookup_arp_table(table: &str, ip: IpAddr) -> Option<MacAddress> {
    let ip = ip.to_string();
    for line in table.lines().skip(1) {
        let mut columns = line.split_whitespace();
        let (Some(entry_ip), Some(_hw_type), Some(flags), Some(mac)) = (
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
        ) else {
            continue;
        };
        // 0x2 = ATF_COM (complete entry)
        if entry_ip == ip && flags.contains('2') {
            return MacAddress::parse(mac).ok();
        }
    }
    None
}

/// Parse `arp -n <ip>` output (BSD/macOS shape: `... (ip) at mac on if`).
#[must_use]
pub fn parse_arp_command_output(output: &str, ip: &str) -> Option<MacAddress> {
    output
        .lines()
        .find(|line| line.contains(ip) && line.contains(" at "))
        .and_then(|line| {
            line.split_whitespace()
                .find(|token| token.contains(':') && token.len() == 17)
                .and_then(|mac| MacAddress::parse(mac).ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_response_head_and_title() {
        let raw = b"HTTP/1.0 200 OK\r\nServer: uwWMPre/1.00\r\nContent-Type: text/html\r\n\r\n<html><head><title>Setup</title></head></html>";
        let parsed = parse_http_response(raw);
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.server_header.as_deref(), Some("uwWMPre/1.00"));
        assert_eq!(parsed.title.as_deref(), Some("Setup"));
    }

    #[test]
    fn parses_case_insensitive_title_and_missing_fields() {
        let raw = b"HTTP/1.0 401\r\n\r\n<HTML><HEAD><TITLE> OpenWrt LuCI </TITLE>";
        let parsed = parse_http_response(raw);
        assert_eq!(parsed.status, 401);
        assert_eq!(parsed.server_header, None);
        assert_eq!(parsed.title.as_deref(), Some("OpenWrt LuCI"));
    }

    #[test]
    fn garbage_yields_zero_status_not_panic() {
        let parsed = parse_http_response(b"\x00\x01not-http");
        assert_eq!(parsed.status, 0);
        assert!(parsed.server_header.is_none());
    }

    #[test]
    fn body_snippet_captured_from_response_body() {
        let raw = b"HTTP/1.0 200 OK\r\n\r\n<html><body><h1>Firmware Upgrade</h1></body></html>";
        let parsed = parse_http_response(raw);
        assert_eq!(
            parsed.body_snippet.as_deref(),
            Some("<html><body><h1>Firmware Upgrade</h1></body></html>")
        );
    }

    #[test]
    fn body_snippet_truncated_to_limit_and_lossy() {
        let raw = [b"HTTP/1.0 200 OK\r\n\r\n".as_slice(), &[0xffu8; 600][..]].concat();
        let parsed = parse_http_response(&raw);
        let snippet = parsed.body_snippet.expect("non-empty body has a snippet");
        // 256 source bytes, each lossy-decoded to one replacement char.
        assert_eq!(snippet.chars().count(), 256);
        assert!(snippet.chars().all(|c| c == char::REPLACEMENT_CHARACTER));
    }

    #[test]
    fn empty_body_yields_no_snippet() {
        let parsed = parse_http_response(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(parsed.body_snippet, None);
    }

    #[test]
    fn arp_table_lookup() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                     192.168.1.1      0x1         0x2         e0:63:da:12:34:56     *        enp5s0\n\
                     192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        enp5s0\n";
        let found = lookup_arp_table(table, IpAddr::from([192, 168, 1, 1]));
        assert_eq!(
            found.map(|m| m.to_string()),
            Some("e0:63:da:12:34:56".into())
        );
        // Incomplete entry (flags 0x0) is not returned.
        assert!(lookup_arp_table(table, IpAddr::from([192, 168, 1, 2])).is_none());
        // Absent IP.
        assert!(lookup_arp_table(table, IpAddr::from([10, 0, 0, 9])).is_none());
    }

    #[test]
    fn arp_command_output_lookup() {
        let output = "? (192.168.1.1) at e0:63:da:12:34:56 on en0 ifscope [ethernet]";
        let found = parse_arp_command_output(output, "192.168.1.1");
        assert_eq!(
            found.map(|m| m.to_string()),
            Some("e0:63:da:12:34:56".into())
        );
        assert!(parse_arp_command_output(output, "10.1.2.3").is_none());
    }
}
