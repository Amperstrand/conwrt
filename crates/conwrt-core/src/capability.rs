//! Capability traits (ADR-0003): small, composable, executor-agnostic.
//!
//! Providers implement these; workflows consume them via generics. Byte-
//! stream-shaped capabilities will build on `embedded-io-async` when the
//! local-std provider lands (M2); `LinkProbe` and `Time` are conwrt-native
//! because no ecosystem trait covers them.

use alloc::string::String;
use core::net::IpAddr;
use core::str::FromStr;

/// Read-only network probing of a candidate target.
///
/// All methods are non-mutating toward the target by contract: ping, HTTP
/// GET, SSH banner read, ARP lookup. Flashing lives in other capabilities
/// (later milestones) behind explicit authorization.
pub trait LinkProbe {
    /// Whether the local link has carrier (None = unknown / not applicable).
    async fn link_up(&mut self) -> Result<Option<bool>, ProbeError>;

    /// ICMP echo reachability.
    async fn ping(&mut self, ip: IpAddr) -> Result<bool, ProbeError>;

    /// Fetch `path` over HTTP; `Ok(None)` = connection refused/timeout
    /// (nothing listening), not an error.
    async fn http_get(
        &mut self,
        ip: IpAddr,
        path: &str,
    ) -> Result<Option<HttpProbeResult>, ProbeError>;

    /// Read the SSH identification string; `Ok(None)` = nothing listening.
    async fn ssh_banner(&mut self, ip: IpAddr) -> Result<Option<SshBanner>, ProbeError>;

    /// ARP/neighbor-table MAC for `ip`; `Ok(None)` = no entry.
    async fn arp_mac(&mut self, ip: IpAddr)
    -> Result<Option<conwrt_types::MacAddress>, ProbeError>;
}

/// A time source (ADR-0002 §5: time is a capability).
pub trait Time {
    /// Sleep for `ms` milliseconds (pacing/retry hooks; mocks return
    /// immediately so tests stay fast and deterministic).
    async fn sleep_ms(&mut self, ms: u64);
}

/// Result of a minimal HTTP probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpProbeResult {
    /// HTTP status code (e.g. 200).
    pub status: u16,
    /// `Server` response header, if present.
    pub server_header: Option<String>,
    /// `<title>` contents, if any (used for stock-UI heuristics).
    pub title: Option<String>,
    /// First ~256 bytes of the response body, lossy-decoded. Recovery-page
    /// markers live here when the server sends no `Server` header and an
    /// empty title (issue #131) — the classifier never needs more.
    pub body_snippet: Option<String>,
}

/// The SSH identification banner (`SSH-2.0-<software>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshBanner {
    /// Software component of the banner, e.g. `dropbear_2024.86`.
    pub software: String,
}

/// Board identity read over a key-authenticated SSH session.
///
/// The management-interface scope signal: a headless OpenWrt box (no
/// LuCI/uhttpd) presents dropbear and nothing else to unauthenticated
/// probes — indistinguishable from stock vendor firmware. An
/// authenticated read of `/tmp/sysinfo/board_name` +
/// `/etc/openwrt_release` disambiguates both directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedBoard {
    /// `/tmp/sysinfo/board_name`, e.g. `dlink,covr-x1860-a1`.
    pub board_name: String,
    /// `DISTRIB_ID` from `/etc/openwrt_release`; empty when the file is
    /// absent — which is itself the not-OpenWrt signal.
    pub distrib_id: String,
}

impl AuthenticatedBoard {
    /// `DISTRIB_ID` is `OpenWrt` on every release the corpus covers.
    #[must_use]
    pub fn is_openwrt(&self) -> bool {
        self.distrib_id.eq_ignore_ascii_case("OpenWrt")
    }
}

impl SshBanner {
    /// Parse the raw banner line `SSH-2.0-software comment`.
    pub fn parse(raw: &str) -> Option<Self> {
        let rest = raw.trim().strip_prefix("SSH-2.0-")?;
        let software = rest.split_whitespace().next()?;
        if software.is_empty() {
            return None;
        }
        Some(Self {
            software: software.into(),
        })
    }
}

impl FromStr for SshBanner {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

/// A capability probe failed (transport-level; distinct from "the target is
/// unreachable", which is expressed via `Ok(false)` / `Ok(None)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// The local capability is unavailable (interface gone, permissions...).
    Unavailable(String),
}

impl core::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProbeError::Unavailable(msg) => write!(f, "probe capability unavailable: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProbeError {}
