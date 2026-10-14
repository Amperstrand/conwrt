//! IPv6 dark-device discovery (issue #156, born from the 2026-10-12 x1860
//! incident — see `docs/postmortem-2026-10-12-x1860-sysupgrade.md`).
//!
//! The incident's costliest failure mode was blindness: the target was fully
//! up and beaconing (odhcpd RAs every 600 s), but the probe host had IPv6
//! disabled and nobody solicited. This module turns the AGENTS.md
//! dark-device playbook into three checks:
//!
//! 1. [`V6SelfCheck`] — is the *probe host* even able to speak v6 on this
//!    interface? (existence, carrier, `disable_ipv6` sysctl, link-local).
//!    Audit the prober before the probed.
//! 2. [`solicit_router_advertisement`] — ACTIVE Router Solicitation via the
//!    standard `rdisc6` tool (same subprocess pattern as `ping` in
//!    [`crate::LocalProber`]): an answer in ~1 s instead of gambling a
//!    short listen against a 600 s beacon.
//! 3. [`RouterAdvertisement`] — decode the RA (router MAC → link-local via
//!    EUI-64, prefixes, DNS, flags) into ready-to-use commands.
//!
//! All parsing is pure and unit-tested; the fs/subprocess edges are thin.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream};
use std::path::Path;
use std::time::Duration;

use conwrt_types::MacAddress;

/// Errors from v6 discovery.
#[derive(Debug)]
pub enum V6DiscoveryError {
    /// The interface does not exist.
    NoSuchInterface(String),
    /// `rdisc6` is not installed (part of the `ndisc6` package).
    ToolMissing,
    /// The `rdisc6` invocation failed.
    ToolFailed(String),
    /// Reading a /proc or /sys entry failed unexpectedly.
    Sys(String),
}

impl std::fmt::Display for V6DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            V6DiscoveryError::NoSuchInterface(i) => write!(f, "interface {i:?} not found"),
            V6DiscoveryError::ToolMissing => write!(
                f,
                "rdisc6 not on PATH — install the 'ndisc6' package (sudo apt-get install ndisc6)"
            ),
            V6DiscoveryError::ToolFailed(m) => write!(f, "rdisc6 failed: {m}"),
            V6DiscoveryError::Sys(m) => write!(f, "kernel interface read failed: {m}"),
        }
    }
}

impl std::error::Error for V6DiscoveryError {}

/// Probe-host readiness report for one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V6SelfCheck {
    /// The interface this check ran against.
    pub interface: String,
    /// `/sys/class/net/<if>` exists.
    pub exists: bool,
    /// Carrier present (None = unknown/not readable).
    pub carrier: Option<bool>,
    /// `net.ipv6.conf.<if>.disable_ipv6` (None = unreadable, e.g. v6 off system-wide).
    pub ipv6_disabled: Option<bool>,
    /// A fe80:: link-local is configured (None = could not read /proc/net/if_inet6).
    pub link_local: Option<Ipv6Addr>,
}

impl V6SelfCheck {
    /// Everything wrong, as operator-ready fix commands / explanations.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.exists {
            out.push(format!("interface {:?} does not exist", self.interface));
            return out;
        }
        if self.carrier == Some(false) {
            out.push("no carrier — the link partner is down or unplugged".into());
        }
        if self.ipv6_disabled == Some(true) {
            out.push(format!(
                "IPv6 is DISABLED on {} — this blinded the x1860 incident for ~14 h. Fix:\n  \
                 sudo sysctl -w net.ipv6.conf.{}.disable_ipv6=0",
                self.interface, self.interface
            ));
        }
        if self.ipv6_disabled.is_none() {
            out.push(format!(
                "cannot read the IPv6 sysctl for {} — IPv6 may be off system-wide",
                self.interface
            ));
        }
        if self.link_local.is_none() {
            out.push(format!(
                "no link-local on {} — solicitations still work if another v6 address \
                 is configured, but a link-local is the reliable source:\n  \
                 sudo ip link set {} up (or toggle disable_ipv6 off and re-add addresses)",
                self.interface, self.interface
            ));
        }
        out
    }

    /// Whether the host can speak v6 on this interface at all.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.exists && self.carrier != Some(false) && self.ipv6_disabled != Some(true)
    }
}

/// Probe the LOCAL interface's v6 readiness (the "audit the prober" check).
pub fn self_check(interface: &str) -> V6SelfCheck {
    let sys = Path::new("/sys/class/net").join(interface);
    let exists = sys.exists();
    V6SelfCheck {
        interface: interface.to_string(),
        exists,
        carrier: read_one_line(sys.join("carrier")).map(|l| l.trim() == "1"),
        ipv6_disabled: read_one_line(
            Path::new("/proc/sys/net/ipv6/conf")
                .join(interface)
                .join("disable_ipv6"),
        )
        .and_then(|l| parse_sysctl_bool(&l)),
        link_local: read_one_line(Path::new("/proc/net/if_inet6"))
            .and_then(|content| parse_link_local(&content, interface)),
    }
}

/// Decoded Router Advertisement, ready to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAdvertisement {
    /// Router's link-local, derived (EUI-64) from the RA's source
    /// link-layer address option.
    pub router_link_local: Option<Ipv6Addr>,
    /// Router's MAC as advertised in the RA.
    pub router_mac: Option<MacAddress>,
    /// On-link, auto-configurable prefixes (PIO entries).
    pub prefixes: Vec<String>,
    /// Advertised recursive DNS servers (RDNSS entries).
    pub dns_servers: Vec<Ipv6Addr>,
    /// The M flag (managed: use DHCPv6 for addresses).
    pub stateful_address: bool,
    /// The O flag (other stateful config).
    pub stateful_other: bool,
    /// Advertised MTU, when present.
    pub mtu: Option<u32>,
}

impl RouterAdvertisement {
    /// Operator-ready next commands for the discovered router.
    #[must_use]
    pub fn commands(&self, interface: &str) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(ll) = self.router_link_local {
            out.push(format!(
                "ssh -o StrictHostKeyChecking=no root@{ll}%{interface}"
            ));
            out.push(format!("curl -g --interface {interface} 'http://[{ll}]/'"));
        }
        if let Some(prefix) = self.prefixes.first() {
            out.push(format!(
                "# SLAAC-able prefix: {prefix} (add an address in it to probe globals)"
            ));
        }
        out
    }
}

/// Actively solicit an RA on `interface` via `rdisc6` and decode it.
///
/// Returns `Ok(None)` when no router answers within the retries window.
pub fn solicit_router_advertisement(
    interface: &str,
    retries: u32,
) -> Result<Option<RouterAdvertisement>, V6DiscoveryError> {
    let output = std::process::Command::new("rdisc6")
        .args(["-1", "-r"])
        .arg(retries.to_string())
        .arg(interface)
        .output()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => V6DiscoveryError::ToolMissing,
            _ => V6DiscoveryError::ToolFailed(e.to_string()),
        })?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err(V6DiscoveryError::ToolFailed(format!(
            "exit {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(parse_rdisc6(&String::from_utf8_lossy(&output.stdout)))
}

/// Pure parser for `rdisc6` output (unit-tested against a synthetic fixture
/// shaped like real 1.0.7 output).
#[must_use]
pub fn parse_rdisc6(output: &str) -> Option<RouterAdvertisement> {
    let mut ra = RouterAdvertisement {
        router_link_local: None,
        router_mac: None,
        prefixes: Vec::new(),
        dns_servers: Vec::new(),
        stateful_address: false,
        stateful_other: false,
        mtu: None,
    };
    let mut saw_any = false;
    for line in output.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("Stateful address conf.") {
            if v.contains("Yes") {
                ra.stateful_address = true;
                saw_any = true;
            }
        } else if let Some(v) = t.strip_prefix("Stateful other conf") {
            if v.contains("Yes") {
                ra.stateful_other = true;
                saw_any = true;
            }
        } else if let Some(v) = t.strip_prefix("Source link-layer address") {
            if let Some(mac) = v.split(':').next() {
                // value looks like ": AA:BB:CC:DD:EE:FF" after the split
                let _ = mac;
            }
            if let Some(rest) = t.split_whitespace().last() {
                if let Ok(mac) = MacAddress::parse(rest) {
                    ra.router_mac = Some(mac);
                    ra.router_link_local = Some(derive_eui64_link_local(&mac));
                    saw_any = true;
                }
            }
        } else if let Some(p) = field_value(t, "Prefix") {
            ra.prefixes.push(p.to_string());
            saw_any = true;
        } else if let Some(m) = field_value(t, "MTU").and_then(|s| s.parse().ok()) {
            ra.mtu = Some(m);
            saw_any = true;
        } else if let Some(a) = field_value(t, "Recursive DNS server").and_then(|s| s.parse().ok())
        {
            ra.dns_servers.push(a);
            saw_any = true;
        }
    }
    if saw_any { Some(ra) } else { None }
}

/// `field_value(" Prefix  : fd00::/64", "Prefix") == Some("fd00::/64")` —
/// rdisc6 pads keys to a column then separates with `:` before the value.
fn field_value(line: &str, key: &str) -> Option<String> {
    let rest = line.trim().strip_prefix(key)?;
    let rest = rest.trim_start().strip_prefix(':')?;
    rest.split_whitespace().next().map(ToString::to_string)
}

/// Derive the EUI-64 link-local (`fe80::…`) from a MAC — the AGENTS.md
/// dark-device rule: any observed source MAC yields a probeable v6 address
/// even when IPv4 is completely broken.
#[must_use]
pub fn derive_eui64_link_local(mac: &MacAddress) -> Ipv6Addr {
    let o = mac.octets();
    let mut groups = [0u16; 8];
    groups[0] = 0xfe80;
    groups[1] = 0;
    groups[2] = 0;
    groups[3] = 0;
    groups[4] = ((o[0] ^ 0x02) as u16) << 8 | o[1] as u16;
    groups[5] = (o[2] as u16) << 8 | 0xff;
    groups[6] = 0xfe00 | o[3] as u16;
    groups[7] = (o[4] as u16) << 8 | o[5] as u16;
    Ipv6Addr::new(
        groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7],
    )
}

/// Read the interface index (`/sys/class/net/<if>/ifindex`) — needed for
/// scoped v6 connects.
#[must_use]
pub fn interface_index(interface: &str) -> Option<u32> {
    read_one_line(Path::new("/sys/class/net").join(interface).join("ifindex"))
        .and_then(|l| l.trim().parse().ok())
}

/// TCP-connect (with v6 scope) and grab the first bytes — banner probe for
/// link-local addresses where `%zone` cannot go through hostname resolution.
pub fn banner_probe_v6(
    addr: Ipv6Addr,
    ifindex: u32,
    port: u16,
    timeout: Duration,
) -> Option<String> {
    let sa = SocketAddr::V6(SocketAddrV6::new(addr, port, 0, ifindex));
    let mut stream = TcpStream::connect_timeout(&sa, timeout).ok()?;
    use std::io::Read;
    let mut buf = [0u8; 48];
    let n = stream
        .set_read_timeout(Some(timeout))
        .ok()
        .and_then(|()| stream.read(&mut buf).ok())?;
    let raw = &buf[..n];
    let end = raw
        .iter()
        .position(|b| *b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(n);
    Some(String::from_utf8_lossy(&raw[..end]).trim().to_string())
}

fn read_one_line(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path.as_ref()).ok().map(|s| {
        // kernel single-value files end with \n
        s.lines().next().unwrap_or_default().to_string()
    })
}

/// `parse_sysctl_bool("1\n") == Some(true)` — pure, testable.
fn parse_sysctl_bool(line: &str) -> Option<bool> {
    match line.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

/// Parse `/proc/net/if_inet6` content for the interface's link-local.
///
/// The kernel prints each 16-bit group right-aligned in 4 columns
/// (`%4s`-style), so zero groups appear as space padding: the address is
/// the whitespace-split tokens BEFORE the `<ifindex> <name>` pair. Rebuild
/// it by left-padding every token back to 4 hex chars.
fn parse_link_local(if_inet6: &str, interface: &str) -> Option<Ipv6Addr> {
    for line in if_inet6.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(name_pos) = fields.iter().position(|f| *f == interface) else {
            continue;
        };
        // <addr tokens…> <ifindex> <name>: need at least the 8 addr tokens.
        if name_pos < 9 {
            continue;
        }
        let addr_tokens = &fields[..name_pos - 1];
        if addr_tokens.len() != 8 {
            continue;
        }
        let mut hex = String::with_capacity(32);
        for tok in addr_tokens {
            if tok.len() > 4 || !tok.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            for _ in tok.len()..4 {
                hex.push('0');
            }
            hex.push_str(tok);
        }
        if !hex.starts_with("fe80") {
            continue;
        }
        let mut groups = [0u16; 8];
        for (i, chunk) in hex.as_bytes().chunks(4).enumerate() {
            let s = std::str::from_utf8(chunk).ok()?;
            groups[i] = u16::from_str_radix(s, 16).ok()?;
        }
        return Some(Ipv6Addr::new(
            groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7],
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic rdisc6 fixture — same shape as real 1.0.7 output, with
    /// placeholder data (no real bench identifiers in-tree).
    const RDISC6_FIXTURE: &str = "Soliciting ff02::2 (ff02::2) on testif...\n\
        \n\
        Hop limit                 :           64 (      0x40)\n\
        Stateful address conf.    :          Yes\n\
        Stateful other conf.      :          Yes\n\
        Mobile home agent         :           No\n\
        Router preference         :       medium\n\
        Neighbor discovery proxy  :           No\n\
        Router lifetime           :            0 (0x00000000) seconds\n\
        Reachable time            :  unspecified (0x00000000)\n\
        Retransmit time           :  unspecified (0x00000000)\n\
         Source link-layer address: 02:11:22:33:44:55\n\
         MTU                      :         1500 bytes (valid)\n\
         Prefix                   : fd00:dead:beef::/64\n\
          On-link                 :          Yes\n\
          Autonomous address conf.:          Yes\n\
          Valid time              :         5400 (0x00001518) seconds\n\
          Pref. time              :         2700 (0x0000000a8c) seconds\n\
         Route                    : fd00:dead:beef::/48\n\
          Route preference        :       medium\n\
          Recursive DNS server     : fd00:dead:beef::1\n\
         DNS server lifetime      :         1800 (0x00000708) seconds\n";

    #[test]
    fn parses_rdisc6_fixture() {
        let ra = parse_rdisc6(RDISC6_FIXTURE).expect("fixture should parse");
        assert_eq!(
            ra.router_mac,
            Some(MacAddress::parse("02:11:22:33:44:55").unwrap())
        );
        assert_eq!(
            ra.router_link_local,
            Some("fe80::11:22ff:fe33:4455".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(ra.prefixes, ["fd00:dead:beef::/64"]);
        assert_eq!(
            ra.dns_servers,
            ["fd00:dead:beef::1".parse::<Ipv6Addr>().unwrap()]
        );
        assert!(ra.stateful_address && ra.stateful_other);
        assert_eq!(ra.mtu, Some(1500));
    }

    #[test]
    fn parses_no_router_output() {
        assert!(parse_rdisc6("Soliciting ff02::2 (ff02::2) on testif...\n").is_none());
        assert!(parse_rdisc6("").is_none());
    }

    #[test]
    fn eui64_matches_the_classic_examples() {
        // Local bit (0x02) cleared -> 00; ff:fe inserted in the middle.
        let a = derive_eui64_link_local(&MacAddress::parse("02:11:22:33:44:55").unwrap());
        assert_eq!(a.to_string(), "fe80::11:22ff:fe33:4455");
        // Local bit set (aa) -> flipped to a8.
        let b = derive_eui64_link_local(&MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap());
        assert_eq!(b.to_string(), "fe80::a8bb:ccff:fedd:eeff");
    }

    #[test]
    fn sysctl_bool_parsing() {
        assert_eq!(parse_sysctl_bool("1\n"), Some(true));
        assert_eq!(parse_sysctl_bool("0\n"), Some(false));
        assert_eq!(parse_sysctl_bool("garbage"), None);
    }

    #[test]
    fn link_local_parse_handles_space_padded_address() {
        // fe80::209:3670:1f:c8d2 — zero groups are space-padded per the
        // kernel's %4s-per-group format; the parser must rebuild them.
        let content = "fe80   0   0   0 209 3670   1f c8d2 08 testif 20 80 10 80\n\
                       \n00000000000000000000000000000001 01 lo 80 10 80\n\
                       \nfe80 111 222 333 444 555 666 777 09 other0 20 80\n";
        assert_eq!(
            parse_link_local(content, "testif"),
            Some("fe80::209:3670:1f:c8d2".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(parse_link_local(content, "lo"), None); // not link-local
        assert_eq!(parse_link_local(content, "missing"), None);
    }

    #[test]
    fn self_check_problems_name_the_fixes() {
        let sc = V6SelfCheck {
            interface: "testif".into(),
            exists: true,
            carrier: Some(true),
            ipv6_disabled: Some(true),
            link_local: None,
        };
        let problems = sc.problems();
        assert!(problems.iter().any(|p| p.contains("disable_ipv6=0")));
        assert!(!sc.ready());
    }
}
