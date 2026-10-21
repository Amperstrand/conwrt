//! Port-probe state classification — the `classify_state` port of
//! `router-probe.py`, over typed probe outcomes.
//!
//! Evidence in → [`RouterState`] out: fully unit-testable,
//! transport-independent (the probes themselves — curl, ssh, tcpdump —
//! live outside; this module never performs I/O). The precedence below
//! is the Python if-chain, verbatim.

use crate::banner::{HttpGetSignature, HttpHeadSignature};

/// The classified router boot state — the Python `RouterStates` tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterState {
    /// Link down and ping unreachable.
    Off,
    /// Bootloader (recovery) web server detected.
    Uboot,
    /// Link up, failsafe broadcast seen, not yet SSH-able.
    OpenwrtBooting,
    /// OpenWrt SSH answered AND failsafe markers present.
    OpenwrtFailsafe,
    /// OpenWrt SSH answered (`/etc/openwrt_release` readable).
    OpenwrtRunning,
    /// GL.iNet stock admin panel.
    GlinetStock,
    /// Linksys stock web interface.
    LinksysStock,
    /// Insufficient or contradictory evidence.
    Unknown,
}

impl RouterState {
    /// Stable machine name (the Python state strings).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            RouterState::Off => "off",
            RouterState::Uboot => "uboot",
            RouterState::OpenwrtBooting => "openwrt_booting",
            RouterState::OpenwrtFailsafe => "openwrt_failsafe",
            RouterState::OpenwrtRunning => "openwrt_running",
            RouterState::GlinetStock => "glinet_stock",
            RouterState::LinksysStock => "linksys_stock",
            RouterState::Unknown => "unknown",
        }
    }
}

/// `probe_ssh` outcome vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SshStatus {
    /// `/etc/openwrt_release` read over SSH.
    OpenwrtSsh,
    /// SSH connected, release file absent.
    SshOk,
    /// Auth required (`Permission denied`).
    SshAuthRequired,
    /// Port closed (`Connection refused`).
    SshRefused,
    /// Connect timeout.
    SshTimeout,
    /// Nothing answered.
    #[default]
    NoResponse,
}

/// `probe_link_state` outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkStatus {
    /// Interface up, carrier present.
    LinkUp,
    /// No link.
    #[default]
    NoLink,
}

/// `probe_failsafe_broadcast` outcome (UDP 4919).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailsafeBroadcastStatus {
    /// "Please press button now to enter failsafe" seen.
    Detected,
    /// Not seen.
    #[default]
    NotDetected,
}

/// `probe_ping` outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PingStatus {
    /// ICMP reply received.
    Reachable,
    /// No reply.
    #[default]
    Unreachable,
}

/// `probe_ssh_failsafe` outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SshFailsafeStatus {
    /// `/tmp/failsafe` exists, or no overlay mounted.
    Failsafe,
    /// Not failsafe.
    #[default]
    NotFailsafe,
}

/// Everything `classify_state` looks at; defaults mirror the Python
/// `probe_map.get(name, ("no_response"|"not_detected"|...))` fallbacks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeEvidence {
    /// HTTP GET `/` classification.
    pub http_get: HttpGetSignature,
    /// HTTP HEAD `/` classification.
    pub http_head: HttpHeadSignature,
    /// SSH probe outcome.
    pub ssh: SshStatus,
    /// Local link state.
    pub link: LinkStatus,
    /// Failsafe UDP broadcast detection.
    pub failsafe_broadcast: FailsafeBroadcastStatus,
    /// ICMP reachability.
    pub ping: PingStatus,
    /// SSH failsafe markers.
    pub ssh_failsafe: SshFailsafeStatus,
}

/// Classify the router state from probe evidence — the Python
/// `classify_state` precedence, verbatim:
///
/// 1. U-Boot HTTP (GET or HEAD) wins outright.
/// 2. OpenWrt SSH: failsafe markers split running vs failsafe.
/// 3. GL.iNet / Linksys stock HTTP.
/// 4. Link up + failsafe broadcast (and no OpenWrt SSH) = booting.
/// 5. No link + unreachable = off.
/// 6. Anything else answering = unknown.
#[must_use]
pub fn classify(evidence: &ProbeEvidence) -> RouterState {
    if evidence.http_get == HttpGetSignature::Uboot
        || evidence.http_head == HttpHeadSignature::Uboot
    {
        return RouterState::Uboot;
    }
    if evidence.ssh == SshStatus::OpenwrtSsh {
        if evidence.ssh_failsafe == SshFailsafeStatus::Failsafe {
            return RouterState::OpenwrtFailsafe;
        }
        return RouterState::OpenwrtRunning;
    }
    if evidence.http_get == HttpGetSignature::GlinetStock {
        return RouterState::GlinetStock;
    }
    if evidence.http_get == HttpGetSignature::LinksysStock {
        return RouterState::LinksysStock;
    }
    if evidence.link == LinkStatus::LinkUp
        && evidence.failsafe_broadcast == FailsafeBroadcastStatus::Detected
        && evidence.ssh != SshStatus::OpenwrtSsh
    {
        return RouterState::OpenwrtBooting;
    }
    if evidence.link == LinkStatus::NoLink && evidence.ping == PingStatus::Unreachable {
        return RouterState::Off;
    }
    RouterState::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uboot_http_wins_over_everything() {
        let ev = ProbeEvidence {
            http_head: HttpHeadSignature::Uboot,
            ssh: SshStatus::OpenwrtSsh,
            ..Default::default()
        };
        assert_eq!(classify(&ev), RouterState::Uboot);
    }

    #[test]
    fn openwrt_ssh_running_when_not_failsafe() {
        let ev = ProbeEvidence {
            ssh: SshStatus::OpenwrtSsh,
            ..Default::default()
        };
        assert_eq!(classify(&ev), RouterState::OpenwrtRunning);
    }

    #[test]
    fn openwrt_ssh_failsafe_split() {
        let ev = ProbeEvidence {
            ssh: SshStatus::OpenwrtSsh,
            ssh_failsafe: SshFailsafeStatus::Failsafe,
            ..Default::default()
        };
        assert_eq!(classify(&ev), RouterState::OpenwrtFailsafe);
    }

    #[test]
    fn stock_http_classification() {
        let glinet = ProbeEvidence {
            http_get: HttpGetSignature::GlinetStock,
            ..Default::default()
        };
        assert_eq!(classify(&glinet), RouterState::GlinetStock);
        let linksys = ProbeEvidence {
            http_get: HttpGetSignature::LinksysStock,
            ..Default::default()
        };
        assert_eq!(classify(&linksys), RouterState::LinksysStock);
    }

    #[test]
    fn booting_requires_link_and_failsafe_broadcast() {
        let base = ProbeEvidence {
            link: LinkStatus::LinkUp,
            failsafe_broadcast: FailsafeBroadcastStatus::Detected,
            ..Default::default()
        };
        assert_eq!(classify(&base), RouterState::OpenwrtBooting);
        // failsafe broadcast without link: rule 5 needs link up, and
        // no-link + unreachable then classifies off (Python precedence)
        let no_link = ProbeEvidence {
            failsafe_broadcast: FailsafeBroadcastStatus::Detected,
            ..Default::default()
        };
        assert_eq!(classify(&no_link), RouterState::Off);
    }

    #[test]
    fn no_link_unreachable_is_off() {
        assert_eq!(classify(&ProbeEvidence::default()), RouterState::Off);
    }

    #[test]
    fn reachable_or_link_is_unknown() {
        let ping = ProbeEvidence {
            ping: PingStatus::Reachable,
            ..Default::default()
        };
        assert_eq!(classify(&ping), RouterState::Unknown);
        let link = ProbeEvidence {
            link: LinkStatus::LinkUp,
            ..Default::default()
        };
        assert_eq!(classify(&link), RouterState::Unknown);
    }

    #[test]
    fn state_names_match_python() {
        assert_eq!(RouterState::OpenwrtBooting.as_str(), "openwrt_booting");
        assert_eq!(RouterState::GlinetStock.as_str(), "glinet_stock");
        assert_eq!(RouterState::Unknown.as_str(), "unknown");
    }
}
