//! Device-state classification — a pure function over probe evidence.
//!
//! Port of the semantics of conwrt 1.x `scripts/router-probe.py` /
//! `scripts/conwrt/flash/detect.py` (boot-state detection: off / uboot /
//! openwrt / stock), expressed as evidence in → state out so it is fully
//! unit-testable and provider-independent.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use conwrt_types::MacAddress;

/// The classified boot/management state of a probed target.
///
/// These are **evidence classes**, not confirmed facts: `OpenWrt` requires
/// positive OpenWrt fingerprints, never an SSH banner alone (stock vendor
/// firmware also ships Dropbear/OpenSSH). Classifier output is advisory for
/// diagnostics only — destructive operations (flashing, sysupgrade) must
/// independently pass the model + board + specimen identity gates from
/// `AGENTS.md` and must never be authorized from a classifier result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// Link is down: powered off or cable pulled.
    Off,
    /// Nothing responds at all; cannot distinguish power state without link.
    Unreachable,
    /// A bootloader recovery server answered (HTTP with recovery
    /// fingerprints, no SSH).
    UbootRecovery,
    /// **Confirmed** OpenWrt: an SSH server answered **and** positive
    /// OpenWrt HTTP fingerprints (uhttpd server header, LuCI/OpenWrt title)
    /// were observed.
    OpenWrt,
    /// An SSH server answered but the OS identity is **unconfirmed**: some
    /// stock firmwares also run Dropbear. Authenticated board evidence
    /// (`/etc/openwrt_release`, `/tmp/sysinfo/board_name`) upgrades this to
    /// `OpenWrt`; until then no firmware-planning decision may treat it as
    /// OpenWrt.
    SshOnly,
    /// HTTP answered with a vendor UI and no SSH — stock firmware.
    StockVendor,
    /// Contradictory or insufficient evidence.
    Unknown,
}

impl DeviceState {
    /// Short machine-friendly name (event/JSON serialization).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceState::Off => "off",
            DeviceState::Unreachable => "unreachable",
            DeviceState::UbootRecovery => "uboot-recovery",
            DeviceState::OpenWrt => "openwrt",
            DeviceState::SshOnly => "ssh-only",
            DeviceState::StockVendor => "stock-vendor",
            DeviceState::Unknown => "unknown",
        }
    }
}

/// Everything the classifier looks at. Providers fill this in; the
/// classifier never performs I/O.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeEvidence {
    /// Carrier state of the local link, if knowable.
    pub link_up: Option<bool>,
    /// ICMP echo result.
    pub ping: bool,
    /// HTTP GET `/` outcome.
    pub http: Option<crate::capability::HttpProbeResult>,
    /// SSH identification banner.
    pub ssh_banner: Option<crate::capability::SshBanner>,
    /// Neighbor/ARP MAC of the target.
    pub mac: Option<MacAddress>,
}

/// Server-header fragments that fingerprint bootloader recovery web servers
/// (U-Boot httpd and OEM recovery stacks observed in conwrt captures).
pub const DEFAULT_RECOVERY_HINTS: &[&str] = &[
    "uboot",
    "u-boot",
    "goahead",
    "wmpre",
    "boa/",
    "alphapd",
    "thttpd/2.",
];

/// Classify with the default recovery fingerprints.
#[must_use]
pub fn classify(evidence: &ProbeEvidence) -> DeviceState {
    classify_with_notes(evidence, DEFAULT_RECOVERY_HINTS).0
}

/// Classify, returning human-oriented notes for the diagnosis audit trail.
/// `recovery_hints` are case-insensitive substrings matched against the HTTP
/// `Server` header; model-specific `signatures` data can extend these later.
#[must_use]
pub fn classify_with_notes(
    evidence: &ProbeEvidence,
    recovery_hints: &[&str],
) -> (DeviceState, Vec<String>) {
    let mut notes = Vec::new();

    if evidence.link_up == Some(false) {
        notes.push("link is down: powered off or unplugged".into());
        return (DeviceState::Off, notes);
    }

    if evidence.ssh_banner.is_none() && evidence.http.is_none() {
        if evidence.ping {
            notes.push(
                "answers ICMP only (no HTTP, no SSH): not a management interface we speak".into(),
            );
            (DeviceState::Unknown, notes)
        } else if evidence.mac.is_some() {
            notes.push(
                "ARP/neighbor entry but no L3/L7 responses: stale entry, silent host, or \
                 management interfaces not yet probed"
                    .into(),
            );
            (DeviceState::Unknown, notes)
        } else {
            notes.push("no responses on any channel".into());
            (DeviceState::Unreachable, notes)
        }
    } else if let Some(banner) = &evidence.ssh_banner {
        let openwrt_http = evidence.http.as_ref().is_some_and(is_openwrt_http);
        let recovery_http = evidence
            .http
            .as_ref()
            .is_some_and(|http| matches_recovery_hints(http, recovery_hints));
        if openwrt_http {
            notes.push(format!(
                "SSH banner '{}' plus OpenWrt HTTP fingerprints",
                banner.software
            ));
            (DeviceState::OpenWrt, notes)
        } else if recovery_http {
            notes.push(format!(
                "contradictory evidence: SSH banner '{}' beside recovery HTTP fingerprints",
                banner.software
            ));
            (DeviceState::Unknown, notes)
        } else {
            notes.push(format!(
                "SSH banner '{}' answered with no identifying HTTP evidence",
                banner.software
            ));
            notes.push(
                "OS unconfirmed: stock firmwares also run dropbear; board evidence refines this"
                    .into(),
            );
            (DeviceState::SshOnly, notes)
        }
    } else {
        let http = evidence.http.as_ref().expect("checked both channels above");
        if matches_recovery_hints(http, recovery_hints) {
            notes.push(format!(
                "HTTP server header {:?} matches recovery fingerprints",
                http.server_header.as_deref().unwrap_or_default()
            ));
            notes.push("no SSH while a recovery server answers: bootloader mode".into());
            (DeviceState::UbootRecovery, notes)
        } else {
            notes.push(format!(
                "HTTP answered (status {}, server {:?}, title {:?}) with no SSH",
                http.status,
                http.server_header.as_deref().unwrap_or_default(),
                http.title.as_deref().unwrap_or("")
            ));
            notes.push("vendor UI without SSH: treating as stock firmware".into());
            (DeviceState::StockVendor, notes)
        }
    }
}

fn matches_recovery_hints(
    http: &crate::capability::HttpProbeResult,
    recovery_hints: &[&str],
) -> bool {
    let server = http.server_header.as_deref().unwrap_or_default();
    let lowered = server.to_ascii_lowercase();
    recovery_hints
        .iter()
        .any(|hint| lowered.contains(&hint.to_ascii_lowercase()))
}

/// OpenWrt HTTP fingerprints (uhttpd or a LuCI/OpenWrt title).
fn is_openwrt_http(http: &crate::capability::HttpProbeResult) -> bool {
    let server = http
        .server_header
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let title = http
        .title
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    server.contains("uhttpd")
        || title.contains("openwrt")
        || title.contains("luci")
        || title.contains("openwrt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{HttpProbeResult, SshBanner};

    fn http(status: u16, server: Option<&str>, title: Option<&str>) -> Option<HttpProbeResult> {
        Some(HttpProbeResult {
            status,
            server_header: server.map(String::from),
            title: title.map(String::from),
        })
    }

    fn banner(software: &str) -> Option<SshBanner> {
        Some(SshBanner {
            software: software.into(),
        })
    }

    #[test]
    fn link_down_is_off() {
        let ev = ProbeEvidence {
            link_up: Some(false),
            ..Default::default()
        };
        assert_eq!(classify(&ev), DeviceState::Off);
    }

    #[test]
    fn silence_is_unreachable() {
        let ev = ProbeEvidence::default();
        assert_eq!(classify(&ev), DeviceState::Unreachable);
    }

    #[test]
    fn icmp_only_is_unknown() {
        let ev = ProbeEvidence {
            ping: true,
            ..Default::default()
        };
        assert_eq!(classify(&ev), DeviceState::Unknown);
    }

    #[test]
    fn recovery_server_header_is_uboot() {
        for server in ["uwWMPre/1.0", "GoAhead-http", "Boa/0.94.14rc21"] {
            let ev = ProbeEvidence {
                http: http(200, Some(server), None),
                ..Default::default()
            };
            assert_eq!(classify(&ev), DeviceState::UbootRecovery, "server={server}");
        }
    }

    #[test]
    fn custom_recovery_hints_extend_matching() {
        let ev = ProbeEvidence {
            http: http(200, Some("VendorRecovery/9"), None),
            ..Default::default()
        };
        assert_eq!(classify(&ev), DeviceState::StockVendor);
        assert_eq!(
            classify_with_notes(&ev, &["vendorrecovery"]).0,
            DeviceState::UbootRecovery
        );
    }

    #[test]
    fn vendor_ui_without_ssh_is_stock() {
        let ev = ProbeEvidence {
            http: http(200, Some("lighttpd/1.4"), Some("DIR-1960 Setup")),
            ..Default::default()
        };
        assert_eq!(classify(&ev), DeviceState::StockVendor);
    }

    #[test]
    fn ssh_banner_alone_is_ssh_only_not_openwrt() {
        let ev = ProbeEvidence {
            ssh_banner: banner("dropbear_2024.86"),
            ..Default::default()
        };
        assert_eq!(classify(&ev), DeviceState::SshOnly);
        let (_, notes) = classify_with_notes(&ev, DEFAULT_RECOVERY_HINTS);
        assert!(notes.iter().any(|n| n.contains("OS unconfirmed")));
    }

    #[test]
    fn stock_dropbear_beside_vendor_ui_is_ssh_only() {
        // Regression (external review 2026-10-12): stock firmware running
        // dropbear next to its vendor web UI must NOT be classified OpenWrt.
        let ev = ProbeEvidence {
            ssh_banner: banner("SSH-2.0-dropbear"),
            http: http(200, Some("mini_httpd"), Some("Vendor Setup")),
            ping: true,
            ..Default::default()
        };
        assert_eq!(classify(&ev), DeviceState::SshOnly);
    }

    #[test]
    fn ssh_beside_recovery_header_is_contradictory_unknown() {
        // A bootloader recovery server does not run SSH; both answering at
        // once means the evidence is unreliable (NAT reflection, stale
        // probe, MITM) — refuse to guess.
        let ev = ProbeEvidence {
            ssh_banner: banner("SSH-2.0-OpenSSH_9.6"),
            http: http(200, Some("Boa/0.94.14rc21"), None),
            ping: true,
            ..Default::default()
        };
        let (state, notes) = classify_with_notes(&ev, DEFAULT_RECOVERY_HINTS);
        assert_eq!(state, DeviceState::Unknown);
        assert!(notes.iter().any(|n| n.contains("contradictory")));
    }

    #[test]
    fn arp_entry_without_responses_is_unknown() {
        let ev = ProbeEvidence {
            mac: Some(MacAddress::parse("94:83:c4:0a:0b:0c").unwrap()),
            ..Default::default()
        };
        let (state, notes) = classify_with_notes(&ev, DEFAULT_RECOVERY_HINTS);
        assert_eq!(state, DeviceState::Unknown);
        assert!(notes.iter().any(|n| n.contains("ARP/neighbor")));
    }

    #[test]
    fn ssh_plus_uhttpd_is_openwrt_certain() {
        let ev = ProbeEvidence {
            ssh_banner: banner("dropbear_2024.86"),
            http: http(200, Some("uhttpd/1.0"), Some("OpenWrt LuCI")),
            ..Default::default()
        };
        let (state, notes) = classify_with_notes(&ev, DEFAULT_RECOVERY_HINTS);
        assert_eq!(state, DeviceState::OpenWrt);
        assert!(notes.iter().any(|n| n.contains("fingerprints")));
    }

    #[test]
    fn state_names_are_stable() {
        assert_eq!(DeviceState::UbootRecovery.as_str(), "uboot-recovery");
        assert_eq!(DeviceState::SshOnly.as_str(), "ssh-only");
        assert_eq!(DeviceState::StockVendor.as_str(), "stock-vendor");
    }
}
