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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// Link is down: powered off or cable pulled.
    Off,
    /// Nothing responds at all; cannot distinguish power state without link.
    Unreachable,
    /// A bootloader recovery server answered (HTTP with recovery
    /// fingerprints, no SSH).
    UbootRecovery,
    /// An SSH server answered (dropbear/OpenSSH) — a running OS.
    OpenWrt,
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
        } else {
            notes.push("no responses on any channel".into());
            (DeviceState::Unreachable, notes)
        }
    } else if let Some(banner) = &evidence.ssh_banner {
        let openwrt_http = evidence.http.as_ref().is_some_and(is_openwrt_http);
        if openwrt_http {
            notes.push(format!(
                "SSH banner '{}' plus OpenWrt HTTP fingerprints",
                banner.software
            ));
            (DeviceState::OpenWrt, notes)
        } else {
            notes.push(format!(
                "SSH banner '{}' answered; OpenWrt-classified (dropbear/OpenSSH present)",
                banner.software
            ));
            notes.push(
                "note: some stock firmwares also run dropbear; board fingerprinting refines this"
                    .into(),
            );
            (DeviceState::OpenWrt, notes)
        }
    } else {
        let http = evidence.http.as_ref().expect("checked both channels above");
        let server = http.server_header.as_deref().unwrap_or_default();
        let lowered = server.to_ascii_lowercase();
        if recovery_hints
            .iter()
            .any(|hint| lowered.contains(&hint.to_ascii_lowercase()))
        {
            notes.push(format!(
                "HTTP server header {server:?} matches recovery fingerprints"
            ));
            notes.push("no SSH while a recovery server answers: bootloader mode".into());
            (DeviceState::UbootRecovery, notes)
        } else {
            notes.push(format!(
                "HTTP answered (status {}, server {:?}, title {:?}) with no SSH",
                http.status,
                server,
                http.title.as_deref().unwrap_or("")
            ));
            notes.push("vendor UI without SSH: treating as stock firmware".into());
            (DeviceState::StockVendor, notes)
        }
    }
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
    fn ssh_banner_is_openwrt() {
        let ev = ProbeEvidence {
            ssh_banner: banner("dropbear_2024.86"),
            ..Default::default()
        };
        assert_eq!(classify(&ev), DeviceState::OpenWrt);
        let (_, notes) = classify_with_notes(&ev, DEFAULT_RECOVERY_HINTS);
        assert!(notes.iter().any(|n| n.contains("stock firmwares")));
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
    fn ssh_overrides_http_vendor_guess() {
        // dropbear answering next to a vendor-titled page: trust SSH.
        let ev = ProbeEvidence {
            ssh_banner: banner("SSH-2.0-dropbear"),
            http: http(200, Some("mini_httpd"), Some("Vendor")),
            ..Default::default()
        };
        assert_eq!(classify(&ev), DeviceState::OpenWrt);
    }

    #[test]
    fn state_names_are_stable() {
        assert_eq!(DeviceState::UbootRecovery.as_str(), "uboot-recovery");
        assert_eq!(DeviceState::StockVendor.as_str(), "stock-vendor");
    }
}
