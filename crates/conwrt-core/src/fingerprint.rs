//! Authenticated OpenWrt identity: the confirmation layer above the
//! passive classifier (`state.rs`).
//!
//! A passive probe can at most establish `SshOnly` (an SSH server answered;
//! the OS is unconfirmed — stock vendors also ship Dropbear). This module
//! parses the **authenticated** evidence gathered over an established SSH
//! session: `/etc/openwrt_release` (shell-style `KEY='value'` pairs) and
//! `/tmp/sysinfo/board_name`. Only that upgrades `SshOnly` to `OpenWrt`
//! (the 2026-10-12 external review's P1 follow-through: identify OpenWrt
//! with read-only, authenticated evidence and retain ambiguity otherwise).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::state::DeviceState;

/// Parsed `/etc/openwrt_release` (fields absent from the file stay `None`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenwrtRelease {
    /// `DISTRIB_ID` — e.g. `OpenWrt`.
    pub id: Option<String>,
    /// `DISTRIB_RELEASE` — e.g. `24.10.2`.
    pub release: Option<String>,
    /// `DISTRIB_DESCRIPTION` — e.g. `OpenWrt 24.10.2 r28427`.
    pub description: Option<String>,
    /// `DISTRIB_ARCH` — e.g. `mipsel_24kc`.
    pub arch: Option<String>,
    /// `DISTRIB_TARGET` — e.g. `ramips/mt7621`.
    pub target: Option<String>,
}

impl OpenwrtRelease {
    /// Whether this is positively an OpenWrt-family distribution.
    #[must_use]
    pub fn is_openwrt(&self) -> bool {
        self.id
            .as_deref()
            .is_some_and(|id| id.eq_ignore_ascii_case("openwrt") || id.eq_ignore_ascii_case("lede"))
    }
}

/// Parse `/etc/openwrt_release` contents. Returns `None` when nothing
/// recognizable is present (empty file, garbage, wrong format).
#[must_use]
pub fn parse_openwrt_release(contents: &str) -> Option<OpenwrtRelease> {
    let mut release = OpenwrtRelease::default();
    let mut seen = 0usize;
    for line in contents.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim_matches('\'').trim_matches('"');
        match key.trim() {
            "DISTRIB_ID" => {
                release.id = Some(value.to_string());
                seen += 1;
            }
            "DISTRIB_RELEASE" => {
                release.release = Some(value.to_string());
                seen += 1;
            }
            "DISTRIB_DESCRIPTION" => {
                release.description = Some(value.to_string());
                seen += 1;
            }
            "DISTRIB_ARCH" => {
                release.arch = Some(value.to_string());
                seen += 1;
            }
            "DISTRIB_TARGET" => {
                release.target = Some(value.to_string());
                seen += 1;
            }
            _ => {}
        }
    }
    if seen == 0 { None } else { Some(release) }
}

/// Upgrade a passively classified state with authenticated evidence.
///
/// `SshOnly` + a parsed release whose `DISTRIB_ID` is OpenWrt/LEDE ⇒
/// `OpenWrt` (confirmed). Everything else — including a release file that
/// names a *vendor* distribution — keeps the passive classification:
/// absence of evidence must not manufacture confirmation.
#[must_use]
pub fn confirm(state: DeviceState, release: Option<&OpenwrtRelease>) -> DeviceState {
    match (state, release) {
        (DeviceState::SshOnly, Some(release)) if release.is_openwrt() => DeviceState::OpenWrt,
        (other, _) => other,
    }
}

/// The full authenticated fingerprint of one device, gathered read-only
/// over SSH.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FingerprintReport {
    /// `/etc/openwrt_release`, when present and parseable.
    pub release: Option<OpenwrtRelease>,
    /// `/tmp/sysinfo/board_name`, when present.
    pub board_name: Option<String>,
    /// `/proc/sys/kernel/hostname`, when readable.
    pub hostname: Option<String>,
    /// The unclassified-by-this-module facts still worth reporting.
    pub notes: Vec<String>,
}
