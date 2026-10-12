//! Wire types for the ASU `/api/v1/build` API.
//!
//! Field access mirrors the tolerant `.get(...)` pattern of
//! `scripts/firmware-manager.py`: unknown JSON fields are ignored and known
//! fields default to empty values instead of failing deserialization.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use std::fmt;

/// ASU build request payload (`POST /api/v1/build`).
///
/// Field-for-field parity with the dict `cmd_request` builds in
/// `scripts/firmware-manager.py`: `packages` and `defaults` are omitted from
/// the serialized JSON when unset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildRequest {
    /// Distribution; firmware-manager always sends `openwrt`.
    pub distro: String,
    /// OpenWrt release, e.g. `24.10.2`.
    pub version: String,
    /// Target subtarget, e.g. `ramips/mt7621`.
    pub target: String,
    /// ASU device profile, e.g. `dlink_covr_x1860_a1`.
    pub profile: String,
    /// Extra packages to bake into the image; omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packages: Option<Vec<String>>,
    /// First-boot defaults script (`uci` commands); omitted from JSON when
    /// `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defaults: Option<String>,
}

impl BuildRequest {
    /// Creates an `openwrt` build request — the only distro
    /// firmware-manager.py ever sends.
    pub fn openwrt(
        version: impl Into<String>,
        target: impl Into<String>,
        profile: impl Into<String>,
    ) -> Self {
        Self {
            distro: "openwrt".to_string(),
            version: version.into(),
            target: target.into(),
            profile: profile.into(),
            packages: None,
            defaults: None,
        }
    }
}

/// The polymorphic `status` field of ASU build responses.
///
/// ASU reports status either as a number (HTTP-style code: `202` while
/// queued, `200` when done) or as a string (`pending`, `building`, `done`,
/// or a failure label). firmware-manager.py compares against both shapes;
/// so does this type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StatusValue {
    /// Numeric status. ASU sends `202` while the build is queued or
    /// building and `200` once it completes.
    Number(u16),
    /// String status (`pending`, `building`, `done`, `failed`, ...).
    Text(String),
}

impl StatusValue {
    /// `true` while the build is queued or in progress and polling must
    /// continue.
    ///
    /// Matches `status in ("pending", "building", 202)` from
    /// firmware-manager.py, deliberately extended to also accept the string
    /// spellings `"202"` and `"queued"` emitted by some ASU versions.
    pub fn is_in_progress(&self) -> bool {
        match self {
            Self::Number(n) => *n == 202,
            Self::Text(s) => matches!(s.as_str(), "pending" | "building" | "202" | "queued"),
        }
    }

    /// `true` when the build completed successfully.
    ///
    /// Matches `status in ("done", 200)` from firmware-manager.py, extended
    /// to accept the string spelling `"200"`.
    pub fn is_done(&self) -> bool {
        match self {
            Self::Number(n) => *n == 200,
            Self::Text(s) => matches!(s.as_str(), "done" | "200"),
        }
    }

    /// Human-readable label for error messages (`202`, `done`, ...).
    pub fn label(&self) -> String {
        match self {
            Self::Number(n) => n.to_string(),
            Self::Text(s) => s.clone(),
        }
    }
}

/// Response to a build submission (`POST /api/v1/build`).
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitResponse {
    /// Server-side hash identifying the enqueued build.
    #[serde(default)]
    pub request_hash: String,
    /// Status echoed by the server (usually numeric `202`).
    #[serde(default)]
    pub status: Option<StatusValue>,
}

/// One image entry inside a completed build manifest.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ManifestImage {
    /// Image file name, e.g. `*-squashfs-sysupgrade.bin`.
    #[serde(default)]
    pub name: String,
    /// Expected SHA-256 hex digest of the file.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Image size in bytes.
    #[serde(default)]
    pub size: Option<u64>,
}

/// Completed-build manifest returned by `GET /api/v1/build/{request_hash}`.
///
/// All fields default when absent; firmware-manager.py reads them with
/// `.get(key, fallback)` and this type preserves that tolerance.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BuildManifest {
    /// Server-side hash identifying the build.
    #[serde(default)]
    pub request_hash: String,
    /// Terminal status value.
    #[serde(default)]
    pub status: Option<StatusValue>,
    /// Distro reported back (`openwrt`).
    #[serde(default)]
    pub distro: String,
    /// OpenWrt release of the built image.
    #[serde(default)]
    pub version: String,
    /// Release commit code (`r…`).
    #[serde(default)]
    pub version_code: String,
    /// Target of the built image.
    #[serde(default)]
    pub target: String,
    /// Profile of the built image.
    #[serde(default)]
    pub profile: String,
    /// Full resolved package set (name → version); stored as
    /// `packages_all` in the cache metadata.
    #[serde(default)]
    pub packages: Map<String, Value>,
    /// Image files produced by the build.
    #[serde(default)]
    pub images: Vec<ManifestImage>,
    /// Server-side directory under `/store` that holds the images; falls
    /// back to `request_hash` when absent (same fallback as
    /// firmware-manager.py).
    #[serde(default)]
    pub bin_dir: String,
    /// Kernel version information.
    #[serde(default)]
    pub linux_kernel: Value,
    /// Build completion timestamp (server format).
    #[serde(default)]
    pub build_at: String,
    /// Enqueue timestamp (server format).
    #[serde(default)]
    pub enqueued_at: String,
    /// Failure detail, when the build failed.
    #[serde(default)]
    pub detail: String,
    /// Failure message, when the build failed.
    #[serde(default)]
    pub message: String,
}

/// Result of one build-status poll.
#[derive(Debug, Clone)]
pub enum BuildStatus {
    /// Queued or building (ASU `202` semantics) — keep polling.
    InProgress,
    /// Build finished; carries the full manifest.
    Done(Box<BuildManifest>),
    /// Build reached a terminal, non-done status; carries the manifest
    /// fields reported alongside the failure (`detail` / `message`).
    Failed(Box<BuildManifest>),
}

impl BuildStatus {
    /// Classifies a manifest by its `status` field, mirroring the poll-loop
    /// decisions of firmware-manager.py: pending/building/202 → keep
    /// polling; done/200 → success; anything else (including a missing
    /// status) → failure.
    pub fn classify(manifest: BuildManifest) -> Self {
        match &manifest.status {
            Some(status) if status.is_done() => Self::Done(Box::new(manifest)),
            Some(status) if status.is_in_progress() => Self::InProgress,
            _ => Self::Failed(Box::new(manifest)),
        }
    }
}

/// Firmware image flavour, derived from the file name exactly like
/// firmware-manager.py: `sysupgrade` > `factory` > `recovery` > `unknown`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageType {
    /// `*-sysupgrade*.bin` — for a device already running OpenWrt.
    Sysupgrade,
    /// `*-factory*.bin` — for stock-firmware upload paths.
    Factory,
    /// `*-recovery*.bin` — for bootloader recovery paths.
    Recovery,
    /// Anything else.
    #[default]
    Unknown,
}

impl ImageType {
    /// Classifies an image file name. `sysupgrade` wins over `factory`,
    /// which wins over `recovery` — the same if/elif chain order as
    /// firmware-manager.py.
    pub fn from_filename(name: &str) -> Self {
        if name.contains("sysupgrade") {
            Self::Sysupgrade
        } else if name.contains("factory") {
            Self::Factory
        } else if name.contains("recovery") {
            Self::Recovery
        } else {
            Self::Unknown
        }
    }

    /// Lowercase label used in metadata (`"sysupgrade"`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sysupgrade => "sysupgrade",
            Self::Factory => "factory",
            Self::Recovery => "recovery",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ImageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_omits_optional_fields_when_unset() {
        let request = BuildRequest::openwrt("24.10.2", "ramips/mt7621", "dlink_covr_x1860_a1");
        let value = serde_json::to_value(&request).expect("serialize");
        assert_eq!(
            value,
            serde_json::json!({
                "distro": "openwrt",
                "version": "24.10.2",
                "target": "ramips/mt7621",
                "profile": "dlink_covr_x1860_a1",
            })
        );
    }

    #[test]
    fn build_request_serializes_packages_and_defaults_when_set() {
        let mut request = BuildRequest::openwrt("24.10.2", "ramips/mt7621", "p");
        request.packages = Some(vec!["curl".into(), "htop".into()]);
        request.defaults = Some("uci set x=y".into());
        let value = serde_json::to_value(&request).expect("serialize");
        assert_eq!(value["packages"], serde_json::json!(["curl", "htop"]));
        assert_eq!(value["defaults"], serde_json::json!("uci set x=y"));
    }

    #[test]
    fn status_value_classification_matches_firmware_manager() {
        // In progress: string spellings and numeric 202.
        for value in [
            StatusValue::Text("pending".into()),
            StatusValue::Text("building".into()),
            StatusValue::Number(202),
        ] {
            assert!(value.is_in_progress(), "{value:?} should be in progress");
            assert!(!value.is_done(), "{value:?} should not be done");
        }
        // Done: string spellings and numeric 200.
        for value in [StatusValue::Text("done".into()), StatusValue::Number(200)] {
            assert!(value.is_done(), "{value:?} should be done");
            assert!(
                !value.is_in_progress(),
                "{value:?} should not be in progress"
            );
        }
        // Terminal failure statuses.
        for value in [StatusValue::Text("failed".into()), StatusValue::Number(500)] {
            assert!(!value.is_done());
            assert!(!value.is_in_progress());
        }
    }

    #[test]
    fn status_value_parses_both_shapes() {
        let number: StatusValue = serde_json::from_value(serde_json::json!(202)).expect("parse");
        assert_eq!(number, StatusValue::Number(202));
        let text: StatusValue = serde_json::from_value(serde_json::json!("done")).expect("parse");
        assert_eq!(text, StatusValue::Text("done".into()));
    }

    #[test]
    fn build_status_classify_routes_manifest() {
        let done = BuildManifest {
            status: Some(StatusValue::Number(200)),
            ..BuildManifest::default()
        };
        assert!(matches!(BuildStatus::classify(done), BuildStatus::Done(_)));

        let queued = BuildManifest {
            status: Some(StatusValue::Text("building".into())),
            ..BuildManifest::default()
        };
        assert!(matches!(
            BuildStatus::classify(queued),
            BuildStatus::InProgress
        ));

        // Missing status is a terminal failure, like firmware-manager.py's
        // `status not in ("done", 200)` check after the poll loop.
        let missing = BuildManifest::default();
        assert!(matches!(
            BuildStatus::classify(missing),
            BuildStatus::Failed(_)
        ));
    }

    #[test]
    fn image_type_precedence_matches_firmware_manager() {
        assert_eq!(
            ImageType::from_filename("x-squashfs-sysupgrade-factory.bin"),
            ImageType::Sysupgrade
        );
        assert_eq!(
            ImageType::from_filename("x-squashfs-factory.bin"),
            ImageType::Factory
        );
        assert_eq!(
            ImageType::from_filename("x-recovery.bin"),
            ImageType::Recovery
        );
        assert_eq!(ImageType::from_filename("kernel.bin"), ImageType::Unknown);
    }

    #[test]
    fn manifest_tolerates_missing_fields_and_ignores_unknowns() {
        let manifest: BuildManifest =
            serde_json::from_value(serde_json::json!({"unknown_field": 1}))
                .expect("tolerant parse");
        assert_eq!(manifest.request_hash, "");
        assert!(manifest.images.is_empty());
        assert!(manifest.packages.is_empty());
    }
}
