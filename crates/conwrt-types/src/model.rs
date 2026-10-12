//! Species-level device model types, parsed from `models/*.json`
//! (shared asset with conwrt 1.x — ADR-0001/0009).
//!
//! Unknown fields are ignored on purpose: the JSON Schema keeps
//! `additionalProperties: true` during migration and the de-facto field set
//! is being tightened incrementally (issue #118). Parsing must never reject
//! a model file that the 1.x Python validator accepts.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A device model definition (`models/{id}.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceModel {
    /// conwrt slug; must match the `models/{id}.json` filename.
    pub id: String,
    /// Vendor / manufacturer display name.
    pub vendor: String,
    /// Human-readable model description.
    pub description: String,
    /// OpenWrt build/flash coordinates.
    pub openwrt: OpenwrtInfo,
    /// Hardware capability tags (validated against the schema enum).
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
    /// Available flash methods, keyed by method name (e.g. `sysupgrade`,
    /// `recovery-http`). At least one is required by the schema.
    pub flash_methods: Option<BTreeMap<String, FlashMethod>>,
    /// Known OUI prefixes for this model (species-level; never unit MACs).
    #[serde(default)]
    pub mac_oui: Vec<String>,
}

/// OpenWrt target coordinates for a model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenwrtInfo {
    /// OpenWrt target, `target/subtarget` (e.g. `ath79/generic`).
    pub target: String,
    /// OpenWrt DEVICE/DTS name (e.g. `glinet,gl-ar150`).
    pub device: String,
    /// ImageBuilder / ASU profile (e.g. `glinet_gl-ar150`).
    pub profile: String,
    /// OpenWrt version or branch track (e.g. `24`, `25.12.5`).
    pub version: String,
    /// Optional `/tmp/sysinfo/board_name` for auto-detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board_name: Option<String>,
    /// Default LAN IP after flashing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_ip: Option<String>,
}

/// One flash method entry.
///
/// Common parameters from the model schema are typed; method-specific extras
/// are intentionally ignored here until the schema tightening (#118) gives
/// them a home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashMethod {
    /// What this method does (required by the schema).
    pub description: String,
    /// Recovery-mode IP of the device (e.g. U-Boot recovery server).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_ip: Option<String>,
    /// Client IP to configure on the host side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// HTTP upload endpoint for web-upload recovery methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_endpoint: Option<String>,
    /// Expected flash duration in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flash_time_seconds: Option<u32>,
    /// Silence timeout before declaring the flash stalled, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub silence_timeout: Option<u32>,
}

impl DeviceModel {
    /// Capability tags (empty when the model declares none).
    #[must_use]
    pub fn capability_tags(&self) -> &[String] {
        self.capabilities.as_deref().unwrap_or(&[])
    }

    /// Parsed OUI prefixes plus any malformed entries (reported, not fatal).
    pub fn parsed_mac_ouis(&self) -> (Vec<crate::mac::OuiPrefix>, Vec<String>) {
        crate::mac::OuiPrefix::parse_all(self.mac_oui.iter().map(String::as_str))
    }

    /// Flash method names, sorted (BTreeMap iteration order).
    pub fn flash_method_names(&self) -> impl Iterator<Item = &String> {
        self.flash_methods
            .as_ref()
            .map(BTreeMap::keys)
            .into_iter()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid model, structurally modeled on `glinet-gl-ar150.json`.
    const MINIMAL: &str = r#"{
        "id": "glinet-gl-ar150",
        "vendor": "GL.iNet",
        "description": "AR150 Mini Router (all variants)",
        "openwrt": {
            "target": "ath79/generic",
            "device": "glinet,gl-ar150",
            "profile": "glinet_gl-ar150",
            "version": "24",
            "default_ip": "192.168.8.1"
        },
        "mac_oui": ["94:83:C4"],
        "flash_methods": {
            "sysupgrade": {
                "description": "SSH sysupgrade from existing OpenWrt",
                "command": "sysupgrade -n /tmp/firmware.bin",
                "exit_code": 246
            }
        },
        "capabilities": ["ethernet", "wifi", "usb"]
    }"#;

    fn parse(s: &str) -> DeviceModel {
        serde_json::from_str(s).expect("fixture should parse")
    }

    #[test]
    fn parses_minimal_model() {
        let m = parse(MINIMAL);
        assert_eq!(m.id, "glinet-gl-ar150");
        assert_eq!(m.openwrt.target, "ath79/generic");
        assert_eq!(m.capability_tags(), ["ethernet", "wifi", "usb"]);
        let methods: Vec<_> = m.flash_method_names().cloned().collect();
        assert_eq!(methods, ["sysupgrade"]);
        // `command`/`exit_code` extras are ignored, not rejected.
        let sys = &m.flash_methods.as_ref().unwrap()["sysupgrade"];
        assert_eq!(sys.description, "SSH sysupgrade from existing OpenWrt");
        assert!(sys.recovery_ip.is_none());
    }

    #[test]
    fn missing_optional_collections_default() {
        let m = parse(
            r#"{"id":"x","vendor":"v","description":"d",
                "openwrt":{"target":"t/t","device":"d","profile":"p","version":"1"},
                "flash_methods":{"m":{"description":"x"}}}"#,
        );
        assert!(m.capabilities.is_none());
        assert!(m.mac_oui.is_empty());
    }

    #[test]
    fn missing_required_field_fails_to_parse() {
        let bad = r#"{"id":"x","vendor":"v","description":"d",
            "flash_methods":{"m":{"description":"x"}}}"#;
        assert!(serde_json::from_str::<DeviceModel>(bad).is_err());
    }

    #[test]
    fn serializes_round_trip() {
        let m = parse(MINIMAL);
        let s = serde_json::to_string(&m).unwrap();
        let m2: DeviceModel = serde_json::from_str(&s).unwrap();
        assert_eq!(m, m2);
    }
}
