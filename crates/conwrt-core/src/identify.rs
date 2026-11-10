//! MAC → model identification over species-level model data
//! (mirrors `scripts/model_match.py` OUI matching).

use alloc::string::String;
use alloc::vec::Vec;
use conwrt_types::{DeviceModel, MacAddress, OuiPrefix};

/// How a model was matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// MAC OUI prefix appears in the model's `mac_oui` list.
    OuiPrefix,
}

impl MatchKind {
    /// Machine-friendly name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            MatchKind::OuiPrefix => "oui-prefix",
        }
    }
}

/// One identification candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelMatch {
    /// The matched model id (`models/{id}.json`).
    pub model_id: String,
    /// Vendor display name.
    pub vendor: String,
    /// Which evidence produced the match.
    pub kind: MatchKind,
    /// The OUI prefix that matched.
    pub oui: OuiPrefix,
}

/// Identify model candidates for a MAC address against a registry slice.
///
/// Returns matches sorted by model id (deterministic order). OUIs are
/// species-level (a vendor may make many models), so a match is a
/// *candidate*, never a confirmation — board fingerprinting (M2 SSH
/// identify) is the confirming layer.
pub fn identify_by_mac(models: &[DeviceModel], mac: Option<&MacAddress>) -> Vec<ModelMatch> {
    let Some(mac) = mac else {
        return Vec::new();
    };
    identify_by_mac_ref(models, mac)
}

/// Same as [`identify_by_mac`], taking `Option<&MacAddress>` directly
/// (used by the diagnose workflow, which owns an optional MAC).
#[must_use]
pub fn identify_by_mac_ref(models: &[DeviceModel], mac: &MacAddress) -> Vec<ModelMatch> {
    let mut matches = Vec::new();
    for model in models {
        let (ouis, _bad) = model.parsed_mac_ouis(); // malformed prefixes are a validation-layer concern
        for oui in ouis {
            if oui.matches(mac) {
                matches.push(ModelMatch {
                    model_id: model.id.clone(),
                    vendor: model.vendor.clone(),
                    kind: MatchKind::OuiPrefix,
                    oui,
                });
            }
        }
    }
    matches.sort_by(|a, b| a.model_id.cmp(&b.model_id));
    matches
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    fn model(id: &str, vendor: &str, ouis: &[&str]) -> DeviceModel {
        DeviceModel {
            id: id.into(),
            vendor: vendor.into(),
            description: "test model".into(),
            openwrt: conwrt_types::OpenwrtInfo {
                target: "ath79/generic".into(),
                device: "test,dev".into(),
                profile: "test_dev".into(),
                version: "24".into(),
                board_name: None,
                default_ip: None,
            },
            capabilities: Some(vec!["ethernet".into()]),
            flash_methods: Some(BTreeMap::from([(
                "sysupgrade".into(),
                conwrt_types::FlashMethod {
                    description: "SSH sysupgrade".into(),
                    recovery_ip: None,
                    client_ip: None,
                    upload_endpoint: None,
                    flash_time_seconds: None,
                    silence_timeout: None,
                },
            )])),
            mac_oui: ouis.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn no_mac_yields_no_matches() {
        let out = identify_by_mac(&[model("a", "A", &["94:83:C4"])], None);
        assert!(out.is_empty());
    }

    #[test]
    fn oui_match_returns_candidates_sorted() {
        let models = [
            model("zyxel-nr7101", "ZyXEL", &["5c:6a:80"]),
            model("zyxel-gs1900-8hp-a1", "ZyXEL", &["5c:6a:80", "b0:7f:11"]),
        ];
        let mac = MacAddress::parse("5C:6A:80:11:22:33").unwrap();
        let out = identify_by_mac(&models, Some(&mac));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].model_id, "zyxel-gs1900-8hp-a1");
        assert_eq!(out[1].model_id, "zyxel-nr7101");
        assert_eq!(out[0].kind.as_str(), "oui-prefix");
    }

    #[test]
    fn unknown_oui_matches_nothing() {
        let mac = MacAddress::parse("02:00:00:00:00:01").unwrap();
        let out = identify_by_mac(&[model("a", "A", &["94:83:C4"])], Some(&mac));
        assert!(out.is_empty());
    }

    #[test]
    fn malformed_oui_in_model_is_skipped() {
        let mac = MacAddress::parse("94:83:c4:00:00:01").unwrap();
        let out = identify_by_mac(&[model("a", "A", &["garbage", "94:83:C4"])], Some(&mac));
        assert_eq!(out.len(), 1);
    }
}
