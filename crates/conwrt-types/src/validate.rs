//! Validation with parity to `schemas/model.schema.json` (draft-07).
//!
//! Collects *all* problems per model (like the ajv-based `make
//! validate-models`), rather than failing on the first one, so a report can
//! fix everything in one pass. The JSON Schema is deliberately loose
//! (`additionalProperties: true` everywhere); everything it does pin down is
//! pinned down here too.

use crate::model::DeviceModel;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Capability tags allowed by the schema enum.
pub const KNOWN_CAPABILITIES: &[&str] = &[
    "ethernet",
    "wifi",
    "bluetooth",
    "usb",
    "lte",
    "cellular",
    "serial",
    "ssh",
    "tftp",
];

/// Validate a model the way `schemas/model.schema.json` does.
///
/// `filename_stem` is the `models/` filename without `.json`; when supplied,
/// the model `id` must match it (schema description: "must match
/// models/{id}.json filename").
///
/// Returns every violation found; an empty vector means valid.
#[must_use]
pub fn validate_model(model: &DeviceModel, filename_stem: Option<&str>) -> Vec<String> {
    let mut problems = Vec::new();

    // id: minLength 1 + pattern ^[a-z0-9][a-z0-9-]*[a-z0-9]$ | ^[a-z0-9]$
    if model.id.is_empty() {
        problems.push("id: must not be empty".to_string());
    } else if !valid_model_id(&model.id) {
        problems.push(format!(
            "id: {:?} must match ^[a-z0-9][a-z0-9-]*[a-z0-9]$ (lowercase slug)",
            model.id
        ));
    }
    if let Some(stem) = filename_stem {
        if stem != model.id {
            problems.push(format!(
                "id: {:?} does not match filename {:?}",
                model.id, stem
            ));
        }
    }

    if model.vendor.is_empty() {
        problems.push("vendor: must not be empty".to_string());
    }
    if model.description.is_empty() {
        problems.push("description: must not be empty".to_string());
    }

    // openwrt.target pattern: ^[a-z0-9_-]+/[a-z0-9_-]+$
    if model.openwrt.target.is_empty() {
        problems.push("openwrt.target: must not be empty".to_string());
    } else if !valid_openwrt_target(&model.openwrt.target) {
        problems.push(format!(
            "openwrt.target: {:?} must look like target/subtarget ([a-z0-9_-]+/[a-z0-9_-]+)",
            model.openwrt.target
        ));
    }
    if model.openwrt.device.is_empty() {
        problems.push("openwrt.device: must not be empty".to_string());
    }
    if model.openwrt.profile.is_empty() {
        problems.push("openwrt.profile: must not be empty".to_string());
    }
    if model.openwrt.version.is_empty() {
        problems.push("openwrt.version: must not be empty".to_string());
    }
    if model.openwrt.default_ip.as_deref() == Some("") {
        problems.push("openwrt.default_ip: must not be empty".to_string());
    }

    // capabilities: required, enum, uniqueItems
    match &model.capabilities {
        None => problems.push("capabilities: is required".to_string()),
        Some(caps) => {
            for cap in caps {
                if !KNOWN_CAPABILITIES.contains(&cap.as_str()) {
                    problems.push(format!(
                        "capabilities: {:?} is not one of the allowed values {:?}",
                        cap, KNOWN_CAPABILITIES
                    ));
                }
            }
            let mut sorted = caps.clone();
            sorted.sort();
            sorted.dedup();
            if sorted.len() != caps.len() {
                problems.push("capabilities: must be unique (uniqueItems)".to_string());
            }
        }
    }

    // flash_methods: required, minProperties 1, each has non-empty description
    match &model.flash_methods {
        None => problems.push("flash_methods: is required".to_string()),
        Some(methods) if methods.is_empty() => {
            problems.push("flash_methods: must have at least one method".to_string());
        }
        Some(methods) => {
            for (name, method) in methods {
                if method.description.is_empty() {
                    problems.push(format!(
                        "flash_methods.{name}: description must not be empty"
                    ));
                }
            }
        }
    }

    // mac_oui: warn-class (schema is loose), but malformed prefixes are a
    // real identification hazard — treat as problems.
    for oui in &model.mac_oui {
        if crate::mac::OuiPrefix::parse(oui).is_err() {
            problems.push(format!("mac_oui: {oui:?} is not a valid OUI prefix"));
        }
    }

    // serial_console: dual-typed section (#118) — the baud range the JSON
    // schema also enforces. Same numbers, both languages, parity-tested.
    if let Some(sc) = &model.serial_console {
        if !(1200..=921_600).contains(&sc.baud) {
            problems.push(format!(
                "serial_console.baud: {} outside 1200-921600 (the NR7101 lesson:                  a wrong baud in prose costs hours — here it must not parse)",
                sc.baud
            ));
        }
        if sc.console_device.is_empty() {
            problems.push("serial_console.console_device: must not be empty".to_string());
        }
    }

    // warnings: dual-typed (#118) — typed as array of strings by the parse
    // itself; nothing further to check beyond non-empty entries.
    if let Some(warnings) = &model.warnings {
        for w in warnings {
            if w.trim().is_empty() {
                problems.push("warnings: entries must not be empty".to_string());
            }
        }
    }

    problems
}

/// Schema pattern for model ids: `^[a-z0-9][a-z0-9-]*[a-z0-9]$` or a single
/// alphanumeric character.
#[must_use]
pub fn valid_model_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    match bytes.len() {
        0 => false,
        1 => bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit(),
        n => {
            let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
            let last_ok = bytes[n - 1].is_ascii_lowercase() || bytes[n - 1].is_ascii_digit();
            let middle_ok = bytes[1..n - 1]
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
            first_ok && middle_ok && last_ok
        }
    }
}

/// Schema pattern for openwrt.target: `^[a-z0-9_-]+/[a-z0-9_-]+$`.
#[must_use]
pub fn valid_openwrt_target(target: &str) -> bool {
    let Some((left, right)) = target.split_once('/') else {
        return false;
    };
    let valid_part = |p: &str| {
        !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    };
    // exactly one slash
    valid_part(left) && valid_part(right) && !right.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    fn base_model() -> DeviceModel {
        DeviceModel {
            id: "vendor-model-1".into(),
            vendor: "Vendor".into(),
            description: "A model".into(),
            openwrt: crate::model::OpenwrtInfo {
                target: "ath79/generic".into(),
                device: "vendor,model-1".into(),
                profile: "vendor_model-1".into(),
                version: "24".into(),
                board_name: None,
                board_names: None,
                default_ip: None,
                extras: Default::default(),
            },
            capabilities: Some(vec!["ethernet".into()]),
            flash_methods: Some(BTreeMap::from([(
                "sysupgrade".into(),
                crate::model::FlashMethod {
                    description: "SSH sysupgrade".into(),
                    recovery_ip: None,
                    client_ip: None,
                    upload_endpoint: None,
                    flash_time_seconds: None,
                    silence_timeout: None,
                    extras: Default::default(),
                },
            )])),
            mac_oui: vec![],
            serial_console: None,
            warnings: None,
            extras: crate::ordered_map::OrderedMap::new(),
        }
    }

    #[test]
    fn default_ip_empty_is_rejected_like_the_schema() {
        // schemas/model.schema.json enforces minLength 1 on
        // openwrt.default_ip; the Rust validator must agree (#473).
        let mut m = base_model();
        assert!(validate_model(&m, Some("vendor-model-1")).is_empty());
        m.openwrt.default_ip = Some("192.168.8.1".into());
        assert!(validate_model(&m, Some("vendor-model-1")).is_empty());
        m.openwrt.default_ip = Some(String::new());
        assert_eq!(
            validate_model(&m, Some("vendor-model-1")),
            vec!["openwrt.default_ip: must not be empty".to_string()]
        );
    }

    #[test]
    fn serial_console_baud_range_is_enforced_like_the_schema() {
        let mut m = base_model();
        m.serial_console = Some(crate::model::SerialConsole {
            baud: 115_200,
            console_device: "ttyS0".into(),
            parity: Some("n81".into()),
            bootloader: None,
            verified_from: None,
            note: None,
        });
        assert!(validate_model(&m, Some("vendor-model-1")).is_empty());

        m.serial_console.as_mut().expect("set").baud = 12;
        assert!(
            validate_model(&m, Some("vendor-model-1"))
                .iter()
                .any(|p| p.contains("serial_console.baud"))
        );

        m.serial_console.as_mut().expect("set").baud = 4_000_000;
        assert!(
            validate_model(&m, Some("vendor-model-1"))
                .iter()
                .any(|p| p.contains("serial_console.baud"))
        );

        m.serial_console.as_mut().expect("set").baud = 57_600;
        m.serial_console
            .as_mut()
            .expect("set")
            .console_device
            .clear();
        assert!(
            validate_model(&m, Some("vendor-model-1"))
                .iter()
                .any(|p| p.contains("console_device"))
        );
    }

    #[test]
    fn empty_warnings_entries_are_problems() {
        let mut m = base_model();
        m.warnings = Some(vec!["real warning".into()]);
        assert!(validate_model(&m, Some("vendor-model-1")).is_empty());
        m.warnings = Some(vec!["ok".into(), "  ".into()]);
        assert!(
            validate_model(&m, Some("vendor-model-1"))
                .iter()
                .any(|p| p.contains("warnings"))
        );
    }

    #[test]
    fn base_model_is_valid() {
        assert!(validate_model(&base_model(), Some("vendor-model-1")).is_empty());
    }

    #[test]
    fn collects_all_problems() {
        let mut m = base_model();
        m.id = "Bad_ID".into();
        m.vendor.clear();
        m.description.clear();
        m.openwrt.target = "not-a-target".into();
        m.capabilities = Some(vec![
            "ethernet".into(),
            "telepathy".into(),
            "ethernet".into(),
        ]);
        m.flash_methods = Some(BTreeMap::new());
        m.mac_oui = vec!["garbage".into()];

        let problems = validate_model(&m, None);
        assert!(problems.iter().any(|p| p.contains("id:")));
        assert!(problems.iter().any(|p| p.contains("vendor:")));
        assert!(problems.iter().any(|p| p.contains("description:")));
        assert!(problems.iter().any(|p| p.contains("openwrt.target")));
        assert!(problems.iter().any(|p| p.contains("telepathy")));
        assert!(problems.iter().any(|p| p.contains("unique")));
        assert!(problems.iter().any(|p| p.contains("at least one method")));
        assert!(problems.iter().any(|p| p.contains("mac_oui")));
        assert_eq!(
            problems.len(),
            8,
            "expected every problem reported, got: {problems:?}"
        );
    }

    #[test]
    fn missing_required_collections() {
        let mut m = base_model();
        m.capabilities = None;
        m.flash_methods = None;
        let problems = validate_model(&m, None);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("capabilities: is required"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("flash_methods: is required"))
        );
    }

    #[test]
    fn filename_mismatch_is_reported() {
        let m = base_model();
        let problems = validate_model(&m, Some("some-other-file"));
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("does not match filename"));
    }

    #[test]
    fn method_without_description() {
        let mut m = base_model();
        let mut methods = BTreeMap::new();
        methods.insert(
            "recovery-http".into(),
            crate::model::FlashMethod {
                description: String::new(),
                recovery_ip: None,
                client_ip: None,
                upload_endpoint: None,
                flash_time_seconds: None,
                silence_timeout: None,
                extras: Default::default(),
            },
        );
        m.flash_methods = Some(methods);
        let problems = validate_model(&m, None);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("recovery-http") && p.contains("description"))
        );
    }

    #[test]
    fn id_pattern_edges() {
        assert!(valid_model_id("a"));
        assert!(valid_model_id("a1"));
        assert!(valid_model_id("zyxel-nr7101"));
        assert!(!valid_model_id(""));
        assert!(!valid_model_id("A-b"));
        assert!(!valid_model_id("-ab"));
        assert!(!valid_model_id("ab-"));
        assert!(!valid_model_id("ab_c"));
    }

    #[test]
    fn target_pattern_edges() {
        assert!(valid_openwrt_target("ath79/generic"));
        assert!(valid_openwrt_target("mediatek/filogic"));
        assert!(valid_openwrt_target("x86/64"));
        assert!(!valid_openwrt_target("ath79"));
        assert!(!valid_openwrt_target("ath79/"));
        assert!(!valid_openwrt_target("ATH79/generic"));
        assert!(!valid_openwrt_target("a/b/c"));
    }
}
