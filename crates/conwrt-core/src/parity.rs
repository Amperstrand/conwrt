//! Cross-implementation parity harness (Rust side).
//!
//! The conwrt plan pipeline exists twice: the complete 1.x Python
//! implementation (`scripts/use_cases/*` → `profile.ops.render_shell`) and
//! the Rust workspace port (`plan.rs` + this crate's profiles). This
//! module is the Rust half of the parity proof: it renders the SAME JSON
//! fixtures (`tests/fixtures/parity/*.json`) through the Rust planner and
//! renderer, so the Python half (`tests/test_parity_rust_plan.py`) can
//! diff the two outputs for the same use case + params.
//!
//! The fixtures and the Python-side goldens are authoritative; the gap
//! list (`tests/fixtures/parity/manifest.json`) records which presets
//! have NOT reached parity yet and why. The list must shrink — never
//! silently change.
//!
//! Enabled for tests and via the `parity-fixture` feature (used by the
//! `conwrt-plan-render` binary in `apps/conwrt-cli`). Requires std.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::plan::{
    AdguardProfile, DohProfile, Mwan3Profile, Profile, SqmProfile, SshHardeningProfile,
    WireguardClientProfile, WireguardServerProfile, render_shell,
};
use crate::state::DeviceState;
use conwrt_types::DeviceModel;

/// Model id used for parity plans (the model only labels the plan header).
pub const PARITY_MODEL_ID: &str = "parity-fixture";

fn parity_model() -> DeviceModel {
    let json = r#"{"id":"parity-fixture","vendor":"Parity","description":"fixture",
        "openwrt":{"target":"x/y","device":"t,d","profile":"t_d","version":"24"},
        "mac_oui":[]}"#;
    serde_json::from_str(json).expect("parity fixture model parses")
}

fn get_str(params: &serde_json::Value, key: &str) -> Option<String> {
    params.get(key).and_then(|v| {
        if v.is_string() {
            v.as_str().map(String::from)
        } else if v.is_number() {
            Some(v.to_string())
        } else {
            None
        }
    })
}

fn get_u16(params: &serde_json::Value, key: &str, default: u16) -> u16 {
    params
        .get(key)
        .and_then(|v| v.as_u64())
        .map_or(default, |v| u16::try_from(v).unwrap_or(default))
}

fn get_bool(params: &serde_json::Value, key: &str, default: bool) -> bool {
    params.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

/// Map a parity fixture `{"use_case": ..., "params": {...}}` to a Profile.
///
/// Defaults mirror the Python `_resolve_params` helpers exactly so a
/// fixture may omit any param the Python side defaults too.
pub fn profile_from_fixture(fixture: &serde_json::Value) -> Result<Profile, String> {
    let use_case = fixture
        .get("use_case")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "fixture missing 'use_case'".to_string())?;
    let params = fixture
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    match use_case {
        "wireguard-client" => {
            let mut p = WireguardClientProfile::default();
            if let Some(v) = get_str(&params, "private_key") {
                p.private_key = v;
            }
            if let Some(v) = get_str(&params, "peer_public_key") {
                p.peer_public_key = v;
            }
            if let Some(v) = get_str(&params, "endpoint_host") {
                p.endpoint_host = v;
            }
            p.endpoint_port = get_u16(&params, "endpoint_port", p.endpoint_port);
            if let Some(v) = get_str(&params, "peer_psk") {
                p.peer_psk = v;
            }
            if let Some(v) = get_str(&params, "address") {
                p.address = v;
            }
            if let Some(v) = get_str(&params, "dns") {
                p.dns = v;
            }
            p.kill_switch = get_bool(&params, "kill_switch", p.kill_switch);
            if let Some(v) = get_str(&params, "allowed_ips") {
                p.allowed_ips = v;
            }
            Ok(Profile::WireguardClient(p))
        }
        "wireguard-server" => {
            let mut p = WireguardServerProfile::default();
            if let Some(v) = get_str(&params, "private_key") {
                p.private_key = v;
            }
            p.listen_port = get_u16(&params, "listen_port", p.listen_port);
            if let Some(v) = get_str(&params, "subnet") {
                p.subnet = v;
            }
            if let Some(v) = get_str(&params, "peer1_public_key") {
                p.peer1_public_key = v;
            }
            if let Some(v) = get_str(&params, "peer1_allowed_ips") {
                p.peer1_allowed_ips = v;
            }
            if let Some(v) = get_str(&params, "peer1_psk") {
                p.peer1_psk = v;
            }
            Ok(Profile::WireguardServer(p))
        }
        "sqm" => {
            let mut p = SqmProfile {
                download_kbps: 10_000,
                upload_kbps: 5_000,
                interface: "wan".into(),
                qdisc: "cake".into(),
                script: "piece_of_cake.qos".into(),
                link_layer: "none".into(),
                overhead: 0,
            };
            if let Some(v) = params.get("download_kbps").and_then(|v| v.as_u64()) {
                p.download_kbps = u32::try_from(v).map_err(|_| "download_kbps out of range")?;
            }
            if let Some(v) = params.get("upload_kbps").and_then(|v| v.as_u64()) {
                p.upload_kbps = u32::try_from(v).map_err(|_| "upload_kbps out of range")?;
            }
            if let Some(v) = get_str(&params, "interface") {
                p.interface = v;
            }
            if let Some(v) = get_str(&params, "qdisc") {
                p.qdisc = v;
            }
            if let Some(v) = get_str(&params, "script") {
                p.script = v;
            }
            if let Some(v) = get_str(&params, "link_layer") {
                p.link_layer = v;
            }
            if let Some(v) = params.get("overhead").and_then(|v| v.as_u64()) {
                p.overhead = u16::try_from(v).map_err(|_| "overhead out of range")?;
            }
            Ok(Profile::Sqm(p))
        }
        "doh" => {
            let p = DohProfile {
                provider: get_str(&params, "provider").unwrap_or_else(|| "cloudflare".into()),
                listen_port: get_u16(&params, "listen_port", 5053),
            };
            Ok(Profile::Doh(p))
        }
        "adguard" => {
            let p = AdguardProfile {
                listen_ip: get_str(&params, "listen_ip").unwrap_or_else(|| "0.0.0.0".into()),
                web_port: get_u16(&params, "web_port", 3000),
                dns_port: get_u16(&params, "dns_port", 5353),
            };
            Ok(Profile::Adguard(p))
        }
        "ssh-hardening" => {
            let p = SshHardeningProfile {
                disable_password_auth: get_bool(&params, "disable_password_auth", true),
                idle_timeout: params
                    .get("idle_timeout")
                    .and_then(|v| v.as_u64())
                    .map(|v| u32::try_from(v).map_err(|_| "idle_timeout out of range"))
                    .transpose()?
                    .unwrap_or(300),
                max_auth_tries: params
                    .get("max_auth_tries")
                    .and_then(|v| v.as_u64())
                    .map(|v| u32::try_from(v).map_err(|_| "max_auth_tries out of range"))
                    .transpose()?
                    .unwrap_or(3),
                port: get_u16(&params, "port", 22),
                restrict_gateway_ports: get_bool(&params, "restrict_gateway_ports", true),
            };
            Ok(Profile::SshHardening(p))
        }
        "mwan3" => {
            let mut p = Mwan3Profile::default();
            if let Some(v) = get_str(&params, "primary") {
                p.primary = v;
            }
            if let Some(v) = get_str(&params, "secondary") {
                p.secondary = v;
            }
            if let Some(v) = get_str(&params, "policy") {
                p.policy = v;
            }
            if let Some(list) = params.get("track_ips").and_then(|v| v.as_array()) {
                p.track_ips = list
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
            }
            Ok(Profile::Mwan3(p))
        }
        other => Err(format!("no Rust profile for use case '{other}' yet")),
    }
}

/// Render a parity fixture through the full Rust pipeline:
/// fixture → Profile → `plan_profile` → `render_shell`.
pub fn render_fixture(fixture: &serde_json::Value) -> Result<String, String> {
    let profile = profile_from_fixture(fixture)?;
    let plan = crate::plan::plan_profile(&DeviceState::OpenWrt, &parity_model(), &profile)
        .map_err(|e| e.to_string())?;
    Ok(render_shell(&plan))
}

/// Read a fixture file and render it (std convenience for the
/// `conwrt-plan-render` binary).
pub fn render_fixture_file(path: &std::path::Path) -> Result<String, String> {
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let fixture: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parsing {}: {e}", path.display()))?;
    render_fixture(&fixture)
}

/// Strip presentation-only lines shared by both renderers: shebang,
/// `set -e`, comment lines, blank lines, and the 2.x-only package-install
/// preamble (`EnsurePackage` apk/opkg blocks — a deliberate Rust-side
/// extension; 1.x Python bakes packages into the image, so its configure
/// render has no install lines; same exclusion as
/// `tests/use_case_goldens.rs`). The 2.x preamble is `set -e` where 1.x
/// runs bare, so 2.x guards best-effort command substitutions with
/// `|| true` (the #365 set-e-kills-assignments lesson) — those guards
/// are stripped here for the same reason the preamble is: they are the
/// 2.x shell-options shim, not semantic drift. What remains is the
/// pure command stream — the level at which parity is asserted on the
/// Rust side (EQUAL fixtures must match the Python golden byte-for-byte
/// after this filter).
pub fn command_lines(script: &str) -> Vec<String> {
    script
        .lines()
        .map(|l| l.trim())
        .map(|l| l.replace(" || true)", ")").replace(" || true ;", " ;"))
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with('#')
                && *l != "set -e"
                && !l.starts_with("#!")
                && !l.starts_with("opkg install ")
                && !l.starts_with("if command -v apk ")
                && !l.starts_with("&& apk add ")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/parity")
            .canonicalize()
            .expect("tests/fixtures/parity exists (run from repo checkout)")
    }

    fn manifest() -> serde_json::Value {
        let raw = std::fs::read_to_string(fixtures_dir().join("manifest.json"))
            .expect("parity manifest.json readable");
        serde_json::from_str(&raw).expect("parity manifest.json parses")
    }

    /// Every fixture whose manifest entry says EQUAL must render, through
    /// the Rust pipeline, the exact command lines of the Python-generated
    /// golden file (comments/blank lines stripped on both sides).
    #[test]
    fn equal_fixtures_match_python_goldens() {
        let manifest = manifest();
        let fixtures = manifest
            .get("fixtures")
            .and_then(|v| v.as_object())
            .expect("manifest has fixtures");
        let mut checked = 0;
        for (stem, entry) in fixtures {
            if entry.get("expect").and_then(|v| v.as_str()) != Some("EQUAL") {
                continue;
            }
            let fixture_path = fixtures_dir().join(format!("{stem}.json"));
            let rendered = render_fixture_file(&fixture_path)
                .unwrap_or_else(|e| panic!("{stem}: render failed: {e}"));
            let golden = std::fs::read_to_string(fixtures_dir().join(format!("golden/{stem}.sh")))
                .unwrap_or_else(|e| panic!("{stem}: golden missing: {e}"));
            let got = command_lines(&rendered);
            let want = command_lines(&golden);
            assert_eq!(
                want,
                got,
                "{stem}: Rust render diverged from Python golden{}",
                first_diff(&want, &got)
            );
            checked += 1;
        }
        assert!(checked > 0, "no EQUAL fixtures recorded in manifest");
    }

    /// GAP fixtures must still render (the gap is in output parity, not in
    /// plannability) and must carry at least one documented reason.
    #[test]
    fn gap_fixtures_render_and_are_documented() {
        let manifest = manifest();
        let fixtures = manifest
            .get("fixtures")
            .and_then(|v| v.as_object())
            .expect("manifest has fixtures");
        for (stem, entry) in fixtures {
            if entry.get("expect").and_then(|v| v.as_str()) != Some("GAP") {
                continue;
            }
            let reasons = entry
                .get("gap_reasons")
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("{stem}: GAP entry needs gap_reasons"));
            assert!(!reasons.is_empty(), "{stem}: gap_reasons must not be empty");
            let fixture_path = fixtures_dir().join(format!("{stem}.json"));
            assert!(
                render_fixture_file(&fixture_path).is_ok(),
                "{stem}: GAP fixture must still render through Rust"
            );
        }
    }

    fn first_diff(want: &[String], got: &[String]) -> String {
        for (i, (w, g)) in want.iter().zip(got.iter()).enumerate() {
            if w != g {
                return format!(
                    "\nfirst diff at line {}:\n  python: {w}\n  rust:   {g}",
                    i + 1
                );
            }
        }
        if want.len() != got.len() {
            return format!(
                "\nline count differs: python {} vs rust {}",
                want.len(),
                got.len()
            );
        }
        String::new()
    }

    #[test]
    fn command_lines_strips_presentation() {
        let script = "#!/bin/sh\n# comment\nset -e\n\nuci commit firewall\n";
        assert_eq!(
            command_lines(script),
            vec!["uci commit firewall".to_string()]
        );
    }
}
