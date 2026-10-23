//! Golden parity for the typed-ops use-case ports (parity-matrix §4):
//! the rendered plans must emit the SAME command-line sequence as the
//! 1.x Python builders (`scripts/use_cases/{usb_tether,wireguard_client,
//! wireguard_server,guest_wifi}.py`).
//!
//! Goldens are the verbatim stdout of the 1.x builders and live in
//! `tests/goldens/<use-case>.sh`. Regenerate with:
//!
//! ```text
//! cd scripts && python3 - <<'EOF'
//! import sys; sys.path.insert(0, ".")
//! from use_cases import registry
//! r = registry()
//! print(r["tether"].build_configure({}))
//! print(r["tether-android"].build_configure({}))
//! print(r["tether-android-adb"].build_configure({}))
//! print(r["tether-ios"].build_configure({}))
//! print(r["wireguard-client"].build_configure({
//!     "peer_public_key": "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ=",
//!     "endpoint_host": "vpn.example.com",
//!     "endpoint_port": 51820,
//!     "peer_psk": "cHNrLTMyLWJ5dGVzLXRlc3QtdmFsdWU=",
//!     "address": "10.67.0.2/32",
//!     "dns": "1.1.1.1",
//!     "kill_switch": True,
//!     "allowed_ips": "0.0.0.0/0, ::/0",
//! }))
//! print(r["wireguard-server"].build_configure({
//!     "private_key": "generate",
//!     "listen_port": 51820,
//!     "subnet": "10.1.99.1/24",
//!     "peer1_public_key": "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ=",
//!     "peer1_allowed_ips": "10.1.99.2/32",
//!     "peer1_psk": "cHNrLTMyLWJ5dGVzLXRlc3QtdmFsdWU=",
//! }))
//! print(r["ssh-hardening"].build_configure({}))
//! print(r["travelmate"].build_configure({}))
//! print(r["adguard"].build_configure({}))
//! print(r["mesh11sd"].build_configure({"mesh_id": "testmesh"}))
//! print(r["rescue-watchdog"].build_configure({"target": "192.168.105.10"}))
//! print(r["mwan3"].build_configure({}))
//! print(r["pbr"].build_configure({}))
//! print(r["nodns"].build_configure({}))
//! print(r["auto-sqm"].build_configure({}))
//! print(r["guest-wifi"].build_configure({}))
//! EOF
//! ```
//!
//! Comparison is over the **command-line sequence**: comments, blank
//! lines, the 2.x script header (`#!/bin/sh`, `set -e`), and the
//! 2.x-only `EnsurePackage` opkg/apk install lines are filtered from
//! the Rust render (1.x delivers packages via the ASU image build, not
//! the configure script). Every remaining line — order, quoting, and
//! bytes — must match exactly.

use conwrt_core::plan::{
    AdguardProfile, AutoSqmProfile, DohProfile, GuestWifiProfile, Mesh11sdProfile, Mwan3Profile,
    NodnsProfile, PbrProfile, Profile, RescueWatchdogProfile, SqmProfile, SshHardeningProfile,
    TetherProfile, TetherVariant, TravelmateProfile, WireguardClientProfile,
    WireguardServerProfile, plan_profile, render_shell,
};
use conwrt_core::state::DeviceState;
use conwrt_types::DeviceModel;

fn model_with_capabilities(caps: Option<Vec<String>>) -> DeviceModel {
    let caps_json = caps.map(|c| {
        let list: Vec<String> = c.iter().map(|c| format!("\"{c}\"")).collect();
        format!(", \"capabilities\": [{}]", list.join(", "))
    });
    let json = format!(
        "{{\"id\":\"test-model\",\"vendor\":\"Test\",\"description\":\"d\",\
          \"openwrt\":{{\"target\":\"x/y\",\"device\":\"t,d\",\"profile\":\"t_d\",\"version\":\"24\"}},\
          \"mac_oui\":[]{}}}",
        caps_json.unwrap_or_default()
    );
    serde_json::from_str(&json).expect("fixture model parses")
}

/// Command lines only: drop comments, blanks, the 2.x-only script
/// preamble and package-install lines (see module docs).
///
/// #421's apk-aware `EnsurePackage` render emits a two-line install block
/// per package (`if command -v apk … || { apk update \` +
/// `&& apk add …; }; else … opkg install …; }; fi`) — same semantic
/// exclusion as the legacy single `opkg install ` line.
///
/// mwan3 track-ip wiring is dropped from BOTH sides: 1.x renders it as
/// bare `list track_ip '<ip>'` lines — broken shell that no-`set -e`
/// 1.x silently ignored — while 2.x renders the intended
/// `uci add_list mwan3.<sec>.track_ip` ops. A documented 1.x defect the
/// port fixes; the corrected lines are pinned by unit test instead of
/// golden parity.
fn command_lines(script: &str) -> Vec<String> {
    script
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter(|l| l.trim() != "set -e")
        .filter(|l| !l.starts_with("opkg install "))
        .filter(|l| !l.starts_with("if command -v apk "))
        .filter(|l| !l.starts_with("&& apk add "))
        .filter(|l| !l.starts_with("list track_ip "))
        .filter(|l| !(l.starts_with("uci add_list mwan3.") && l.contains(".track_ip=")))
        // auto-sqm dynamic cron: 2.x makes re-apply idempotent by
        // dropping prior entries first (1.x plain-appends and
        // accumulates duplicates); both line forms are excluded from
        // golden comparison, the corrected form is unit-pinned
        .filter(|l| !(l.starts_with("sed -i '/auto-sqm/d'") && l.contains("crontabs")))
        .filter(|l| !(l.starts_with("echo '0 */") && l.contains("/usr/sbin/auto-sqm'")))
        .map(|l| l.to_string())
        .collect()
}

fn assert_plan_matches_golden(profile: Profile, golden: &str) {
    let model = model_with_capabilities(profile.requires().first().map(|cap| vec![(*cap).into()]));
    let plan = plan_profile(&DeviceState::OpenWrt, &model, &profile)
        .unwrap_or_else(|e| panic!("plan must build: {e}"));
    let rendered = render_shell(&plan);
    let want = command_lines(golden);
    let got = command_lines(&rendered);
    assert_eq!(
        want, got,
        "rendered command lines must equal the 1.x golden byte-for-byte"
    );
}

#[test]
fn tether_auto_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::Tether(TetherProfile::default()),
        include_str!("goldens/tether.sh"),
    );
}

#[test]
fn tether_android_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::Tether(TetherProfile {
            variant: TetherVariant::Android,
            ..TetherProfile::default()
        }),
        include_str!("goldens/tether-android.sh"),
    );
}

#[test]
fn tether_android_adb_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::Tether(TetherProfile {
            variant: TetherVariant::AndroidAdb,
            ..TetherProfile::default()
        }),
        include_str!("goldens/tether-android-adb.sh"),
    );
}

#[test]
fn tether_ios_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::Tether(TetherProfile {
            variant: TetherVariant::Ios,
            ..TetherProfile::default()
        }),
        include_str!("goldens/tether-ios.sh"),
    );
}

#[test]
fn wireguard_client_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::WireguardClient(WireguardClientProfile {
            peer_public_key: "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ=".into(),
            endpoint_host: "vpn.example.com".into(),
            endpoint_port: 51820,
            peer_psk: "cHNrLTMyLWJ5dGVzLXRlc3QtdmFsdWU=".into(),
            address: "10.67.0.2/32".into(),
            dns: "1.1.1.1".into(),
            kill_switch: true,
            ..WireguardClientProfile::default()
        }),
        include_str!("goldens/wireguard-client.sh"),
    );
}

#[test]
fn wireguard_server_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::WireguardServer(WireguardServerProfile {
            peer1_public_key: "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ=".into(),
            peer1_psk: "cHNrLTMyLWJ5dGVzLXRlc3QtdmFsdWU=".into(),
            ..WireguardServerProfile::default()
        }),
        include_str!("goldens/wireguard-server.sh"),
    );
}

#[test]
fn ssh_hardening_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::SshHardening(SshHardeningProfile::default()),
        include_str!("goldens/ssh-hardening.sh"),
    );
}

#[test]
fn travelmate_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::Travelmate(TravelmateProfile::default()),
        include_str!("goldens/travelmate.sh"),
    );
}

#[test]
fn adguard_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::Adguard(AdguardProfile::default()),
        include_str!("goldens/adguard.sh"),
    );
}

#[test]
fn mesh11sd_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::Mesh11sd(Mesh11sdProfile {
            mesh_id: "testmesh".into(),
            ..Mesh11sdProfile::default()
        }),
        include_str!("goldens/mesh11sd.sh"),
    );
}

#[test]
fn rescue_watchdog_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::RescueWatchdog(RescueWatchdogProfile {
            target: "192.168.105.10".into(),
        }),
        include_str!("goldens/rescue-watchdog.sh"),
    );
}

#[test]
fn mwan3_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::Mwan3(Mwan3Profile::default()),
        include_str!("goldens/mwan3.sh"),
    );
}

#[test]
fn pbr_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::Pbr(PbrProfile::default()),
        include_str!("goldens/pbr.sh"),
    );
}

#[test]
fn nodns_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::Nodns(NodnsProfile::default()),
        include_str!("goldens/nodns.sh"),
    );
}

#[test]
fn auto_sqm_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::AutoSqm(AutoSqmProfile::default()),
        include_str!("goldens/auto-sqm.sh"),
    );
}

#[test]
fn guest_wifi_matches_1x_golden() {
    assert_plan_matches_golden(
        Profile::GuestWifi(GuestWifiProfile::default()),
        include_str!("goldens/guest-wifi.sh"),
    );
}

/// The comparator itself must be honest: sqm (a profile whose 1.x twin
/// re-expresses two shell idioms in set -e-safe typed form) is expected
/// NOT to be byte-parity — pin that this file only asserts golden parity
/// for the three ports above by proving the filter does not silently
/// swallow real drift (an empty-vs-nonempty sanity check).
#[test]
fn golden_files_are_command_scripts_not_empty() {
    for (name, golden) in [
        ("tether", include_str!("goldens/tether.sh")),
        (
            "wireguard-server",
            include_str!("goldens/wireguard-server.sh"),
        ),
        ("guest-wifi", include_str!("goldens/guest-wifi.sh")),
    ] {
        assert!(
            command_lines(golden).len() > 10,
            "{name}: golden must contain real commands"
        );
    }
}

// The existing sqm/doh profiles keep their own unit tests in plan.rs.
// sqm now reaches 1.x parity (tests/fixtures/parity/manifest.json: EQUAL);
// these assertions pin the invariants that must survive either way.
#[test]
fn sqm_and_doh_renders_unchanged_shape() {
    let model = model_with_capabilities(None);
    let sqm = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Sqm(SqmProfile {
            download_kbps: 10_000,
            upload_kbps: 5_000,
            interface: "wan".into(),
            qdisc: "cake".into(),
            script: "piece_of_cake.qos".into(),
            link_layer: "none".into(),
            overhead: 0,
        }),
    )
    .expect("plans");
    let script = render_shell(&sqm);
    assert!(script.contains("uci set sqm.wan=queue"));
    assert!(script.contains("uci set sqm.wan.download='10000'"));
    assert!(script.contains("/etc/init.d/sqm restart"));

    let doh = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Doh(DohProfile {
            provider: "cloudflare".into(),
            listen_port: 5053,
        }),
    )
    .expect("plans");
    let script = render_shell(&doh);
    assert!(script.contains(
        "uci set https-dns-proxy.main.resolver_url='https://cloudflare-dns.com/dns-query'"
    ));
}
