//! Ring-3 lifecycle e2e (real hardware): ONE package-bearing profile —
//! wireguard-client — through the full apply → verify → revert cycle
//! with the 2.x executor, including the #427 staged-baseline revert
//! preamble (deliberate debris is staged before the apply and must be
//! gone after it, never merged into a commit).
//!
//! Gated by env (all required, else skip):
//! - `CONWRT_HW_TARGET`     — `ip:port` of the router
//! - `CONWRT_HW_KEY`        — SSH key path
//! - `CONWRT_HW_EXPECT_MAC` — specimen gate: br-lan MAC that must match
//!
//! Same env pins as `hw_travelmate.rs` — runnable unattended against
//! any specimen:
//! ```text
//! CONWRT_HW_TARGET=<ip:22> CONWRT_HW_KEY=<key> \
//! CONWRT_HW_EXPECT_MAC=<br-lan mac> \
//! cargo test -p conwrt-local-std --test hw_lifecycle -- --nocapture
//! ```
//!
//! Scope (honest): this asserts the APPLY LIFECYCLE — script exit 0,
//! the plan's own verification checks, packages present via the
//! apk-aware EnsurePackage ops, uci readbacks, the #427 debris revert,
//! and a verified config teardown (sections gone). Package REMOVAL is
//! not part of the automated revert: an apk del/reinstall round-trip
//! on a NAT-fed bench blows the <2 min budget nondeterministically, so
//! it is exercised in the lane's manual teardown evidence instead (PR
//! body). The test does NOT assert a WireGuard handshake or a
//! netifd-up wg0: on an internet-less bench the endpoint host-route
//! dependency is unresolvable and netifd tears wg0 down (2026-10-22
//! x1860-1 finding: `proto_add_host_dependency` fails when the
//! endpoint subnet lives only in runtime state; a real handshake
//! against a temporary host listener was proven separately in PR
//! evidence with `nohostroute=1`). Prerequisite: device either has
//! internet (apk feeds) or the three packages preinstalled — the
//! EnsurePackage ops are honest no-ops for installed packages.

use conwrt_core::confirm;
use conwrt_core::plan::Profile::WireguardClient;
use conwrt_core::plan::{WireguardClientProfile, plan_profile};
use conwrt_core::ssh::{MemoryTrustStore, TrustMode};
use conwrt_core::state::DeviceState;
use conwrt_local_std::execute::apply_plan;
use conwrt_local_std::fingerprint::fingerprint;
use conwrt_local_std::ssh::{SshAuth, SshOptions, SshTarget, connect};

const WG_PACKAGES: &[&str] = &["kmod-wireguard", "wireguard-tools", "luci-proto-wireguard"];

fn hw_enabled() -> Option<(String, String, String)> {
    let target = std::env::var("CONWRT_HW_TARGET").ok()?;
    let key = std::env::var("CONWRT_HW_KEY").ok()?;
    let mac = std::env::var("CONWRT_HW_EXPECT_MAC").ok()?;
    Some((target, key, mac))
}

#[tokio::test]
async fn wireguard_client_apply_verify_revert_lifecycle_on_real_hardware() {
    let Some((target, key, expect_mac)) = hw_enabled() else {
        eprintln!("skipping: CONWRT_HW_TARGET/KEY/EXPECT_MAC not set");
        return;
    };

    let mut store = MemoryTrustStore::new();
    let session = connect(
        &SshTarget {
            addr: target.clone(),
            user: "root".into(),
            auth: SshAuth::KeyFile {
                path: key.clone().into(),
                passphrase: None,
            },
        },
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("connect to router");

    let report = fingerprint(&session).await.expect("fingerprint");
    assert_eq!(
        confirm(DeviceState::SshOnly, report.release.as_ref()),
        DeviceState::OpenWrt
    );
    let mac = session
        .exec("ip link show br-lan | grep ether | awk '{print $2}' | tr 'A-F' 'a-f'")
        .await
        .expect("mac readback");
    let mac = String::from_utf8_lossy(&mac.stdout).trim().to_string();
    assert_eq!(
        mac,
        expect_mac.to_lowercase(),
        "SPECIMEN GATE: br-lan MAC mismatch"
    );

    // Config-preservation gate (Codex review P1): the teardown deletes
    // the plan-owned sections unconditionally — refuse to run on a
    // device that already carries wireguard config this test did not
    // create. Use a clean specimen (or remove the sections yourself).
    let preexisting = session
        .exec("uci -q get network.wg0.proto >/dev/null 2>&1 && echo present; uci -q get firewall.wg_client_vpn.name >/dev/null 2>&1 && echo present")
        .await
        .expect("preexisting-config readback");
    let preexisting = String::from_utf8_lossy(&preexisting.stdout).into_owned();
    assert!(
        !preexisting.contains("present"),
        "REFUSING: wg0 / wg_client_* sections already configured on the specimen — \
         this lifecycle test would overwrite and then delete them"
    );

    let model = conwrt_types::DeviceModel {
        id: format!("hw-{}", report.board_name.clone().unwrap_or_default()),
        vendor: "D-Link".into(),
        description: "lifecycle specimen".into(),
        openwrt: conwrt_types::OpenwrtInfo {
            target: "ramips/mt7621".into(),
            device: report.board_name.clone().unwrap_or_default(),
            profile: "dlink_covr_x1860_a1".into(),
            version: report
                .release
                .as_ref()
                .and_then(|r| r.release.clone())
                .unwrap_or_default(),
            board_name: report.board_name.clone(),
            board_names: None,
            default_ip: None,
            extras: Default::default(),
        },
        capabilities: Some(vec!["ethernet".into(), "wifi".into()]),
        flash_methods: None,
        mac_oui: Vec::new(),
        serial_console: None,
        warnings: None,
        extras: Default::default(),
    };

    // Endpoint is plan data only (the lifecycle never connects); the
    // default is RFC 5737 TEST-NET-1 — bench listeners come via env.
    let endpoint_host =
        std::env::var("CONWRT_HW_WG_ENDPOINT").unwrap_or_else(|_| "192.0.2.1".into());
    let profile = WireguardClient(WireguardClientProfile {
        peer_public_key: "dGhpcyBpcyBhIGJlbmNoIGxpc3RlbmVyIHB1YmxpYyBrZXk=".into(),
        endpoint_host: endpoint_host.clone(),
        endpoint_port: 51820,
        address: "10.203.0.2/32".into(),
        allowed_ips: "10.203.0.0/24".into(),
        ..WireguardClientProfile::default()
    });
    let plan =
        plan_profile(&DeviceState::OpenWrt, &model, &profile).expect("plan for confirmed hardware");

    // Deterministic budget: preinstall missing packages OUTSIDE the
    // measured lifecycle (a cold apk fetch over a NAT-fed bench is the
    // one nondeterministic step); with them installed the apply's
    // EnsurePackage ops are genuine no-op checks and the whole cycle
    // stays under the 2-minute budget.
    session
        .exec(&format!(
            "apk add {} 2>&1 | tail -1; true",
            WG_PACKAGES.join(" ")
        ))
        .await
        .expect("package preinstall");

    // #427 hardware proof: stage debris an aborted session would leave
    // in /tmp/.uci, in configs this plan commits.
    session
        .exec("uci set firewall.hw_lifecycle_debris=rule; uci set network.hw_lifecycle_debris=interface")
        .await
        .expect("stage debris");

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 on hardware (apk needs feeds or preinstalled packages):\n{}",
        outcome.stderr
    );
    assert!(
        outcome.fully_verified(),
        "verification failed: {:?}",
        outcome.verification
    );

    // Packages really present (apk-aware EnsurePackage semantics).
    let pkgs = session
        .exec(&format!(
            "apk list --installed 2>/dev/null | grep -cE '^({})'",
            WG_PACKAGES.join("|")
        ))
        .await
        .expect("package readback");
    assert_eq!(
        String::from_utf8_lossy(&pkgs.stdout).trim(),
        WG_PACKAGES.len().to_string(),
        "all three packages must be installed"
    );

    // uci readbacks (value-level, AGENTS.md).
    for (query, want) in [
        ("network.wg0.proto", "wireguard"),
        ("network.wg0_peer.endpoint_host", endpoint_host.as_str()),
        (
            "network.wg0_peer.public_key",
            "dGhpcyBpcyBhIGJlbmNoIGxpc3RlbmVyIHB1YmxpYyBrZXk=",
        ),
    ] {
        let got = session
            .exec(&format!("uci -q get {query}"))
            .await
            .expect("uci readback");
        assert_eq!(
            String::from_utf8_lossy(&got.stdout).trim(),
            want,
            "readback {query}"
        );
    }

    // #427: the debris must be gone — reverted by the preamble, never
    // merged into a commit, and no staging residue left.
    let debris = session
        .exec("uci changes | wc -l; uci show firewall.hw_lifecycle_debris 2>/dev/null | wc -l; uci show network.hw_lifecycle_debris 2>/dev/null | wc -l; grep -c hw_lifecycle_debris /etc/config/firewall /etc/config/network")
        .await
        .expect("debris readback");
    let debris_out = String::from_utf8_lossy(&debris.stdout).into_owned();
    let lines: Vec<&str> = debris_out.lines().map(str::trim).collect();
    assert_eq!(lines[0], "0", "no staged changes may survive the apply");
    assert_eq!(lines[1], "0", "firewall debris must not exist");
    assert_eq!(lines[2], "0", "network debris must not exist");
    assert!(
        lines[3..].iter().all(|l| l.ends_with(":0")),
        "committed files must be debris-free: {lines:?}"
    );

    // Revert (teardown): the uci sections this plan owns, firewall
    // reloaded. Idempotent — safe on a clean device. Package removal is
    // exercised in the lane's manual teardown (see module docs).
    let revert = session
        .exec(
            "uci -q delete network.wg0; uci -q delete network.wg0_peer; \
               uci -q delete firewall.wg_client_vpn; uci -q delete firewall.wg_client_fwd; \
               uci -q delete firewall.wg_client_killswitch; \
               uci commit network; uci commit firewall; \
               /etc/init.d/firewall restart; true",
        )
        .await
        .expect("revert");
    assert_eq!(revert.exit_code, Some(0), "revert script must succeed");

    // Verified teardown: plan-owned sections gone, no staging residue.
    let clean = session
        .exec(
            "uci -q get network.wg0.proto >/dev/null 2>&1 && echo left || echo clean; \
               uci -q get firewall.wg_client_vpn.name >/dev/null 2>&1 && echo left || echo clean; \
               uci changes | wc -l",
        )
        .await
        .expect("teardown verify");
    let clean_out = String::from_utf8_lossy(&clean.stdout).into_owned();
    let clean_lines: Vec<&str> = clean_out.lines().map(str::trim).collect();
    assert_eq!(clean_lines[0], "clean", "wg0 survived teardown");
    assert_eq!(clean_lines[1], "clean", "vpn zone survived teardown");
    assert_eq!(clean_lines[2], "0", "teardown left staged changes behind");
}
