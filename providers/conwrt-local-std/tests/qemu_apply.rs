//! Ring-2 (QEMU OpenWrt VM, ADR-0011): apply desired-state plans to a
//! **real OpenWrt userspace** end-to-end — fingerprint-confirmed
//! identity, plan, apply over SSH, read-only verification. Gated by
//! `CONWRT_QEMU_VM=1` plus a reachable VM. The VM's forwarded SSH port
//! comes from `CONWRT_VM_SESSION_PORT` (default 2222) so sibling lanes
//! can run isolated VMs on this shared host (AGENTS.md multi-agent
//! rules); boot via the integration fixture with the same env var.
//! Mutations are confined to the throwaway VM overlay.
//!
//! Coverage: `sqm` (prebaked packages), `wireguard-client` (packages
//! prebaked in the fixture image — full plan applies, kill-switch verify
//! loop runs its real 30 s failure tail), `tether` (shell surface
//! only: the USB kmods are NOT prebakeable into the fixture image and
//! the VM has no USB device, so `EnsurePackage` ops are stripped and the
//! hardware-gated parts — USB detection actually finding a device,
//! `network.usbwan` coming up — are marked and not asserted; what IS
//! asserted is the script applying cleanly and the ADB hotplug hook
//! installing, the parts a VM can prove), `openclash` + `ssl` (§4
//! ports of PR #486: config surface only — package delivery is stripped
//! like tether's (luci-app-openclash is third-party, not prebakeable;
//! the ssl TLS-backend guard is package-manager territory), a stub
//! rc.common service + the package's default uci section stand in for
//! the package, and ssl is proven in BOTH the cert-less negative
//! (skips loudly, verification fails by name) and the cert-present
//! positive (host-minted self-signed certs, full verify)), and
//! `nodns` + `pbr` (§4 ring-2 leg: nodns carries zero fixture-foreign
//! dependencies so the FULL plan — initd + poll-script heredocs,
//! dnsmasq addn-hosts wiring, service enable — applies verbatim; pbr
//! follows the openclash strip+stub pattern for its non-prebaked
//! packages, with the unquoted interface lines applied and read back).

use conwrt_core::plan::{
    NodnsProfile, OpenClashProfile, PbrProfile, PlanOp, Profile, SqmProfile, SslProfile,
    TetherProfile, VpnNordvpnProfile, VpnPiaOpenvpnProfile, WireguardClientProfile,
    WireguardServerProfile, plan_profile,
};
use conwrt_core::ssh::{MemoryTrustStore, TrustMode};
use conwrt_core::state::DeviceState;
use conwrt_core::{confirm, render_shell};
use conwrt_local_std::execute::apply_plan;
use conwrt_local_std::fingerprint::fingerprint;
use conwrt_local_std::ssh::{SshAuth, SshOptions, SshTarget, connect};
use core::net::{IpAddr, SocketAddr};
use std::net::TcpStream;
use std::path::Path;
use tokio::sync::{Mutex, MutexGuard};

/// All tests in this file share ONE VM; concurrent `apk add` invocations
/// race on the apk database lock and fail spuriously. Applying plans to
/// the shared VM is serialized regardless of harness flags.
static VM_MUTEX: Mutex<()> = Mutex::const_new(());

async fn vm_lock() -> MutexGuard<'static, ()> {
    VM_MUTEX.lock().await
}

fn vm_port() -> u16 {
    std::env::var("CONWRT_VM_SESSION_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(2222)
}

fn vm_available() -> bool {
    if std::env::var("CONWRT_QEMU_VM").ok().as_deref() != Some("1") {
        return false;
    }
    TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::from([127, 0, 0, 1]), vm_port()),
        std::time::Duration::from_secs(2),
    )
    .is_ok()
}

fn vm_key() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/integration/.vm_ssh_key")
}

fn vm_target() -> SshTarget {
    SshTarget {
        addr: format!("127.0.0.1:{}", vm_port()),
        user: "root".into(),
        auth: SshAuth::KeyFile {
            path: vm_key(),
            passphrase: None,
        },
    }
}

async fn connected_openwrt_session()
-> (conwrt_local_std::ssh::SshSession, conwrt_types::DeviceModel) {
    let mut store = MemoryTrustStore::new();
    let session = connect(
        &vm_target(),
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("connect to VM");

    let report = fingerprint(&session).await.expect("fingerprint");
    let state = confirm(DeviceState::SshOnly, report.release.as_ref());
    assert_eq!(state, DeviceState::OpenWrt, "VM must be confirmed OpenWrt");
    let release = report.release.as_ref().unwrap();

    let model = conwrt_types::DeviceModel {
        id: format!("qemu-vm-{}", release.release.as_deref().unwrap_or("?")),
        vendor: "QEMU".into(),
        description: "integration VM".into(),
        openwrt: conwrt_types::OpenwrtInfo {
            target: release.target.clone().unwrap_or_default(),
            device: report.board_name.clone().unwrap_or_default(),
            profile: "generic".into(),
            version: release.release.clone().unwrap_or_default(),
            board_name: report.board_name.clone(),
            board_names: None,
            default_ip: None,
            extras: Default::default(),
        },
        capabilities: Some(vec!["ethernet".into(), "usb".into()]),
        flash_methods: None,
        mac_oui: Vec::new(),
        serial_console: None,
        warnings: None,
        extras: Default::default(),
    };
    (session, model)
}

#[tokio::test]
async fn sqm_plan_applies_and_verifies_on_real_openwrt() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let _vm = vm_lock().await;

    let (session, model) = connected_openwrt_session().await;

    let profile = Profile::Sqm(SqmProfile {
        download_kbps: 10_000,
        upload_kbps: 5_000,
        interface: "wan".into(),
        ..sqm_defaults()
    });
    let plan =
        plan_profile(&DeviceState::OpenWrt, &model, &profile).expect("plan for confirmed VM");
    let script = render_shell(&plan);

    // hardware-safe dry-run evidence: the script must be exactly what the
    // ring-1 tests pinned (op order + quoting), against a real userspace
    assert!(script.contains("apk add 'sqm-scripts'"));

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 on the VM; stderr:\n{}\nscript:\n{}",
        outcome.stderr, outcome.script
    );
    assert!(
        outcome.fully_verified(),
        "verification failed: {:?}",
        outcome.verification
    );

    // rollback so repeated runs stay clean
    let _ = session
        .exec("for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; uci commit sqm; /etc/init.d/sqm stop 2>/dev/null; true")
        .await;
}

#[tokio::test]
async fn wireguard_client_plan_applies_and_verifies_on_real_openwrt() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let _vm = vm_lock().await;

    let (session, model) = connected_openwrt_session().await;

    // Same parameter set the 1.x VM suite uses
    // (tests/integration/test_use_cases_runtime.py).
    let profile = Profile::WireguardClient(WireguardClientProfile {
        peer_public_key: "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ=".into(),
        endpoint_host: "vpn.example.com".into(),
        endpoint_port: 51820,
        address: "10.0.0.2/32".into(),
        allowed_ips: "10.0.0.0/24".into(),
        ..WireguardClientProfile::default()
    });
    let plan =
        plan_profile(&DeviceState::OpenWrt, &model, &profile).expect("plan for confirmed VM");

    // Full plan INCLUDING EnsurePackage: wireguard-tools and
    // luci-proto-wireguard are prebaked into the fixture image, so the
    // opkg/apk install lines succeed against a real package database.
    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 on the VM:\n{}",
        outcome.script
    );
    assert!(
        outcome.fully_verified(),
        "verification failed: {:?}",
        outcome.verification
    );
    // The kill-switch verify loop's 30 s tail must have removed the rule
    // (no real tunnel endpoint exists on the VM — fail-open by design).
    let killswitch = session
        .exec("uci -q get firewall.wg_client_killswitch.target || echo gone")
        .await
        .expect("killswitch readback");
    assert!(String::from_utf8_lossy(&killswitch.stdout).trim() == "gone");

    // rollback so repeated runs stay clean
    let _ = session
        .exec(
            "uci -q delete network.wg0; uci -q delete network.wg0_peer; \
             uci -q delete firewall.wg_client_vpn; uci -q delete firewall.wg_client_fwd; \
             uci -q delete firewall.wg_client_killswitch; \
             uci commit network; uci commit firewall; true",
        )
        .await;
}

#[tokio::test]
async fn tether_shell_surface_applies_on_vm_hardware_gated() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let _vm = vm_lock().await;

    let (session, model) = connected_openwrt_session().await;

    let mut plan = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Tether(TetherProfile {
            detect_timeout_secs: 3,
            ..TetherProfile::default()
        }),
    )
    .expect("plan for confirmed VM");

    // HARDWARE-GATED, deliberately stripped for this VM run: the USB
    // kmod packages cannot be prebaked into the fixture image (the
    // prebake list is Python-side and frozen for this port) and the VM
    // has no USB controller — on real hardware the full plan (packages
    // included) applies unchanged. What the VM proves: the detection
    // loop times out safely under `set -e`, the skip branch runs, and
    // the ADB hotplug hook heredoc installs.
    plan.ops
        .retain(|op| !matches!(op, PlanOp::EnsurePackage { .. }));

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 on the VM:\n{}",
        outcome.script
    );
    assert!(
        outcome.fully_verified(),
        "verification failed: {:?}",
        outcome.verification
    );
    // hardware-gated negative: with no USB device the interface section
    // must NOT have been created (the 1.x skip branch)
    let usbwan = session
        .exec("uci -q get network.usbwan.proto || echo absent")
        .await
        .expect("usbwan readback");
    assert!(String::from_utf8_lossy(&usbwan.stdout).trim() == "absent");

    // rollback so repeated runs stay clean
    let _ = session
        .exec("rm -f /etc/hotplug.d/usb/99-usb-tether-adb; true")
        .await;
}

#[tokio::test]
async fn wireguard_server_plan_applies_and_verifies_on_real_openwrt() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let _vm = vm_lock().await;

    let (session, model) = connected_openwrt_session().await;

    let profile = Profile::WireguardServer(WireguardServerProfile {
        peer1_public_key: "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ=".into(),
        ..WireguardServerProfile::default()
    });
    let plan =
        plan_profile(&DeviceState::OpenWrt, &model, &profile).expect("plan for confirmed VM");

    // Full plan INCLUDING EnsurePackage: wireguard-tools,
    // luci-proto-wireguard, and qrencode are all prebaked into the
    // fixture image (tests/integration/conftest.py prebake list).
    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 on the VM:\n{}",
        outcome.script
    );
    assert!(
        outcome.fully_verified(),
        "verification failed: {:?}",
        outcome.verification
    );

    // The listener must actually be up: private_key='generate' makes the
    // netifd wireguard proto mint a real key on ifup, so wg0 answers
    // `wg show` with a concrete public key (not the literal 'generate').
    let pubkey = session
        .exec("wg show wg0 public-key 2>/dev/null || echo nokey")
        .await
        .expect("pubkey readback");
    let pubkey = String::from_utf8_lossy(&pubkey.stdout).trim().to_string();
    assert!(
        !pubkey.is_empty() && pubkey != "nokey",
        "wg0 must hold a generated keypair after apply"
    );
    let listen = session
        .exec("netstat -lnu 2>/dev/null | grep -q ':51820 ' && echo listening || echo silent")
        .await
        .expect("listen readback");
    assert_eq!(
        String::from_utf8_lossy(&listen.stdout).trim(),
        "listening",
        "wg0 must listen on UDP 51820"
    );

    // rollback so repeated runs stay clean
    let _ = session
        .exec(
            "uci -q delete network.wg0; uci -q delete network.wg0_peer1; \
             uci -q delete firewall.wg_server_vpn; uci -q delete firewall.wg_server_fwd_lan; \
             uci -q delete firewall.wg_server_fwd_wan; uci -q delete firewall.wg_server_allow; \
             rm -f /etc/wireguard/server_public_key; \
             uci commit network; uci commit firewall; true",
        )
        .await;
}

#[tokio::test]
async fn nodns_full_plan_applies_and_verifies_on_real_openwrt() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let _vm = vm_lock().await;

    let (session, model) = connected_openwrt_session().await;

    // FULL plan, nothing stripped: the preset's whole footprint is
    // shell + curl + dnsmasq addn-hosts wiring — all in the fixture
    // base image. The initd + poll-script heredocs, the dnsmasq
    // addn-hosts list, and the service enable all run for real.
    let plan = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Nodns(NodnsProfile::default()),
    )
    .expect("plan for confirmed VM");

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 on the VM:\n{}",
        outcome.script
    );
    assert!(
        outcome.fully_verified(),
        "verification failed: {:?}",
        outcome.verification
    );

    let readback = session
        .exec(
            "uci -q get dhcp.@dnsmasq[0].addnhosts; \
             test -x /usr/bin/nodns-poll.sh && echo poll-ok; \
             test -f /etc/init.d/nodns-bridge && echo initd-ok; \
             grep -q 'API_URL=\"https://nodns.shop\"' /usr/bin/nodns-poll.sh && echo url-ok",
        )
        .await
        .expect("nodns readback");
    let readback = String::from_utf8_lossy(&readback.stdout);
    assert!(
        readback.contains("/etc/dnsmasq.d/nodns.hosts"),
        "got: {readback}"
    );
    assert!(readback.contains("poll-ok"), "got: {readback}");
    assert!(readback.contains("initd-ok"), "got: {readback}");
    assert!(readback.contains("url-ok"), "got: {readback}");

    // rollback so repeated runs stay clean (stop first — respawn would
    // relaunch the poll loop against the live URL)
    let _ = session
        .exec(
            "/etc/init.d/nodns-bridge stop 2>/dev/null; \
             /etc/init.d/nodns-bridge disable 2>/dev/null; \
             rm -f /etc/init.d/nodns-bridge /usr/bin/nodns-poll.sh /etc/rc.d/S99nodns-bridge; \
             uci -q del_list dhcp.@dnsmasq[0].addnhosts='/etc/dnsmasq.d/nodns.hosts'; \
             uci commit dhcp; rm -rf /etc/dnsmasq.d; true",
        )
        .await;
}

#[tokio::test]
async fn pbr_config_surface_applies_on_real_openwrt() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let _vm = vm_lock().await;

    let (session, model) = connected_openwrt_session().await;

    // Stand-ins for the not-prebaked packages (openclash pattern): the
    // pbr package ships /etc/config/pbr and an init script the plan's
    // enable/restart + enabled-verification target.
    let _ = session
        .exec(
            "touch /etc/config/pbr; \
             printf '#!/bin/sh /etc/rc.common\\nSTART=99\\nUSE_PROCD=1\\nstart() { :; }\\n' > /etc/init.d/pbr; \
             chmod +x /etc/init.d/pbr; true",
        )
        .await;

    let mut plan = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Pbr(PbrProfile {
            wan_interface: "wwan".into(),
            lan_interface: "guest".into(),
            strict_enforcement: false,
        }),
    )
    .expect("plan for confirmed VM");
    plan.ops
        .retain(|op| !matches!(op, PlanOp::EnsurePackage { .. }));

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 on the VM:\n{}",
        outcome.script
    );
    assert!(
        outcome.fully_verified(),
        "verification failed: {:?}",
        outcome.verification
    );

    // the UNQUOTED interface lines are the byte-parity risk this port
    // gates with its charset validator — read them back on a real uci
    let uci = session
        .exec("uci -q show pbr.config")
        .await
        .expect("pbr readback");
    let uci = String::from_utf8_lossy(&uci.stdout);
    assert!(uci.contains("enabled='1'"), "got: {uci}");
    assert!(uci.contains("strict_enforcement='0'"), "got: {uci}");
    assert!(
        uci.contains("netifd_interface_default='wwan'"),
        "got: {uci}"
    );
    assert!(uci.contains("netifd_interface_local='guest'"), "got: {uci}");

    // rollback so repeated runs stay clean
    let _ = session
        .exec("rm -f /etc/init.d/pbr /etc/rc.d/S99pbr; rm -f /etc/config/pbr; true")
        .await;
}

fn sqm_defaults() -> SqmProfile {
    SqmProfile {
        download_kbps: 10_000,
        upload_kbps: 5_000,
        interface: "wan".into(),
        qdisc: "cake".into(),
        script: "piece_of_cake.qos".into(),
        link_layer: "none".into(),
        overhead: 0,
    }
}

/// Strip the package-delivery ops a VM cannot honor: luci-app-openclash
/// is third-party (vernesong feed — not prebakeable into the fixture
/// image), the dnsmasq→dnsmasq-full swap is opkg/apk territory, and the
/// ssl TLS-backend guard may attempt a package install on a backend-less
/// fixture (the VM has no package feeds). On real hardware the full
/// plan applies unchanged (tether precedent).
fn strip_package_ops(plan: &mut conwrt_core::plan::Plan) {
    plan.ops.retain(|op| match op {
        PlanOp::EnsurePackage { .. } => false,
        PlanOp::Shell { command } => {
            // both guards open by probing the installed-package state
            !command.starts_with("if [ -n \"$(opkg list-installed dnsmasq")
                && !command.starts_with("if ! (opkg list-installed")
        }
        _ => true,
    });
}

#[tokio::test]
async fn vpn_nordvpn_applies_and_proves_the_honest_failure_path() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let _vm = vm_lock().await;

    let (session, model) = connected_openwrt_session().await;

    // wireguard-tools + kmod-wireguard are prebaked in the fixture
    // image (the wg-client ring-2 test creates real wg0 keys) — the
    // FULL plan applies with nothing stripped and no stubs.
    let plan = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::VpnNordvpn(VpnNordvpnProfile {
            private_key: "STUBPRIVKEYbase64filledfortestonly0000=".into(),
            server_public_key: "STUBPUBKEYbase64filledfortestonly0000=".into(),
            endpoint_host: "de500.nordvpn.com".into(),
            route_target: "193.29.107.10".into(),
            upstream_gateway: String::new(), // exercise the discovery branch
            ..VpnNordvpnProfile::default()
        }),
    )
    .expect("plan for confirmed VM");

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 (the failure TAIL restores WAN by design):\n{}\nstderr:\n{}",
        outcome.script, outcome.stderr
    );

    // honest-failure contract: with no reachable endpoint the handshake
    // verification FAILS BY NAME instead of reading as success
    assert!(
        !outcome.fully_verified(),
        "a tunnel-less VM must NOT verify as applied"
    );
    let failed: Vec<&str> = outcome
        .verification
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.description.as_str())
        .collect();
    assert!(
        failed.iter().any(|d| d.contains("handshake observed")),
        "the handshake check must be the named failure, got: {failed:?}"
    );

    // what a VM CAN prove on real userspace: wg0 configured, the
    // kill switch REMOVED by the failure tail, tunnel DNS, and the
    // endpoint route absent (discovery timed out — VM has no upstream)
    let uci = session
        .exec(
            "uci -q get network.wg0.proto; \
             uci -q get firewall.vpn_killswitch.target || echo killswitch-gone; \
             uci -q get dhcp.@dnsmasq[0].server | tr '\n' ' '; \
             uci -q get network.nordvpn_server_route.target || echo route-absent",
        )
        .await
        .expect("nord readback");
    let uci = String::from_utf8_lossy(&uci.stdout);
    assert!(uci.contains("wireguard"), "wg0 proto: {uci}");
    assert!(
        uci.contains("killswitch-gone"),
        "the failure tail must have removed the kill switch: {uci}"
    );
    assert!(uci.contains("103.86.99.100"), "tunnel DNS: {uci}");

    // rollback so repeated runs stay clean
    let _ = session
        .exec(
            r#"rm -f /tmp/vpn_setup.sh;              uci -q delete network.wg0; uci -q delete network.nordvpn_server_route;              while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do uci delete network.@wireguard_wg0[0]; done;              while uci -q show firewall 2>/dev/null | grep -q "name='vpn'"; do _s=$(uci -q show firewall | grep "name='vpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci -q delete "firewall.$_s"; done;              uci -q delete firewall.vpn_fwd; uci -q delete firewall.vpn_mgmt;              for d in 103.86.96.100 103.86.99.100; do uci -q del_list dhcp.@dnsmasq[0].server="$d"; done;              uci -q delete dhcp.@dnsmasq[0].noresolv;              uci commit network; uci commit firewall; uci commit dhcp; true"#,
        )
        .await;
}

#[tokio::test]
async fn vpn_pia_openvpn_applies_and_proves_the_honest_failure_path() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let _vm = vm_lock().await;

    let (session, model) = connected_openwrt_session().await;

    // Stand-ins for the not-prebaked openvpn-openssl package: uci needs
    // the config file to exist, and the payload's restart-||-start tail
    // needs the init script (openclash stub pattern).
    let _ = session
        .exec(
            "touch /etc/config/openvpn; \
             printf '#!/bin/sh /etc/rc.common\\nSTART=99\\nstart() { :; }\\nrestart() { :; }\\n' > /etc/init.d/openvpn; \
             chmod +x /etc/init.d/openvpn; true",
        )
        .await;

    let mut plan = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::VpnPiaOpenvpn(VpnPiaOpenvpnProfile {
            username: "p1234567".into(),
            password: "ring2-testpass".into(),
            upstream_gateway: "192.168.8.1".into(),
            ..VpnPiaOpenvpnProfile::default()
        }),
    )
    .expect("plan for confirmed VM");
    plan.ops
        .retain(|op| !matches!(op, PlanOp::EnsurePackage { .. }));

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 (the failure TAIL restores WAN by design):\n{}\nstderr:\n{}",
        outcome.script, outcome.stderr
    );

    // The honest-failure contract (#514 round-1 review): with no real
    // tunnel the tun0 verification check FAILS BY NAME instead of the
    // apply reading as success.
    assert!(
        !outcome.fully_verified(),
        "a tunnel-less VM must NOT verify as applied"
    );
    let failed: Vec<&str> = outcome
        .verification
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.description.as_str())
        .collect();
    assert!(
        failed.iter().any(|d| d.contains("tun0 has an address")),
        "the tun0 readiness check must be the named failure, got: {failed:?}"
    );

    // Everything a VM CAN prove read back on real uci: the openvpn
    // instance, the vpn zone migration (wg0 → tun0), the kill switch
    // REMOVED by the failure tail, and the tunnel DNS.
    let uci = session
        .exec(
            "uci -q get openvpn.pia.enabled; \
             uci -q get firewall.vpn_zone.network; \
             uci -q get firewall.vpn_killswitch.target || echo killswitch-gone; \
             uci -q get dhcp.@dnsmasq[0].server | tr '\\n' ' '; \
             uci -q get dhcp.@dnsmasq[0].noresolv",
        )
        .await
        .expect("pia readback");
    let uci = String::from_utf8_lossy(&uci.stdout);
    assert!(uci.contains("1"), "openvpn.pia.enabled: {uci}");
    assert!(uci.contains("tun0"), "vpn_zone.network: {uci}");
    assert!(
        uci.contains("killswitch-gone"),
        "the failure tail must have removed the kill switch: {uci}"
    );
    assert!(uci.contains("10.0.0.243"), "tunnel DNS: {uci}");
    // the noresolv readback prints the bare value `1` (trailing newline)
    assert!(
        uci.trim_end().ends_with('1'),
        "noresolv must read back 1: {uci}"
    );

    // rollback so repeated runs stay clean
    let _ = session
        .exec(
            r#"rm -f /etc/init.d/openvpn /etc/rc.d/S99openvpn /etc/config/openvpn \
                   /tmp/pia_openvpn_setup.sh /etc/openvpn/pia-ca.rsa.4096.crt /etc/openvpn/pia.auth; \
             rmdir /etc/openvpn 2>/dev/null; \
             while uci -q show firewall 2>/dev/null | grep -q "name='vpn'"; do _s=$(uci -q show firewall | grep "name='vpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci -q delete "firewall.$_s"; done; \
             uci -q delete firewall.vpn_fwd; uci -q delete firewall.vpn_mgmt; \
             for d in 10.0.0.241 10.0.0.242 10.0.0.243; do uci -q del_list dhcp.@dnsmasq[0].server="$d"; done; \
             uci -q delete dhcp.@dnsmasq[0].noresolv; \
             uci commit firewall; uci commit dhcp; true"#,
        )
        .await;
}

#[tokio::test]
async fn openclash_config_surface_applies_on_real_openwrt() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let _vm = vm_lock().await;

    let (session, model) = connected_openwrt_session().await;

    // Stand-ins for the not-prebakeable package: the package ships
    // /etc/config/openclash with a named `config` section (the plan's
    // SetUciOptions targets it) and an rc.common init script (the
    // plan's Service enable + enabled verification target it).
    let _ = session
        .exec(
            "touch /etc/config/openclash; uci set openclash.config=openclash; uci commit openclash; \
             printf '#!/bin/sh /etc/rc.common\\nSTART=99\\nstart() { :; }\\n' > /etc/init.d/openclash; \
             chmod +x /etc/init.d/openclash; true",
        )
        .await;

    let mut plan = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::OpenClash(OpenClashProfile::default()),
    )
    .expect("plan for confirmed VM");
    strip_package_ops(&mut plan);

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 on the VM:\n{}",
        outcome.script
    );
    assert!(
        outcome.fully_verified(),
        "verification failed: {:?}",
        outcome.verification
    );

    let uci = session
        .exec("uci -q show openclash.config")
        .await
        .expect("openclash readback");
    let uci = String::from_utf8_lossy(&uci.stdout);
    assert!(uci.contains("enable='1'"), "got: {uci}");
    assert!(uci.contains("core_type='Meta'"), "got: {uci}");
    assert!(uci.contains("proxy_type='ss'"), "got: {uci}");
    assert!(uci.contains("operation_mode='redir-host'"), "got: {uci}");

    // rollback so repeated runs stay clean
    let _ = session
        .exec(
            "rm -f /etc/init.d/openclash /etc/rc.d/S99openclash; \
             rm -rf /etc/openclash /etc/config/openclash; true",
        )
        .await;
}

#[tokio::test]
async fn ssl_certless_negative_and_cert_present_positive_on_real_openwrt() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }
    let _vm = vm_lock().await;

    let (session, model) = connected_openwrt_session().await;

    // Phase A — cert-less negative: the runtime guard must skip the
    // uhttpd wiring loudly and the apply must FAIL verification by
    // name instead of reporting `applied` for a no-op (the #486
    // round-3 contract).
    let mut plan = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Ssl(SslProfile::default()),
    )
    .expect("plan for confirmed VM");
    strip_package_ops(&mut plan);

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "cert-less script must still exit 0 (guard skips, nds absent skips):\n{}",
        outcome.script
    );
    assert!(
        !outcome.fully_verified(),
        "cert-less apply must NOT verify as applied"
    );
    let failed: Vec<&str> = outcome
        .verification
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.description.as_str())
        .collect();
    assert!(
        failed.iter().any(|d| d.contains("certs deployed")),
        "the certs-present check must be the named failure, got: {failed:?}"
    );

    // Phase B — cert-present positive: host-minted self-signed certs
    // written to the VM, then the same plan wires uhttpd end-to-end
    // and fully verifies (certs-present, cert path, listen_https).
    let dir = std::env::temp_dir().join("conwrt-ring2-ssl");
    std::fs::create_dir_all(&dir).expect("cert scratch dir");
    let (crt, key) = (dir.join("server.crt"), dir.join("server.key"));
    let openssl = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            crt.to_str().unwrap(),
            "-days",
            "2",
            "-subj",
            "/CN=ring2-vm.local",
        ])
        .output()
        .expect("host openssl");
    assert!(openssl.status.success(), "openssl must mint a test cert");

    let write_pem = |path: &std::path::Path, remote: &str| {
        let body = std::fs::read_to_string(path).expect("pem read");
        let mut args = String::from("mkdir -p /etc/tollgate/ssl; printf '%s\\n' ");
        for line in body.lines() {
            args.push('\'');
            args.push_str(line);
            args.push_str("' ");
        }
        args.push_str(&format!("> {remote}; true"));
        args
    };
    let _ = session
        .exec(&write_pem(&crt, "/etc/tollgate/ssl/server.crt"))
        .await;
    let _ = session
        .exec(&write_pem(&key, "/etc/tollgate/ssl/server.key"))
        .await;
    let staged = session
        .exec("ls /etc/tollgate/ssl/server.crt /etc/tollgate/ssl/server.key >/dev/null 2>&1 && echo staged || echo missing")
        .await
        .expect("cert staging check");
    assert_eq!(
        String::from_utf8_lossy(&staged.stdout).trim(),
        "staged",
        "certs must be on the VM before the positive phase"
    );

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "cert-present script must exit 0 on the VM:\n{}\nstderr:\n{}",
        outcome.script, outcome.stderr
    );
    assert!(
        outcome.fully_verified(),
        "verification failed: {:?}",
        outcome.verification
    );

    let uci = session
        .exec("uci -q get uhttpd.main.listen_https")
        .await
        .expect("listen_https readback");
    let uci = String::from_utf8_lossy(&uci.stdout);
    assert!(uci.contains("0.0.0.0:443"), "got: {uci}");
    assert!(uci.contains("[::]:443"), "got: {uci}");

    // rollback so repeated runs stay clean
    let _ = session
        .exec(
            "uci -q delete uhttpd.main.cert; uci -q delete uhttpd.main.key; \
             uci -q delete uhttpd.main.listen_https; \
             uci add_list uhttpd.main.listen_https='0.0.0.0:443'; \
             uci add_list uhttpd.main.listen_https='[::]:443'; \
             uci commit uhttpd; rm -rf /etc/tollgate/ssl; true",
        )
        .await;
    let _ = std::fs::remove_dir_all(&dir);
}

// --- #555 deadman/recovery window on a real OpenWrt VM -------------------
//
// The VM's slirp network makes the channel-severing nondeterministic (the
// guest re-DHCPs to the same address; dropbear may survive the restart or
// not). Both tests therefore assert DEVICE STATE after the window, not the
// transport path that got them there.

async fn vm_exec(cmd: &str) -> String {
    let (session, _model) = connected_openwrt_session().await;
    let out = session
        .exec(cmd)
        .await
        .expect("exec on VM")
        .stdout
        .iter()
        .map(|b| *b as char)
        .collect::<String>()
        .trim()
        .to_string();
    drop(session);
    out
}

fn deadman_probe_plan(passing_verify: bool) -> conwrt_core::plan::Plan {
    use conwrt_core::plan::{ServiceAction, VerificationCheck};
    conwrt_core::plan::Plan {
        profile_id: "deadman-probe".into(),
        model_id: "virtual-x86-64".into(),
        ops: vec![
            // committed configs = {system, network} (shell-embedded commits,
            // the dual-scan shape) — the deadman snapshots exactly these
            PlanOp::Shell {
                command: "uci set system.deadman_probe=test; uci commit system; \
                          uci set network.deadman_note=note; uci commit network"
                    .into(),
            },
            PlanOp::Service {
                name: "network".into(),
                action: ServiceAction::Restart,
            },
        ],
        verification: vec![VerificationCheck {
            description: "deadman probe marker".into(),
            // section-id addressing, NOT `.type`: BusyBox uci does not
            // expose a named section's type as an option — `uci -q get
            // system.deadman_probe.type` returns rc=1/empty; the section
            // id itself yields its type value ("test")
            command: "uci -q get system.deadman_probe || true".into(),
            expect_contains: if passing_verify {
                "test"
            } else {
                "never-matches"
            }
            .into(),
        }],
    }
}

/// Verified-good apply → deadman cancelled → the mutation SURVIVES the
/// window (no revert).
#[tokio::test]
async fn deadman_cancelled_on_verified_apply_survives_window() {
    let _vm = vm_lock().await;
    if !vm_available() {
        eprintln!("[qemu_apply] skipping: CONWRT_QEMU_VM not set / VM down");
        return;
    }
    let plan = deadman_probe_plan(true);
    let (session, _model) = connected_openwrt_session().await;
    let addr = vm_target();
    let reconnect = move || {
        let addr = addr.clone();
        async move {
            let mut store = MemoryTrustStore::new();
            connect(
                &addr,
                &mut store,
                &SshOptions {
                    mode: TrustMode::TrustOnFirstUse,
                    ..Default::default()
                },
            )
            .await
        }
    };
    // short window: if cancellation were skipped, the revert would fire
    // inside the test's own wait
    let outcome = conwrt_local_std::execute::apply_plan_with_recovery_windowed(
        &session, &plan, reconnect, 8, 1,
    )
    .await
    .expect("apply completes (recovered or clean)");
    drop(session);
    assert!(
        outcome.fully_verified(),
        "verification: {:?}",
        outcome.verification
    );

    // wait past the window + revert's own network restart
    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
    let marker = vm_exec("uci -q get system.deadman_probe || true").await;
    assert_eq!(marker, "test", "verified apply must NOT be reverted");
    // Codex #597 P1 (idempotent confirm): a won handshake must survive a
    // REPLAY — if the original confirmation's exit status was lost, the
    // retry sees `cancel` already present and still confirms
    let replay = vm_exec(&conwrt_local_std::execute::deadman_cancel_cmd()).await;
    assert_eq!(
        replay, "deadman-cancelled",
        "replaying a won cancel must confirm again, not report revert"
    );
    // Codex #597 P1 (snapshot secrecy): deadman state is 0700 even on a
    // umask-022 device — the snapshots hold live secrets (ls -ld, not
    // stat: the BusyBox image may lack the stat applet)
    let mode = vm_exec("ls -ld /tmp/conwrt-deadman").await;
    assert!(
        mode.starts_with("drwx------"),
        "deadman root dir must be root-only, got: {mode:?}"
    );
    // fired lands in the generation dir (Codex #597 isolation)
    let fired = vm_exec(
        r#"[ -n "$(ls -d /tmp/conwrt-deadman/*/fired 2>/dev/null)" ] && echo fired || echo quiet"#,
    )
    .await;
    assert_eq!(fired, "quiet", "deadman never fired");
    // rollback
    vm_exec(
        "uci -q delete system.deadman_probe; uci -q commit system; \
             uci -q delete network.deadman_note; uci -q commit network; \
             rm -rf /tmp/conwrt-deadman",
    )
    .await;
}

/// Unverified apply → NO cancel → window expires → the device re-imports
/// its pre-apply snapshots: the mutation is GONE and the fired marker
/// names the recovery entry.
#[tokio::test]
async fn deadman_reverts_unverified_apply_at_window_expiry() {
    let _vm = vm_lock().await;
    if !vm_available() {
        eprintln!("[qemu_apply] skipping: CONWRT_QEMU_VM not set / VM down");
        return;
    }
    let plan = deadman_probe_plan(false);
    let (session, _model) = connected_openwrt_session().await;
    let addr = vm_target();
    let reconnect = move || {
        let addr = addr.clone();
        async move {
            let mut store = MemoryTrustStore::new();
            connect(
                &addr,
                &mut store,
                &SshOptions {
                    mode: TrustMode::TrustOnFirstUse,
                    ..Default::default()
                },
            )
            .await
        }
    };
    // Whatever the transport did (clean failure with failing verification,
    // or channel loss + failed re-verify), the DEADMAN decides on-device:
    let _ = conwrt_local_std::execute::apply_plan_with_recovery_windowed(
        &session, &plan, reconnect, 8, 1,
    )
    .await;
    drop(session);

    // window (8s) + revert's own network restart — then assert state
    tokio::time::sleep(std::time::Duration::from_secs(25)).await;
    let marker = vm_exec("uci -q get system.deadman_probe || true").await;
    assert!(
        marker.is_empty(),
        "unverified apply must be reverted by the deadman, marker={marker:?}"
    );
    let fired = vm_exec(
        r#"[ -n "$(ls -d /tmp/conwrt-deadman/*/fired 2>/dev/null)" ] && echo fired || echo quiet"#,
    )
    .await;
    assert_eq!(fired, "fired", "the recovery entry is named on the device");
    // rollback (defensive — the revert already restored the snapshots)
    vm_exec("rm -rf /tmp/conwrt-deadman").await;
}

/// Codex #597 P1 (stale-arming isolation): a second network-restarting
/// apply that arms while a previous, NEVER-cancelled deadman is still in
/// its window must supersede it — the stale process (earlier deadline)
/// must not roll the NEW apply back prematurely, and the new cancel must
/// not be observed by the old generation. Old arm: window 8, unverified
/// (no cancel). New arm at ~t=3: verified + cancelled. If supersession
/// is broken, the stale window fires at t=8 and deletes the marker.
#[tokio::test]
async fn deadman_rearm_supersedes_stale_window() {
    let _vm = vm_lock().await;
    if !vm_available() {
        eprintln!("[qemu_apply] skipping: CONWRT_QEMU_VM not set / VM down");
        return;
    }
    let addr = vm_target();
    let reconnect1 = {
        let addr = addr.clone();
        move || {
            let addr = addr.clone();
            async move {
                let mut store = MemoryTrustStore::new();
                connect(
                    &addr,
                    &mut store,
                    &SshOptions {
                        mode: TrustMode::TrustOnFirstUse,
                        ..Default::default()
                    },
                )
                .await
            }
        }
    };
    let reconnect2 = {
        let addr = addr.clone();
        move || {
            let addr = addr.clone();
            async move {
                let mut store = MemoryTrustStore::new();
                connect(
                    &addr,
                    &mut store,
                    &SshOptions {
                        mode: TrustMode::TrustOnFirstUse,
                        ..Default::default()
                    },
                )
                .await
            }
        }
    };
    // arm #1: unverified (never cancelled) — a stale live window remains
    let (session, _model) = connected_openwrt_session().await;
    let outcome = conwrt_local_std::execute::apply_plan_with_recovery_windowed(
        &session,
        &deadman_probe_plan(false),
        reconnect1,
        8,
        1,
    )
    .await;
    // unverified: Ok(!fully_verified) or Err(recovery) — either way the
    // FIRST deadman stays armed; nothing here may cancel it
    if let Ok(o) = &outcome {
        assert!(!o.fully_verified(), "arm #1 is unverified by design");
        assert!(!o.deadman_cancelled, "arm #1 must NOT be cancelled");
    }
    drop(session);

    // ~3s into arm #1's 8s window: arm #2 (same mutation, verified) —
    // supersede: retire #1, own the device state going forward
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let (session2, _model2) = connected_openwrt_session().await;
    let outcome2 = conwrt_local_std::execute::apply_plan_with_recovery_windowed(
        &session2,
        &deadman_probe_plan(true),
        reconnect2,
        8,
        1,
    )
    .await
    .expect("arm #2 completes (recovered or clean)");
    drop(session2);
    assert!(
        outcome2.fully_verified(),
        "arm #2 verifies AND its cancel is confirmed: {:?}",
        outcome2.verification
    );

    // past BOTH windows (+revert margin): the verified apply must have
    // survived — the stale window never fired
    tokio::time::sleep(std::time::Duration::from_secs(25)).await;
    let marker = vm_exec("uci -q get system.deadman_probe || true").await;
    assert_eq!(
        marker, "test",
        "stale window must not roll back the superseding verified apply"
    );
    let fired = vm_exec(
        r#"[ -n "$(ls -d /tmp/conwrt-deadman/*/fired 2>/dev/null)" ] && echo fired || echo quiet"#,
    )
    .await;
    assert_eq!(fired, "quiet", "no generation may fire");
    // rollback
    vm_exec(
        "uci -q delete system.deadman_probe; uci -q commit system; \
             uci -q delete network.deadman_note; uci -q commit network; \
             rm -rf /tmp/conwrt-deadman",
    )
    .await;
}

/// Codex #597 P1 (cancel-vs-rollback race): once rollback has STARTED,
/// the cancel command must FAIL — `mv armed cancel` cannot succeed after
/// revert.sh removed `armed` at its transition. A confirmed cancel from
/// that point on would be a lie about a config the device is actively
/// reverting.
#[tokio::test]
async fn deadman_cancel_after_rollback_started_is_rejected() {
    let _vm = vm_lock().await;
    if !vm_available() {
        eprintln!("[qemu_apply] skipping: CONWRT_QEMU_VM not set / VM down");
        return;
    }
    let addr = vm_target();
    let reconnect = move || {
        let addr = addr.clone();
        async move {
            let mut store = MemoryTrustStore::new();
            connect(
                &addr,
                &mut store,
                &SshOptions {
                    mode: TrustMode::TrustOnFirstUse,
                    ..Default::default()
                },
            )
            .await
        }
    };
    let (session, _model) = connected_openwrt_session().await;
    // unverified apply, 2s window: the deadman FIRES at ~2s and the
    // transition removes `armed`
    let _ = conwrt_local_std::execute::apply_plan_with_recovery_windowed(
        &session,
        &deadman_probe_plan(false),
        reconnect,
        2,
        1,
    )
    .await;
    drop(session);
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;

    // rollback underway/done: the atomic handshake must reject the cancel
    let cancel = vm_exec(&conwrt_local_std::execute::deadman_cancel_cmd()).await;
    assert_ne!(
        cancel, "deadman-cancelled",
        "cancel after rollback started must FAIL, got confirmation"
    );
    vm_exec("rm -rf /tmp/conwrt-deadman").await;
}

/// Codex #597 P1 (apply outliving the window): a plan whose prerequisites
/// outlast the window must not keep mutating after the rollback — expiry
/// STOPS the apply shell before restoring the snapshots. The marker is
/// written AFTER a 10s sleep inside a 2s window: it must never exist.
#[tokio::test]
async fn deadman_expiry_stops_post_window_mutations() {
    let _vm = vm_lock().await;
    if !vm_available() {
        eprintln!("[qemu_apply] skipping: CONWRT_QEMU_VM not set / VM down");
        return;
    }
    let plan = conwrt_core::plan::Plan {
        profile_id: "deadman-slow".into(),
        model_id: "virtual-x86-64".into(),
        ops: vec![
            PlanOp::Shell {
                command: "sleep 10; uci set system.dm_slow=1; uci commit system; \
                          echo done > /tmp/dm_slow_marker"
                    .into(),
            },
            PlanOp::Service {
                name: "network".into(),
                action: conwrt_core::plan::ServiceAction::Restart,
            },
        ],
        verification: vec![conwrt_core::plan::VerificationCheck {
            description: "slow marker".into(),
            command: "cat /tmp/dm_slow_marker || true".into(),
            expect_contains: "done".into(),
        }],
    };
    let addr = vm_target();
    let reconnect = move || {
        let addr = addr.clone();
        async move {
            let mut store = MemoryTrustStore::new();
            connect(
                &addr,
                &mut store,
                &SshOptions {
                    mode: TrustMode::TrustOnFirstUse,
                    ..Default::default()
                },
            )
            .await
        }
    };
    let (session, _model) = connected_openwrt_session().await;
    // window 2s, poll 1s: the deadman fires mid-sleep and kills the apply
    let outcome = conwrt_local_std::execute::apply_plan_with_recovery_windowed(
        &session, &plan, reconnect, 2, 1,
    )
    .await;
    drop(session);
    if let Ok(o) = &outcome {
        assert!(
            !o.fully_verified(),
            "an apply the deadman reverted must not read as success"
        );
    }

    // past the sleep (10s) + margin: the marker must NEVER have been
    // written — the apply shell was stopped at window expiry
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    let marker = vm_exec("cat /tmp/dm_slow_marker 2>/dev/null || true").await;
    assert!(
        marker.is_empty(),
        "apply mutated after window expiry+rollback: marker={marker:?}"
    );
    let slow_opt = vm_exec("uci -q get system.dm_slow || true").await;
    assert!(slow_opt.is_empty(), "no post-expiry uci may survive");
    // rollback
    vm_exec("rm -f /tmp/dm_slow_marker; rm -rf /tmp/conwrt-deadman").await;
}
