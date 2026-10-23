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
//! loop runs its real 30 s failure tail), and `tether` (shell surface
//! only: the USB kmods are NOT prebakeable into the fixture image and
//! the VM has no USB device, so `EnsurePackage` ops are stripped and the
//! hardware-gated parts — USB detection actually finding a device,
//! `network.usbwan` coming up — are marked and not asserted; what IS
//! asserted is the script applying cleanly and the ADB hotplug hook
//! installing, the parts a VM can prove), and `openclash` + `ssl` (§4
//! ports of PR #486: config surface only — package delivery is stripped
//! like tether's (luci-app-openclash is third-party, not prebakeable;
//! the ssl TLS-backend guard is package-manager territory), a stub
//! rc.common service + the package's default uci section stand in for
//! the package, and ssl is proven in BOTH the cert-less negative
//! (skips loudly, verification fails by name) and the cert-present
//! positive (host-minted self-signed certs, full verify).

use conwrt_core::plan::{
    OpenClashProfile, PlanOp, Profile, SqmProfile, SslProfile, TetherProfile,
    WireguardClientProfile, WireguardServerProfile, plan_profile,
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
