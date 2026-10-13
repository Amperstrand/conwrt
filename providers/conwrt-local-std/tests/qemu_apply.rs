//! Ring-2 (QEMU OpenWrt VM, ADR-0011): apply a desired-state plan to a
//! **real OpenWrt userspace** end-to-end — fingerprint-confirmed identity,
//! sqm plan, apply over SSH, read-only verification. Gated exactly like
//! `qemu_dropbear.rs`: `CONWRT_QEMU_VM=1` plus a reachable VM on
//! 127.0.0.1:2222 (boot via the integration fixture or the conftest qemu
//! command). Mutations are confined to the throwaway VM overlay.

use conwrt_core::plan::{Profile, SqmProfile, plan_profile};
use conwrt_core::ssh::{MemoryTrustStore, TrustMode};
use conwrt_core::state::DeviceState;
use conwrt_core::{confirm, render_shell};
use conwrt_local_std::execute::apply_plan;
use conwrt_local_std::fingerprint::fingerprint;
use conwrt_local_std::ssh::{SshAuth, SshOptions, SshTarget, connect};
use core::net::{IpAddr, SocketAddr};
use std::net::TcpStream;
use std::path::Path;

fn vm_available() -> bool {
    if std::env::var("CONWRT_QEMU_VM").ok().as_deref() != Some("1") {
        return false;
    }
    TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 2222),
        std::time::Duration::from_secs(2),
    )
    .is_ok()
}

fn vm_key() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/integration/.vm_ssh_key")
}

fn vm_target() -> SshTarget {
    SshTarget {
        addr: "127.0.0.1:2222".into(),
        user: "root".into(),
        auth: SshAuth::KeyFile {
            path: vm_key(),
            passphrase: None,
        },
    }
}

#[tokio::test]
async fn sqm_plan_applies_and_verifies_on_real_openwrt() {
    if !vm_available() {
        eprintln!("skipping: CONWRT_QEMU_VM=1 not set or VM unreachable");
        return;
    }

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
            default_ip: None,
        },
        capabilities: Some(vec!["ethernet".into()]),
        flash_methods: None,
        mac_oui: Vec::new(),
    };

    let profile = Profile::Sqm(SqmProfile {
        download_kbps: 10_000,
        upload_kbps: 5_000,
        interface: "wan".into(),
        ..sqm_defaults()
    });
    let plan = plan_profile(&state, &model, &profile).expect("plan for confirmed VM");
    let script = render_shell(&plan);

    // hardware-safe dry-run evidence: the script must be exactly what the
    // ring-1 tests pinned (op order + quoting), against a real userspace
    assert!(script.contains("apk add 'sqm-scripts'"));

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 on the VM; stderr:\n{}",
        outcome.stderr
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
