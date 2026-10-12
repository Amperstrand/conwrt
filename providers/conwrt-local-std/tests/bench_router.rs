//! Ring-3 test: the SSH provider against a **physical bench router**
//! (ADR-0011). Gated behind `CONWRT_BENCH_ROUTER=<ip>` (plus an
//! `CONWRT_BENCH_KEY` private-key path, defaulting to the VM key) — never
//! run in CI, only against hardware the operator has explicitly designated.
//!
//! Identity gates before anything else (AGENTS.md): the test snapshots the
//! live ARP MAC of the target and requires `CONWRT_BENCH_MAC` to match it
//! when set — the specimen gate — before exercising any capability. All
//! remote writes are confined to `/tmp` and cleaned up.
//!
//! Run (bench x1860 example):
//! ```text
//! CONWRT_BENCH_ROUTER=192.168.104.52 \
//! CONWRT_BENCH_MAC=a8:63:7d:8f:61:a8 \
//! cargo test -p conwrt-local-std --test bench_router -- --nocapture
//! ```

use conwrt_core::capability::LinkProbe;
use conwrt_core::ssh::{MemoryTrustStore, TrustMode};
use conwrt_local_std::LocalProber;
use conwrt_local_std::ssh::{SshAuth, SshError, SshOptions, SshTarget, connect};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

fn bench_target() -> Option<(SshTarget, String)> {
    let ip = std::env::var("CONWRT_BENCH_ROUTER").ok()?;
    let key = std::env::var("CONWRT_BENCH_KEY").unwrap_or_else(|_| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/integration/.vm_ssh_key")
            .to_string_lossy()
            .into_owned()
    });
    let target = SshTarget {
        addr: format!("{ip}:22"),
        user: "root".to_string(),
        auth: SshAuth::KeyFile {
            path: PathBuf::from(&key),
            passphrase: None,
        },
    };
    Some((target, ip))
}

fn bench_mac_specimen() -> Option<String> {
    std::env::var("CONWRT_BENCH_MAC")
        .ok()
        .filter(|m| !m.is_empty())
}

/// Specimen gate: the live ARP MAC must equal the expected specimen MAC
/// before any capability is exercised.
fn assert_specimen_mac(ip: &str) {
    let Some(expected) = bench_mac_specimen() else {
        eprintln!("note: CONWRT_BENCH_MAC not set — specimen gate skipped");
        return;
    };
    let expected = conwrt_types::MacAddress::parse(&expected).expect("parse CONWRT_BENCH_MAC");
    let table =
        std::fs::read_to_string("/proc/net/arp").expect("read /proc/net/arp on Linux benches");
    let found = conwrt_local_std::lookup_arp_table(&table, ip.parse().unwrap());
    assert_eq!(
        found,
        Some(expected),
        "SPECIMEN GATE FAILED: live ARP MAC for {ip} does not match the expected specimen — \
         refuse to proceed (AGENTS.md: verify the specimen, not just the model)"
    );
}

#[tokio::test]
async fn bench_router_exec_exit_codes_and_release() {
    let Some((target, ip)) = bench_target() else {
        eprintln!("skipping: CONWRT_BENCH_ROUTER not set");
        return;
    };
    assert_specimen_mac(&ip);

    let mut store = MemoryTrustStore::new();
    let session = connect(
        &target,
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("connect to bench router");

    let release = session
        .exec("cat /etc/openwrt_release")
        .await
        .expect("exec");
    assert_eq!(release.exit_code, Some(0));
    let text = String::from_utf8_lossy(&release.stdout);
    assert!(text.contains("OpenWrt"), "got: {text}");

    assert_eq!(session.exec("true").await.expect("true").exit_code, Some(0));
    assert_eq!(
        session.exec("false").await.expect("false").exit_code,
        Some(1)
    );
}

#[tokio::test]
async fn bench_router_scp_roundtrip_tmp_only() {
    let Some((target, ip)) = bench_target() else {
        eprintln!("skipping: CONWRT_BENCH_ROUTER not set");
        return;
    };
    assert_specimen_mac(&ip);

    let mut store = MemoryTrustStore::new();
    let session = connect(
        &target,
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("connect to bench router");

    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let remote = format!("/tmp/conwrt-ring3-{}.bin", std::process::id());
    session.scp_upload(&payload, &remote).await.expect("upload");

    let sum = session
        .exec(&format!("wc -c < {remote}"))
        .await
        .expect("byte count");
    assert_eq!(
        String::from_utf8_lossy(&sum.stdout).trim(),
        "65536",
        "on-device byte count mismatch"
    );

    let downloaded = session.scp_download(&remote).await.expect("download");
    assert_eq!(downloaded, payload, "roundtrip must be byte-identical");

    session
        .exec(&format!("rm -f {remote}"))
        .await
        .expect("cleanup");
}

#[tokio::test]
async fn bench_router_trust_ladder_and_banner() {
    let Some((target, ip)) = bench_target() else {
        eprintln!("skipping: CONWRT_BENCH_ROUTER not set");
        return;
    };
    assert_specimen_mac(&ip);

    // Strict mode must refuse the (still-unknown) bench host with the pin
    // hint — refusal-as-data on real hardware.
    let mut store = MemoryTrustStore::new();
    let err = connect(&target, &mut store, &SshOptions::default())
        .await
        .expect_err("strict mode must refuse unknown host");
    match &err {
        SshError::HostKeyRefused(refusal) => {
            assert!(refusal.hint.contains("--trust-host-key SHA256:"));
        }
        other => panic!("expected refusal, got {other:?}"),
    }

    // TOFU learns the fingerprint; a pin of that fingerprint then connects
    // in strict mode.
    let mut store = MemoryTrustStore::new();
    let session = connect(
        &target,
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("TOFU connect");
    let pin = session.presented_key.fingerprint.clone();
    let mut fresh_store = MemoryTrustStore::new();
    connect(
        &target,
        &mut fresh_store,
        &SshOptions {
            pin: Some(pin),
            ..Default::default()
        },
    )
    .await
    .expect("pinned strict connect");

    // Banner probe through the local provider (real interface).
    let ip_addr: IpAddr = ip.parse().unwrap();
    let iface = std::env::var("CONWRT_BENCH_IFACE").unwrap_or_else(|_| "enp5s0".to_string());
    let mut prober = LocalProber::on_interface(iface).with_ports(0, 22);
    let banner = prober
        .ssh_banner(ip_addr)
        .await
        .expect("probe")
        .expect("banner");
    assert!(
        banner.software.starts_with("dropbear"),
        "got: {}",
        banner.software
    );
}
