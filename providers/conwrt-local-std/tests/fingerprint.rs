//! Ring-1 tests for authenticated fingerprinting: the SSH fixture serves
//! `/etc/openwrt_release`, board name, and hostname from its in-memory
//! filesystem; the provider gathers them read-only and the classifier
//! confirmation rule upgrades `SshOnly` → `OpenWrt` only on positive,
//! authenticated OpenWrt evidence.

use conwrt_core::fingerprint::{confirm, parse_openwrt_release};
use conwrt_core::ssh::TrustMode;
use conwrt_core::state::DeviceState;
use conwrt_local_std::fingerprint::fingerprint;
use conwrt_local_std::ssh::{SshAuth, SshOptions, SshTarget, connect};

#[path = "common/mod.rs"]
mod common;

const RELEASE: &str = "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10.2'\nDISTRIB_DESCRIPTION='OpenWrt 24.10.2 r28427-6b67453ca0'\nDISTRIB_ARCH='mipsel_24kc'\nDISTRIB_TARGET='ramips/mt7621'\n";

#[test]
fn parses_release_with_quotes_and_missing_keys() {
    let r = parse_openwrt_release(RELEASE).expect("parses");
    assert_eq!(r.id.as_deref(), Some("OpenWrt"));
    assert_eq!(r.release.as_deref(), Some("24.10.2"));
    assert_eq!(r.target.as_deref(), Some("ramips/mt7621"));
    assert!(r.is_openwrt());

    let partial = parse_openwrt_release("DISTRIB_ID='OpenWrt'\n").expect("partial parses");
    assert!(partial.release.is_none());

    assert!(parse_openwrt_release("").is_none());
    assert!(parse_openwrt_release("not a release file\nat all\n").is_none());
    assert!(
        parse_openwrt_release("DISTRIB_ID='VendorOS'\n")
            .expect("parses")
            .id
            .as_deref()
            == Some("VendorOS"),
        "vendor IDs parse — refusing them happens in confirm()"
    );
}

#[test]
fn confirmation_requires_authenticated_openwrt_evidence() {
    let openwrt = parse_openwrt_release(RELEASE).unwrap();
    let vendor = parse_openwrt_release("DISTRIB_ID='VendorOS'\nDISTRIB_RELEASE='9.9'\n").unwrap();

    assert_eq!(
        confirm(DeviceState::SshOnly, Some(&openwrt)),
        DeviceState::OpenWrt
    );
    // vendor release file does NOT confirm OpenWrt
    assert_eq!(
        confirm(DeviceState::SshOnly, Some(&vendor)),
        DeviceState::SshOnly
    );
    // no release file at all: ambiguity retained
    assert_eq!(confirm(DeviceState::SshOnly, None), DeviceState::SshOnly);
    // already-confirmed and unrelated states pass through unchanged
    assert_eq!(confirm(DeviceState::OpenWrt, None), DeviceState::OpenWrt);
    assert_eq!(
        confirm(DeviceState::StockVendor, Some(&openwrt)),
        DeviceState::StockVendor
    );
}

#[tokio::test]
async fn fingerprint_gathers_over_real_ssh_channels() {
    let fixture = common::Fixture::start().await;
    fixture.put_file("/etc/openwrt_release", RELEASE);
    fixture.put_file("/tmp/sysinfo/board_name", "glinet,gl-ar150\n");
    fixture.put_file("/proc/sys/kernel/hostname", "OpenWrt\n");

    let mut store = conwrt_core::ssh::MemoryTrustStore::new();
    let session = connect(
        &target_for(fixture.addr.as_str()),
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("connect");

    let report = fingerprint(&session).await.expect("gather");
    let release = report.release.expect("release present");
    assert_eq!(release.release.as_deref(), Some("24.10.2"));
    assert_eq!(report.board_name.as_deref(), Some("glinet,gl-ar150"));
    assert_eq!(report.hostname.as_deref(), Some("OpenWrt"));
    assert!(report.notes.is_empty());

    drop(session);
}

#[tokio::test]
async fn stock_device_yields_absent_release_as_signal() {
    let fixture = common::Fixture::start().await;
    fixture.put_file("/etc/os-release", "ID=vendoros\n");
    // no /etc/openwrt_release in the fixture filesystem

    let mut store = conwrt_core::ssh::MemoryTrustStore::new();
    let session = connect(
        &target_for(fixture.addr.as_str()),
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("connect");

    let report = fingerprint(&session).await.expect("gather");
    assert!(report.release.is_none());
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("/etc/openwrt_release"))
    );
    assert_eq!(
        confirm(DeviceState::SshOnly, report.release.as_ref()),
        DeviceState::SshOnly,
        "a dropbear-only stock device must stay unconfirmed"
    );

    drop(session);
}

fn target_for(addr: &str) -> SshTarget {
    SshTarget {
        addr: addr.to_string(),
        user: "root".to_string(),
        auth: SshAuth::Password(FIXTURE_PASSWORD.to_string()),
    }
}

use common::FIXTURE_PASSWORD;
