//! The diagnose workflow against the mock provider — the M1 slice of the
//! "same workflow, any provider" acceptance test (ADR-0003, ADR-0011).

use conwrt_core::mock::{MockProber, NamedScenario};
use conwrt_core::{DeviceState, diagnose};
use core::net::IpAddr;
use std::path::Path;

fn models_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models")
}

fn real_registry() -> Vec<conwrt_types::DeviceModel> {
    let (registry, invalid) =
        conwrt_types::registry::ModelRegistry::load_dir(&models_dir()).expect("models dir loads");
    assert!(invalid.is_empty());
    registry.models().to_vec()
}

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::from([a, b, c, d])
}

#[test]
fn workflow_classifies_named_scenarios() {
    let cases = [
        (NamedScenario::Off, DeviceState::Off),
        (NamedScenario::Unreachable, DeviceState::Unreachable),
        (NamedScenario::UbootRecovery, DeviceState::UbootRecovery),
        (NamedScenario::OpenWrt, DeviceState::OpenWrt),
        (NamedScenario::StockVendor, DeviceState::StockVendor),
    ];
    for (scenario, expected) in cases {
        let target = ip(192, 168, 0, 1);
        let mut prober = MockProber::responding(target, scenario);
        let diagnosis =
            pollster::block_on(diagnose(&mut prober, target, &real_registry())).unwrap();
        assert_eq!(diagnosis.state, expected, "scenario {scenario:?}");
        assert_eq!(diagnosis.ip, target);
    }
}

#[test]
fn workflow_identifies_model_from_oui() {
    // Named scenarios carry a GL.iNet OUI (94:83:c4).
    let target = ip(192, 168, 8, 1);
    let mut prober = MockProber::responding(target, NamedScenario::OpenWrt);
    let diagnosis = pollster::block_on(diagnose(&mut prober, target, &real_registry())).unwrap();

    assert_eq!(diagnosis.state, DeviceState::OpenWrt);
    assert!(diagnosis.mac.is_some());
    let ids: Vec<&str> = diagnosis
        .model_candidates
        .iter()
        .map(|m| m.model_id.as_str())
        .collect();
    assert!(
        ids.iter().all(|id| id.starts_with("glinet-")),
        "expected GL.iNet candidates, got {ids:?}"
    );
    assert!(!ids.is_empty());
}

#[test]
fn workflow_records_capability_calls_in_order() {
    let target = ip(10, 0, 0, 5);
    let mut prober = MockProber::responding(target, NamedScenario::UbootRecovery);
    pollster::block_on(diagnose(&mut prober, target, &real_registry())).unwrap();

    let calls = prober.calls();
    let names: Vec<&str> = calls
        .iter()
        .map(|c| match c {
            conwrt_core::mock::Call::LinkUp => "link",
            conwrt_core::mock::Call::Ping(_) => "ping",
            conwrt_core::mock::Call::HttpGet(..) => "http",
            conwrt_core::mock::Call::SshBanner(_) => "ssh",
            conwrt_core::mock::Call::ArpMac(_) => "arp",
            conwrt_core::mock::Call::Sleep(_) => "sleep",
        })
        .collect();
    // Read-only surface: exactly the five probes + one pacing sleep.
    assert_eq!(
        names,
        ["link", "ping", "sleep", "http", "ssh", "arp"],
        "journal: {}",
        prober.calls_summary()
    );
}

#[test]
fn same_workflow_two_providers_same_result() {
    // The provider-swap acceptance slice: two independently constructed
    // mocks (later: local-std vs remote-agent) must yield identical
    // diagnoses for identical evidence.
    let target = ip(172, 16, 1, 1);
    let mut a = MockProber::responding(target, NamedScenario::OpenWrt);
    let mut b = {
        let mut m = MockProber::default();
        m.set(target, NamedScenario::OpenWrt.evidence());
        m
    };
    let models = real_registry();
    let da = pollster::block_on(diagnose(&mut a, target, &models)).unwrap();
    let db = pollster::block_on(diagnose(&mut b, target, &models)).unwrap();
    assert_eq!(da.state, db.state);
    assert_eq!(da.mac, db.mac);
    assert_eq!(da.model_candidates, db.model_candidates);
}

#[test]
fn notes_explain_the_classification() {
    let target = ip(192, 168, 0, 9);
    let mut prober = MockProber::responding(target, NamedScenario::UbootRecovery);
    let diagnosis = pollster::block_on(diagnose(&mut prober, target, &real_registry())).unwrap();
    assert!(diagnosis.notes.iter().any(|n| n.contains("recovery")));
}
