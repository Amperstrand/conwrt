//! Workflow tests for the MAAS lab components (issue #169) — every test
//! runs against the in-memory mocks from `conwrt_maas::mock`: no MAAS
//! region, no coordinator, no disk, no network (ADR-0011).

use conwrt_maas::flash::{CloudInitSeed, DiskFlashPlan, FlashError, Sha256, execute_flash};
use conwrt_maas::mock::{MockBlockWriter, MockMaas, NoTime};
use conwrt_maas::provider::{ComputeError, ComputeProvider, MaasProvider, MachineState, VmSpec};

const IMAGE: &[u8] = b"conwrt maas lab image bytes (stand-in for an ubuntu raspi img)";

fn spec(name: &str) -> VmSpec {
    VmSpec {
        name: name.into(),
        cores: 2,
        memory_mib: 2048,
        disk_gib: 20,
    }
}

// ---------------------------------------------------------------- flash

#[test]
fn flash_happy_path_writes_verifies_grows_and_seeds() {
    let plan = DiskFlashPlan::new(Sha256::hash(IMAGE))
        .with_grow()
        .with_seed(CloudInitSeed {
            user_data: "#cloud-config\n".into(),
            meta_data: "instance-id: pi-lab".into(),
            network_config: None,
        });
    let mut writer = MockBlockWriter::new();

    let report = pollster::block_on(execute_flash(&plan, IMAGE, &mut writer)).unwrap();

    assert_eq!(report.bytes_written, IMAGE.len());
    assert!(report.partition_grown && report.seed_staged);
    assert_eq!(
        writer.calls,
        ["write_image", "read_back", "grow_partition", "write_seed"]
    );
    assert_eq!(writer.disk, IMAGE);
    assert!(writer.seed.is_some());
}

#[test]
fn flash_aborts_before_write_on_checksum_mismatch() {
    let plan = DiskFlashPlan::new(Sha256::hash(b"a DIFFERENT image"));
    let mut writer = MockBlockWriter::new();

    let err = pollster::block_on(execute_flash(&plan, IMAGE, &mut writer)).unwrap_err();

    match err {
        FlashError::ImageChecksum { .. } => {}
        other => panic!("expected ImageChecksum, got {other:?}"),
    }
    // The safety property: NOTHING touched the disk.
    assert!(writer.calls.is_empty());
    assert!(writer.disk.is_empty());
}

#[test]
fn flash_aborts_before_grow_and_seed_on_corrupt_readback() {
    let plan = DiskFlashPlan::new(Sha256::hash(IMAGE))
        .with_grow()
        .with_seed(CloudInitSeed {
            user_data: "#cloud-config\n".into(),
            meta_data: "m".into(),
            network_config: None,
        });
    let mut writer = MockBlockWriter {
        corrupt_readback: true,
        ..MockBlockWriter::new()
    };

    let err = pollster::block_on(execute_flash(&plan, IMAGE, &mut writer)).unwrap_err();

    assert!(matches!(err, FlashError::WrittenChecksum { .. }));
    assert_eq!(writer.calls, ["write_image", "read_back"]);
    assert!(writer.seed.is_none(), "no seed may be injected");
}

#[test]
fn flash_writer_failure_surfaces_and_stops_the_pipeline() {
    let plan = DiskFlashPlan::new(Sha256::hash(IMAGE)).with_grow();
    let mut writer = MockBlockWriter {
        fail_at: Some("write_image"),
        ..MockBlockWriter::new()
    };

    let err = pollster::block_on(execute_flash(&plan, IMAGE, &mut writer)).unwrap_err();

    assert!(matches!(err, FlashError::Writer(_)));
    assert_eq!(writer.calls, ["write_image"]);
    assert!(writer.disk.is_empty(), "failed write must not fake success");
}

#[test]
fn flash_without_seed_or_grow_is_minimal() {
    let plan = DiskFlashPlan::new(Sha256::hash(IMAGE));
    let mut writer = MockBlockWriter::new();

    let report = pollster::block_on(execute_flash(&plan, IMAGE, &mut writer)).unwrap();

    assert!(!report.partition_grown && !report.seed_staged);
    assert_eq!(writer.calls, ["write_image", "read_back"]);
}

#[test]
fn sha256_parses_hex_and_rejects_garbage() {
    let h = Sha256::hash(IMAGE);
    let parsed: Sha256 = h.as_hex().parse().unwrap();
    assert_eq!(parsed, h);
    assert_eq!(parsed.to_string(), h.as_hex());
    assert!("not-hex".parse::<Sha256>().is_err());
    assert!("zz".parse::<Sha256>().is_err());
    assert!("0".repeat(63).parse::<Sha256>().is_err()); // 63 chars: too short
}

// -------------------------------------------------------------- provider

#[test]
fn create_vm_composes_allocates_deploys_to_deployed() {
    let maas = MockMaas::new();
    let mut provider = MaasProvider::new(maas, NoTime::default());

    let vm = pollster::block_on(provider.create_vm(&spec("lab-vm-1"))).unwrap();

    assert_eq!(vm.system_id, "sys-1");
    assert_eq!(vm.hostname, "lab-vm-1");
    assert_eq!(vm.state, MachineState::Deployed);

    let calls = &provider.client().calls;
    let compose = calls.iter().filter(|c| c.starts_with("compose")).count();
    let allocate = calls.iter().filter(|c| c.starts_with("allocate")).count();
    let deploy = calls.iter().filter(|c| c.starts_with("deploy")).count();
    assert_eq!((compose, allocate, deploy), (1, 1, 1));
    // Order: compose → (poll to Ready) → allocate → deploy → (poll to Deployed).
    let first_alloc = calls
        .iter()
        .position(|c| c.starts_with("allocate"))
        .unwrap();
    let deploy_at = calls.iter().position(|c| c.starts_with("deploy")).unwrap();
    assert!(first_alloc < deploy_at);
    let last_machine = calls
        .iter()
        .rposition(|c| c.starts_with("machine"))
        .unwrap();
    assert!(deploy_at < last_machine);
}

#[test]
fn create_vm_rejects_invalid_spec_before_any_client_call() {
    let maas = MockMaas::new();
    let mut provider = MaasProvider::new(maas, NoTime::default());
    let bad = VmSpec {
        name: "not a dns label!".into(),
        cores: 2,
        memory_mib: 2048,
        disk_gib: 20,
    };

    let err = pollster::block_on(provider.create_vm(&bad)).unwrap_err();

    assert!(matches!(err, ComputeError::InvalidSpec(_)));
    assert!(provider.client().calls.is_empty(), "nothing may reach MAAS");
}

#[test]
fn create_vm_times_out_bounded_when_commissioning_never_completes() {
    let mut maas = MockMaas::new();
    maas.stuck.push("sys-1".into()); // deterministic: first compose is sys-1
    let mut provider = MaasProvider::new(maas, NoTime::default()).with_polling(10, 5);

    let err = pollster::block_on(provider.create_vm(&spec("stuck-vm"))).unwrap_err();

    match err {
        ComputeError::NeverReached { wanted, polls, .. } => {
            assert_eq!(wanted, "Ready");
            assert_eq!(polls, 5, "poll bound is respected, no infinite loop");
        }
        other => panic!("expected NeverReached, got {other:?}"),
    }
    let machine_polls = provider
        .client()
        .calls
        .iter()
        .filter(|c| c.starts_with("machine"))
        .count();
    assert_eq!(machine_polls, 5);
}

#[test]
fn destroy_deployed_vm_releases_then_deletes() {
    let maas = MockMaas::new();
    let mut provider = MaasProvider::new(maas, NoTime::default());
    let vm = pollster::block_on(provider.create_vm(&spec("gone-soon"))).unwrap();

    pollster::block_on(provider.destroy_vm(&vm.system_id)).unwrap();

    let calls = &provider.client().calls;
    assert!(calls.iter().any(|c| c.starts_with("release sys-1")));
    assert!(calls.iter().any(|c| c.starts_with("delete sys-1")));
    // Release precedes delete; the machine is gone afterwards.
    let rel = calls.iter().position(|c| c == "release sys-1").unwrap();
    let del = calls.iter().position(|c| c == "delete sys-1").unwrap();
    assert!(rel < del);
    assert!(provider.client().machines.is_empty());
    let err = pollster::block_on(provider.describe_vm("sys-1")).unwrap_err();
    assert!(matches!(err, ComputeError::Client(_)));
}

#[test]
fn destroy_ready_vm_deletes_without_releasing() {
    let mut maas = MockMaas::new();
    use conwrt_maas::provider::MaasClient;
    // A machine already sitting in the pool.
    pollster::block_on(maas.compose(&spec("pool-vm"))).unwrap();
    pollster::block_on(maas.machine("sys-1")).unwrap(); // New → Commissioning
    pollster::block_on(maas.machine("sys-1")).unwrap(); // → Ready
    let ready = pollster::block_on(maas.machine("sys-1")).unwrap();
    assert_eq!(ready.state, MachineState::Ready);

    let mut provider = MaasProvider::new(maas, NoTime::default());
    pollster::block_on(provider.destroy_vm("sys-1")).unwrap();

    assert!(
        !provider
            .client()
            .calls
            .iter()
            .any(|c| c.starts_with("release"))
    );
    assert!(provider.client().machines.is_empty());
}

#[test]
fn list_and_describe_map_machine_records() {
    let maas = MockMaas::new();
    let mut provider = MaasProvider::new(maas, NoTime::default());
    let vm = pollster::block_on(provider.create_vm(&spec("listed"))).unwrap();

    let list = pollster::block_on(provider.list_vms()).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].system_id, vm.system_id);

    let d = pollster::block_on(provider.describe_vm(&vm.system_id)).unwrap();
    assert_eq!(d.state, MachineState::Deployed);
}

// ------------------------------------------------------- state machine

#[test]
fn machine_state_parses_maas_status_names() {
    use MachineState as S;
    assert_eq!("New".parse::<S>().unwrap(), S::New);
    assert_eq!("Deployed".parse::<S>().unwrap(), S::Deployed);
    assert_eq!(
        "Failed commissioning".parse::<S>().unwrap(),
        S::FailedCommissioning
    );
    assert_eq!(
        "Failed deployment".parse::<S>().unwrap(),
        S::FailedDeployment
    );
    let future = "SomeFutureStatus".parse::<S>().unwrap();
    assert_eq!(future, S::Other("SomeFutureStatus".into()));
    assert!(!future.can_allocate());
}

#[test]
fn machine_state_gates_allocation_and_reports_failures() {
    use MachineState as S;
    assert!(S::Ready.can_allocate());
    assert!(!S::New.can_allocate());
    assert!(!S::Deployed.can_allocate());
    assert!(S::Deployed.is_deployed());
    assert!(S::FailedTesting.is_failed());
    assert!(S::Broken.is_failed());
    assert!(!S::Ready.is_failed());
}
