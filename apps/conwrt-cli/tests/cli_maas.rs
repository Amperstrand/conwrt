//! Binary integration tests for `conwrt maas …` (#169 slice 3): exercise
//! the REAL CLI against tempfiles and an httpmock region — no hardware,
//! no live MAAS, no real network beyond the loopback mock server.

use std::process::Command;

use httpmock::prelude::*;
use serde_json::json;

fn conwrt() -> Command {
    Command::new(env!("CARGO_BIN_EXE_conwrt"))
}

const IMAGE: &[u8] = b"ubuntu raspi stand-in image bytes for the lab disk";

fn sha256_hex() -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(IMAGE);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn machine_json(id: &str, status: &str) -> serde_json::Value {
    json!({
        "system_id": id,
        "hostname": format!("vm-{id}"),
        "status_name": status,
    })
}

#[test]
fn maas_flash_writes_and_seeds_on_happy_path() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("img.img");
    let target = dir.path().join("disk.img");
    let user_data = dir.path().join("user-data");
    let meta_data = dir.path().join("meta-data");
    std::fs::write(&image, IMAGE).unwrap();
    std::fs::write(&user_data, "#cloud-config\n").unwrap();
    std::fs::write(&meta_data, "instance-id: pi-lab").unwrap();

    let out = conwrt()
        .args([
            "maas",
            "flash",
            "--image",
            image.to_str().unwrap(),
            "--sha256",
            &sha256_hex(),
            "--target",
            target.to_str().unwrap(),
            "--user-data",
            user_data.to_str().unwrap(),
            "--meta-data",
            meta_data.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("read-back verified"), "stdout: {stdout}");
    assert!(stdout.contains("seed:      staged"), "stdout: {stdout}");
    assert_eq!(std::fs::read(&target).unwrap(), IMAGE);
    // target is disk.img → seed stages at disk.img.seed/
    assert_eq!(
        std::fs::read_to_string(dir.path().join("disk.img.seed").join("user-data")).unwrap(),
        "#cloud-config\n"
    );
}

#[test]
fn maas_flash_refuses_to_write_on_checksum_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("img.img");
    let target = dir.path().join("disk.img");
    std::fs::write(&image, IMAGE).unwrap();

    let out = conwrt()
        .args([
            "maas",
            "flash",
            "--image",
            image.to_str().unwrap(),
            "--sha256",
            &"0".repeat(64),
            "--target",
            target.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("refusing to write"), "stderr: {stderr}");
    assert!(!target.exists(), "the disk must not be touched");
}

#[test]
fn maas_flash_accepts_serial_whitelist_on_regular_file_target() {
    // Regular-file targets (CI, staging) bypass the block-device
    // specimen gate; the whitelist flag must still parse and not change
    // the outcome. Block-device gating is unit-covered in
    // conwrt-local-std::specimen (no USB devices in CI).
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("img.img");
    let target = dir.path().join("disk.img");
    std::fs::write(&image, IMAGE).unwrap();

    let out = conwrt()
        .args([
            "maas",
            "flash",
            "--image",
            image.to_str().unwrap(),
            "--sha256",
            &sha256_hex(),
            "--target",
            target.to_str().unwrap(),
            "--serial-whitelist",
            "LAB-USB-001,LAB-USB-002",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&target).unwrap(), IMAGE);
}

#[test]
fn maas_vm_list_prints_region_machines() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/MAAS/api/2.0/machines/");
        then.status(200).json_body(json!([
            machine_json("sys-1", "Ready"),
            machine_json("sys-2", "Deployed"),
        ]));
    });

    let out = conwrt()
        .args([
            "maas",
            "vm",
            "list",
            "--region",
            &format!("{}/MAAS/api/2.0", server.base_url()),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("sys-1"), "stdout: {stdout}");
    assert!(stdout.contains("Deployed"), "stdout: {stdout}");
}

#[test]
fn maas_vm_create_runs_the_verb_chain_and_reports_bounded_polling() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST)
            .path("/MAAS/api/2.0/vm-hosts/7/op-compose");
        then.status(200)
            .json_body(machine_json("sys-1", "Commissioning"));
    });
    let machine = server.mock(|when, then| {
        when.method(GET).path("/MAAS/api/2.0/machines/sys-1/");
        then.status(200).json_body(machine_json("sys-1", "Ready"));
    });
    server.mock(|when, then| {
        when.method(POST)
            .path("/MAAS/api/2.0/machines/")
            .query_param("op", "allocate")
            .body_contains("name=vm-sys-1");
        then.status(200)
            .json_body(machine_json("sys-1", "Allocated"));
    });
    server.mock(|when, then| {
        when.method(POST)
            .path("/MAAS/api/2.0/machines/sys-1/")
            .query_param("op", "deploy");
        then.status(200).json_body(json!({}));
    });

    // machine() always reports Ready → stage-2 (await Deployed) hits the
    // bound (static mock bodies cannot sequence two lifecycle answers).
    let out = conwrt()
        .args([
            "maas",
            "vm",
            "create",
            "--name",
            "lab-vm-1",
            "--region",
            &format!("{}/MAAS/api/2.0", server.base_url()),
            "--vm-host",
            "7",
            "--poll-ms",
            "1",
            "--max-polls",
            "3",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("never reached Deployed after 3 polls"),
        "stderr: {stderr}"
    );
    machine.assert_hits(5); // 1 (await Ready) + 1 (allocate name lookup) + 3 (bounded await Deployed)
}

#[test]
fn maas_vm_destroy_deletes_ready_machine_without_release() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/MAAS/api/2.0/machines/sys-1/");
        then.status(200).json_body(machine_json("sys-1", "Ready"));
    });
    let release = server.mock(|when, then| {
        when.method(POST)
            .path("/MAAS/api/2.0/machines/sys-1/")
            .query_param("op", "release");
        then.status(200).json_body(json!({}));
    });
    server.mock(|when, then| {
        when.method(DELETE).path("/MAAS/api/2.0/machines/sys-1/");
        then.status(200).json_body(json!({}));
    });

    let out = conwrt()
        .args([
            "maas",
            "vm",
            "destroy",
            "--system-id",
            "sys-1",
            "--region",
            &format!("{}/MAAS/api/2.0", server.base_url()),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("destroyed: sys-1"), "stdout: {stdout}");
    release.assert_hits(0);
}

#[test]
fn maas_flash_img_xz_is_decompressed_not_written_compressed() {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let raw = b"decompressed lab image bytes: not an xz stream, a partition table lives here";
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    use std::io::Write as _;
    encoder.write_all(raw).unwrap();
    let archive = encoder.finish().unwrap();
    let image = dir.path().join("img.img.xz");
    std::fs::write(&image, &archive).unwrap();
    let target = dir.path().join("disk.img");

    let archive_sha: String = Sha256::digest(&archive)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let out = conwrt()
        .args([
            "maas",
            "flash",
            "--image",
            image.to_str().unwrap(),
            "--sha256",
            &archive_sha,
            "--target",
            target.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(&target).unwrap(),
        raw,
        "the DECOMPRESSED image must land on the target"
    );
}

#[test]
fn maas_flash_wrong_checksum_on_xz_archive_refuses_before_write() {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let raw = b"decompressed lab image bytes";
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    use std::io::Write as _;
    encoder.write_all(raw).unwrap();
    let archive = encoder.finish().unwrap();
    let image = dir.path().join("img.img.xz");
    std::fs::write(&image, &archive).unwrap();
    let target = dir.path().join("disk.img");

    let wrong_sha: String = Sha256::digest(b"not the archive")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let out = conwrt()
        .args([
            "maas",
            "flash",
            "--image",
            image.to_str().unwrap(),
            "--sha256",
            &wrong_sha,
            "--target",
            target.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(
        !target.exists(),
        "nothing written on archive checksum mismatch"
    );
}

#[test]
fn maas_flash_network_config_alone_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("img.img");
    let nc = dir.path().join("network-config");
    std::fs::write(&image, IMAGE).unwrap();
    std::fs::write(&nc, "network: {}").unwrap();

    let out = conwrt()
        .args([
            "maas",
            "flash",
            "--image",
            image.to_str().unwrap(),
            "--sha256",
            &sha256_hex(),
            "--target",
            dir.path().join("d.img").to_str().unwrap(),
            "--network-config",
            nc.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "--network-config without the seed pair must be rejected"
    );
}

#[test]
fn maas_flash_unreadable_network_config_exits_cleanly_not_panicking() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("img.img");
    let ud = dir.path().join("user-data");
    let md = dir.path().join("meta-data");
    std::fs::write(&image, IMAGE).unwrap();
    std::fs::write(&ud, "#cloud-config\n").unwrap();
    std::fs::write(&md, "instance-id: x").unwrap();

    let out = conwrt()
        .args([
            "maas",
            "flash",
            "--image",
            image.to_str().unwrap(),
            "--sha256",
            &sha256_hex(),
            "--target",
            dir.path().join("d.img").to_str().unwrap(),
            "--user-data",
            ud.to_str().unwrap(),
            "--meta-data",
            md.to_str().unwrap(),
            "--network-config",
            dir.path().join("no-such-network-config").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "controlled exit 2, stderr: {stderr}"
    );
    assert!(stderr.contains("cannot read network-config"), "{stderr}");
}
