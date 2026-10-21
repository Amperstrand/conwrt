//! Specimen gate for the MAAS flash path (issue #302): the Rust port of
//! `scripts/maas_flash.py::verify_disk`. Before a destructive write to a
//! block device, the CLI must gather identity evidence (transport,
//! serial, size, read-only state, mountpoints) and refuse anything that
//! is not a verified, unmounted, writable USB disk — AGENTS.md's
//! specimen/serial gates made mechanical.
//!
//! CI-provable part: [`check_disk_identity`] is a pure decision over a
//! gathered [`DiskIdentity`] (unit-tested below). The gathering
//! ([`verify_disk`]) shells out to `lsblk` and reads sysfs — lab-side
//! system utilities, same honesty split as [`crate::block`].

use std::path::Path;
use std::process::Command;

/// The evidence one disk must present before a destructive write.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiskIdentity {
    /// Transport from `lsblk -o TRAN` (`usb`, `sata`, …).
    pub transport: Option<String>,
    /// Serial from `lsblk -o SERIAL`.
    pub serial: Option<String>,
    /// Size in bytes from sysfs (`/sys/block/<dev>/size` × 512).
    pub size_bytes: Option<u64>,
    /// Read-only flag from sysfs (`/sys/block/<dev>/ro`).
    pub read_only: Option<bool>,
    /// Non-empty mountpoints from `lsblk -o MOUNTPOINTS`.
    pub mountpoints: Vec<String>,
}

/// Minimum writable disk the lab recipe accepts (30 GB, as the Python
/// original).
pub const MIN_DISK_BYTES: u64 = 30_000_000_000;

/// Pure gate: does this identity describe a disk we may overwrite?
/// `allowed_serials` MUST be non-empty — a missing specimen identity is
/// a refusal, not a pass (AGENTS.md specimen/serial gates). Refusals
/// are `ABORT: …` messages, mirroring `verify_disk`.
pub fn check_disk_identity(
    dev: &Path,
    id: &DiskIdentity,
    allowed_serials: &[String],
) -> Result<(), String> {
    match id.transport.as_deref() {
        Some("usb") => {}
        other => {
            return Err(format!(
                "ABORT: {} transport is {}, not USB",
                dev.display(),
                other.unwrap_or("unknown")
            ));
        }
    }

    if allowed_serials.is_empty() {
        return Err(format!(
            "ABORT: no serial whitelist given for {} — block-device targets need explicit \
             specimen identity (--serial-whitelist)",
            dev.display()
        ));
    }
    match id.serial.as_deref() {
        Some(s) if allowed_serials.iter().any(|a| a == s) => {}
        Some(s) => {
            return Err(format!(
                "ABORT: serial {s:?} not in whitelist {allowed_serials:?}"
            ));
        }
        None => return Err("ABORT: no serial reported, whitelist given".to_string()),
    }

    let size = id.size_bytes.ok_or_else(|| {
        format!(
            "ABORT: cannot determine size of {} (no /sys/block entry)",
            dev.display()
        )
    })?;
    if size < MIN_DISK_BYTES {
        return Err(format!(
            "ABORT: {} too small ({}GB, need ≥{}GB)",
            dev.display(),
            size / 1_000_000_000,
            MIN_DISK_BYTES / 1_000_000_000
        ));
    }

    match id.read_only {
        Some(false) => {}
        Some(true) => return Err(format!("ABORT: {} is read-only", dev.display())),
        None => {
            return Err(format!(
                "ABORT: cannot determine read-only state of {} (no /sys/block entry)",
                dev.display()
            ));
        }
    }

    if !id.mountpoints.is_empty() {
        return Err(format!(
            "ABORT: {} has mounted filesystems: {}",
            dev.display(),
            id.mountpoints.join(" ")
        ));
    }

    Ok(())
}

/// Gather `dev`'s identity (lsblk + sysfs) and run [`check_disk_identity`].
/// On success the verified identity is returned for the evidence trail.
/// `allowed_serials` must be non-empty.
pub fn verify_disk(dev: &Path, allowed_serials: &[String]) -> Result<DiskIdentity, String> {
    let identity = gather_identity(dev)?;
    check_disk_identity(dev, &identity, allowed_serials)?;
    Ok(identity)
}

/// Parse one `lsblk --pairs` line (`KEY="VALUE" KEY="VALUE"`) into pairs.
/// `--pairs` keeps values with spaces intact — raw column output would
/// split a serial like `USB SERIAL 001` into unattributable fields.
fn parse_lsblk_pairs(line: &str) -> Vec<(String, String)> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b' ' {
            i += 1;
            continue;
        }
        let key_start = i;
        while i < b.len() && b[i] != b'=' {
            i += 1;
        }
        if i + 1 >= b.len() || b[i + 1] != b'"' {
            break;
        }
        let key = line[key_start..i].to_string();
        i += 2;
        let val_start = i;
        while i < b.len() && b[i] != b'"' {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        out.push((key, line[val_start..i].to_string()));
        i += 1;
    }
    out
}

fn gather_identity(dev: &Path) -> Result<DiskIdentity, String> {
    let pairs = parse_lsblk_pairs(&lsblk_pairs(dev, "TRAN,SERIAL")?);
    let get = |k: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    let transport = get("TRAN");
    let serial = get("SERIAL");

    // No `-d` here on purpose: with it, lsblk prints only the whole-disk
    // row and a mounted child partition's mountpoint is invisible — the
    // gate would pass a mounted disk. Without it, every row of the
    // device's tree contributes its non-empty MOUNTPOINTS cell.
    let mountpoints = lsblk_tree(dev, "MOUNTPOINTS")?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();

    // /dev/sdb → sdb; partition nodes (sdb1) have no /sys/block entry of
    // their own and are refused by the unknown-size gate below.
    let Some(base) = dev.file_name().and_then(|n| n.to_str()) else {
        return Err(format!(
            "ABORT: cannot derive sysfs name from {}",
            dev.display()
        ));
    };
    let size_bytes =
        read_sysfs_u64(&format!("/sys/block/{base}/size")).map(|sectors| sectors * 512);
    let read_only = read_sysfs_u64(&format!("/sys/block/{base}/ro")).map(|ro| ro == 1);

    Ok(DiskIdentity {
        transport,
        serial,
        size_bytes,
        read_only,
        mountpoints,
    })
}

fn read_sysfs_u64(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn lsblk_pairs(dev: &Path, columns: &str) -> Result<String, String> {
    let out = Command::new("lsblk")
        .arg("-dn")
        .arg("--pairs")
        .arg("-o")
        .arg(columns)
        .arg(dev)
        .output()
        .map_err(|e| format!("verify_disk needs the `lsblk` utility: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "lsblk failed for {}: {}",
            dev.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Whole-device tree (children included): `-n -o COLUMNS` without `-d`.
fn lsblk_tree(dev: &Path, columns: &str) -> Result<String, String> {
    let out = Command::new("lsblk")
        .arg("-n")
        .arg("-o")
        .arg(columns)
        .arg(dev)
        .output()
        .map_err(|e| format!("verify_disk needs the `lsblk` utility: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "lsblk failed for {}: {}",
            dev.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_identity() -> DiskIdentity {
        DiskIdentity {
            transport: Some("usb".into()),
            serial: Some("USB SERIAL 001".into()),
            size_bytes: Some(61_999_001_792),
            read_only: Some(false),
            mountpoints: Vec::new(),
        }
    }

    fn whitelisted() -> Vec<String> {
        vec!["USB SERIAL 001".to_string()]
    }

    #[test]
    fn verified_usb_disk_passes() {
        assert_eq!(
            check_disk_identity(Path::new("/dev/sdb"), &ok_identity(), &whitelisted()),
            Ok(())
        );
    }

    #[test]
    fn empty_whitelist_is_refused() {
        let msg = check_disk_identity(Path::new("/dev/sdb"), &ok_identity(), &[]).unwrap_err();
        assert!(
            msg.starts_with("ABORT:") && msg.contains("--serial-whitelist"),
            "{msg}"
        );
    }

    #[test]
    fn non_usb_transport_is_refused() {
        let mut id = ok_identity();
        for tran in ["sata", "nvme", "virtio"] {
            id.transport = Some(tran.into());
            let msg = check_disk_identity(Path::new("/dev/sdb"), &id, &whitelisted()).unwrap_err();
            assert!(msg.starts_with("ABORT:") && msg.contains(tran), "{msg}");
        }
    }

    #[test]
    fn unknown_transport_is_refused() {
        let mut id = ok_identity();
        id.transport = None;
        let msg = check_disk_identity(Path::new("/dev/sdb"), &id, &whitelisted()).unwrap_err();
        assert!(msg.contains("not USB"), "{msg}");
    }

    #[test]
    fn serial_outside_whitelist_is_refused() {
        let msg = check_disk_identity(Path::new("/dev/sdb"), &ok_identity(), &["other".into()])
            .unwrap_err();
        assert!(
            msg.starts_with("ABORT:") && msg.contains("whitelist"),
            "{msg}"
        );
    }

    #[test]
    fn serial_must_be_present_when_whitelist_is_given() {
        let mut id = ok_identity();
        id.serial = None;
        assert!(
            check_disk_identity(Path::new("/dev/sdb"), &id, &whitelisted()).is_err(),
            "no serial is not evidence"
        );
    }

    #[test]
    fn too_small_disk_is_refused() {
        let mut id = ok_identity();
        id.size_bytes = Some(MIN_DISK_BYTES - 1);
        let msg = check_disk_identity(Path::new("/dev/sdb"), &id, &whitelisted()).unwrap_err();
        assert!(
            msg.starts_with("ABORT:") && msg.contains("too small"),
            "{msg}"
        );
    }

    #[test]
    fn unknown_size_is_refused() {
        let mut id = ok_identity();
        id.size_bytes = None;
        let msg = check_disk_identity(Path::new("/dev/sdb"), &id, &whitelisted()).unwrap_err();
        assert!(msg.contains("size"), "{msg}");
    }

    #[test]
    fn read_only_disk_is_refused() {
        let mut id = ok_identity();
        id.read_only = Some(true);
        let msg = check_disk_identity(Path::new("/dev/sdb"), &id, &whitelisted()).unwrap_err();
        assert!(
            msg.starts_with("ABORT:") && msg.contains("read-only"),
            "{msg}"
        );
    }

    #[test]
    fn unknown_read_only_state_is_refused() {
        let mut id = ok_identity();
        id.read_only = None;
        assert!(check_disk_identity(Path::new("/dev/sdb"), &id, &whitelisted()).is_err());
    }

    #[test]
    fn mounted_disk_is_refused() {
        let mut id = ok_identity();
        id.mountpoints = vec!["/media/ubuntu/labdisk".into()];
        let msg = check_disk_identity(Path::new("/dev/sdb"), &id, &whitelisted()).unwrap_err();
        assert!(
            msg.starts_with("ABORT:") && msg.contains("mounted"),
            "{msg}"
        );
    }
}

#[cfg(test)]
mod pairs_tests {
    use super::parse_lsblk_pairs;

    #[test]
    fn parses_single_pair() {
        assert_eq!(
            parse_lsblk_pairs(r#"TRAN="usb""#),
            vec![("TRAN".to_string(), "usb".to_string())]
        );
    }

    #[test]
    fn keeps_spaces_inside_values() {
        assert_eq!(
            parse_lsblk_pairs(r#"TRAN="usb" SERIAL="USB SERIAL 001""#),
            vec![
                ("TRAN".to_string(), "usb".to_string()),
                ("SERIAL".to_string(), "USB SERIAL 001".to_string()),
            ]
        );
    }

    #[test]
    fn empty_value_is_preserved() {
        assert_eq!(
            parse_lsblk_pairs(r#"TRAN="usb" SERIAL="""#),
            vec![
                ("TRAN".to_string(), "usb".to_string()),
                ("SERIAL".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn garbage_stops_instead_of_misparsing() {
        assert!(parse_lsblk_pairs("not pairs at all").is_empty());
        assert!(parse_lsblk_pairs(r#"KEY="unterminated"#).is_empty());
    }
}
