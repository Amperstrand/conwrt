//! Partition backup over serial — the Rust port of
//! `scripts/serial-backup.py` (parity-matrix §5), for dumping flash
//! partitions when SSH is unavailable. Factory/calibration dumps are
//! IRREPLACEABLE: this path exists so they can be taken over a serial
//! console before any flash operation (AGENTS.md).
//!
//! Python parity notes:
//!
//! * `cat /proc/mtd` parsing ([`parse_proc_mtd`]) is byte-faithful:
//!   `mtd12: 00080000 00080000 "Factory"`
//! * The dump rides the RC-marker collector (`cat /dev/mtdX | base64`
//!   plus the `__RC0__` tail) instead of the Python "read until the
//!   prompt looks like base64" heuristic — collection ends at the
//!   device's own completion marker, then the base64 lines are decoded
//!   per line (exactly what BusyBox `base64` emitted per line).
//! * The Python size discipline is kept: an exact-size dump is clean;
//!   below [`INCOMPLETE_FRACTION`] (95%) of the partition size is a
//!   typed failure (the dump is useless); 95–100% is returned with
//!   the mismatch recorded (Python printed ⚠ and kept the file).
//! * Factory is the default target ("most critical", Python parity);
//!   partition-name matching is case-insensitive.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use thiserror::Error;

use crate::collect::CmdOutcome;
use crate::console::{PortOpener, SerialConsole, Sleeper};
use crate::io::ConsoleError;

/// Below this fraction of the partition size a dump is rejected as
/// incomplete (Python's 0.95 threshold).
pub const INCOMPLETE_FRACTION: f64 = 0.95;

/// BusyBox `base64` wraps at 76 chars ⇒ 57 raw bytes per line; the
/// Python estimator used ~48 B/line at 50 ms/line — kept for the
/// timeout budget only.
const EST_BYTES_PER_LINE: f64 = 48.0;
const EST_SECONDS_PER_LINE: f64 = 0.05;

/// One `/proc/mtd` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// Device node basename, e.g. `mtd12` (dumped as `/dev/mtd12`).
    pub device: String,
    /// Partition size in bytes (hex in `/proc/mtd`).
    pub size: u64,
    /// Quoted partition name, e.g. `Factory`.
    pub name: String,
}

/// Why a backup failed. Messages are operator-safe.
#[derive(Debug, Error)]
pub enum BackupError {
    /// Transport failure.
    #[error(transparent)]
    Console(#[from] ConsoleError),
    /// `cat /proc/mtd` did not complete with rc 0.
    #[error("reading /proc/mtd failed (rc {rc}): {output}")]
    ProcMtdFailed {
        /// The collected rc.
        rc: u8,
        /// Collected console output.
        output: String,
    },
    /// The reply parsed to zero partitions (wrong device? not Linux?).
    #[error("could not parse /proc/mtd reply: {raw:?}")]
    NoPartitions {
        /// The raw collected output.
        raw: String,
    },
    /// No partition matched the requested name.
    #[error("partition {requested:?} not found in: {available}")]
    PartitionNotFound {
        /// The requested (case-insensitive) name.
        requested: String,
        /// The partition names that exist.
        available: String,
    },
    /// No `Factory` partition exists and no explicit selection was
    /// given (Python parity: the default target is Factory).
    #[error("no Factory partition found — use an explicit partition or --all semantics")]
    NoFactory,
    /// The dump command failed on the device.
    #[error("dumping {device} failed (rc {rc}): {output}")]
    DumpFailed {
        /// The device that failed, e.g. `mtd12`.
        device: String,
        /// The collected rc.
        rc: u8,
        /// Collected console output.
        output: String,
    },
    /// The captured base64 stream did not decode (corrupt capture).
    #[error("base64 decode of {device} dump failed: {source}")]
    DecodeFailed {
        /// The device being dumped.
        device: String,
        /// The decode error.
        #[source]
        source: base64::DecodeError,
    },
    /// Less than 95% of the partition size arrived — the dump is
    /// incomplete and was NOT written.
    #[error(
        "dump of {device} incomplete: {got} of {expected} bytes ({pct:.1}%) — file NOT written"
    )]
    Incomplete {
        /// The device being dumped.
        device: String,
        /// Bytes actually captured.
        got: u64,
        /// The partition size from `/proc/mtd`.
        expected: u64,
        /// The coverage percentage.
        pct: f64,
    },
    /// The dump file could not be written on the host.
    #[error("cannot write dump {path}: {source}")]
    DumpFile {
        /// The host path that failed.
        path: PathBuf,
        /// The underlying write error.
        #[source]
        source: std::io::Error,
    },
}

/// A completed partition dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpOutcome {
    /// The partition that was dumped.
    pub partition: Partition,
    /// Decoded bytes written.
    pub bytes: u64,
    /// `Some((expected, actual))` when the size did not match exactly
    /// but stayed within the 95% threshold (Python's ⚠-and-keep).
    pub size_mismatch: Option<(u64, u64)>,
    /// Where the dump landed (`<output_dir>/<name>.bin`).
    pub path: PathBuf,
}

/// Parse `/proc/mtd` output (`mtd12: 00080000 00080000 "Factory"`).
/// Pure, no regex — the Python `re` match ported by hand.
#[must_use]
pub fn parse_proc_mtd(output: &str) -> Vec<Partition> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("mtd") else {
            continue;
        };
        let Some(colon) = rest.find(':') else {
            continue;
        };
        let device = format!("mtd{}", &rest[..colon]);
        let mut fields = rest[colon + 1..].split_whitespace();
        let (Some(size_hex), Some(_erase_hex), Some(name_field)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Some(inner) = name_field
            .strip_prefix('"')
            .and_then(|n| n.strip_suffix('"'))
        else {
            continue;
        };
        if let Ok(size) = u64::from_str_radix(size_hex, 16) {
            out.push(Partition {
                device,
                size,
                name: inner.to_string(),
            });
        }
    }
    out
}

/// Which partitions to dump (the Python CLI flags).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupSelection {
    /// `--partition NAME` — case-insensitive name match.
    ByName(String),
    /// `--all`.
    All,
    /// Default: Factory only ("most critical", IRREPLACEABLE).
    FactoryDefault,
}

/// Resolve the dump targets from a partition list. Pure.
///
/// # Errors
/// [`BackupError::PartitionNotFound`] / [`BackupError::NoFactory`] per
/// the Python CLI exits.
pub fn select_targets(
    partitions: &[Partition],
    selection: &BackupSelection,
) -> Result<Vec<Partition>, BackupError> {
    match selection {
        BackupSelection::ByName(name) => {
            let targets: Vec<Partition> = partitions
                .iter()
                .filter(|p| p.name.eq_ignore_ascii_case(name))
                .cloned()
                .collect();
            if targets.is_empty() {
                return Err(BackupError::PartitionNotFound {
                    requested: name.clone(),
                    available: partitions
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                });
            }
            Ok(targets)
        }
        BackupSelection::All => Ok(partitions.to_vec()),
        BackupSelection::FactoryDefault => partitions
            .iter()
            .filter(|p| p.name == "Factory")
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .next()
            .map(|p| vec![p])
            .ok_or(BackupError::NoFactory),
    }
}

/// `cat /proc/mtd` and parse the partition table.
///
/// # Errors
/// [`BackupError::ProcMtdFailed`] / [`BackupError::NoPartitions`] /
/// [`BackupError::Console`].
pub fn list_partitions<S: Sleeper, O: PortOpener>(
    console: &mut SerialConsole<S, O>,
    timeout: std::time::Duration,
) -> Result<Vec<Partition>, BackupError> {
    let out: CmdOutcome = console.run("cat /proc/mtd", timeout)?;
    if out.rc != 0 {
        return Err(BackupError::ProcMtdFailed {
            rc: out.rc,
            output: out.output,
        });
    }
    let partitions = parse_proc_mtd(&out.output);
    if partitions.is_empty() {
        return Err(BackupError::NoPartitions { raw: out.output });
    }
    Ok(partitions)
}

/// Extract the pure base64 payload from a collected dump reply:
/// keep only lines that are entirely base64 (the Python line filter —
/// prompt lines, the command echo, and `__RC` markers drop out). Pure.
#[must_use]
pub fn extract_base64_lines(reply: &str) -> Vec<&str> {
    reply
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("root@")
                && !line.starts_with('#')
                && !line.contains("cat ")
                && line
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        })
        .collect()
}

/// Decode the captured BusyBox base64 dump: per-line decode (each line
/// is an independent wrapped segment; only the last line carries
/// padding), concatenated.
///
/// # Errors
/// [`BackupError::DecodeFailed`] on the first malformed line.
pub fn decode_dump_lines(device: &str, lines: &[&str]) -> Result<Vec<u8>, BackupError> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(line.as_bytes())
                .map_err(|source| BackupError::DecodeFailed {
                    device: device.to_string(),
                    source,
                })?,
        );
    }
    Ok(out)
}

/// Timeout budget for a partition dump (Python: `max(30, est × 3)`).
#[must_use]
pub fn dump_timeout(size: u64) -> std::time::Duration {
    let est_lines = size as f64 / EST_BYTES_PER_LINE;
    let est_seconds = est_lines * EST_SECONDS_PER_LINE;
    let seconds = (est_seconds * 3.0).max(30.0);
    std::time::Duration::from_secs(seconds as u64)
}

/// Dump one partition over the console and write `<name>.bin` into
/// `output_dir`. `progress(decoded_bytes, total)` reports the decoded
/// size once the collection completes (the RC collector is opaque to
/// per-chunk progress; the Python ~16 KB cadence applied to its raw
/// read loop).
///
/// # Errors
/// [`BackupError::DumpFailed`] when the device command fails;
/// [`BackupError::DecodeFailed`] / [`BackupError::Incomplete`] /
/// [`BackupError::DumpFile`] / [`BackupError::Console`].
pub fn dump_partition<S: Sleeper, O: PortOpener>(
    console: &mut SerialConsole<S, O>,
    partition: &Partition,
    output_dir: &Path,
    mut progress: impl FnMut(u64, u64),
) -> Result<DumpOutcome, BackupError> {
    let dev_path = format!("/dev/{}", partition.device);
    let cmd = format!("cat {dev_path} | base64");
    let out = console.run(&cmd, dump_timeout(partition.size))?;
    if out.rc != 0 {
        return Err(BackupError::DumpFailed {
            device: partition.device.clone(),
            rc: out.rc,
            output: out.output,
        });
    }
    let lines = extract_base64_lines(&out.output);
    let raw = decode_dump_lines(&partition.device, &lines)?;
    progress(raw.len() as u64, partition.size);

    let got = raw.len() as u64;
    let expected = partition.size;
    if got < expected {
        let fraction = got as f64 / expected as f64;
        if fraction < INCOMPLETE_FRACTION {
            return Err(BackupError::Incomplete {
                device: partition.device.clone(),
                got,
                expected,
                pct: fraction * 100.0,
            });
        }
    }

    std::fs::create_dir_all(output_dir).map_err(|source| BackupError::DumpFile {
        path: output_dir.to_path_buf(),
        source,
    })?;
    let path = output_dir.join(format!("{}.bin", partition.name.to_lowercase()));
    std::fs::write(&path, &raw).map_err(|source| BackupError::DumpFile {
        path: path.clone(),
        source,
    })?;

    Ok(DumpOutcome {
        partition: partition.clone(),
        bytes: got,
        size_mismatch: if got == expected {
            None
        } else {
            Some((expected, got))
        },
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_MTD: &str = "dev:    size   erasesize  name\n\
                            mtd0: 00030000 00010000 \"u-boot\"\n\
                            mtd1: 00030000 00010000 \"u-boot-env\"\n\
                            mtd2: 00080000 00010000 \"Factory\"\n\
                            mtd12: 00200000 00010000 \"firmware\"\n";

    #[test]
    fn parses_proc_mtd_rows() {
        let parts = parse_proc_mtd(PROC_MTD);
        assert_eq!(parts.len(), 4);
        assert_eq!(
            parts[2],
            Partition {
                device: "mtd2".to_string(),
                size: 0x0008_0000,
                name: "Factory".to_string()
            }
        );
        assert_eq!(parts[3].size, 0x0020_0000);
    }

    #[test]
    fn parse_ignores_header_and_noise() {
        let parts = parse_proc_mtd("dev: size erasesize name\njunk line\nmtd9: bad row\n");
        assert!(parts.is_empty());
    }

    #[test]
    fn selection_by_name_is_case_insensitive() {
        let parts = parse_proc_mtd(PROC_MTD);
        let targets = select_targets(&parts, &BackupSelection::ByName("factory".into())).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "Factory");
        let err = select_targets(&parts, &BackupSelection::ByName("nope".into())).unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[test]
    fn selection_factory_default_and_all() {
        let parts = parse_proc_mtd(PROC_MTD);
        assert_eq!(
            select_targets(&parts, &BackupSelection::FactoryDefault)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            select_targets(&parts, &BackupSelection::All).unwrap().len(),
            4
        );
        let no_factory = parse_proc_mtd("mtd0: 00010000 00010000 \"boot\"\n");
        assert!(matches!(
            select_targets(&no_factory, &BackupSelection::FactoryDefault),
            Err(BackupError::NoFactory)
        ));
    }

    #[test]
    fn extract_keeps_only_base64_lines() {
        let reply = "cat /dev/mtd2 | base64\r\n\
                     Qm9vdA==\r\n\
                     cm93Mg==\r\n\
                     root@OpenWrt:~# \r\n__RC0__\r\n";
        assert_eq!(extract_base64_lines(reply), vec!["Qm9vdA==", "cm93Mg=="]);
    }

    #[test]
    fn decode_per_line_concatenates() {
        let decoded = decode_dump_lines("mtd2", &["Qm9vdA==", "cm93Mg=="]).unwrap();
        assert_eq!(decoded, b"Bootrow2");
    }

    #[test]
    fn decode_rejects_garbage_line() {
        assert!(decode_dump_lines("mtd2", &["!!!not-base64!!!"]).is_err());
    }

    #[test]
    fn timeout_floor_is_30s_and_scales() {
        assert_eq!(dump_timeout(1024), std::time::Duration::from_secs(30));
        // 48 MiB partition: 48*2^20/48 = 2^20 lines * 0.05s * 3
        assert_eq!(
            dump_timeout(48 * 1024 * 1024),
            std::time::Duration::from_secs(157_286)
        );
    }
}
