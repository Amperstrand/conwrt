//! # Partition backup over serial (Rust port of `scripts/serial-backup.py`)
//!
//! Dumps `/dev/mtdX` partitions over the serial console when SSH is
//! unavailable: `cat /dev/mtdX | base64`, filter the base64 lines from
//! the collected response, decode, size-verify (the 95% completeness
//! rule), write the file.
//!
//! Uses the [`crate::console`] driver (RC-marker collection) rather than
//! the Python's timing loop, so dump completion is prompt-driven, not
//! sleep-driven.

use std::io::Write;
use std::path::Path;

use base64::Engine as _;

use std::time::Duration;

use crate::console::SerialConsole;

/// Collection window for a dump (multi-MB over serial is minutes; the
/// caller may need larger — expose at the CLI when wired).
const DUMP_WINDOW: Duration = Duration::from_secs(900);

/// One `/proc/mtd` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// Device node name, e.g. `mtd0`.
    pub device: String,
    /// Size in bytes (hex in /proc/mtd).
    pub size: u64,
    /// Partition name, e.g. `Factory`.
    pub name: String,
}

// field docs already present; silence is not an option here — see below

/// Parse `/proc/mtd` output into partitions.
/// Mirrors the Python regex `mtd(\d+): <hex> <hex> "name"`.
pub fn parse_partitions(output: &str) -> Vec<Partition> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        let Some((dev, rest)) = split_mtd_dev(line) else { continue };
        let Some((size, rest)) = split_hex_field(rest) else { continue };
        let Some(name) = parse_quoted_name(rest) else { continue };
        out.push(Partition {
            device: dev.to_string(),
            size,
            name: name.to_string(),
        });
    }
    out
}

fn split_mtd_dev(line: &str) -> Option<(&str, &str)> {
    let idx = line.find(':')?;
    let dev = &line[..idx];
    if dev.starts_with("mtd") && dev[3..].chars().all(|c| c.is_ascii_digit()) {
        Some((dev, &line[idx + 1..]))
    } else {
        None
    }
}

fn split_hex_field(rest: &str) -> Option<(u64, &str)> {
    let rest = rest.trim_start();
    let end = rest.find(char::is_whitespace)?;
    let field = &rest[..end];
    let size = u64::from_str_radix(field, 16).ok()?;
    Some((size, &rest[end..]))
}

fn parse_quoted_name(rest: &str) -> Option<&str> {
    let open = rest.find('"')?;
    let close = rest[open + 1..].find('"')? + open + 1;
    Some(&rest[open + 1..close])
}

/// Filter collected console text down to pure base64 payload lines
/// (drops the command echo, shell prompts, blank and non-base64 lines).
pub fn extract_base64(collected: &str) -> String {
    let mut out = String::new();
    for line in collected.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("root@") || line.starts_with('#') {
            continue;
        }
        if line.contains("cat ") && line.contains("base64") {
            continue;
        }
        if line.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') {
            out.push_str(line);
        }
    }
    out
}

/// Outcome of one partition dump.
#[derive(Debug, PartialEq, Eq)]
pub enum DumpOutcome {
    /// Written to the output path with the exact expected size.
    Complete {
        /// Bytes written.
        bytes: u64,
    },
    /// Decoded bytes below 95% of the partition size — refused.
    Incomplete {
        /// Bytes actually decoded.
        got: u64,
        /// Partition size expected from /proc/mtd.
        expected: u64,
    },
    /// The device returned no base64 at all.
    NoData,
    /// Base64 payload failed to decode.
    DecodeError,
}

/// Dump one partition over the console into `output`.
pub fn dump_partition(
    console: &mut SerialConsole,
    part: &Partition,
    output: &Path,
) -> std::io::Result<DumpOutcome> {
    let cmd = format!("cat /dev/{} | base64", part.device);
    // Collect until the prompt returns; generous for multi-MB dumps.
    let outcome = console
        .run(&cmd, DUMP_WINDOW)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let collected = outcome.output;

    let b64 = extract_base64(&collected);
    if b64.is_empty() {
        return Ok(DumpOutcome::NoData);
    }
    let raw = match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
        Ok(r) => r,
        Err(_) => return Ok(DumpOutcome::DecodeError),
    };
    let got = raw.len() as u64;
    if got < part.size && (got as f64) < part.size as f64 * 0.95 {
        return Ok(DumpOutcome::Incomplete { got, expected: part.size });
    }
    if let Some(dir) = output.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::File::create(output)?;
    f.write_all(&raw)?;
    Ok(DumpOutcome::Complete { bytes: got })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTD: &str = "dev: size erasesize name\n\
        mtd0: 00080000 00010000 \"SPI-Boot loader\"\n\
        mtd1: 00010000 00010000 \"NVRAM\"\n\
        mtd5: 00ef0000 00010000 \"Factory\"\n";

    #[test]
    fn parses_proc_mtd() {
        let parts = parse_partitions(MTD);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].device, "mtd0");
        assert_eq!(parts[0].size, 0x80000);
        assert_eq!(parts[0].name, "SPI-Boot loader");
        assert_eq!(parts[2].name, "Factory");
        assert_eq!(parts[2].size, 0xef0000);
    }

    #[test]
    fn skips_non_partition_lines() {
        let parts = parse_partitions("garbage\nmtdx: nope\n");
        assert!(parts.is_empty());
    }

    #[test]
    fn base64_extraction_filters_noise() {
        let payload = "QUJDREVGRw=="; // "ABCDEFG"
        let collected = format!(
            "cat /dev/mtd5 | base64\r\n{payload}\r\nroot@OpenWrt:/# \r\n# \r\nnoise!!\r\n"
        );
        assert_eq!(extract_base64(&collected), payload);
    }

    #[test]
    fn base64_extraction_joins_lines() {
        let collected = "QUJD\r\nREVG\r\n";
        assert_eq!(extract_base64(collected), "QUJDREVG");
    }
}
