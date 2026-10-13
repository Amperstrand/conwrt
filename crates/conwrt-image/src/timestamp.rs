//! Minimal UTC timestamp formatting without a datetime dependency.
//!
//! firmware-manager.py writes `downloaded_at` as
//! `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")`. This module
//! reproduces that exact format from `SystemTime` using the well-known
//! days-to-civil algorithm (Howard Hinnant), keeping the crate free of a
//! chrono/jiff dependency for one timestamp field.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current UTC time formatted as `YYYY-MM-DDTHH:MM:SS`.
pub fn utc_now() -> String {
    format_epoch(SystemTime::now())
}

/// Formats a `SystemTime` as `YYYY-MM-DDTHH:MM:SS` (UTC).
///
/// Times before the Unix epoch clamp to the epoch, matching the practical
/// domain of cache metadata.
pub fn format_epoch(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_epoch_secs(secs)
}

/// Formats seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SS` (UTC).
pub fn format_epoch_secs(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Converts days since 1970-01-01 to a proleptic-Gregorian `(y, m, d)`
/// triple. Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Goldens produced with python3:
    // datetime.fromtimestamp(n, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    #[test]
    fn formats_match_python_goldens() {
        assert_eq!(format_epoch_secs(0), "1970-01-01T00:00:00");
        assert_eq!(format_epoch_secs(1_760_000_000), "2025-10-09T08:53:20");
        // Leap day.
        assert_eq!(format_epoch_secs(951_782_400), "2000-02-29T00:00:00");
        // Century boundary (2100 is not a leap year).
        assert_eq!(format_epoch_secs(4_102_444_800), "2100-01-01T00:00:00");
    }

    #[test]
    fn format_epoch_accepts_systemtime() {
        let t = UNIX_EPOCH + Duration::from_secs(1_760_000_000);
        assert_eq!(format_epoch(t), "2025-10-09T08:53:20");
    }

    #[test]
    fn utc_now_is_well_formed() {
        let now = utc_now();
        assert_eq!(now.len(), 19);
        assert_eq!(&now[4..5], "-");
        assert_eq!(&now[10..11], "T");
        assert_eq!(&now[16..17], ":");
    }
}
