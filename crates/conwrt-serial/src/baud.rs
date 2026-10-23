//! # Baud rate detection and boot stage identification (Rust port of
//! `scripts/serial_baud.py`)
//!
//! Extracted from the Python for testability; scoring algorithm based on
//! ComScope and baudowl auto-baud research (three metrics: printable-ASCII
//! ratio, known boot-pattern matches, byte-distribution entropy + error
//! byte penalties). Pure functions — no I/O — so the Python and Rust
//! versions are directly parity-testable.

/// Boot stage signature table (byte patterns per stage).
const BOOT_SIGNATURES: &[(&str, &[&[u8]])] = &[
    (
        "uboot",
        &[
            b"U-Boot",
            b"u-boot",
            b"Bootloader",
            b"bootmenu",
            b"Hit any key to stop autoboot",
            b"Net:   ",
            b"eth0: ",
            b"ethaddr=",
        ],
    ),
    (
        "zloader",
        &[
            b"Z-Loader",
            b"Z-LOADER",
            b"ZyNOS",
            b"BootBase",
            b"Multiboot",
            b"Press ENTER to debug mode",
            b"multiboot listening",
            b"Multiboot Listening",
        ],
    ),
    (
        "kernel",
        &[
            b"[    0.000000] Linux version",
            b"Starting kernel",
            b"Booting Linux",
            b"Decompressing Linux",
        ],
    ),
    (
        "openwrt",
        &[b"OpenWrt", b"LEDE", b"BusyBox", b"root@OpenWrt"],
    ),
];

/// Detect the boot stage from a byte sample; keeps `current` when nothing
/// matches (stage transitions are sticky, like the Python).
pub fn detect_boot_stage(data: &[u8], current: &str) -> String {
    for (stage, patterns) in BOOT_SIGNATURES {
        for p in *patterns {
            if contains(data, p) {
                return (*stage).to_string();
            }
        }
    }
    current.to_string()
}

/// Common baud rates for router bootloaders, ranked by frequency.
pub const COMMON_BAUDS: &[u32] = &[
    115_200, 57_600, 38_400, 9_600, 19_200, 4_800, 230_400, 460_800, 921_600,
];

/// Known boot patterns that indicate a correct baud rate.
const BOOT_PATTERNS: &[&[u8]] = &[
    b"U-Boot",
    b"u-boot",
    b"uboot",
    b"Z-Loader",
    b"Z-LOADER",
    b"ZyNOS",
    b"BootBase",
    b"Linux version",
    b"Starting kernel",
    b"Booting",
    b"OpenWrt",
    b"LEDE",
    b"BusyBox",
    b"Decompressing",
    b"Loading",
    b"\r\n",
];

fn is_printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || matches!(b, 0x0a | 0x0d | 0x08 | 0x09)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len().max(1)).any(|w| w == needle)
}

/// Score received data for likelihood of being valid at the current baud.
/// Returns `(score, human_reason)` — higher is better.
pub fn score_baud_data(data: &[u8]) -> (u32, String) {
    if data.is_empty() {
        return (0, "no data".to_string());
    }
    let total = data.len() as f64;
    let printable = data.iter().filter(|&&b| is_printable(b)).count() as f64;
    let ascii_ratio = printable / total;

    let pattern_hits = BOOT_PATTERNS.iter().filter(|&&p| contains(data, p)).count();

    // byte-distribution entropy
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / total;
            entropy -= p * p.log2();
        }
    }

    let nulls = counts[0] as usize;
    let ffs = counts[255] as usize;
    let high_bit = data.iter().filter(|&&b| (0x80..=0xfe).contains(&b)).count();

    let mut max_run = 0usize;
    let mut run = 0usize;
    for &b in data {
        if is_printable(b) {
            run += 1;
            max_run = max_run.max(run);
        } else {
            run = 0;
        }
    }
    let has_newlines = data.contains(&b'\n') || data.contains(&b'\r');

    let mut score = 0i32;
    score += (ascii_ratio * 100.0) as i32;
    score += pattern_hits as i32 * 50;
    if entropy < 5.0 {
        score += ((5.0 - entropy) * 20.0) as i32;
    }
    if max_run > 6 {
        score += 20;
    }
    if has_newlines {
        score += 15;
    }
    if nulls > 0 {
        score -= (80.0 * (nulls as f64 / total)) as i32;
    }
    if ffs > 0 {
        score -= (80.0 * (ffs as f64 / total)) as i32;
    }
    if ascii_ratio < 0.5 {
        score -= 40;
    }
    if high_bit as f64 > total * 0.1 {
        score -= 20;
    }

    let score = score.max(0) as u32;
    let reason = format!(
        "ascii={:.0}%, patterns={}, entropy={:.1}, nulls={}, run={}",
        ascii_ratio * 100.0,
        pattern_hits,
        entropy,
        nulls,
        max_run
    );
    (score, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_detection() {
        assert_eq!(detect_boot_stage(b"U-Boot 2016.07", "unknown"), "uboot");
        assert_eq!(detect_boot_stage(b"Starting kernel ...", "uboot"), "kernel");
        assert_eq!(detect_boot_stage(b"root@OpenWrt:~#", "kernel"), "openwrt");
        assert_eq!(detect_boot_stage(b"garbage", "sticky"), "sticky");
    }

    #[test]
    fn scoring_prefers_clean_console_text() {
        let good = b"U-Boot 2016.07\r\nNet:   eth0 \r\n";
        let bad = [0x00u8, 0xff, 0x92, 0x37, 0x00, 0xff, 0xab, 0x13];
        let (gs, _) = score_baud_data(good);
        let (bs, _) = score_baud_data(&bad);
        assert!(gs > bs, "good {gs} should beat bad {bs}");
        assert!(gs > 100, "clean console text scores high, got {gs}");
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(score_baud_data(b"").0, 0);
    }
}
