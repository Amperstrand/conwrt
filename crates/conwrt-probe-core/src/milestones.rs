//! Serial boot-milestone detection — the extraction of
//! `scripts/flash/serial_monitor.py`'s `_MILESTONE_PATTERNS` and its
//! [`SerialBootMonitor::_feed`] semantics: each milestone latches ONCE
//! per monitor lifetime, matching runs over a rolling buffer (bytes
//! that arrived split across chunks still match), and the detail is the
//! line carrying the match, stripped and capped.
//!
//! The vocabulary below is species-level and taken verbatim from the
//! source (observed on the AP3915i bench capture referenced there):
//!
//! ```text
//! U-Boot 2012.07.22 (Jul 19 2022 - 10:26:07) (primary)  -> UbootBanner
//! Starting kernel ...                                   -> KernelStart
//! [    3.873775] init: - preinit -                      -> ProcdPreinit
//!    13.054844] procd: - init -                         -> ProcdInit
//! root@OpenWrt:~#                                        -> LoginPrompt
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::vocab::Pattern;

/// One serial boot milestone (the Python `Event::SERIAL_*` milestone
/// set). Wire-shared: the agent protocol reports these verbatim
/// (#215 slice 5), so host and firmware name findings identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootMilestone {
    /// `U-Boot \d` — the bootloader banner.
    UbootBanner,
    /// `Starting kernel` — the bootloader handed off to the kernel.
    KernelStart,
    /// `init: - preinit -` — preinit stage.
    ProcdPreinit,
    /// `(?:init|procd): - init -` — procd init stage.
    ProcdInit,
    /// `root@` — a shell prompt (boot complete).
    LoginPrompt,
}

impl BootMilestone {
    /// Stable machine name (the Python event name, lowercased).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            BootMilestone::UbootBanner => "serial_uboot_banner",
            BootMilestone::KernelStart => "serial_kernel_start",
            BootMilestone::ProcdPreinit => "serial_procd_preinit",
            BootMilestone::ProcdInit => "serial_procd_init",
            BootMilestone::LoginPrompt => "serial_login_prompt",
        }
    }
}

/// The distinct milestones, in vocabulary order (ProcdInit once).
pub const ALL_MILESTONES: &[BootMilestone] = &[
    BootMilestone::UbootBanner,
    BootMilestone::KernelStart,
    BootMilestone::ProcdPreinit,
    BootMilestone::ProcdInit,
    BootMilestone::LoginPrompt,
];

/// The milestone vocabulary, in source order. `procd: - init -` and
/// `init: - init -` are the Python regex alternation split into two
/// literal patterns — both latch the same [`BootMilestone::ProcdInit`]
/// exactly once.
pub const MILESTONE_PATTERNS: &[(Pattern, BootMilestone)] = &[
    (
        Pattern::LiteralThenDigit(b"U-Boot "),
        BootMilestone::UbootBanner,
    ),
    (
        Pattern::Literal(b"Starting kernel"),
        BootMilestone::KernelStart,
    ),
    (
        Pattern::Literal(b"init: - preinit -"),
        BootMilestone::ProcdPreinit,
    ),
    (
        Pattern::Literal(b"init: - init -"),
        BootMilestone::ProcdInit,
    ),
    (
        Pattern::Literal(b"procd: - init -"),
        BootMilestone::ProcdInit,
    ),
    (Pattern::Literal(b"root@"), BootMilestone::LoginPrompt),
];

/// Buffer cap — the source's `_MAX_BUFFER`: console history beyond
/// this is trimmed to [`KEEP_TAIL`] bytes.
pub const MAX_BUFFER: usize = 65_536;
/// Retained tail after a [`MAX_BUFFER`] trim (the source's
/// `_KEEP_TAIL`).
pub const KEEP_TAIL: usize = 32_768;

/// Detail-line cap (the source's `[:120]`).
pub const DETAIL_LINE_MAX: usize = 120;

/// Latch-once milestone tracker: feed it console bytes, get the newly
/// latched milestones (with their carrying line) per chunk.
///
/// This is the pure state machine under the Python monitor thread —
/// transport (serial/TCP bridge, break recovery) stays outside, so the
/// host and the F746 firmware drive the SAME tracker.
#[derive(Debug, Default)]
pub struct BootMilestoneTracker {
    latched: [bool; 5],
    buf: Vec<u8>,
}

impl BootMilestoneTracker {
    /// New tracker; nothing latched, empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one chunk of console bytes; returns the milestones newly
    /// latched by this chunk, each with the line that carried it
    /// (stripped, ≤[`DETAIL_LINE_MAX`] bytes as a lossy UTF-8 string).
    ///
    /// Matching re-scans the whole rolling buffer (the source does the
    /// same), so milestones whose pattern spans a chunk boundary latch
    /// on the chunk that completes them.
    #[must_use]
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<(BootMilestone, String)> {
        self.buf.extend_from_slice(chunk);
        let mut latched = Vec::new();
        for (pattern, milestone) in MILESTONE_PATTERNS {
            let idx = milestone_index(*milestone);
            if self.latched[idx] {
                continue;
            }
            if let Some(at) = pattern.find(&self.buf) {
                self.latched[idx] = true;
                latched.push((*milestone, self.line_at(at, at + pattern_len(pattern))));
            }
        }
        if self.buf.len() > MAX_BUFFER {
            let drop = self.buf.len() - KEEP_TAIL;
            self.buf.drain(..drop);
        }
        latched
    }

    /// Whether this milestone has latched.
    #[must_use]
    pub fn has_latched(&self, milestone: BootMilestone) -> bool {
        self.latched[milestone_index(milestone)]
    }

    /// Every milestone latched so far, in vocabulary order (each
    /// milestone once, even though ProcdInit has two patterns).
    #[must_use]
    pub fn latched_milestones(&self) -> Vec<BootMilestone> {
        ALL_MILESTONES
            .iter()
            .copied()
            .filter(|&m| self.has_latched(m))
            .collect()
    }

    /// The line containing bytes `start..end` of the buffer, stripped
    /// and capped — the source's `_line_at`.
    fn line_at(&self, start: usize, end: usize) -> String {
        let line_start = self.buf[..start]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |p| p + 1);
        let line_end = self.buf[end..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(self.buf.len(), |p| end + p);
        let line = self.buf[line_start..line_end].trim_ascii();
        let capped = &line[..line.len().min(DETAIL_LINE_MAX)];
        String::from_utf8_lossy(capped).into_owned()
    }
}

fn milestone_index(milestone: BootMilestone) -> usize {
    match milestone {
        BootMilestone::UbootBanner => 0,
        BootMilestone::KernelStart => 1,
        BootMilestone::ProcdPreinit => 2,
        BootMilestone::ProcdInit => 3,
        BootMilestone::LoginPrompt => 4,
    }
}

/// How many buffer bytes the pattern's match consumes (line-detail
/// anchoring only; not used for matching).
fn pattern_len(pattern: &Pattern) -> usize {
    match *pattern {
        Pattern::Literal(b) => b.len(),
        Pattern::LiteralThenDigit(p) => p.len() + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AP3915i bench boot lines documented in serial_monitor.py —
    /// real console shapes, species-level (no unit data).
    const BOOT_LOG: &[&str] = &[
        "U-Boot 2012.07.22 (Jul 19 2022 - 10:26:07) (primary)",
        "Starting kernel ...",
        "[    3.873775] init: - preinit -",
        "   13.054844] procd: - init -",
        "root@OpenWrt:~#",
    ];

    #[test]
    fn full_boot_latches_all_five_milestones_in_order() {
        let mut t = BootMilestoneTracker::new();
        let mut seen = Vec::new();
        for line in BOOT_LOG {
            for (m, detail) in t.feed(format!("{line}\r\n").as_bytes()) {
                assert!(!detail.is_empty(), "detail carries the line");
                seen.push(m);
            }
        }
        assert_eq!(
            seen,
            vec![
                BootMilestone::UbootBanner,
                BootMilestone::KernelStart,
                BootMilestone::ProcdPreinit,
                BootMilestone::ProcdInit,
                BootMilestone::LoginPrompt,
            ]
        );
        assert_eq!(t.latched_milestones().len(), 5);
    }

    #[test]
    fn each_milestone_latches_once() {
        let mut t = BootMilestoneTracker::new();
        // the same banner three times (kernel cmdline echoes it in the
        // source's motivating example)
        for _ in 0..3 {
            let latched = t.feed(b"U-Boot 2012.07\r\n");
            assert!(latched.len() <= 1);
        }
        assert_eq!(t.latched_milestones(), vec![BootMilestone::UbootBanner]);
    }

    #[test]
    fn split_patterns_latch_when_completed() {
        let mut t = BootMilestoneTracker::new();
        assert!(t.feed(b"Starting ker").is_empty());
        let latched = t.feed(b"nel ...\r\n");
        assert_eq!(latched.len(), 1);
        assert_eq!(latched[0].0, BootMilestone::KernelStart);
        assert_eq!(latched[0].1, "Starting kernel ...");
    }

    #[test]
    fn procd_init_alternates_latch_once() {
        // the regex alternation: whichever literal hits first wins,
        // the other stays silent
        let mut t = BootMilestoneTracker::new();
        let first = t.feed(b"init: - init -\r\n");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, BootMilestone::ProcdInit);
        let second = t.feed(b"procd: - init -\r\n");
        assert!(second.is_empty(), "ProcdInit latches once");
    }

    #[test]
    fn uboot_banner_requires_digit() {
        let mut t = BootMilestoneTracker::new();
        assert!(t.feed(b"U-Boot bootloader\r\n").is_empty());
        assert!(!t.has_latched(BootMilestone::UbootBanner));
    }

    #[test]
    fn detail_line_is_stripped_and_capped() {
        let mut t = BootMilestoneTracker::new();
        let long_prefix = "x".repeat(300);
        let line = format!("{long_prefix} root@OpenWrt:~# payload-after\r\n");
        let latched = t.feed(line.as_bytes());
        assert_eq!(latched[0].0, BootMilestone::LoginPrompt);
        assert_eq!(latched[0].1.len(), DETAIL_LINE_MAX);
        assert!(latched[0].1.starts_with('x'));
    }

    #[test]
    fn buffer_caps_and_keeps_tail() {
        let mut t = BootMilestoneTracker::new();
        // feed past the cap in one shot; the tail must remain matchable
        let mut chunk = vec![b'a'; MAX_BUFFER];
        chunk.extend_from_slice(b"\r\nroot@box:~# \r\n");
        let latched = t.feed(&chunk);
        assert_eq!(latched.len(), 1);
        assert!(t.buf.len() <= MAX_BUFFER);
    }

    #[test]
    fn milestone_names_are_stable() {
        assert_eq!(BootMilestone::UbootBanner.as_str(), "serial_uboot_banner");
        assert_eq!(BootMilestone::LoginPrompt.as_str(), "serial_login_prompt");
    }
}
