//! # Bench rescue: state classification + action ladder (field-validated
//! 2026-10-23 on the wedged GS1900-8hp bench switch)
//!
//! The morning's rescue session produced four field-validated lessons that
//! this module encodes:
//!
//! 1. A box sitting at the **U-Boot prompt** is remotely rebootable by
//!    sending `reset` — no Linux required (the 2026-10-23 dark-box event
//!    was a silent U-Boot, not a dead box).
//! 2. The livelock has **two depths**: *shallow* (BREAK+b sysrq reaches
//!    the kernel — 1-second recovery, proven 25+ times) and *deep*
//!    (BREAK+b ignored: the CPU stalls before the serial RX path runs —
//!    mains cycle only).
//! 3. A **pre-U-Boot stall** has a unique signature: console output
//!    freezes *mid-line* during the DDR/PHY register dump. Serial is
//!    useless there; mains cycle only.
//! 4. A **silent reader** is not a silent box: the standing journal
//!    reader died while the port kept producing bytes. The rescue tool
//!    therefore owns the port exclusively and reports its own liveness.
//!
//! The ladder (see [`action_for`]): every state maps to exactly one next
//! action, and only the two hardware states escalate to "needs mains".

use std::time::Duration;

/// Classified console state of a possibly-wedged box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleState {
    /// No bytes at all — either dead reader or dead box (see [`action_for`]
    /// note; the caller owns the reader, so silence here means silence).
    Silent,
    /// Bootloader prompt observed (`RTL838x#`, `=>` etc.).
    UbootPrompt,
    /// Kernel timestamps advancing.
    Booting,
    /// Linux up (shell prompt / login banner).
    LinuxAlive,
    /// Livelock tick stream present (WEDGE-TICK … STUCK-AT alternating).
    Livelock,
    /// Output froze mid-line inside a boot register dump and then silence.
    PreUbootStall,
}

/// The single next action for a state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RescueAction {
    /// Keep waiting; box is progressing on its own.
    Wait,
    /// Send `reset\r` — U-Boot is alive and will reboot the box.
    SendReset,
    /// Probe with BREAK+b sysrq; if no reboot signature follows within
    /// [`BREAK_PROBE_WINDOW`], reclassify as deep (mains).
    ProbeBreakRecover,
    /// Serial cannot reach it. A human must pull power.
    NeedsMains {
        /// Human-readable reason for the escalation.
        why: &'static str,
    },
}

/// How long to watch for a reboot signature after a BREAK+b probe before
/// declaring the wedge deep.
pub const BREAK_PROBE_WINDOW: Duration = Duration::from_secs(20);

/// Classify a console tail (most recent output, raw, at least a few
/// hundred bytes when available).
pub fn classify(tail: &str) -> ConsoleState {
    let trimmed = tail.trim_end();
    if trimmed.is_empty() {
        return ConsoleState::Silent;
    }
    // Livelock fingerprint: the wedge tick stream with alternating stuck
    // PCs (both barrier PCs observed in the field).
    if trimmed.contains("WEDGE-TICK") && trimmed.contains("STUCK-AT") {
        return ConsoleState::Livelock;
    }
    // U-Boot prompts seen on this family.
    let uboot_prompts = ["RTL838x# ", "RTL838x#", "=> ", "Zyxel> "];
    if uboot_prompts.iter().any(|p| trimmed.ends_with(p.trim_end())) {
        return ConsoleState::UbootPrompt;
    }
    // A register-dump line that stops without a newline = froze mid-line.
    let last_line = trimmed.lines().next_back().unwrap_or("");
    if trimmed.contains("Registers(") || trimmed.contains("DDR") {
        let ends_open = last_line.ends_with(':') || last_line.ends_with(',');
        if ends_open && !trimmed.ends_with('\n') && !trimmed.ends_with('\r') {
            return ConsoleState::PreUbootStall;
        }
    }
    // Advancing kernel timestamps = booting.
    if trimmed.contains("Linux version") || last_line.contains("] ") {
        return ConsoleState::Booting;
    }
    if trimmed.contains("root@") || trimmed.contains("login:") {
        return ConsoleState::LinuxAlive;
    }
    ConsoleState::Silent
}

/// The action ladder. Field-validated mappings:
///
/// * `UbootPrompt` → `SendReset` (2026-10-23: dark box was a silent
///   U-Boot; `reset` brought it back with zero human involvement).
/// * `Livelock` → `ProbeBreakRecover` (shallow recovers in ~1 s; deep
///   ignores the probe — the timeout is the discriminator).
/// * `PreUbootStall` / `Silent` → `NeedsMains` (CPU hung before the
///   bootloader finished; there is no code left to talk to).
pub fn action_for(state: &ConsoleState) -> RescueAction {
    match state {
        ConsoleState::Silent => RescueAction::NeedsMains {
            why: "no console output — box never started booting or console dead",
        },
        ConsoleState::UbootPrompt => RescueAction::SendReset,
        ConsoleState::Booting | ConsoleState::LinuxAlive => RescueAction::Wait,
        ConsoleState::Livelock => RescueAction::ProbeBreakRecover,
        ConsoleState::PreUbootStall => RescueAction::NeedsMains {
            why: "froze mid-line in the boot register dump — pre-U-Boot MMIO stall",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uboot_prompt_demands_reset() {
        let tail = "Unknown command 'uname' - try 'help'\r\nRTL838x# ";
        assert_eq!(classify(tail), ConsoleState::UbootPrompt);
        assert_eq!(action_for(&classify(tail)), RescueAction::SendReset);
    }

    #[test]
    fn livelock_demands_break_probe() {
        let tail = "[  101.0] WEDGE-TICK: h=hrtimer_interrupt STUCK-AT=__r4k_wait+0x20 ERR=6 CAUSE=10800000\r\n";
        assert_eq!(classify(tail), ConsoleState::Livelock);
        assert_eq!(action_for(&classify(tail)), RescueAction::ProbeBreakRecover);
    }

    #[test]
    fn mid_dump_freeze_is_pre_uboot_stall() {
        // Real field capture: PHY dump stops after the address, no newline.
        let tail = "PHY Registers(0xb8001500):\r\n0xb8001540:";
        assert_eq!(classify(tail), ConsoleState::PreUbootStall);
        assert!(matches!(action_for(&classify(tail)), RescueAction::NeedsMains { .. }));
    }

    #[test]
    fn booting_kernel_waits() {
        let tail = "[    1.290841] Found SoC ID: 8380: RTL8380M, family 8380\r\n";
        assert_eq!(classify(tail), ConsoleState::Booting);
        assert_eq!(action_for(&classify(tail)), RescueAction::Wait);
    }

    #[test]
    fn complete_dump_line_is_not_a_stall() {
        // A dump that completed its line and moved on is just booting.
        let tail = "PHY Registers(0xb8001500):\r\n0xb8001540:0x1e, 0x1e\r\n[    0.1] U-Boot 2016\r\n";
        assert_ne!(classify(tail), ConsoleState::PreUbootStall);
    }

    #[test]
    fn silence_needs_mains() {
        assert_eq!(classify(""), ConsoleState::Silent);
        assert!(matches!(action_for(&ConsoleState::Silent), RescueAction::NeedsMains { .. }));
    }
}
