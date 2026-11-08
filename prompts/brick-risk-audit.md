# Brick-Risk Audit — run this BEFORE any flash, bootloader write, or destructive goform

Prompt owner: bench/flash lanes. Born from the MF286D campaign close calls (conwrt
issue #621, Nov 2026; full audit: EXP-022 in the bench evidence). Run every field.
A single NO blocks the operation until resolved.

## Device identity and image provenance
1. Exact device identity verified live (board/`/proc/mtd`/labels) — not assumed from
   the package name or a sibling model.
2. The image manifest's PARTITION SET matches THIS SoC/board, verified against the
   device's OWN partition table (live readout), not the vendor package's manifest.
   **Never flash a package whose manifest describes another SoC's chain** (close call
   #1: a modem-SoC NOR manifest was one checkbox away from being written to a router
   NOR chain — the "update boot" checkbox).
3. Every file to be written: named target partition, size vs partition size, sha256
   recorded in the run log.
4. NOR/bootloader partitions (SBL/MIBIB/QSEE/CDT/DDRPARAMS/ENV/APPBL and equivalents):
   is ANY of them in the write set? If yes → STOP, human gate with explicit brick
   acknowledgment. There is no serial on this class of device.

## Backup gate
5. Unit-specific backup of ALL partitions (incl. NOR chain + calibration/ART + config
   areas) exists, INDEPENDENTLY verified (sizes vs live geometry + hash recheck).
6. Backup copied OFF the operating host (second copy); restore path named (even if
   unproven, write the intended mechanism + its precondition).
7. Calibration/ART/identity partitions marked IRREPLACEABLE in the run plan — they are
   never "reflashable from the kit" (kits carry generic images, not per-unit data).

## Concurrency and liveness
8. No auto-retry/auto-reboot loop is armed on the bench (kill and verify dead — pgrep
   the watchers) (close call #2: an auto factory-Open+reboot loop could reboot the
   device mid-write; it survived only because it never fired during a write window).
9. Exactly ONE lane owns the device for the whole write window; ownership recorded.
10. No power moves planned during the window; write duration estimated and bounded.
11. Boot-mode flags (factory/download mode, bootcmd, bootcount/fallback) listed with
    their current value, the value they'll have AFTER the operation, and how to return
    them (close call #3: a persisted factory flag put the device in a 40 s boot cycle
    for hours — safe only because nothing was mid-write).

## Destructive-surface enumeration (BEFORE probing)
12. All destructive variants of the surfaces you will touch are ENUMERATED from
     disassembly/strings first (`clean`, `erase`, `rm`, `dd`, `firstboot`,
     `mtd erase`, `mode_change clean`-class commands). Blind matrix probing of a
     handler family can fire one (close call #4: multiple lanes probed a bootloader
     mode-switch surface for days; the `clean` variant was never fired — partly luck).
13. Interrupted-write behavior considered per target: what does a power loss at 50 %
     leave? (Main-system region = recoverable; NOR = brick. Sequence accordingly.)
14. Two-slot/fallback awareness: which boot slots exist, which one does the write
     corrupt, and what still boots afterwards? Name the recovery door for each stage.

## Recovery ladder (write it down before starting)
15. Door 1..N in order, with preconditions: e.g. factory/recovery web UI (independent
     slot) → bootloader auto-TFTP recovery (server address!) → programmer/Sahara path
     → serial (note honestly if absent). If the ladder is empty for any failure stage,
     the operation is not idiot-proof: STOP.

## Recording
16. Ledger row BEFORE firing (hypothesis, observer, reversibility), verdict + evidence
    after; close calls recorded as lessons in AGENTS.md with the incident that
    motivated them.
