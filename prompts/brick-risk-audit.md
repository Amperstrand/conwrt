# Brick-Risk Audit — run this BEFORE any flash, bootloader write, or destructive goform

Prompt owner: bench/flash lanes. Born from the MF286D campaign close calls (conwrt
issue #621, Nov 2026; full audit: EXP-022 in the bench evidence). Run every field.
A single NO blocks the operation until resolved.

**Item 0 — run the executable preflight**: `python3 scripts/preflight-flash.py
--config <campaign>.json` (template: `scripts/preflight-flash.example.json`).
It machine-verifies the assumptions this audit encodes: fence listener + ownership,
recovery-IP uniqueness, routing, host firewall (udp/69!), payload sha/size/magic
(zeros are not triggers), rollback pairing, specimen MAC, verify-alive, exfil
verb end-to-end, watcher heartbeat, console/waiver. Exit 2 = BLOCKED. Fields 1-16
below remain the human analysis layer on top of it.

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

## Config applies (2026-11-08 addendum — the "silent router" incident)
17. Applying another lane's committed-but-unapplied uci is a FLASH-CLASS action:
    audit every value first; apply + verify + hand off in one motion.
18. A firewall UCI reset does NOT touch /etc/nftables.d/ or other rule-include
    dirs — when an input-drop survives a reset, check the includes. (An include
    that looks custom may be the stock template — read contents before declaring
    root cause.) Runtime-injected rules (custom daemons at boot) defeat every
    config-file reset; pristine-overlay wipe is the only cure for that class.
19. **Interactive prompts defeat non-interactive rescue.** `firstboot` /
    `factoryreset` asks "Are you sure? [N/y]"; run without `-y` from a script it
    gets EOF, answers No, and exits 255 having wiped NOTHING — three "factory
    resets" silently declined this way. Always pass the tool's non-interactive
    flag (`factoryreset -y`), treat nonzero exits as failures, AND verify the
    state actually changed (config files post-reset, pre-reboot). Proven fix:
    `factoryreset -y` exits 0 and wipes; the failsafe manual primitive is
    `rm -rf /overlay/upper/*` after mount_root.
20. **Test rescue tooling before the incident** (a rescue script with an
    unwritable log path silently disabled itself during a live recovery), and
    **test both auth paths** after any credential change — raw `$6$` shadow
    edits were silently rejected by the target's dropbear (it accepts its own
    passwd-applet `$5$`); use the device's own tools for credential changes,
    and verify with a REAL interactive-style login (sshpass can false-fail;
    pexpect confirmed).
21. Secrets through ssh: NEVER inline `$`-containing values (hashes!) in
    double-quoted remote commands — shell expansion mangles them silently.
    Bake into a script file and pipe via `ssh ... "sh -s" < file`.
22. Species failsafe quirks (MF286D): entry = SINGLE press-release while the
    blue status LED blinks (holding = U-Boot intercepts into silent state);
    the port needs an unplug/replug LINK EVENT once in failsafe; failsafe
    networking = 192.168.1.1, passwordless root, overlay via mount_root;
    first boot after an overlay wipe may need one power cycle (dropbear
    connection-reset window).
23. **IP changes must use the platform's own config form.** On OpenWrt, a
    bare `uci set network.lan.ipaddr='x.x.x.x'` (no netmask) leaves the
    address without an on-link route: ARP ANSWERS but every IP reply routes
    out the default interface — identical symptom to a firewall drop, survives
    every reset, and cost a full day to diagnose (two concurrent bench faults
    made it worse). Always set explicit CIDR (`uci add_list
    network.lan.ipaddr='x.x.x.x/24'`) and verify with a ping through the same
    path operators will use. 'ARP answers but ping fails' on OpenWrt: suspect
    the address FORM before the firewall.
