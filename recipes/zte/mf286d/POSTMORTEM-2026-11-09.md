# MF286D campaign post-mortem — 2026-11-09 outage + lessons

Device-lane account of the modem service outage (conwrt #621 bench unit d1),
written same-day per the "record the lesson where the next agent will trip
over it" rule. Complements: notes.md (species facts), CAMPAIGN-STATE.md
(x280, live index), conwrt-bench map (bench facts).

## What happened (timeline, one paragraph each)

1. **The trigger**: during the flash-backup campaign we read `mtd1`/`mibib`
   and `mtd2`/`efs2` — the documented crasher partitions — with minimal
   canaries, to discriminate why they refuse reads (char-vs-block path).
   Each read panicked the whole modem SoC (~5 panics total). Goal was
   legitimate (backup + the mtdblock discovery unlocked 12 partitions),
   the read discipline was right (4KB canaries, uptime gates).
2. **The damage**: from the first panic onward the modem's service layer
   never re-registered: AT and QMI dead; diag/DM, NV, EFS, adb all alive.
   Cellular (LTE data) down; the unit became a bench terminal.
3. **The diagnosis night**: every self-contained theory was tested to a
   named death — warm-boot SMEM persistence (killed by a true cold boot:
   fresh *different* garbage TOC), EFS-backed service registry (killed by
   AMSS static sweep), flash content damage (killed by hash-identical
   mtd9 + volume-identical mtd16), fwfs runtime-image damage (killed by
   byte-identical firmware files). Seven reset/reboot classes all land on
   the same failure. Remaining live theories: (a) the service table was
   provisioned by ZTE's factory flow and normal boot cannot rebuild it —
   leader; (b) subtle EFS *value* damage (present-but-wrong file, only
   visible against a healthy reference).

## Why it happened — the root causes, honestly

- **The risk model was wrong, not the discipline.** "Worst case = reboot,
  and it has survived reboots" failed because the modem's service state
  appears to be provisioned ONCE (factory/early conditions) and preserved
  by warm-reboot semantics; a panic is not a warm reboot. Prior "harmless"
  crashes were harmless only because that state had never been wiped
  before. We priced the observable, not the mechanism.
- **No control group.** One powered unit, no healthy-boot reference, no
  factory docs — every diagnosis was inference from n=1. Structural, and
  the reason the fix path runs through device 2.
- **Momentum bias at the frontier**: the session was winning all day
  (backups flowing, CRC cracked, blocklist captured); "one more read" felt
  cheap exactly when the remaining actions carried the invisible tail risk.

## The compounding errors (each now guarded)

| Error | Cost | Guard |
|---|---|---|
| Presented experiments as fixes ("cold boot will fix it", 2×) | operator trust, dead theories stated as cures | call every rung a discriminating test until it works |
| Hand-converted partition size wrong (74454720 vs 74448896); rejected a perfect dump; invented "transport tail-loss" | ~1h + a false root-cause story | verify expected sizes against `/proc/mtd` hex, never hand math |
| Skipped the runbook's "retire stale untagged addrs" step | post-cabling ARP chase | runbooks verbatim; steps are load-bearing until proven otherwise |
| Propagated the tool's "everything wiped" artifact (ran the tool, saw drift, never checked tool→device reachability) | two lanes chased a nonexistent wipe | tools fail loud on unreachable, and readers ask "could this be empty-state?" |
| Morning port race (two sessions, one AT port) | garbled probes, false "mute port" reading | single-device-owner split (worked the rest of the night) |

## What held (the fair accounting)

Backup-first discipline: 14/17 partitions + 4096-item NV sweep + blocklist
+ EFS tree banked and hashed before/despite the outage — the mistake is
recoverable because of it. Canary+uptime protocol on every flash read.
Read-only discipline on EFS/eSIM (no ungated writes). Theory-kill method
(named experiments, documented deaths). The diff-against-reference method
(B14 package → drift check → volume diff) resolved three questions that
theorizing never would.

## Lessons (canon-grade candidates)

1. **A kernel panic is not free.** Crash-class experiments on undocumented
   hardware can destroy state that no reboot rebuilds. Price panics as
   potential-permanent damage; ask "what state survives this crash, and who
   rebuilds it?" BEFORE the first one.
2. **Power button ≠ power cycle.** PMIC warm/cold domains decide what
   survives; "restart" can preserve everything that matters.
3. **No reference, no diagnosis.** On single-unit species, capturing the
   healthy-state baseline (boot logs, config trees, service tables) is a
   FIRST-session task — it converts future outages into diffs.
4. **A tool's "empty" is not "absent".** Unreachable-device artifacts read
   as total drift; guard with reachability checks and positive controls.

## Getting cellular back (ranked, current)

1. **Device 2 control diff** (surgical): healthy dmesg oracles + EFS tree +
   channel table + aid_list → the difference names the fault → likely a
   single reversible EFS write. Needs: device 2 powered + USB NIC.
2. **Factory-flow restore** (blunt, device-2-less): re-run ZTE's official
   FOTA path (engine binaries extracted) with a B12-family package —
   re-provisions factory state. Never B14 (QMI breaker).
3. **EDL official-package flash** (heavy, prepared): full factory flow via
   `adb reboot edl` + community tooling; images banked.
4. Worst case: unit stays a research terminal (DM/EFS fully working);
   device 2 becomes the production unit.

## RESOLUTION (2026-11-10 addendum — the outage is CLOSED)

Device 1's cellular RECOVERED on 2026-11-10 after the operator power-cycled
both units. QMI/AT/DM all live; SIM state ready; network registered.

- Attribution: the recovery boot carried the SAME dmesg "oracle lines"
  (warm class, uninitialized-allocation-table chatter, garbage TOC id) as
  every degraded boot — captured in the healthy baseline
  (d1-healthy-baseline/, bench evidence). Those lines are NORMAL for this
  species on every boot; they were never the fault. What actually differed
  between the last failed boot and the recovery boot remains one of: (a) a
  power-removal class difference invisible in logs, or (b) the #672 EFS
  session's writes (denylist zeroed + lpa_support created) repairing a
  crash-damaged init dependency — the recovery boot was the first after
  those writes. The discriminating experiment (restore banked aid_list +
  reboot) is documented but OPTIONAL; the unit works.
- Route B (ISD-R unlock via EFS): REFUTED live — all three deny layers
  unchanged after the writes. The reservation is compiled Qualcomm
  behavior (LPA-owns-ISD-R); apdu_security files are additive restrictions
  above the compiled base.
- Route A (drive the internal LPA via QMI UIM m2m/euicc) is the remaining
  path; lpa_support=1 in place. Next session: QMI message enumeration
  (IDs extractable statically from qmi_uim_m2m_euicc.c in the pristine
  mtd9).
- Postmortem lesson set stands, plus one: the "oracle lines" trap — capture
  the healthy baseline BEFORE reading meaning into boot logs. It took a
  healthy boot to prove those lines meaningless.
