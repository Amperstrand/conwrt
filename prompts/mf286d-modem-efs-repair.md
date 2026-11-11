# MF286D modem EFS repair — continuation prompt (2026-11-11, post-stabilization)

Hand this to the session that fixes the modem. The router is DONE; the
modem is STABLE but parked. Everything below is verified-live evidence
unless marked.

## UPDATE (2026-11-11 late): the EDL client is qtools, not bkerler/edl

The full community playbook was found (eko.one.pl thread 21790 p21,
Leo-PL + stich86, proven on this exact modem):

- **bkerler/edl FAILS at the hello stage** ("Sahara error state", before
  any loader upload — with stock AND patched loaders). Not signatures, not
  transport: qtools' `sahara.c` implements the handshake variant these
  nandprg-era PBLs expect; edl.py's newer flow does not.
- **The proven dump recipe**: `qdload -k12 -i -pPORT` (emergency loader
  into 9008) → `qrflash -k12 -s@ -m -pPORT` (P-table) →
  `qrflash -k12 -s@ -o out.bin -pPORT` (FULL DUMP, per-partition files).
  "Slow as molasses, but it works."
- **EFS2 IS dumpable this way** (Leo-PL: EFS2 content == EFSBAK content
  on their unit) — our campaign gap is fillable.
- qtools = Maks-2012 fork (has the `-k12` chipset.cfg mapping; upstream
  forth32 lacks it). C codebase, Linux Makefile — buildable anywhere.
  ALSO contains `qefs.c`, `qnvram.c`, `efsio.c`, `mc-efs-plugin` — EFS/NV
  tooling beyond dumps.
- Transport: qtools speaks serial (-pPORT). On Linux: bind usbserial to
  the 9008 device, or the lane's PTY-USB bridge on the router directly.
- Port exclusivity: nothing else may hold the port during qtools runs.
- Write-path intel (for the later repair): SB3.0/qtools writes don't
  erase unselected partitions; some units refuse partition.mbn; the
  fota-cookie (recoveryfs boot-loop) class needs fota erased; the
  fastboot alternative exists (erase boot+recovery → aboot fastboot →
  flash boot/system/modem/recovery/zterw/recoveryfs by name).
- Our machinery that stands (live-proven): `adb shell sys_reboot edl`
  → 9008 (05c6:9008, reliable); the PBL falls through to ZTE ARMPRG
  (05c6:900e) after ~5s of host silence — win the race with an instant
  hotplug bind + pre-waiting client; usbip export router→ai-legion works
  (kmod-usbip-* on 25.12.6, hotplug binder script in edl-prep/).
- Partition table: triple-confirmed (kit partition.mbn == live /proc/mtd
  == the community's device-read P-Table): 17 partitions, 512MiB total,
  EFS2=44 blocks @20, MIBIB=10 @10.

## Current state (2026-11-11 evening)

- **Router (d1)**: fully recovered, 25.12.6, `mf286d` @ 192.168.34.1/24,
  stable. Rust conwrt recovery worked end-to-end (PR #685).
- **Modem**: STABLE in QMI low-power mode (`qmicli --dms-set-operating-mode=
  low-power`, took two tries). Uptime unlimited; USB cycle counter frozen.
  Alive in this state: ADB (root, no auth), QMI CTL/DMS/WDS (reads AND the
  operating-mode SET work), AT. Dead: UIM/NAS (the EFS-dependent services).
- **The stabilization is RUNTIME-ONLY**: any reboot/power cycle resumes the
  crash loop (40-200 s variable period). Re-apply low-power first thing.
- Cellular: none (no SIM service in any state since v8 — the modem had no
  data function whether looping or parked; nothing is lost by parking).

## Root cause (high confidence, evidence-based)

The v8 register probe (0x67 with VALID 8B u64, EXP-043) wrote a malformed
persistent client-state record via the m2m_euicc service (which was enabled
by OUR lpa_support=1 EFS write, EXP-035/037). Every baseband boot:
mmgsdi/m2m init reads the corrupt record → init never completes → the
SBL-level watchdog resets the module (BELOW Linux — kernel log silent, no
"Restarting system", subsys stays ONLINE; reboot-daemon/diagrebootapp are
DIAG-commanded servants, NOT the trigger). lpa_support=1 ALONE was proven
healthy (EXP-037: full services with it in EFS) — the corrupt RECORD is
the trigger, lpa_support is the enabler.

## Hard constraints (verified 2026-11-11)

1. **NO EFS backup image exists**: mtd2-efs2.img = 0 bytes (crasher
   partition, never dumped); mtd5-efsbak.img = FULLY ERASED (no golden
   copy on this unit). The only EFS material: 3 individual policy files +
   the NV XML (numbered items) + the Nov-10 file-level pulls.
2. **DIAG port has NEVER been alive on unit 1** (ttyUSB0 silent since day
   one) — all qfenix/qcdm-efs2 paths are dead ends HERE.
3. **No /nv mount on the modem Linux** (ZTE layout ≠ Quectel /nv);
   EFS is daemon-mediated with no shell tool found.
4. **mtd1/mtd2 reads crash the modem** (species-proven, community-
   confirmed) — do not attempt.
5. **No EFS write path currently exists.** The repair must CREATE one.

## The mapped repair paths (ranked, with what's known)

### P1: The boot updater + ZFD01.02 delta package (most promising)
- `zte_topsw_dua` consumes **/cache/delta.bin** at EVERY boot (~2 s in,
  before the crash window; update.log shows each attempt). Stages:
  pre_update → system/recovery → **efs_transfer** → post_update
  (strings: "update efs failed", "efs_transfer_stage", postprocessing.mld).
- **delta.bin = ZFD01.02 container** — the SAME format the B14 campaign
  decoded (`extract_zfd.py`: header + path/lzma-bsdiff entries + trailer;
  NO signature fields seen in the mld layer).
- The header IS version-gated ("UA_ZFDSUSDK_VERSION is not correct" string
  in the binary) — the usdk version string must match.
- SHA256_Init/Update/Final imported; ONE call cluster (~0xe184). Whether
  it VERIFIES (vs just digests) is UNRESOLVED — first RE task.
- Corpus: `b14/unpacked/mld/efs.mld` (2,695 B, ZTE-built, right SoC
  generation) — its config_1.p/config_2.p framing is NOT yet decoded
  (FINDINGS S7: "identified but NOT decoded" — ZTE-custom LZMA-framed
  hunks). Decoding it gives a template of what an efs delta carries.
- GOAL: craft a minimal ZFD package whose efs part deletes/rewrites
  lpa_support (or the corrupt record's path). Deploy: adb push to
  /cache/delta.bin, reboot, updater applies at ~2 s of boot.
- START HERE: disassemble zte_topsw_dua (asm dump at
  /tmp/opencode/dua.asm, 53K lines; binary in the mtd16-now extract) —
  the parse_header function (strings at vaddr 0x491xx) answers the
  signature question definitively.

### P2: QMI DMS restore-factory-defaults (reachable, UNBOUNDED risk)
- DMS is alive (IMEI reads: 866754044602964). qmicli has
  `--dms-restore-factory-defaults=[SPC]`. Handler: ds_qmi_dms.c:6487
  (Qshrink DB). SPC likely 000000.
- RISK: if it wipes EFS calibration → UNRECOVERABLE (constraint 1: no
  restore image). Only run AFTER the handler's scope is RE'd from the
  pristine AMSS (mtd9-files/ + regenerated Qshrink at
  /tmp/opencode/qshrink-db.bin, regen recipe: zlib stream at qdb offset
  0x40).

### P3: EDL (window-free but imageless)
- Entry EXISTS: `adb shell` → `sys_reboot edl` (reboot-daemon strings) or
  DIAG 4b250300 (dead port, skip). EDL = host-controlled, no reset race.
- But mtd2 has NO source image (constraint 1) — EDL can only reflash what
  we hold. Useful only for OTHER partitions or a future donor image.

### P4: Donor EFS from device 2 (device 2's modem is healthy)
- Same species/carrier; its EFS would be clean AND carrier-provisioned.
- Same constraints apply to READING it (crasher partition, DIAG unknown
  on that unit — never tested; device 2 is parked at U-Boot awaiting
  serial, its modem reachable only after router recovery).

## Session-ready assets

- Stabilization procedure + loop forensics: AGENTS.md (conwrt) sections
  "MF286D modem crash-loop" + "Recovery Management Plane: v6-first"
- Qshrink DB regenerated: /tmp/opencode/qshrink-db.bin (21 MB) — grep
  for handler names/file:lines (ds_qmi_dms.c entries verified present)
- zte_topsw_dua disasm: /tmp/opencode/dua.asm
- Corpus: ~/mf286d-work/evidence/modem-fw-re/live-b12/dumps/ (15 real
  partition images, mtd9-files pristine AMSS tree, mtd16 modem-Linux
  extracts) + b14/ (B12→B14.up unpacked, extract_zfd.py, efs.mld)
- The modem is reachable via: ai-legion → root@192.168.34.1 → adb/qmicli

## After the EFS repair succeeds

1. Bring baseband online (`--dms-set-operating-mode=online`), verify UIM/
   NAS/WDS + AT + cellular data.
2. The eSIM lane resumes: v9 `enablecall` on **0x53** (the prime LPA
   enable-gate candidate, built+deployed, never run), DIAG F3 watch-list.
3. Re-baseline the species docs with the findings.
