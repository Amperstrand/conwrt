# MF286D "go" cycle — host-side findings complementing EXP-034

Date: 2026-11-09. Software-only; no device ops. Read-only on other lanes' artifacts
(`~/mf286d-work/evidence/`, `/tmp/opencode/b14/`, `/tmp/opencode/backup-dryrun*/`).
This file complements `modem-fw-re/ANALYSIS.md` (EXP-034) §7c and my earlier
`/tmp/opencode/deepaccess/RESEARCH.md`.

## 1. ⚠️ DATA-INTEGRITY: the "backup-dryrun*" modem dumps are PLACEHOLDER JUNK

`/tmp/opencode/backup-dryrun{,2,3}/0_*.bin` look like real partition dumps
(`0_EFS2.bin`, `0_TZ.bin`, `0_aboot.bin`, `0_modem.bin` … with a plausible
MANIFEST.tsv of sizes+sha256), but every one is a repeating
`[32-byte constant][MF286D-UNIT-BACKUP-DRYRUN\n]` stream:
- modem: 1,235,862 identical chunks (all `486a6969…1b3a`), distinct values = 2
  (constant + 4-byte tail)
- boot: 253,105 identical chunks (different constant)
The manifest hashes describe the JUNK, not the flash. Any future agent (or
automation) that treats these as the modem backup will have a false safety gate.

**Real modem backup status: NOT DONE.** EXP-021's verified 22-partition backup is
the ROUTER (factory-mode RCE acquisition, mtd0..21 incl. NOR chain — geometry
matches the router, not the modem's 17). The modem's EFS2/EFSBAK/TZ/aboot/mibib
exist nowhere as verified real data yet. **The QCN-first + off-CPU extraction
paths in RESEARCH.md §"Ranked safe-extraction recommendations" are the gate
before ANY modem write experiment (incl. version-shop flashes).**

## 2. Modem kernel (B02 kit vmlinux.bin): mtdblock present, no zte_ MTD hooks

- `strings vmlinux.bin`: `mtdblock` driver string present → /dev/mtdblockN should
  exist on the modem → the **mtdblock discriminating test** (RESEARCH.md §"The
  discriminating test") is viable as-is on this unit (verify node presence first).
- NO `zte_nand`-class hooks in the modem kernel (all `zte_` symbols are
  battery/PMIC — unlike the ROUTER kernel, which has zte_nand_local_read). The
  mtd1-panic guard, if kernel-side, is not an obviously-named ZTE patch; the
  QPIC-class driver or CP-side enforcement remain the candidates. Live B12 ≠ B02
  kit — re-diff when the B12 modem dump lands.

## 3. AT table: `*EUICC` is a dead stub (corroborates ANALYSIS §4)

`at-table.txt`: `*EUICC  ctx=0x00000000 t=0` — registered in the parser table
with a NULL handler context = unwired in this build. The proprietary eUICC
management surface exists in the codebase but is compiled out/stubbed. All
+CCHO/+CGLA/+CCHC/+CSIM/+CRSM rows have real contexts (handlers present) — the
gating is below them (CP/CI level), as EXP-034 concluded.

## 4. cfg/NV policy surface — kit side exhausted

- Rootfs cfg stack: `/usr/bin/cfg`, `libzte_cfg.so`, `zte_topsw_cfg`, `/bin/nvmcp`,
  `/bin/nvmproxy`. No sim/uim/euicc/apdu/channel key names in any of their strings.
- No static cfg store/DB in the kit rootfs (store is runtime/OEMD-side, factory-
  empty in kit). → the NV-policy hypothesis is **only decidable live** (EXP-034
  §7c steps 1–4 stand as written; nothing further to mine statically).
- ARBI CP strings do show live eUICC machinery: `*EUICC: %d` (x2),
  `sacDevGLSwapRecvEuiccInd` — the CP knows about eUICC; enforcement shape still
  needs the runtime dump (cp_resolve.py flow).

## 5. Version-shop logistics (plan step 1) — resource survey

- Public mirrors: dl.eko.one.pl/orig/zte_mf286d/NORDIC/{B02..B12} are now EMPTY
  (only breadcrumbs); T-MOBILE/ has router mtd8/mtd9 dumps only. The public full
  modem image supply has dried up.
- Local resources (already in hand, adequate): `~/mf286d-work/kit/UPDATE/`
  (B02-era full modem set incl. NON-HLOS.ubi class images),
  `~/mf286d-work/mf286d-openwrt/resources/Nordic Modem Update (up to B12).zip`
  (delta chain), the decoded B14 delta payloads + working zfd decoder
  (`/tmp/opencode/b14/`, LZMA1+bsdiff40 cracked).
- Version-shop therefore means: B02 kit full image (in hand) vs live B12 (dump
  pending) — a 2-point comparison, not a wide ladder. Deprioritize until the
  real modem backup exists.

## 6. Feeds for the live session (overseer-owned)

1. BEFORE any modem write: real modem backup (QCN via diag first; raw via the
   factory-mode/dload path that already worked for the router, if the modem's
   dload daemon exposes it, or EDL/qtools per RESEARCH.md).
2. On first modem adb shell: `ls /dev/mtdblock*` → run the one-command
   mtdblock discriminator (mibib, 4KB) per RESEARCH.md — it double-serves the
   crash-guard question AND validates the kernel-side read path.
3. `cfg show` / nvmproxy / OEMD reads per EXP-034 §7c steps 1+4 — the policy
   table, if it exists, is in there; my kit-side scans confirm it can't be
   found statically.

## Sources
- Local artifacts (read-only): ANALYSIS.md, at-table.txt, arbi-strings.txt,
  extracted/{vmlinux.bin,sysj-root}, backup-dryrun3/*, exp-020/021 evidence.
- Prior turns: /tmp/opencode/deepaccess/RESEARCH.md (community + kernel-path
  research with URLs).
