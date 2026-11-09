# Prompt: MF286D modem firmware — acquisition guide (all known paths)

Species-level. Three hardware generations exist in the wild; know which one
you are holding before pulling.

## Which modem do you have?

| Generation | Where | Identification | Firmware form |
|---|---|---|---|
| **Marvell PXA1826 "asrmod"** | 2019 B02 service kit (`asrmod/FBF_h.bin` + timheaders + Dkb.bin) | `DFBF`/`Marvell_FBF` magic; ASR strings inside | FBF container (9 partitions: TIM4/OSLO/TIM1/OEMD/SYSJ-squashfs/ZIMG-zImage/ARBI/GRBI/RFBI) |
| **Qualcomm MDM9650 (live B12+ units)** | The physical modem card | USB `19d2:1485`; `ATI` → `MF286DMODULE, BD_TELIAMF286DV1.0.0B12`; soc0 machine `MDM9650` | NAND mtd partitions + OTA `.up` packages |
| (B14 era) | OTA packages | `.up` suffix, contains BSDIFF40 patches vs B12 base | see notes.md "B14 continuation" |

## Path A — ADB (live device, read-only, easiest)

Prereq: router on bench (`ssh root@192.168.34.1` via ai-legion), adb +
adb-enablemodem installed (persistent). See `modem-fw-01` for the full
access runbook.

```
adb shell cat /proc/mtd                 # partition map
adb shell cat /dev/mtd9ro > /tmp/mtd9.img   # modem/MPSS image (71MB) — WORKS
adb shell cat /dev/mtd2ro > /tmp/efs2.img   # efs2/NV — CAUTION: warm reads
                                            # destabilize adb; attempt ONCE
                                            # right after a modem reboot,
                                            # never hammer
adb shell cat /dev/mtd16ro > system.img     # modem Linux rootfs (UBIFS)
```
Record sha256 for everything; move dumps off the router (tmpfs) immediately.
The modem boots ~2.5 min after `adb reboot`.

## Path B — ZTE OTA `.up` packages (static, no device)

Public ZTE server serves carrier packages; B12→B02(B14-line) example URL
(from web-research lane, operator-verified):
`https://dleu.ztems.com/zxmdmp/download.do?doWhat=getUp&filename=firmwarepackages/DE/ZTE/MF286D/337964/TELIA_MF286DV1.0.0B12-TELIA_MF286DV1.0.1B02.up`
(TELIA naming: B12 router-fw → V1.0.1 "B02" line of the next generation.)
`.up` packages carry the modem-side update incl. **NV scripts** (community
extracted `nv set net_select=…`, band locks) and BSDIFF40 patches against
the running base — with our mtd9 dump as the base, the diffs apply cleanly
for offline study. Package format: standard ZTE update container (zip-like
header); carve with binwalk, then look for `DIFF40`/`BSDIFF40` magic and
`nv set` script text.

## Path C — service-kit FBF (Marvell generation only)

The 2019 kit's `FBF_h.bin` (27.8MB) container is fully decoded:
parsers + carved partitions + full analysis in
`recipes/zte/mf286d/modem/ANALYSIS-b02-kit-marvell.md` (container spec §1,
partition table, ARBI base 0x06480000). Parser scripts live on the bench at
`~/mf286d-work/evidence/modem-fw-re/` (`fbf_parse.py`, `extract_fbf.py`).
NOTE: this generation is NOT in live B12 units — historical/contrast value.

## Path D — ZAS/dload-mode acquisition (router side, last resort)

The ZAS tool / dload web UI paths flash rather than dump; for the *modem*
there is no recovery if bricked. Only relevant if a deliberate modem
reflash is authorized; see `notes.md` (E1–E3 environments, transport notes)
and the EXP-015/016 ledger rows. Do not use for reads — Paths A/B cover it.

## Handling rules (all paths)

- Never write to modem flash without: full per-partition backup + operator
  sign-off + a stated recovery story (there is none for the modem today).
- Treat efs2/NV dumps as unit secrets (IMEI-adjacent) — bench-only, never
  commit to the repo; reference by sha256.
