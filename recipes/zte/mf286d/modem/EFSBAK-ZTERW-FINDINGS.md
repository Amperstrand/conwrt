# efsbak sweep result + zterw identification + B14 update chain (EXP-034/035 cont.)

2026-11-09, mf286d-fwre lane. Offline analysis of ladder-pulled partitions.

## efsbak (mtd5): FACTORY BLANK

sha256 7ed573a5… — 11.5MB **entirely 0xFF** (0/44 blocks ever written).
The backup-EFS partition was never populated on this unit → the efsbak LPA/NV
sweep is dead; **efs2 (mtd2) remains the only NV source** (crasher partition,
and prime suspect in the QMI outage per the unified theory).

## Other partitions triaged

- mtd10-misc, mtd12-fota: blank (0/24 blocks each)
- mtd13-recoveryfs: populated UBI (38 LEBs, vol0 = UBIFS) → **extracted to
  `recovfs-out/`** (616 files; build stamp 2021-07-10 = B12 date)

## Recovery environment findings (the FOTA engine)

- `usr/bin/prestartdua` = the FOTA state machine (`pre/post/system/recovery
  _update_stage`, `update_fsm_proc`, flag `/cache/update.flg`)
- Update chain recovered from its strings:
  1. staged script `/cache/ztedua.sh` (runs on both normal boot & recovery)
  2. `zte_topsw_dua split_delta` — **BSDIFF40 delta splitter** (matches the
     overseer's B14 .up finding)
  3. `/cache/rbtozte` (router→ZTE staged payload handoff)
- `etc/init.d/find_recovery_partitions.sh`: recovery **ubiattaches zterw
  (mtd15) as /dev/ubi3** and mounts `rootfs`→/system + `cachefs`→/cache from
  it. **zterw = RW overlay + FOTA staging** — this is where the B14 .up's
  delta+NV scripts land before application.

## Actionable

1. **PULL mtd15-zterw** (0x09100000 = 145MB) — overseer lane, block-mode
   canary-first. Expected: cachefs (staged updates incl. any B14 remnants on
   units that took OTA) + the RW overlay (ZTE nv config / policy candidates
   for the LPA/ISD-R question).
2. mtd14-ztefile (22.5MB) also unread — secondary candidate.
3. The B14 .up package (public URL, parent lane) + `zte_topsw_dua` (we hold
   the binary in recovfs-out) = complete offline reconstruction of the
   NV-script application mechanics.
