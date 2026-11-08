# ZTE MF286D — species notes (flash, boot, recovery)

Status: species-level facts from the Nov 2026 bring-up campaign (conwrt issue #621,
ledger EXP-001..022 on the bench host). Unit-specific data lives in the private
registry + bench evidence, not here.

## Architecture (rootfs A/B volumes + NOR chain)

- SoC IPQ4019 (ipq40xx/generic), NAND 128 MB + NOR 2 MB, mPCIe Cat-12 modem (do not
  touch its firmware as part of router flashing).
- **MAIN system region**: `web` (8 MiB @ NAND 0x1000000) + `rootfs` (29 MiB @
  0x1800000). The `rootfs` partition holds a UBI layout with the `kernel` and
  `ubi_rootfs` (and `ubi_rootfs_data`) **volumes** — the live /proc/mtd names
  `kernel`/`ubi_rootfs` refer to these volumes, NOT to a separate partition or an
  independent second OS slot.
- **A/B root fallback**: bootipq conditionally selects between `rootfs` and
  `rootfs_1` volume names (disasm: `rootfsname=rootfs`/`rootfs_1`, validity-gated).
  `rootfs_1` is written by the FOTA/OTA delta flow (`lrb`/zdu into data/fota space);
  `lr` overwrites the primary rootfs and blanks `web`. After `lr` the primary wins;
  do NOT count `rootfs_1` as a managed fallback (it may be absent or stale).
- **Factory/download mode** (`fac_mode` flag, persists across reboots): boots the ZTE
  download environment with its GoAhead web (ZTE-Webs/2.5.0) at 192.168.32.1
  (observed live; carries an update UI). Its independence from the rootfs region is
  NOT established — when planning a rootfs rewrite, do not rely on it as a fallback.
- **NOR chain** (mtd12-19 on the live unit): SBL1/MIBIB/QSEE/CDT/DDRPARAMS/APPSBLENV/
  APPSBL — the no-serial brick zone. Never write. Secure boot is fuse-gated and
  fuse-off on this SKU (community images boot; see docs/ZTE-MF286D-ROUND3-AUDIT.md).

## Boot / flash modes (verified)

1. Normal boot (main slot).
2. Factory/download boot (`fac_mode`), incl. its web-upload flash path.
3. U-Boot TFTP client macros: `lr` (system: web+rootfs), `lw`/`lrs` (single region),
   `lrb` (delta), `lu` (**U-Boot into NOR — brick class**), `lp`/`lc` (partition table/
   cdt into NOR — brick class). Factory boot sets `serverip` = **192.0.0.1** (literal,
   from disasm) — the PC must own that address to be the TFTP peer.
4. **U-Boot auto-recovery TFTP** (documented on the MF286 sibling; consistent with this
   bootloader's RE): if the main kernel is unbootable, U-Boot pulls `root_uImage` from
   a TFTP server at 192.0.0.1/8 and flashes it — **a no-serial recovery door**. Keep a
   known-good `root_uImage` + TFTP server recipe staged for this.
5. Sahara/Firehose via armprg (raw partition read/write) — the tool path; read gives
   partition-level backup.

## Known species gotchas

- The community update kit's manifests describe the MODEM SoC chain — do NOT use them
  as the router's partition truth (see AGENTS.md Brick-Zone Audit).
- Stock web on Telia B09 has no exec sink for the MF286R CVE family; the FACTORY web
  build carries a vulnerable `SET_DEVICE_LED` handler (root RCE in download mode).
- Fresh `RD` rotates after factory-Open: recompute the AD token after every Open.
- Units in the wild show NAND bad blocks (documented on mtd11/fota) — check flash
  health before/after writes; the bootloader skips/warns bad blocks.
- Power-supply sensitivity: unstable PSU causes spontaneous reboots (forum-reported) —
  use a clean supply during flash windows.
- MAC derivation: single factory MAC; WAN/WLAN derive by +1/+2/+3 — ART/config
  partitions are irreplaceable per-unit data.

## Recovery ladder (no serial available)

1. Factory slot web UI at 192.168.32.1 (upload/update) — while `fac_mode` reachable.
2. U-Boot auto-TFTP recovery at 192.0.0.1 (root_uImage) — while NOR/U-Boot intact.
3. armprg/Sahara-Firehose read+program — while the download-mode chain is reachable.
4. Serial console (X8, 115200 8N1) — requires opening the case; NOT available to us.

## OpenWrt install path (once main slot is rewritten)

Official 25.12.x `ipq40xx/generic zte_mf286d` sysupgrade; from a running OpenWrt use
plain `sysupgrade` (never `-F`); keep `sysupgrade -b` config backups; do not touch the
modem firmware. Verify against downloads.openwrt.org checksums.
