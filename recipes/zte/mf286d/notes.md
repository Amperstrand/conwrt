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

## Modem / eSIM (B12 modem firmware)

- QMI UIM service: functional (SIM state, PIN, APDU infrastructure)
- **ISD-R (eSIM management applet) BLOCKED** — EXP-035 (2026-11-09, live
  B12): a deliberate **three-layer MPSS defense**, QMI bypass surface
  *proven exhausted* (not assumed): L1 channel-open denies ISD-R AID ≥7 B
  (QMI error 82); L2 any channel whose open-FCI revealed ISD-R receives
  **fabricated card responses** (differential-proven: identical APDUs =
  real data on a USIM channel vs impossible SWs like SELECT-MF→6A82 — the
  card never sees them); L3 an APDU-payload scanner drops any SELECT
  carrying the GSMA RSP RID (≥4 B) even on unflagged channels. Basic
  channel is modem-only; the AT layer is separately cauterized (all
  channel opens denied). The earlier partial-AID (6 B) channel open
  defeats L1 only — L2 fakes everything behind it (no EID was ever read).
  Earlier ideas now DEAD: empty-AID AT+CCHO trick, any QMI-UIM routing
  trick. Remaining in-device paths: offline MPSS RE (AID-compare,
  canned-SW synthesis, boot-time NV gate), NV/diag flag hunt, MBIM
  composition check, MPSS patch class (last resort). Pragmatic path for
  actual eSIM management: NR7101 or USB CCID reader + lpac.
- **Full B12 MPSS firmware banked** (mtd9, 74.7 MB, sha256 55848f96…,
  `evidence/modem-fw-re/live-b12/dumps/` via live ADB) — the modem
  baseline for ALL offline RE incl. the B14 continuation (its 642
  BSDIFF40 patches now have their base). efs2 NV pull deferred (reads
  destabilize adbd; not hammered — device healthy).
- eSIM profile management IN-DEVICE: **not possible** on this firmware.
- AT CCHO/CGLA/CCHC/CSIM: commands IMPLEMENTED in baseband (response strings in
  firmware binary) but blocked by carrier policy. No community workaround for
  MF286D. Same Qualcomm AMSS-level block (QMI error 82) seen on other carrier
  modems (qmi-sim-bridge project). AT+CCHO="" (empty AID) trick from CellPort
  (Quectel EG25-G) worth testing — may bypass if block is at AID-comparison level.
- ifd-modemifd QMI UIM backend: would work for SIM file ops (pySim/OpenSC) but
  NOT for ISD-R (block is upstream). See ifd-modemifd issue #10 for the
  CCHO/CGLA fallback design.
- MF286D hardware: physical 2FF SIM slot only, NO embedded/soldered eUICC.
- Alternatives: USB CCID reader + lpac ipq40xx artifact (deterministic, no
  firmware risk), or a device without the carrier lock (bench comparison).
- Router firmware B10/B12: CVE-2023-25649 live (close_all_led exec).
  B14: close_all_led fixed but NIGHT_MODE_INFO_SETTINGS end_time still
  unvalidated. Full matrix: bench evidence/firmware-matrix.md.
- Modem firmware B14: documented as "the breaker" — do not update to it.

### B14 ("Nordic_B14", Oct 2024) — what actually breaks (2026-11-09 research)

Package = router `V1.0.1B02` (CVE-2023-25649 fix) + modem
`BD_TELIAMF286DV1.0.0B14` + **a modem-side NV script** (users extracted from
the `.up`: `nv set net_select="Only_LTE"`, `nv set …_band_lock=0x…`).
Delta filename `TELIA_MF286DV1.0.0B12-TELIA_MF286DV1.0.1B02.up` is the
B02/B14 naming trap (same package — the wiki-note confusion documented).
Feature history: B11 = VoLTE enable, B12 = upload CA; B14 unpublished.

Under OpenWrt, B14 modem: AT/UIM/NAS/DMS/WDA all work; **QMI WDS
start-network hangs → "Unknown error"** (PAP/CHAP, v4, v4v6 all fail);
`--stop-network --autoconnect` → "No effect"; voice broken; 3G
NV-disabled. Key evidence: `AT+CGPADDR` shows ACTIVE PDP contexts with
real IPs while QMI WDS reports "Out of call" — the modem's data engine
runs sessions external QMI cannot see/stop/start. Stock firmware works
with B14 → host-control problem, not radio.

**Modem architecture (live-proven via ADB root, 2026-11-09)**: B12/B14
units carry a **Qualcomm MDM9650** (soc_id 283, msm baseband, kernel
3.18.31) — the B02-kit FBF used for early static RE is the older
**Marvell PXA1826** generation and its conclusions do NOT transfer.

**Spike verdict (2026-11-09, artifacts in `recipes/zte/mf286d/b14/`)**: the
B14 `.up` package was acquired, unpacked, and parsed. It **rewrites the
modem's own software**: full AMSS baseband re-delta (163 files) **plus the
modem-Linux data-path stack** — `dsi_config.xml`, `libqmi_cci/csi/sap`,
`mcm_ril_service`, `zte_adapter_ppp/cfg`, `libztecmdq` — plus **119 MCFG
carrier-policy files** (Telia patched) and direct modem-EFS writes.

**Extension window — H8, the smoking gun**: the ZFD `.p` codec was cracked
(`[BE32 comp_len][BE32 uncomp_size][LZMA1 props 5D/128K][raw LZMA1
no-EOS]`; 642 records = BSDIFF40 patches needing a B12 base, 230 = full
files readable now — decoder `zfd_decode.py` in-repo). Decoded
`/mnt/system/etc/qmi_ip_cfg.xml` ships **`<mode>multi_client</mode>` +
`<lan_clients_allowed>3</lan_clients_allowed>`** with an init script
starting `/usr/bin/qmi_ip_multiclient` — a modem-side multi-client QMI
data bridge holding one data call per LAN client. The **3 == the three
live PDP contexts** users observe via `AT+CGPADDR` while QMI WDS reports
"out of call"; stop-network "no effect" + start-network "unknown error"
are both mechanically explained. `dsi_config.xml` is **exonerated**
(decoded: stock Qualcomm DSI config, no ZTE knobs). Ranking:
**H8 (qmi_ip_multiclient bridge) > H2 (data-path stack = H8's substrate)
> H3 (carrier/MCFG)**; H1 (NV autoconnect) refuted — the full 30-item NV
script has no QMI/autoconnect item (LTE-only lock, datastall watchdog,
version-identity-in-NV — the last mechanically explains the eko.one.pl
stale-version reports). **Fix candidate without firmware change**:
stop/reconfigure `qmi_ip_multiclient` via ADB (E11, needs a B14 unit);
E8 provenance check (was the daemon absent/single-client in B12?) can be
done TODAY on device 1's live ADB — no flash dump needed for first pass.

Downgrade (community-proven, painful): ZTE Windows framework + stock
firmware first; or B12 mtd8/9 images + factory defaults (NV-cache gotcha).
Wiki warns against upgrading to B14. Fleet rule stands: never update a
unit's modem off B12.

Sources: forum.openwrt.org/t/175362 ("luca" 2025-03-03, full uqmi logs);
eko.one.pl forum id=21790 posts ~791, 803–823; ispreview thread 42622;
delta-finder gist dream-svg/f0ff6b85. Follow-ups:
`prompts/mf286d-b14-01-dig.md` (root-cause dig),
`prompts/mf286d-b14-02-downgrade-automation.md` (conwrt-native downgrade).

## Modem DM/DIAG channel — THE management surface (2026-11-09)

**Open and fully working** (see `modem/DM-PROTOCOL.md` for the protocol
and `modem/dm_*.c` for tooling): router `/dev/ttyUSB0` speaks DM with a
**nonstandard CRC variant** (crcmod 0x11021/init0/xorFFFF; wrong-CRC
requests get `0x13 BAD_CMD`+echo — looks like lockdown, isn't).
Confirmed commands: VERNO (build date), DIAG_VER, **EXT_BUILD
(MPSS.AT.2.5.1-00628-9655_GEN…)**, and **NV_READ — all 4096 NV items
swept with zero errors** (harvest: `live-b12/nv/nvsweep-4096.txt`,
incl. item 550 IMEI). **This is the QCN-equivalent of the efs2 payload,
extracted with zero raw-flash reads** — the crasher partitions never need
touching for NV backup. mtd9 (MPSS) also re-dumped pristine:
sha256 `efd0b8a6…`, 74,448,896 B (= 0x04700000 exactly; an earlier
"short dump" was a bad size constant on our side, not transport loss —
two independent methods agree byte-for-byte). AT stack post-crash note:
`MCM_atcop_svc` won't start (smd8 tty-class sysfs missing; survives adb
reboot; data path + QMI + DM unaffected; cold power cycle is the fix).

**Modem flash backup inventory + partition safety map (2026-11-09)**:

| Partition | Content | Status |
|---|---|---|
| mtd0 sbl | boot loader | ✅ banked (sha `510e928e…`) |
| mtd9 modem | MPSS/baseband | ✅ banked (sha `55848f96…`) |
| mtd16 system | UBI → fwfs + **rootfs** + ztedata | ✅ banked (sha `2f4e3b63…`), extracted to `mtd16-extract/` |
| mtd1 mibib / mtd2 efs2 / mtd3 tz / mtd5 efsbak / mtd6 aboot | boot chain + NV | ⛔ **crasher class — reading mtd1 reboots the whole modem** (proven); cold-boot single-shot protocol only, never hammer warm |
| mtd4/7/10/11/12/13 | rpm/boot/misc/recovery/fota/recoveryfs | unprobed — use the uptime-continuity probe protocol before any dump |

Transfer method (adb 1.0.32 constraints): `exec-out` broken ("error: closed");
raw `adb shell` CRLF-mangles binaries; modem tmpfs only 64 MB. **Working
pipeline**: `adb shell 'dd if=/dev/mtdN bs=65536 2>/dev/null | base64'` →
`tr -d '\r'` → `base64 -d`, sha256 at every hop. Watch for silently-empty
files when a crasher partition kills adbd mid-loop (bit the RE session: four
0-byte "dumps").

**Remote SIM verdict (2026-11-09)**: NO remote-SIM/vSIM/CloudSIM/SIM-over-IP
infrastructure exists at ANY layer — stock router rootfs (zero strings),
modem-Linux rootfs (zero daemons/configs; standard QTI LE data stack only:
MCM suite, netmgrd, qmi_ip_multiclient, atcmdsrv), baseband mtd9 (zero
strings). Vendor never shipped it. The only theoretical path is an
MPSS-level SIM-APDU relay implementation (research-class, ≥ the ISD-R
three-layer effort). For profile management keep using NR7101/USB-CCID.

**H8 narrowing (from the B12 rootfs dump)**: B12 ships the SAME
`qmi_ip_cfg.xml` (`multi_client`, `lan_clients_allowed=3`) and the same
`start_stop_qmi_ip_multiclient` init script as B14 — but the daemon is
**inert on live B12** (`ps` clean; nothing invokes it; no inetd entry; no
overlay override). H8 as "B14's config takes over data calls" is therefore
WEAKENED — the surviving form is "B14's runtime state differs (daemon
started via a path not visible in the full-file set — possibly one of the
642 BSDIFF40 patches)". The posted PR #85 verification prompt still tests
exactly the right thing (runtime `ps` + stop/reconfigure on a real B14
unit). Applying the BSDIFF40 patches to the now-banked B12 base (E1) is
the definitive static answer — queued for the B14 lane.

## OpenWrt install path (once main slot is rewritten)

Official 25.12.x `ipq40xx/generic zte_mf286d` sysupgrade; from a running OpenWrt use
plain `sysupgrade` (never `-F`); keep `sysupgrade -b` config backups; do not touch the
modem firmware. Verify against downloads.openwrt.org checksums.
