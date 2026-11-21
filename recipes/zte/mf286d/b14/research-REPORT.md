# MF286D B14 spike — research report

Date: 2026-11-09. Agent: research subagent (software-only, zero external interactions).
Artifacts analyzed locally (read-only): `/tmp/opencode/b14/` (modem-manifest.txt, system-scan.txt, modem-payloads/, system-payloads/). The read-only evidence dir `~/mf286d-work/evidence/modem-fw-re/` was **not** touched.

**Headline result:** the "undocumented" ZFD01.02 per-file delta stream is **cracked** (see §3). Every `.p.payload` record decodes with raw LZMA1 + bsdiff40/full-file semantics. Working decoder: `/tmp/opencode/b14/research/zfd_decode.py`. The B14 `dsi_config.xml` is fully recovered at `/tmp/opencode/b14/research/dsi_config.B14.dec.xml` and it is a **stock Qualcomm DSI config** (no ZTE carrier-specific data-call knobs).

---

## Task 1 — Qualcomm MCFG (mcfg_sw.mbn) prior art

### Findings
- `mcfg_sw.mbn` is **not** squashfs/FAT. It is a Qualcomm **ELF (MBN secure-boot v5/v6 header) whose payload segment is a proprietary "MCFG" container** of TLV items. Format reverse-engineered and documented in `sbaresearch/mbn-mcfg-tools/FORMAT.md`:
  - ELF/MBN header (image id, version 5/6, signature/cert-chain fields, total length…)
  - `MCFG` segment header: magic `"MCFG"`, format_type, config_type, item count, carrier index, version id+string
  - Items of type 1 (raw NV item), 2/4 (NV_FILE/FILE with path + data), 10 (trailer `"MCFG_TRL"` with carrier-index/version metadata)
- Contents after extraction (verified layout from Biktorgj/mcfg_tools README, mdm9x07-era):
  - `efsitems/policyman/carrier_policy.xml` — band/RAT policy per carrier
  - `efsitems/Data_Profiles/Profile1..3.bin` — **QMI WDS profile records (APN, auth type/user/pass, PDP type, profile enable)** — these govern default data-call behavior
  - `efsitems/nv/item_files/...` — NV-item files incl. `mmode/mode_pref`, `voice_domain_pref`, `sms_domain_pref`, `modem/data/3gpp/dsmgr/*`, `lte/rrc/*`
  - `nvitems/NN_ID_Name.bin` — classic NV items (e.g. 10_848 Acquisition-Order-Preference, 11_849 Network-Selection-Mode)
  - header.bin, footer_complete.bin
- Signatures: modems tested by sbaresearch only checked secure-boot **hashes**, not signatures, for MCFG files; Biktorgj's tools strip signatures entirely. fenrir-naru documents the anti-rollback digest mechanism: EFS `/nv/item_files/mcfg/mcfg_sw_config_digest_version` vs `image/modem_pr/mcfg/configs/.../mcfg_sw.mbn` (+ `mbn_sw.dig`, `mbn_hw.dig`) — the modem re-imports an mcfg only when its digest changes, and flashing modified files is blocked by the digest in the last trailer item (Qualcomm secure-boot digest mismatch).

### Tools (all open-source)
| Tool | Clone URL | Language | Usage for mcfg_sw.mbn |
|---|---|---|---|
| mbn-mcfg-tools (SBARE) | `https://github.com/sbaresearch/mbn-mcfg-tools` | Python | `pip install .` then `mbn-tool -e mcfg_sw.mbn out_dir` (also `-p` repack, `-c` hash check). Auto-generated NV item parsers (imperfect). |
| mcfg_tools (Biktorgj) | `https://github.com/Biktorgj/mcfg_tools` | C | `make` → `./unpack_mcfg -i mcfg_sw.mbn -o dir [-f]` / `pack_mcfg -i dir/dump.list -o out.mbn`. Hardcoded mdm9x07 ELF params; strips signatures. |
| mbn_utils (fenrir-naru) | `https://github.com/fenrir-naru/mbn_utils` | Ruby | `./repack mcfg_sw.mbn` → `mcfg_sw.mbn.extracted/` + `items.txt`; `./nv_print.rb items.txt` for human-readable NV list. Documents digest locations. |
| EfsTools | `https://github.com/JohnBel/EfsTools` | Python | talk to a live modem's EFS over DIAG (not for offline .mbn, but the NV item DB used by others). |
| qtestsign | `https://github.com/msm8916-mainline/qtestsign` | — | re-sign ELF images with test keys (for reflash experiments). |

### Applicability to our artifacts
- Our B14 delta touches 119 MCFG files under `/mnt/modem/image/modem_pr/mcfg/configs/mcfg_sw/generic/...` (matches the standard NON-HLOS `modem_pr/mcfg/configs` layout exactly; see `modem-manifest.txt`).
- **Telia/Telia_SWE/mcfg_sw.mbn** (the carrier our device selects) decodes to a 62,776-byte **BSDIFF40 patch** → needs the B12 baseline file + `bspatch` to reconstruct, then `mbn-tool -e` / `unpack_mcfg` to inspect policyman/Data_Profiles.
- **EU/Telia/MF297D/Telia_SWE/mcfg_sw.mbn** ships as a **full 62,720-byte file** in this same package (`modem-payloads/modem.mld_mnt_modem_image_modem_pr_mcfg_configs_mcfg_sw_generic_EU_Telia_MF297D_Telia_SWE_mcfg_sw.mbn.p.payload`) — the closest sibling available *without* a B12 image; diffing its extraction against a reconstructed Telia_SWE B14 would isolate the actual carrier-policy change.
- Interesting diff targets once reconstructed: `policyman/carrier_policy.xml`, `Data_Profiles/Profile*.bin` (WDS/APN/auth), `mmode/mode_pref` + `voice_domain_pref` (3G/VoLTE removal fits the `net_select="Only_LTE"` nv change, §4).

Sources:
- https://github.com/sbaresearch/mbn-mcfg-tools (+ /blob/main/FORMAT.md, README.md)
- https://github.com/Biktorgj/mcfg_tools (README)
- https://github.com/fenrir-naru/mbn_utils (README)
- https://github.com/JohnBel/EfsTools, https://github.com/msm8916-mainline/qtestsign

---

## Task 2 — dsi_config.xml (DSI netctrl, modem-Linux)

### Findings
- `dsi_config.xml` is the configuration file for Qualcomm's **DSI (Data System Interface) / ds_netctrl** library (`libdsi_netctrl.so`), consumed at boot on QTI modem-Linux (MDM9x0x LE) and on Android at `vendor/etc/data/dsi_config.xml`. Upstream source lives at `vendor/qcom/proprietary/data/dsi_netctrl/src/` (visible in Android vendor trees, e.g. TurboX D660 build logs; LineageOS `proprietary-files.txt` blobs list `vendor/etc/data/dsi_config.xml` alongside `netmgr_config.xml`).
- **Schema (fully documented by our own recovered B14 file + a Xiaomi msm8998 vendor sample):**
  ```xml
  <list name="dsi_config">
    <listitem name="<target-codename>">       <!-- one per SoC/chassis -->
      <data name="qos_enabled" type="int">1</data>
      <data name="rmnet_data_enabled" type="int">1</data>
      <data name="phys_net_dev" type="string">rmnet_ipa0</data>
      <data name="single_qmux_channel_enabled" type="int">1</data>
      <data name="single_qmux_channel_name" type="string">rmnet0</data>
      <data name="num_dsi_handles" type="int">8</data>
      <list name="device_names">…rmnet_data0..7…</list>
      <list name="control_port_names">…rmnet_data0..7…</list>
    </listitem>
  </list>
  ```
  Target listitem names are Qualcomm codenames (`msm`, `mdm`, `tesla` = 9X40/9X45 LE, `atlas` = 9X50/9X55 LE, `cobalt`, `msm8996`, `SDM845`, …). Selection is per detected platform/chassis.
- What affects rmnet data-call bring-up from this file: `phys_net_dev` (which rmnet device anchors QMI_WDS), `single_qmux_channel_enabled/_name` (one QMUX control channel vs per-handle), `num_dsi_handles`/`device_names`/`control_port_names` (how many concurrent WDS clients/bridges), `qos_enabled`. **APN/auth/autoconnect live elsewhere**: WDS profile storage (NV/EFS `Data_Profiles` in mcfg, or QMI WDS profile 3gpp,1 on the modem) and `netmgr_config.xml` (netmgrd) — the B14 package does **not** patch `netmgr_config.xml`; it patches `dsi_config.xml`, `qmi_ip_cfg.xml`, `libdsi_netctrl.so.0`, `qmi_ip_multiclient`, `rmnetcli`, and adds `qmi_shutdown_modem` init hooks (see `system-scan.txt`).

### Our recovered B14 file (evidence)
- `/tmp/opencode/b14/research/dsi_config.B14.dec.xml` — 25,421 bytes, 38 listitems, copyright 2013/2015, includes `cobalt` (MDM9x50/9650-era) entry with stock values (`qos_enabled=1`, `rmnet_data_enabled=1`, `phys_net_dev=rmnet_ipa0`, `single_qmux_channel=rmnet0`, 8 handles, `rmnet_data0..7`).
- **It is byte-for-byte stock-Qualcomm style; no ZTE-specific data-call knobs (no zte_*, no APN, no autoconnect flags).** Conclusion: the community-reported B14 data-call regression is *not* explained by dsi_config.xml content itself. Since the B14 record shipped it as a full-file replacement (not a diff), the B12→B14 delta may be trivial (whitespace/version bump) — worth a diff once a B12 dump exists; the stronger suspects are the patched `libdsi_netctrl.so.0` / `qmi_ip_cfg.xml` / modem AMSS side (modem.b*).

### Sources
- Recovered file: `research/dsi_config.B14.dec.xml` (this repo dir)
- Reference sample (Xiaomi msm8998 vendor): https://gitlab.com/the-muppets/proprietary_vendor_xiaomi/-/blob/ad98b5c9226f5ee224182412804ef72cf36feb71/msm8998-common/proprietary/vendor/etc/data/dsi_config.xml
- dsi_netctrl source path: `vendor/qcom/proprietary/data/dsi_netctrl/src/` (e.g. https://blog.csdn.net/wb4916/article/details/143867386 build log; LineageOS https://github.com/LineageOS/android_device_lge_sm8150-common/blob/lineage-22.2/proprietary-files.txt lists `vendor/etc/data/dsi_config.xml` + `netmgr_config.xml`)

---

## Task 3 — ZTE .up / delta.package / ZFD01.02 prior art (and our crack)

### Prior art found (limited)
- **Nobody publicly documents the ZTE container internals.** Searches for "ZFD01", "0x55AA5588", "NORMDIFF/IMGDIFF2 + ZTE", and ZTE-delta unpacker repos found nothing that covers this format. The community treats the `.up` purely as a ZIP (rename and unzip — confirmed: eko.one.pl post 794) and flashes `delta.package`+`delta.signature` verbatim.
- Community tooling that exists is **discovery/download only**:
  - Gist `dream-svg/mf28x_find_deltas.py` (fork of `Leo-PL`'s, credit "frutis"): SyncML DM/1.2 session against `https://dmeu.ztems.com/zxmdmp/dm` with hardcoded creds `ZTEDM`/`ZTEDM` (MD5 HMAC), reports `NewVersion:Nordic_MF286D_B14` + download URL on `dleu.ztems.com`. https://gist.github.com/dream-svg/f0ff6b8500f8eb09c5803883977ff28a
  - eko.one.pl thread 21847 ("ZTE MF286D - Openwrt") first post links the ZTE **Sales Update Framework** (Windows) and stock mtd dumps: https://dl.eko.one.pl/orig/zte_mf286d/NORDIC/
  - Manual modem-delta flash procedure (AT+FOTACTR via adb push to /cache) — see §4; original write-up by stich86 on eko.one.pl, mirrored at ISPreview.
  - `minanagehsalalma/zte-router-tools` (https://github.com/minanagehsalalma/zte-router-tools) — RE tools for ZTE H188A/H288A firmware: useful *methodology* (binwalk-first), different firmware family, no delta support.
- "IMGDIFF2"/"NORMDIFF" magics are from **Android applypatch** (A/B OTA), not seen inside our ZFD records.

### Our crack (new, verified today on the B14 package)
Each ZFD01.02 per-file record stream (the `0x5D …` stream) is:

```
[BE32 comp_len][BE32 orig_len][5D 00 00 02 00][raw LZMA1 stream, NO EOS marker]
                                     │
                                     └─ LZMA1 props lc=3 lp=0 pb=2 (0x5D),
                                        dict_size LE32 = 0x00020000 (128 KiB)
```

- Decode as `lzma.FORMAT_RAW` FILTER_LZMA1 dict_size=0x20000, **max_length=orig_len** (stream has no end-marker; waiting for EOS fails).
- The decompressed blob is one of:
  - **BSDIFF40 patch** (bsdiff4 magic, standard LE-u64 control triples) → `bspatch(old_B12_file, blob)` reconstructs B14 file;
  - **full replacement file** (e.g. dsi_config.xml above);
  - 12-byte stub records (`comp=0, orig=0`) = directory/metadata entries (mkdir), not files.
- Classification of our extraction (`research/classify-system.txt`, `classify-modem.txt`):
  - system.mld: 558 bsdiff40, 208 full-file, 240 dir-stubs
  - modem.mld: 84 bsdiff40, 22 full-file, 57 dir-stubs
  - No bsdiff-other/IMGDIFF/NORMDIFF magics present.
- Decoder utility: `research/zfd_decode.py` (`--classify <dir>` or single file decode). Run over the two 12-byte-stub classes confirms header-only records.

### Applicability / next step for the spike
- To reconstruct B14 targets you need **B12 baselines** for the 558+84 bsdiff40 files. Two legal local sources: full mtd/modem dumps (dl.eko.one.pl NORDIC dir / own device backup), or the earlier `TELIA_MF286DV1.0.0B10-…B12` deltas chain.
- Full-file records can be analyzed immediately (e.g. `qmi_ip_cfg.xml`, `build.prop`, telnet/login payloads, and the MF297D Telia mcfg).

Sources:
- https://gist.github.com/dream-svg/f0ff6b8500f8eb09c5803883977ff28a (finder script + comments)
- https://eko.one.pl/forum/viewtopic.php?id=21790 (posts 776-825) and https://eko.one.pl/forum/viewtopic.php?id=21847 (posts 3451-3475)
- https://www.ispreview.co.uk/talk/threads/updating-the-modem-firmware-of-the-zte-mf286d.38435/ (FOTA procedure)
- https://github.com/minanagehsalalma/zte-router-tools

---

## Task 4 — Community status: B14 modem on OpenWrt / downgrade B14→B12

### What users actually experienced (eko.one.pl thread 21790, posts 791-823, Oct-Nov 2024)
- **B14 upgrade works but modem won't data-connect on OpenWrt**: post 791 (PiotrekK): modem upgraded to `BD_TELIAMF286DV1.0.0B14` (ATI, post 785), registers, right APN, but never enters "connected"; LED solid blue. Posts 807-808: `AT+CFUN=1,1` and `qmi_shutdown_modem` didn't help; user gave up and rolled back to B12. Same failure independently at ISPreview/OWrt forum: uqmi `--start-network` → "Unknown error", `--get-current-settings` → "Out of call", while `+CGPADDR` shows the PDP context *is* up (luca, OWrt thread 175362) — i.e. B14 breaks the **QMI WDS data-call/rmnet bridge** used by uqmi/ModemManager, not the PDP itself.
- **B14 disables 3G voice**: post 814 — B14 nv script sets `nv set net_select="Only_LTE"`; voice only via VoLTE; outgoing calls fail for some (post 825).
- **B14 removes admin console access**: post 822 ("user admin appears deleted").
- **ZTE's own B14 nv commit block** (posted in full at post 781, frutis): band locks `lte_band_lock=0x2008080045`, `net_select="Only_LTE"`, `cr_version=Nordic_MF286D_B14`, `cr_inner_version=CR_TELIAMF286DV1.0.0B14`, `integrate_version=TELIA_MF286DV1.0.1B02`, datastall monitor `zte_dst_datastall_monitor_switch=1`, cutoff ping probes to `8.8.8.8`, syslog, DDNS providers; deletes `https_ServiceURL*`, `tcm_server_url`.

### Exact downgrade path used (verified multiple users)
1. From OpenWrt: flash back **mtd8+mtd9** (web+rootfs) of stock Nordic (Cezary's dumps at https://dl.eko.one.pl/orig/zte_mf286d/NORDIC/) → boots stock ZTE FW (posts 793, 803; oliva 3464-3475 in thread 21847).
2. **Pitfall — stale version identity:** stock FW then reports B02, not B14/B12: "ZTE doesn't read the version from the modem, it reads it once and caches it in nv variables" → **factory reset** after mtd swap re-reads modem identity (post 804-805; PiotrekK's post 803 mystery explained).
3. From stock: use **ZTE Sales Update Framework** (Windows) to go to B02 (package "framework has all necessary files", post 316098/316108), then **manual FOTA deltas B02→…→B12** to the modem:
   - unzip `.up` (it's a zip), per-step dir `imageB0XnaB0Y/` contains `delta.package`+`delta.signature`
   - `adb push delta.package /cache/ ; adb push delta.signature /cache/`
   - AT on `/dev/ttyUSB1`: `AT+FOTACTR=0` (0=package seen), `=1` (0=signature OK), `=5` (returns package bytes), `=8` (cleanup, may return -1, harmless), then `=2` starts flash; modem reboots twice; do steps one-by-one (B03→B04→…).
   - (ISPreview thread 38435 posts #1-#20; original by stich86.)
4. Result: back on B12, OpenWrt data calls work again (luca: "I managed to revert… and now openwrt can bring up the interface just fine"; wiki note added on https://openwrt.org/toh/zte/mf286d — page currently behind bot-check).
- Alternative downgrade pkg (ilblogdicristiangallo Google-Drive "Nordic to Nordic B12") frequently fails in Framework with **"Invalid selected version"** (blog's own note + oliva post 3475 "all of them say Invalid selected version"); the mtd8/9 route is the reliable one.
- FOTA failing on-device (stuck, `DM_RemoveFile /etc_rw/fota/image.zip`) resolved by: enable auto-update, reboot, re-check manually (happycamper post 798).

### Relevance to our spike
- Our B14 package's data-call regression is real, reproduced by 3+ independent users on uqmi/ModemManager, and **downgrade to B12 restores it** → the behavioral change is in the B14 modem payload itself (modem.mld AMSS + mcfg + dsi/netctrl bits), exactly what this spike is diffing.
- The B12→B14 package's `nv` block and `net_select="Only_LTE"` explain the voice loss, not the QMI failure; `zte_dst_datastall_monitor_switch`/cutoff-ping is router-side (web UI), also not QMI. Prime suspects: `modem.b0x` AMSS bsdiffs, `libdsi_netctrl.so.0`, `qmi_ip_cfg.xml`, and Telia_SWE `mcfg_sw.mbn`.

---

## TOOLING SHORTLIST (for the next agent)

1. **ZFD delta decode (ours, ready)** — `python3 /tmp/opencode/b14/research/zfd_decode.py <file.p.payload> [out]` or `--classify <payload-dir>`. Record format: BE32 comp_len + BE32 orig_len + `5D 00 00 02 00` + raw LZMA1 (no EOS). Outputs full-file or BSDIFF40.
2. **bsdiff** — `apt install bsdiff` (or pip `bsdiff4`) → `bspatch old_B12_file patch.bsdiff new_B14_file` for the 642 bsdiff40 records; baselines from dl.eko.one.pl NORDIC mtd dumps or own device.
3. **mbn-mcfg-tools** — `git clone https://github.com/sbaresearch/mbn-mcfg-tools && pip install .` → `mbn-tool -e mcfg_sw.mbn out/` (`-p` repack, `-c` hash-verify). Best-documented (FORMAT.md).
4. **Biktorgj/mcfg_tools** — `git clone https://github.com/Biktorgj/mcfg_tools && make` → `./unpack_mcfg -i mcfg_sw.mbn -o dir` (C, fast, dump.list-based repack; mdm9x07-hardcoded ELF params — for MDM9650 prefer mbn-tool first).
5. **fenrir-naru/mbn_utils** — `git clone https://github.com/fenrir-naru/mbn_utils` (Ruby) → `./repack mcfg_sw.mbn`; also documents mcfg digest/anti-rollback locations in EFS.
6. **EfsTools** — `git clone https://github.com/JohnBel/EfsTools` for live-EFS NV reads on the device ( DIAG/`/dev/ttyUSB*`), e.g. `/nv/item_files/mcfg/*digest*` to confirm which mcfg actually imported.
7. **General**: `binwalk` (quick triage of any container), `qcsuper` (https://github.com/p1sec/qcsuper, DIAG logs if hardware access ever allowed), `ztems` delta-finder gist (URL above) to enumerate/monitor future Nordic builds.

### Local evidence produced by this research (all under /tmp/opencode/b14/research/)
- `zfd_decode.py` — decoder/classifier (documented header/LZMA/bsdiff semantics)
- `dsi_config.B14.dec.xml` — full recovered B14 DSI config (25,421 B)
- `classify-system.txt`, `classify-modem.txt` — per-record class+size listings
