# MF286D modem B14 — research dig findings & handoff document

Session: 2026-11-09, time-boxed 40-min spike (software-only, zero external interaction).
Scope: acquire + unpack the Nordic B14 `.up` package, extract the full NV script,
establish what B12→B14 actually changes, rank root-cause hypotheses for the
"B14 breaks QMI data under OpenWrt" community consensus, and hand a complete
research kit to future agents. **Goal was NOT to solve B14 — it was to map it.**

All paths below are relative to `~/mf286d-work/evidence/b14/` unless absolute.
Sibling dir `/tmp/opencode/b14/` holds extracted per-file payloads + drafts
(consider copying into evidence before /tmp is wiped — see ARTIFACTS).

---

## 1. STATE — facts established today

Each fact lists its evidence artifact. Hashes: `sha256` prefix (full hashes in
`ARTIFACT-SUMS.txt`).

### S1. The B14 delta package is acquired, verified, and fully unpacked
- `TELIA_B12-V1.0.1B02.up`, 23,920,803 B, sha256
  `7df293bd5188b6aa6a07778bba49d652aec74f4f483e16c80ce3bde994dc9dc9`
  — downloaded from the direct ZTE DMS URL (`dleu.ztems.com/.../337964/TELIA_MF286DV1.0.0B12-TELIA_MF286DV1.0.1B02.up`),
  HTTP 200, no query dance needed. Live as of 2026-11-09.
- It is a **ZIP**: `cpe_postprocessing.sh`, `delta.package` (13,205,536 B),
  `delta.signature`/`key.signature`/`root_uImage.signature` (256 B RSA each),
  `public_ver.pem`, `root_uImage.mld` (10,806,009 B). → `unpacked/`.
- `root_uImage.mld` = router-side rootfs delta, format `ZDF01.05 NORMDIFF`
  (header at offset 0) — **not yet decoded** (needs B12 router base; we hold
  eko B12 router dumps `~/mf286d-re/fw/nordic-B12/` for this).

### S2. delta.package structure is fully mapped; all 15 blobs extracted
- Container magic `0x55AA5588` LE; 15 entries of `name[32] + u32 size + u32 abs_offset`.
- Parser: `parse_delta.py`; blobs in `unpacked/mld/` (boot/aboot/recovery/recoveryfs/
  rpm/sbl/system/tz/**modem**/ztedata/mem_sz/**preprocessing**/clean_mem/**postprocessing**/efs).
- `preprocessing.mld`, `clean_mem.mld`, `postprocessing.mld` are **plaintext shell
  scripts** (readable in full, see ARTIFACTS). `mem_sz.mld` = ASCII `31457280`.
- `preprocessing.mld` shows the update orchestration: kills the ZTE topsw/QCMAP
  daemon tree (`QCMAP_ConnectionManager`, `zte_adapter_*`, `zte_topsw_*`),
  takes `rmnet_data0`/`rndis0` down, remounts `ubi0:rootfs /`, `/dev/ubi1_0
  /firmware`, `ubi0:ztedata /usr/zte_web` → the update engine runs on the
  **MDM9650 modem-Linux** (QTI LE), not the IPQ40xx router.

### S3. The FULL NV-set script is extracted (community only had 5 lines)
- `unpacked/cpe_postprocessing.sh` — 30 `nv set` items, complete list in §1-NV below.
- The community fragment (eko.one.pl id=21790 ~post 791) was exactly lines 17–21
  (net_select + 4 band-lock items). We now hold the whole script incl. `nv save`.
- Separately, `unpacked/mld/postprocessing.mld` (runs inside delta apply) uses a
  **different namespace**: `cfg set` items that are largely ZTE template leftovers
  referencing **MF920T1** (a uFi product) — evidence of copy-paste; the *nv* set
  in `cpe_postprocessing.sh` is the real Nordic/Telia policy payload.
- **NV-CACHED VERSION IDENTITY CONFIRMED**: `cr_version="Nordic_MF286D_B14"`,
  `cr_inner_version="CR_TELIAMF286DV1.0.0B14"`, `integrate_version=TELIA_MF286DV1.0.1B02`.
  This mechanically explains eko posts 803/804 (B12 flashed over B14, UI still
  said B14 until factory defaults): version identity is NV state, not code.

### S4. modem.mld = per-file delta manifest of the modem image tree — 163 files
- Format `ZFD01.02`; record = `[header fields][namelen+name][u32 a][u32 b][0x5D-stream]`.
  Scanner: `scan_zfd.py`; full list: `manifests/modem-manifest.txt`.
- 44 non-MCFG: full AMSS baseband re-delta (`modem.b00…b28`, `modem.mdt`,
  `mba.*`), WLAN/BT fw (`bdwlan30.bin`, `btfw32.tlv`, `qwlan30.bin`, `utf30.bin`,
  `qdsp6a/m.qdb`, `otp30.bin`), and `Ver_Info.txt`.
  Biggest segment deltas: `modem.b11` 1.51 MB, `modem.b08` 156 KB, `modem.b19`
  578 KB, `modem.b15` 244 KB, `modem.b10` 93 KB → substantial baseband change.
- 119 MCFG carrier-policy files (see S6).
- ⚠ Naming trap inside the trap: `modem.b12.p`/`modem.b14.p` are **ELF segment
  files** of the AMSS image, NOT firmware-version files.

### S5. system.mld = per-file delta of the modem-Linux (QTI LE) system partition
- ~600+ records (`manifests/system-scan.txt`), payloads `/tmp/opencode/b14/system-payloads/`.
- **B14 rewrites the modem's data-path stack.** Changed files with data-path roles:
  - `/mnt/system/etc/data/dsi_config.xml` — **Qualcomm DSI netctrl config**
    (how data calls are brought up on rmnet). Header field `x=0` (vs CRC/hash for
    modified files) + target size 1082 B ⇒ likely a **NEW or wholesale-replaced file**.
  - `libqmi_cci.so.1`, `libqmi_csi.so.1`, `libqmi_sap.so.1` — QMI infrastructure libs.
  - `mcm_ril_service` — MCM RIL daemon (modem control/RIL service).
  - `zte_adapter_ppp`, `zte_adapter_cfg`, `zte_adapter_bsp`, `zte_wan_nwinfor` —
    ZTE adapters over the modem data stack.
  - `libztecmdq.so.1`, `zte_topsw_atfwd/sleep/voice`.
  - Boot orchestration: `start_qti_le`, `init_sys_mss`, `power_config`,
    `rcS-zte-before-modem`, `rcS-zte-after-modem`, `S30ipa_fws.sh`, `thermal-engine*`.
- This is modem-side firmware: **OpenWrt users cannot replace any of it** — it
  flashes during the B14 update and stays.

### S6. Carrier policy (MCFG) is part of the B14 delta
- 119 MCFG entries changed across the carrier tree
  (`modem_pr/mcfg/configs/mcfg_sw/generic/...`).
- **Our units' carrier file is patched**:
  `EU/Telia/Telia_SWE/mcfg_sw.mbn.p` (+ sibling `EU/Telia/MF297D/Telia_SWE/mcfg_sw.mbn.p`).
  Also notable: `EU/TIM/MF286D/Commercial/Italy/mcfg_sw.mbn.p` (same species,
  different carrier) and `EU/Elisa/Commercial/FI`.
- `efs.mld` (2,695 B, outer magic `0xAAAAAAAA` + ZFD01.02) patches the modem
  **EFS/NV filesystem** with `fsdelta.bin/config_1.p` + `config_2.p` — direct
  evidence the update writes modem EFS config state (content not yet decoded).
- `ztedata.mld` patches `/mnt/ztedata/config` (ZTE data partition, 165 B target).

### S7. Delta payload encoding: identified but NOT decoded (open)
- Every `.p` payload starts `[BE-u32 a][BE-u32 b]` then a constant 17-byte
  prologue `5D 00 00 02 00 00 00 21 14 C4 8A F6 3F 04 2F F8 5A 93` then
  file-specific bytes. `5D 00 00 02 00` = LZMA properties + 128 KB dict, but
  plain `FORMAT_ALONE` and raw-LZMA1 decodes both fail ⇒ **ZTE-custom delta
  framing** (likely LZMA-compressed bsdiff-style hunks, possibly obfuscated).
- `b` field plausibly = old-file size (Telia mcfg: 62,776 B ≈ plausible B12
  mcfg_sw.mbn size), header `y` field = new-file size (Ver_Info: 178 B;
  dsi_config.xml: 1082 B). Directory records carry 12-byte null payloads.

### S8. Environment facts (corrections received mid-run — do not regress)
- `~/mf286d-work/evidence/modem-fw-re/extracted/` (SYSJ/ARBI/atcmdsrv, Marvell)
  is the **B02-kit artifact = Marvell PXA1826 generation, NOT B12**. Never
  baseline B14 against it.
- Live B12 modem (ADB root, 2026-11-09) = **Qualcomm MDM9650**, soc_id 283,
  kernel 3.18.31 (Jul-10-2021), UBIFS; modem = mtd9 71 MB; efs2 = mtd2.
- **No B12 modem flash dump exists anywhere yet** (device-1 backup is
  router-side only). The B14 modem.mld delta needs a B12 modem base to fully
  reconstruct targets.
- Kit `~/mf286d-work/kit/UPDATE/` holds a **MDM9650 image set** (`mdm-image-
  mdm9650.ubifs`, `mdm9650-boot.img`, `mdm9650-sysfs.ubi`, `NON-HLOS.ubi`,
  `efs.mbn`, `partition.mbn`, `NPRG9x55/ENPRG9x55` firehose programmers) —
  version provenance unverified vs our B12; useful as format reference and
  possibly as delta base candidates (verify first).

### NV item list (full, from cpe_postprocessing.sh) — Qualcomm-router `nv` taxonomy
Band/RAT policy (the community's 5-line fragment):
| item | value | meaning |
|---|---|---|
| `net_select` | `Only_LTE` | RAT selection locked to LTE — explains "3G NV-disabled" symptom under OpenWrt |
| `default_lte_band_lock` / `lte_band_lock` | `0x2008080045` | LTE band bitmask → bits 0,2,6,19,27,37 = **B1,B3,B7,B20,B28,B38** (Telia Nordic profile) |
| `default_gw_band_lock` / `gw_band_lock` | `0x2000000400000` | GSM/WCDMA band mask (inert while LTE-only) |

Identity (explains eko 803/804 NV-cached-version effect):
`cr_version=Nordic_MF286D_B14`, `cr_inner_version=CR_TELIAMF286DV1.0.0B14`,
`integrate_version=integrate_release_version=TELIA_MF286DV1.0.1B02`.

Data/monitoring-adjacent (router-side, but data-path touching):
| item | value | note |
|---|---|---|
| `zte_dst_datastall_monitor_switch` | `1` | **datastall monitor ON** — ZTE data-stall watchdog; candidate participant in data-path conflicts on stock fw |
| `fota_net_set` | `1` | FOTA network setting |
| `cutoff_detect_switch` | `1` | connectivity cutoff detection pings `8.8.8.8` ×2, 5 s timeout (`cutoff_net_link_detect_*`) |

Everything else = router services (syslog set, DDNS provider list,
`gsspone=ONW2Xh6dWMeFgj4biPKE` (opaque token, GSSP service), `log_manage_switch=0`),
and cleared management URLs (`https_ServiceURL*`, `tcm_server_url` deleted).

**Key negative result: the NV script contains NO autoconnect/PDP/QMI-WDS item.**
The NV payload is band/RAT + identity + monitoring — not an obvious "flip QMI
data off" switch.

---

## 2. ARTIFACTS

Under `~/mf286d-work/evidence/b14/`:
| path | what |
|---|---|
| `TELIA_B12-V1.0.1B02.up` | the acquired B14 package (sha256 7df293bd…, S1) |
| `sha256.txt` | hash of the .up |
| `unpacked/` | all 7 zip members |
| `unpacked/mld/` | all 15 delta.package blobs (modem.mld, system.mld, efs.mld, scripts…) |
| `parse_delta.py` | delta.package container parser |
| `scan_zfd.py` | ZFD01.02 per-file record scanner |
| `manifests/modem-manifest.txt` | 163 modem-image files changed B12→B14 |
| `manifests/system-scan.txt` | full system.mld record map (~600+) |
| `ARTIFACT-SUMS.txt` | sha256 of all evidence files |
| `FINDINGS.md` | this document |
| `NEXT-AGENT-PROMPT.md` | ready-to-run continuation prompt |

Under `/tmp/opencode/b14/` (was volatile during the spike — **now persisted,
see below**):
| path | what |
|---|---|
| `modem-payloads/*.payload`, `system-payloads/*.payload` | 1,169 raw per-file `.p` payloads |
| `modem-manifest.txt`, `system-scan.txt` | (copies now also in evidence) |
| `wwand-pr85-reply-draft.md` | DRAFT reply for ddimension/wwand PR #85 — **needs human approval, do not post** |
| `session-input.md` | bullet input for the PR draft |
| `research/REPORT.md` | background research subagent output (MCFG tooling, dsi_config, community downgrade state) |

**Persistence (2026-11-09 shutdown):** everything durable now lives in the
conwrt repo, `recipes/zte/mf286d/b14/` (branch `mf286d-b14/feat`):
- `manifests/`, `research-REPORT.md`, `decoded/` (6 key files),
  `decoded-full/` (all 230 raw full-file decodes, 4.4 MB),
  `drafts/wwand-pr85-reply-draft.md` (DO-NOT-POST banner intact) +
  `drafts/session-input.md`, plus all scripts and docs.
- Binaries (`.up`, `unpacked/`, the 642 bsdiff payloads) are intentionally NOT
  committed (repo convention); they are fully REGENERABLE:
  1. re-download the `.up` from the public ZTE DMS URL (S1), verify sha256
     `7df293bd…`;
  2. `unzip` → `python3 parse_delta.py unpacked/delta.package unpacked/mld`;
  3. `python3 scan_zfd.py unpacked/mld/{modem,system}.mld <outdir>`;
  4. `python3 zfd_decode.py` (or FINDINGS §S9 spec) on each `.payload`.
  Bench-evidence originals remain at `~/mf286d-work/evidence/b14/` (59 MB).

---

## 3. HYPOTHESES — ranked

Community symptom recap (OpenWrt 24.10 on B14): AT ports OK, QMI UIM/NAS/DMS/WDA
OK; `--start-network` hangs → "Unknown error"; `--stop-network 0xffffffff
--autoconnect` → "No effect"; `AT+CGPADDR` shows **3 live PDP contexts with real
IPs while QMI WDS says "Out of call"**; voice broken; 3G NV-disabled. Stock fw
works with B14.

### H2 — Firmware data-path stack change (STRONG, most supported)
B14 replaces the modem-Linux data-path stack (`dsi_config.xml`, `libqmi_*`,
`mcm_ril_service`, `zte_adapter_ppp/cfg`, `libztecmdq`) plus major AMSS segments
(modem.b08/b10/b11/b15/b19) — the new stack brings up/holds data calls
internally (QCMAP/MCM path), so external QMI WDS start/stop conflicts or is
ignored ("No effect", "Out of call" while 3 PDPs are live).
- For: S5 file list is exactly the data-call bring-up machinery; symptom of
  modem-held contexts matches internal data-path management; stock fw uses the
  ZTE-internal bring-up path so it keeps working.
- For: scale of AMSS deltas = real baseband behavior change, not just config.
- Against: not yet proven which component changed *behavior* (payloads
  undecoded); a pure recompile/no-op update would show the same file list.
- Test: E2/E4 below.

### H3 — Carrier-policy change via MCFG (MODERATE–STRONG)
The Telia_SWE `mcfg_sw.mbn` (and 118 other carriers) change in B14. MCFG can
alter NV defaults + policyman behavior (data profiles, call policy, RAT policy)
on the modem — persistent in EFS, invisible to router-side OpenWrt.
- For: carrier policy is precisely the layer that says how data calls are
  managed; `efs.mld` writes EFS config directly; MCFG deltas touch the exact
  policy mechanism Qualcomm uses.
- Against: no decoded content yet; mcfg changes may be routine (band additions)
  across the whole carrier tree (119 files = fleet-wide template bump, not
  Telia-specific surgery).
- Test: E3.

### H1 — Modem-internal-autoconnect via NV item (WEAK as originally framed)
The extracted NV script contains **no** autoconnect/PDP/QMI item — the original
"NV script flips autoconnect" story is not supported by the actual payload.
- For (weakened variant): `nv net_select=Only_LTE` DOES reach the modem (3G
  disabled under OpenWrt proves modem-side persistence of at least RAT policy);
  `zte_dst_datastall_monitor_switch=1` shows ZTE shipping an active data
  watchdog; version-identity items prove NV state survives flashes.
- Against: no WDS/autoconnect NV item exists in the script; the NV world here
  is mostly router-side policy.
- Reframe: H1 survives only as "modem EFS state (via efs.mld/MCFG) encodes
  data-path policy" — which merges into H3. The pure-NV-script variant is
  **effectively refuted** by the full script content.

**Working synthesis for the next agent:** B14 changed the modem's data-path
firmware stack (H2) very likely *in combination with* carrier/EFS policy (H3);
the "NV script" story (H1) is now disproven in its strong form but revealed the
mechanism (NV/EFS persistence) that explains post-flash version identity and
 RAT-lock symptoms.

---

## 4. EXPERIMENTS for a future agent

### Static-only (no hardware)
| # | experiment | how | expected outcome per hypothesis | cost |
|---|---|---|---|---|
| E1 | Decode the ZFD `.p` stream format | The kit's updater (`~/mf286d-work/kit/UPDATE/`, `mdm9650-*` images + router dumps `~/mf286d-re/fw/nordic-B14/mtd8.bin`) contains the delta-apply engine; find it (strings/ghidra: search for the 17-byte prologue or "ZFD"/"NORMDIFF"), reverse the hunk format, write a standalone applier. Test on `Ver_Info.txt.p` (178 B target, ~133 B payload) — its plaintext-ish content makes verification trivial. | Unlocks E2–E4 entirely. | 0.5–2 days RE |
| E2 | Reconstruct + diff modem-Linux system | Apply system.mld payloads (needs B12 system base — see E6) or diff raw payload bytes for changed-data hints; diff `dsi_config.xml` old-vs-new specifically (1082 B target). | H2: expect DSI/queue/profile changes to internal data-call bring-up. | hours after E1 |
| E3 | MCFG analysis | Get B12 `mcfg_sw.mbn` for Telia_SWE (from E6 dump or kit MDM9650 images), apply `Telia_SWE/mcfg_sw.mbn.p`, unpack both with MCFG tooling (see research/REPORT.md), diff policy files (policyman config, mcfg_nv items). | H3: expect data-profile / call-policy / autoconnect-policy deltas. | hours after E1 |
| E4 | AMSS segment diff | Apply modem.b*.p deltas vs B12 segments; strings+bindiff `modem.b11` (1.5 MB delta) for QMI WDS/ds call-policy changes. | H2: expect WDS/DS behavior change near autoconnect/profile logic. | 1 day after E1 |
| E5 | NV-item meaning table | Extend §1-NV table with QC NV IDs (map names→NV numbers using public qc NV enums / modem-fw-re tooling where applicable). | Documents which items are router- vs modem-side persistent. | 2–4 h |
| E7 | Router-side root_uImage.mld delta | Apply vs eko B12 router dumps we already hold (`~/mf286d-re/fw/nordic-B12/`); confirm CVE-2023-25649 fix scope on stock (low priority for QMI breakage). | Context for the "never stock B10/B12" advisories. | 2–4 h after E1 |

### Dynamic (requires a B14-unit or device-1 after upgrade — bench work)
| # | experiment | how | expected outcome | cost |
|---|---|---|---|---|
| D1 | ADB NV/EFS dump on B14 unit | `adb shell` → dump `/nv` + EFS (`/efs2`, mtd2) before/after factory reset; compare vs B12 (device-1). | H3: policy NV items differ; factory reset reverts identity items (mechanically proven by eko 803/804). | bench day |
| D2 | QMI WDS trace B12 vs B14 | On bench: qmicli/UQMI trace (`--device-open` + wds start/stop with qmi_wwan raw-ip) capture qmux messages; compare verdicts/timeouts. | H2: B14 rejects/ignores external WDS bind/start while internal contexts live (CGPADDR evidence). | bench day |
| D3 | Selective revert | On B14 unit: revert only `dsi_config.xml` / only Telia MCFG / only EFS config_1+2 (keep B14 AMSS), reboot, retest QMI. | Isolates H2-firmware vs H3-policy. | bench day |
| D4 | Modem mtd dump on device-1 (B12) | **First thing to get**: `adb shell` dd/ubiread of mtd9 (71 MB modem) + efs2 (mtd2) → the missing B12 baseline for E2–E4. | Creates the B12 modem base; also verifies kit-image provenance. | 1–2 h bench |

### ROADMAP (workstreams for future sessions)
1. **WS-A "Decode"** — E1 (ZFD applier) → E2/E3/E4. Highest leverage; unlocks everything static.
2. **WS-B "Baseline"** — D4 modem dump → verify kit MDM9650 image provenance → enables WS-A fully.
3. **WS-C "Live-probe"** — D1/D2/D3 on a B14 unit; pairs with WS-A outputs to pick revert targets.
4. **WS-D "Community"** — PR #85 reply after human approval (draft ready); wiki note already exists (2026-03-03: don't upgrade modem to B14).

---

## 5. BLOCKERS

- **No B14 hardware on bench** (both campaign devices are B12). All H2/H3
  confirmation is static until a B14 unit or an upgrade+rollback bench window.
- **No B12 modem flash dump exists** (mtd9/efs2 only became reachable via ADB
  root today; RE session owns that interface — dump is post-window task D4).
- **ZFD `.p` payload codec undecoded** (S7) — all content diffs gated on E1.
- Delta reconstruction needs B12 bases for modem image + modem-Linux system;
  kit MDM9650 images are unverified provenance (may be B02-era or regional).
- Checked 2026-11-09: `dl.eko.one.pl/orig/zte_mf286d/NORDIC/B12/` carries only
  router-side dumps (mtd8.bin 8,388,608 B; mtd9.bin 30,408,704 B — duplicates
  of what we already hold in `~/mf286d-re/fw/nordic-B12/`). No modem-side B12
  base exists there. (B14 subdir holds mtd8/mtd9 router dumps too.)
- This session: no git commits (overseer owns the conwrt lane); drafts only,
  human approval required before any external posting.

## 6. Continuation
See `NEXT-AGENT-PROMPT.md` — ready-to-run prompt for the next session.

---

# UPDATE — extension window (2026-11-09, +15 min): ZFD FORMAT CRACKED, H8 FOUND

## S9. The ZFD `.p` payload codec is DECODED (was S7 blocker)
Empirically cracked (and independently confirmed by the research subagent —
no public prior art exists). Payload layout after `name+NUL`:
```
[BE-u32 comp_len][BE-u32 uncomp_size][5B LZMA1 props: 5D 00 00 02 00 (=128 KiB dict)]
[raw LZMA1 stream, NO size field, NO end marker]  → decode = synth header
  b"\x5d\x00\x00\x02\x00" + pack("<Q", uncomp_size) + stream[5:]   (FORMAT_ALONE)
```
Stream decodes to either **BSDIFF40 patch** (642 records — need B12 base +
`bspatch`) or **FULL NEW FILE** (230 records — readable NOW).
Reference decoder: `zfd_decode.py` (evidence/b14/ + research/).
All 872 decodable payloads: `/tmp/opencode/b14/decoded2/` (raw__*/bsdiff__*).
Key decoded files persisted in `evidence/b14/decoded/`.
The earlier "constant 17-byte prologue" was just LZMA of the shared
`BSDIFF40` magic — not encryption.

## S10. NEW EVIDENCE — the multi-client QMI bridge (H8, see below)
Raw (new/wholesale-replaced) files extracted from system.mld:
- **`/mnt/system/etc/qmi_ip_cfg.xml`** (evidence/b14/decoded/qmi_ip_cfg.xml.B14):
  `<mode>multi_client</mode>`, `single_client_udp_port 7788`,
  **`<lan_clients_allowed> 3 </lan_clients_allowed>`**.
- **`/mnt/system/etc/init.d/start_stop_qmi_ip_multiclient`** (decoded/*.B14.sh):
  starts `/usr/bin/qmi_ip_multiclient /etc/qmi_ip_cfg.xml`.
- `data-init`, `netmgr_config.xml` (`qmi_dpm_enabled=0`, rmnet maps),
  `qmi_shutdown_modemd`, `modem-shutdown`, `rcS-zte-before/after-modem` — all raw.
- `dsi_config.xml` (25,421 B, fully decoded): **stock Qualcomm DSI config,
  38 targets, NO ZTE-specific data-call knobs** → dsi_config itself is
  exonerated; it was replaced only because it ships with the stack refresh.

## S11. MCFG tooling + no-base-needed sibling (from research subagent)
- `mcfg_sw.mbn` = ELF/MBN wrapping proprietary MCFG TLV segment. Open tools:
  `github.com/sbaresearch/mbn-mcfg-tools` (`mbn-tool -e`, best docs),
  `github.com/Biktorgj/mcfg_tools`, `github.com/fenrir-naru/mbn_utils`.
  Policy contents: `Data_Profiles/Profile*.bin` (WDS/APN/auth),
  `policyman/carrier_policy.xml`, `mmode/*` NV.
- **`EU/Telia/MF297D/Telia_SWE/mcfg_sw.mbn` ships FULL-FILE** in our package
  (raw, in decoded2/) — the MF286D's own Telia_SWE mcfg is a bsdiff, but the
  MF297D sibling needs no baseline → extract it with mbn-tool NOW to read
  Telia carrier data-call policy of this generation.
- Community downgrade path (eko) fully documented in `research-REPORT.md`
  §4: mtd8/9 reflash → **factory reset required to clear NV-cached modem
  version** → Framework trick → `AT+FOTACTR` stepwise to B12; "Invalid
  selected version" pitfall noted.

## HYPOTHESES — updated ranking (supersedes §3)

### H8 — qmi_ip_multiclient multi-client QMI bridge (NEW, TOP TIER)
B14 ships/enables Qualcomm's `qmi_ip_multiclient` daemon + `multi_client`
config (`lan_clients_allowed=3`). This daemon holds its OWN QMI WDS clients
and brings up data calls on behalf of LAN clients — the modem's data engine
then shows exactly the observed symptom: **three live PDP contexts** external
QMI WDS cannot see/stop (`stop 0xffffffff` → "No effect"), start-network
conflicts → "Unknown error". Stock fw coordinates with it; OpenWrt doesn't.
- For: qmi_ip_cfg.xml raw-new + init script raw-new in B14; `3` == the 3 PDP
  contexts in the wild report; mechanically explains every symptom including
  "Out of call" while CGPADDR shows real IPs.
- Against: must confirm B12 did NOT run the same daemon (check B12 modem
  system dump when D4 lands — or qmi_ip_multiclient binary presence/version
  in bsdiff list: `usr/bin/qmi_ip_multiclient` — see manifests/system-scan.txt).
- Test: E8 below.

### H2 — firmware data-path stack change (STRONG, now mostly = H8's substrate)
Unchanged, but dsi_config.xml specifically is exonerated (stock QC content).
Remaining suspects: `libdsi_netctrl.so`, `libqmi_*`, `mcm_ril_service`,
`qmi_ip_multiclient` binary itself, AMSS segments b08/b10/b11/b15/b19.

### H3 — carrier-policy via MCFG (MODERATE–STRONG, now actionable)
E9 below (mf297d Telia sibling needs no baseline).

### H1 — NV-script autoconnect (REFUTED, strong form) — unchanged.

## NEW EXPERIMENTS (append to §4 table)
| # | experiment | how | expected | cost |
|---|---|---|---|---|
| E8 | qmi_ip_multiclient provenance | Was the daemon present in B12? Check manifests, then B12 modem system dump (D4) for `/usr/bin/qmi_ip_multiclient` + `/etc/qmi_ip_cfg.xml` old content; also strings the bsdiff for the binary if listed. | H8: absent-or-different in B12; `lan_clients_allowed` newly 3 | 1–2 h after D4 |
| E9 | Telia MCFG extraction (no base needed) | `git clone github.com/sbaresearch/mbn-mcfg-tools`; `mbn-tool -e` on decoded2/raw__*Telia_MF297D_Telia_SWE_mcfg_sw.mbn*; read Data_Profiles + policyman/carrier_policy.xml. | H3: data-profile/policy deltas incl. autoconnect-relevant settings | 2–3 h, NO hardware |
| E10 | bsdiff mass-apply | Once D4 dump exists: LZMA-decode all 642 bsdiffs, `bspatch` vs B12 files → full B14 modem-Linux tree → wholesale diff. | Complete B12→B14 changelog with content | 0.5 day after D4 |
| E11 | qmi_ip_cfg live test | On B14 bench unit: `adb shell` kill qmi_ip_multiclient / set mode single_client, restart, retest uqmi/wwand. | H8: QMI WDS starts working → direct fix candidate WITHOUT firmware change | bench hour |

**Fix-without-firmware-change prospect (the PR #85 angle): if H8 holds, the
"fix" for OpenWrt users may be as small as disabling/reconfiguring
qmi_ip_multiclient on the modem via ADB — worth E11 before any downgrade.**
