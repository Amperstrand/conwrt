# Qshrink Debug Database + LPA/QMI-UIM Intelligence (EXP-040)

2026-11-10. Companion to the Hexagon-RE lane. All offline on pristine B12 mtd9.

---

## Executive summary

1. **`qdsp6m.qdb` decoded**: it is a zlib stream (from file offset 0x40) containing the
   complete **Qshrink 4.0 hash database** — 250,312 log-message entries with
   `<hash>:<ss_mask>:<ssid>:<line>:<file>:<string>` covering **4,709 source files**
   of the AMSS. This is the modem's full debug-symbol database, on-disk all along.
2. The **entire internal LPA API** is now enumerated from `lpalib.c` log strings:
   `get_profiles_info, enable_profile, disable_profile, delete_profile,
   card_memory_reset, get_EID, add_profile, add_or_update_profile_nickname,
   send_user_consent, default_server_address`.
3. **`qmi_uim_m2m_euicc.c` is a live QMI handler** — its log
   `Sending response for GET_EID` proves it answers a QMI request (at minimum GET_EID).
   The proprietary message IDs remain to be extracted from the IDL table
   (Ghidra analysis in flight).
4. The **EFS-policy load sites are pinned by file:line**:
   - `qmi_uim.c:1116` — "APDU security AID list type: 0x%x, list count: 0x%x"
   - `qmi_uim.c:1479` — "Silent PIN1 verification configuration: 0x%x,
     **APDU security restrictions configuration**: 0x%x, Close channel sync preference…"
   These are the exact code sites that read the `apdu_security_aid_list` /
   `apdu_security_restrictions` EFS items we probed in EXP-035.
5. Side benefit: with this DB, **live DIAG F3 logs become fully decodable**
   (hash → file:line:string), a major debugging capability for any future work.

---

## 1. Qshrink DB format

```
qdsp6m.qdb:
  0x00: 7F 51 44 42 ("\x7fQDB") + GUID + version 00.10.00
  0x40: zlib stream (78 DA) → 21,231,939 bytes plain text
Content: Qshrink 4.0 hash database
  # Hash File: /home/scl/ci/workspace/Soft4_P82M_H3GSEMF286D_uSDK/...
  # Format: <hash>:<ss_mask>:<ssid>:<line>:<file>:<string>
  250,312 entries / 4,709 distinct source files / subsystem 21 = modem core
```
Decode: `python3 -c "import zlib;open('out','wb').write(zlib.decompress(open('qdsp6m.qdb','rb').read()[0x40:]))"`

## 2. LPA stack source census (from the DB)

```
lpa.c(5) lpa_asn1_decoder.c lpa_asn1_encoder.c lpa_cmd.c(7) lpa_http.c(27)
lpa_json.c lpa_lpd.c(25) lpa_mmgsdi.c(21) lpa_notification.c lpa_state.c
lpa_timer.c lpa_util.c lpalib.c(17)
qmi_uim_m2m_euicc.c(3)  mmgsdi_euicc.c(3)  mmgsdi_euicc_m2m.c(4)
qmi_uim_http.c(27)  qmi_uim_multi_profile.c(25)  uimqmi_task.c(6)
```

## 3. The internal LPA command set (lpalib.c, with queue-status logs)

| LPA API | line |
|---|---|
| lpa_get_profiles_info | L121 |
| lpa_enable_profile | L195 |
| lpa_disable_profile | L263 |
| lpa_delete_profile | L332 |
| lpa_card_memory_reset | L402 |
| lpa_get_EID | L463 |
| lpa_add_profile | L604 |
| lpa_add_or_update_profile_nickname | L676 |
| lpa_send_user_consent (go_ahead) | L724 |
| lpa_default_server_address | L823 |

These queue commands into the LPA task (`lpa.c`); `lpa_mmgsdi.c` drives the card
(Get Challenge/Store Data/Delete/Get Data/Get Status), `lpa_http.c`+`qmi_uim_http.c`
implement the ES9+ transport over QMI-UIM-HTTP.

## 4. Key defense/feature log anchors (hash IDs usable for live F3 decode)

| hash | ssid | file:line | string |
|---|---|---|---|
| 76880 | 21 | mmgsdilib.c:1075 | APDU streaming not allowed on default channel |
| 79158 | 21 | mmgsdi_session.c:3359 | After Manage Channel, Select AID failed |
| 79208 | 21 | mmgsdi_uicc_rsp.c:635 | GSDI_ACCESS_DENIED |
| 79213 | 21 | mmgsdi_uicc_rsp.c:963 | Access Denied sw2: 0x%x |
| 80069 | 21 | uim_sigs.c:577 | STREAMING COMMAND is not allowed for channel 0x%x |
| 80507 | 21 | qmi_uim.c:1479 | …APDU security restrictions configuration: 0x%x… |
| 80509 | 21 | qmi_uim.c:1116 | APDU security AID list type: 0x%x, list count: 0x%x |
| 80675 | 21 | qmi_uim_m2m_euicc.c:137 | Sending response for GET_EID |
| 81270 | 21 | lpalib.c:463 | Queue of command: LPA get EID: status 0x%x |
| 84298 | 21 | mmgsdi_euicc.c:140 | Channel id open failed for channel:0x%x |

## 5. Recommended live tests (cheap, next device session)

1. `QMI_UIM GET_SUPPORTED_MESSAGES (0x0030)` from the host — if the extended
   M2M-euicc messages are exposed on the external UIM service, the returned
   bitmap will show bits above 0x47.
2. Collect DIAG F3 (subsystem 21) during an ISD-R open attempt; decode with this
   DB — the exact deny path will log by file:line in real time.
3. If extended msg IDs appear: drive `GET_EID` first (handler proven present).

## 6. Tooling state (Hexagon lane)

- `llvm-objdump` (LLVM 23) decodes Hexagon locally; minimal-ELF wrapper at
  `mkelf.py`; vaddr map at `vmap.py`.
- **Ghidra 12.2 (native Hexagon) headless analysis of the reassembled 58.4MB
  ELF running on ai-legion** (`/tmp/gproj`, `combine_elf.py` builds the image
  from modem.mdt + b-files). Targets: UIM service registration → IDL msg table
  → proprietary euicc msg IDs; ISD-R AID compare; APDU-security config gates.
- Research notes: Ghidra ≥12.1 has native Hexagon; NerdTIV/QDig loader recovers
  source file/line descriptors from split firmware; IDA 9.4+ ships a Hexagon
  module; SRLabs Hexagon-Fuzz (2025) for full-system emulation if ever needed.

## 7. Artifacts

```
hexagon-re/qshrink-db.txt(.gz)        full decoded DB (21MB / 4.7MB)
hexagon-re/qshrink-uim-lpa-extract.txt 6,104 UIM/LPA/mmgsdi entries
hexagon-re/logsite-hashes.json        hash IDs of the defense/feature sites
hexagon-re/vmap.py, mkelf.py, combine_elf.py
```
