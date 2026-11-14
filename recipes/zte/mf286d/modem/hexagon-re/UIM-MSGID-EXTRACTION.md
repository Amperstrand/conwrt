# QMI UIM Proprietary Message-ID Extraction — COMPLETE (EXP-040 finale)

2026-11-10. Offline static extraction from pristine B12 mtd9. The last open
item of the eSIM arc: the proprietary QMI UIM M2M-euicc message IDs.

---

## Result

The modem's internal **UIM service IDL object** (service 0x0B) was located at
**b16+0x21650 (vaddr 0xc32c0650)** and fully decoded using the public
`qmi_idl_lib_internal.h` struct definitions (quic/qmi-framework):

```
struct qmi_idl_service_object @ 0xc32c0650:
  library_version=6, idl_version=1, service_id=0x0B
  n_msgs: 72 req / 72 resp / 31 ind
  msg tables @ 0xc2316358 / 0xc2316508 / 0xc23166b8
  type table @ 0xc2316774 (76 types, 171 message entries)
```

### The complete REQ message set (72 IDs)

```
PUBLIC (28, in libqmi):
  0x00 Reset                0x20 Read Transparent   0x21 Read Record
  0x22 Write Transparent    0x23 Write Record       0x24 Get File Attributes
  0x25 Set PIN Protection   0x26 Verify PIN         0x27 Unblock PIN
  0x28 Change PIN           0x29 Depersonalization  0x2a Refresh Register
  0x2c Refresh Complete     0x2e Register Events    0x2f Get Card Status
  0x30 Power Off SIM        0x31 Power On SIM       0x38 Change Prov Session
  0x3a Get Configuration    0x3b Send APDU          0x3f Logical Channel
  0x40 Subscription OK      0x42 Open Logical Ch.   0x44 Refresh Register All
  0x46 Switch Slot          0x47 Get Slot Status
  (+0x1e/0x1f common Get Supported Messages/Fields)

PROPRIETARY (44, NOT in libqmi) with req max_msg_len:
  0x2b    41     0x2d    37     0x34  1074     0x35    41
  0x36    48     0x37    45     0x39    37     0x3c    20
  0x3d  1034     0x41     4     0x45    60     0x4b     0
  0x4c 11711  <<< PROFILE DOWNLOAD (Bound Profile Package payload)
  0x4d   191     0x4e     4     0x4f    15     0x51    51
  0x52     4     0x53    15     0x54     4     0x56  1029
  0x57  1029     0x58  1029     0x59  1029     0x5a   685  <<< add-profile class
  0x5b    41     0x5c   327     0x5d  1036     0x5e    14
  0x61    44     0x62    24     0x63     0     0x64    11
  0x65     4     0x66    11     0x67    15     0x68   530
  0x69    79     0x6a   568     0x6b    15     0x6c     8
  0x6d   263     0x6e    20     0x6f    67
```

### Attribution (from IDL name-pool fragments + LPA API cross-match)

The b20 tail-merged name pool contains the proprietary names, partially
recovered: `physical_slot_mapping`, `temporary_identity`, `purge_files(?),
supply_voltage, eid, profile(s), update_nickname, memory, recover, select,
sap_connect_request, get_slots_status, plmn_name_table, imsi, gba…`
Cross-matched with `lpalib.c`'s API (get_EID, add/enable/disable/delete
profile, nickname, user_consent, card_memory_reset, server_address) and
`qmi_uim_multi_profile.c` TLVs (profile state/nickname/spn/name/icon/class/
policy-rules, download error cause, percentage, user consent):
the 0x34-0x6f block = the **M2M-eUICC / multi-profile / SAP / GBA extension
family**, sized consistently (1029-1036B profile-info responses,
11711B profile download, 530-568B euicc-info).

## Caveats (honest)

1. Exact name↔ID pairing still needs the name table (tail-merged, offset-
   referenced); the ID set + sizes are exact, the per-ID names are inferred.
2. **This is the INTERNAL IDL object.** Whether the external QMUX bridge
   (cdc-wdm0) exposes the proprietary IDs to the host is undetermined —
   1-minute live test: `UIM GET_SUPPORTED_MESSAGES (0x1E)` from the router.
   If the bitmap shows bits ≥0x34 set, the LPA could be host-drivable;
   if not, the extended family is modem-internal only.
3. Even if externally reachable, each message's handlers likely enforce the
   same compiled ISD-R policy (the LPA-owns-ISD-R reservation).

## Method (reproducible)

1. Fetched `qmi_idl_lib_internal.h` (quic/qmi-framework) — struct layouts.
2. Scanned data segments for `service_id==0x0B` objects with sane versions
   and pointer fields → 0xc32c0650 (b16, alongside apdu_security strings —
   qmi_uim's module segment).
3. Walked `n_msgs[]`/`msgid_to_msg[]` → {qmi_msg_id, tbl_idx (0x1000 flag =
   common msg), max_msg_len} for all 72+72+31 entries.
4. Cross-checked public set against libqmi's qmi-service-uim.json.

Artifacts: `uim-msgids.json` (full dump), `hunt_results.txt` (Ghidra xrefs),
`Hunt.java`, `function-starts.csv` (91,345), `func-strings.json` (2,302
attributed), `full-disasm.txt` (6.5M lines).
