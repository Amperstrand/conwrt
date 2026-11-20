# MTD9 breakthrough — verification + EFS policy-file map (independent confirmation)

2026-11-09. Verification of the overseer's MTD9-CP-LPA.md against my own
pristine extraction (`dumps/mtd9-files/`, 191 files from vol0-pristine).

## Verification: CONFIRMED, all claims reproduce

| Claim | Status |
|---|---|
| AMSS MDM9650.LE.1.2-10295 (Ver_Info.json, modem MPSS.AT.2.5.1-00628) | ✅ my Ver_Info.txt identical |
| `-lpad` = resident AMSS LPA task (`lpa_task_init`, `lpa_http.c`, UA `gsma-rsp-lpad`) | ✅ modem.b15 @0xa7001c / 0xb48e44 / 0xb4905f |
| Full ES9+ rsp1+rsp2 (`/lpa/json_enc_init_auth`, `asn1_enc_prep_download`, `asn1_dec_isdr_rsp`, `authenticate_server_from_card`, `activation_code_from_user`, `load_bpp_from_card`, `store_data_resp_from_card`…) | ✅ complete phase-name trace set @0xb48c00-0xb49500 |
| Driver = `qmi_uim_m2m_euicc.c` | ✅ @0xa63698 (in AMSS source manifest, next to qmi_uim*.c family) |
| Gate = `/nv/item_files/modem/uim/lpa/lpa_support` (EFS, not numbered NV) | ✅ @0xd5f6b0 |
| `LPA:READY` state string | ✅ @0xb48c92 |

**Reconciliation confirmed**: B02 kit (Marvell/ARBI) and live B12 CP are
different codebases — my EXP-034 maps are species-relative, not live-truth.
Verdict stands; corrected in docs.

## NEW: the complete UIM policy EFS file map (from modem.b15 string table)

The runtime-policy class EXP-034 §5 predicted, now with **names**. All under
`/nv/item_files/`:

### Direct candidates for the observed ISD-R gates (L1/L3!)
- **`modem/qmi/uim/apdu_security_restrictions`** — APDU security policy flags
- **`modem/qmi/uim/apdu_security_aid_list`** — **the AID list the L3 payload
  scanner matches against** (our observed: any SELECT carrying GSMA RSP RID
  ≥4 bytes dropped). If the ISD-R AID lives in this file, **it is the L1+L3
  blocklist** — editable EFS data.
- `modem/qmi/uim/sap_security_restrictions`, `auth_security_restrictions`
- `modem/qmi/uim/gba_fqdn_white_list` / `gba_fqdn_black_list` (pattern: ZTE
  populates white/black lists in EFS)

### LPA path
- `modem/uim/lpa/lpa_support` (the gate)

### Other notable UIM toggles
- `modem/uim/uimdrv/uim_passthrough_mode`
- `modem/uim/remote/uim_remote_service_enable` (UIM Remote!)
- `modem/uim/mmgsdi/features_status_list`, `device_features_status_list`,
  `slot_features_status_list` (the mmgsdi feature layer)
- `modem/qmi/uim/close_channel_sync`, `silent_recovery`, `terminal_capability`

## Priority-ordered EFS read list for the action ladder (device-side)

1. `modem/qmi/uim/apdu_security_aid_list` ← **likely the ISD-R blocklist itself**
2. `modem/qmi/uim/apdu_security_restrictions`
3. `modem/uim/lpa/lpa_support`
4. `modem/uim/uimdrv/uim_passthrough_mode`
5. `modem/qmi/uim/sap_security_restrictions` + `auth_security_restrictions`

The action ladder stands (read → targeted flip → reboot → re-probe), now with
the sharper hypothesis: **flip `apdu_security_aid_list`/`restrictions` to open
the raw host path, and/or `lpa_support` to light up the modem's own LPA**.
Both are EFS-file edits — reversible, no firmware patch.
