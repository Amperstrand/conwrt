# LPA Enable-Gate Analysis (EXP-044) — the reframe

## The insight (from ecosystem research EXP by parent lane)

Quectel's eSIM LPA Application Note (RG50xQ/RM5xxQ, same qmi_uim_m2m_euicc
ancestry as MDM9650) documents the concept: **`lpa_enable` must be set before
ANY LPA command works**. Without it, all LPA operations return errors.

Our 0x65 INTERNAL error is NOT a hard client-state lock — it's the **LPA
enable gate**. The internal LPA hasn't been switched on.

## The evidence chain

1. `AT*EUICC` (atcmdsrv @ 0x4483c): reads euicc-state byte at 0xC5C4C
   → if state==1, returns `*EUICC: <n>` (counter). **Set-op returns ERROR**
   (AT-level gate).
2. `CI_SIM_PRIM_DOWNLOADPROFILE_REQ/CNF` in atcmdsrv: ZTE's download path
   EXISTS in the firmware (just unreachable from AT).
3. Our QMI probe results: 0x63 (eUICC state/phase) returned **{1,1,0}** —
   the first byte (value=1) may be `lpa_disabled` (Quectel convention:
   0=disabled, 1=enabled... or the inverse: our {1,1,0} = phase 1 = disabled).
4. 35 of 44 proprietary messages are externally reachable — including the
   profile operations family — they just error until the LPA is enabled.

## The enable operation — prime candidates

From the protocol spec (all present externally, ACK-only responses):

| ID | REQ shape | Fit |
|---|---|---|
| **0x53** | {slot, u32, u8 OPT} → ACK | **BEST** — u32 = enable/disable flag |
| 0x66 | {slot, u32} → ACK | Same shape, alternate candidate |
| 0x54 | {slot} → ACK | Too simple (no state parameter) |
| 0x46 | {slot, u32} → ACK | Already public (Switch Slot) |

**0x53 is the prime candidate**: {TLV01 slot, TLV02 u32=enable_flag}
The u8 TLV10 optional could be a sub-mode.

## Quectel QESIM → our message mapping

| QESIM op | Our ID (probable) | Evidence |
|---|---|---|
| lpa_enable | **0x53** | {slot, u32_flag} → ACK |
| eid | **0x65** | {slot} → {result + u8[16] varlen EID} |
| profile_brief | **0x34** | {session+filter} → {u8[1024] varlen} |
| profile_detail | **0x35-37** | profile family |
| enable_profile | **0x61** | {slot+iccid(44B)} → ACK |
| disable_profile | **0x62** | {slot, iccid} → {24B resp} |
| delete_profile | **0x64** | {slot, 11B} → ACK |
| nickname | **0x68** | {slot, 530B} → ACK |
| def_svr_addr | **0x51/52** | {slot, address} |
| memory_reset | **0x45** | {slot, 60B} |
| user_consent | **0x6c** | {slot, u8} → ACK |

## Dell DW5829e proof

Same silicon generation (Snapdragon X20 / MDM9250 family) runs eSIM over
QMI via lpac in production since May 2026. The MF286D lock is **vendor
configuration, not silicon limitation**.

## The safe test sequence (when device is back)

1. `callslot 63 1` → read current eUICC state (should be {1,1,0} = disabled)
2. `callslot 53 1` → send {slot=1} first (minimal, MISSING_ARG expected
   since u32 TLV02 is mandatory — this CONFIRMS the shape without acting)
3. Build proper 0x53 body: {TLV01 slot=1, TLV02 u32=1 (enable)} — v9 needed
4. `callslot 63 1` → re-read state (if changed → LPA ENABLED!)
5. `callslot 65 1` → GET_EID (should now return the 16B binary EID!)

**SAFETY**: 0x53's u32 is a simple flag (4 bytes, standard TLV) — completely
different from 0x67's crashed u64. The 0x67 crash was in the register/token
path, NOT in the flag-setter path. 0x53 has no optional u64 fields.

## What this means for the campaign

If 0x53=enable works:
- GET_EID (0x65) → the EID
- Profile list (0x34) → all profiles
- Enable/disable/delete (0x61/62/64) → profile management
- Nickname (0x68) → profile metadata
- All from OpenWrt, over cdc-wdm0, no card removal needed

The profile DOWNLOAD (0x4c, absent externally) still requires the internal
HTTP path — but management of existing profiles becomes fully host-driven.
