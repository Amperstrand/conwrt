# EXP-040 FINAL VERDICT — External QMI eSIM-Family Reachability (LIVE)

2026-11-10. Live probe on device 1 (192.168.34.1, B12 modem, cellular up).
Probe: `uim_bitmap` v2 oracle — deliberately-truncated TLV body guarantees
framework decode failure BEFORE handler execution; `QMI_ERR_INVALID_QMI_CMD
(0x47)` = ID absent from external dispatch, any other error = ID PRESENT.
Calibration validated against EXP-035 live ground truth: 0x42 Open Logical
Channel → PRESENT ✓, 0x3B Send APDU → PRESENT ✓, 0x1E Get Supported Messages
→ absent ✓ (query itself not implemented: FAILURE/0x47, no bitmap TLV — the
"two message IDs" reading of TLV 0x02 is incorrect; it is the standard
result+error pair, 01 00 47 00 = FAILURE + INVALID_QMI_CMD).

## THE ANSWER

**35 of 44 proprietary UIM message IDs are EXTERNALLY PRESENT — the modem's
eSIM/LPA message family IS reachable from the host over cdc-wdm0.**
The campaign's central question ("in-device eSIM management via the modem")
flips from NO (ISD-R direct access) to **YES (via the internal LPA's own QMI
interface — exactly the path we hypothesized in EXP-040).**

## Full sweep map (present ⊇ absent)

PRESENT externally (35): 0x2b 0x2d 0x34 0x35 0x36 0x37 0x39 0x3c 0x3d 0x41
0x45 **0x4b 0x4d 0x4e 0x4f** 0x51 0x52 0x53 0x54 **0x5a 0x5b 0x5c** 0x61
0x62 **0x63** 0x64 0x65 0x66 0x67 0x68 0x69 0x6a 0x6b 0x6c 0x6d

ABSENT (9): **0x4c (profile download / BPP, 11,711B req)** 0x56 0x57 0x58
0x59 **0x5d** 0x5e 0x6e 0x6f

## IDL-structure fingerprints (from the decoded service object)

| ID | REQ c_struct | RESP c_struct / maxlen | reading |
|---|---|---|---|
| 0x4b | **1 (parameterless)** | 20 / 21 | small 2-TLV query — EXECUTED (result=0 SUCCESS) in sweep |
| 0x63 | **1 (parameterless)** | 36 / 31 | small multi-TLV query — EXECUTED (result=0 SUCCESS) in sweep |
| 0x4c | 18,484 | 12 | profile download (BPP) — **absent externally** |
| 0x5a | 696 | 1,860 / 1,855 | **present** — big profile op (add-profile class: activation-code-sized request, profile-sized response) |
| 0x42 | 52 | 276 | Open Logical Channel (calibration ✓) |

Neither 0x4b nor 0x63 is EID-sized (EID = 16B → response maxlen ≥ 26):
they are parameterless status/info queries that already ran clean. Exact
names pending the name-pool offset-table decode / Ghidra dispatcher xrefs;
v3 `call` mode (empty valid request + full response-TLV dump) is deployed
for byte-level identification.

## Interpretation & implications

1. The external UIM service carries the EXTENDED dispatch set — ZTE/Qualcomm
   exposed the M2M/multi-profile family to the host even though the public
   tooling (libqmi/uqmi) has no IDs for it. EXP-035's ISD-R *direct-access*
   block (three-layer defense) and THIS finding are consistent: the modem
   denies raw ISD-R APDUs but serves the *managed* LPA interface.
2. Profile DOWNLOAD (0x4c) is not exposed → full on-modem profile download
   likely still requires the internal LPA's own HTTP path or is gated off.
   But the profile-ops family (0x5a-class, 0x34-0x3d block) IS exposed →
   enable/disable/delete/list/nickname-class operations plausibly drivable.
3. Whether each PRESENT handler enforces additional runtime policy (slot
   state, SIM-lock, LPA task readiness) is unknown — next phase.
4. Device safety: full sweep clean — no crash/reboot, QMI responsive after.

## Next steps (ordered)

1. **v3 `call` mode on 0x4b / 0x63** (empty valid request, dump all
   response TLVs) → byte-level identification. Both already executed once
   under the sweep with garbage bodies — clean re-run with a valid empty
   body is the same safety class.
2. Name-map the 44 IDs offline: decode the IDL name-pool offset table +
   Ghidra xrefs from the dispatcher to the per-message handlers (Qshrink
   gives file:line anchors — qmi_uim.c:1116/1479 already pinned).
3. If a get-EID/list-profiles op identifies among the PRESENT set: drive it
   live from OpenWrt (tooling exists — qmiuim frame layer).
4. Long-form: implement the client for the exposed family; test profile
   ops against the 9eSIM with full card-side logging (CCID reader
   observing card state as ground truth).

Artifacts: `uim_bitmap.c` (v3, modes ver/probe/sweep/call/bitmap),
`uim-msgids.json`, this verdict. Live stdout in lane scrollback.
