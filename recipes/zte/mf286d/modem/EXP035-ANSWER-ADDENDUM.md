# EXP-035 FINAL REPORT ADDENDUM — Where the ISD-R block lives: ANSWERED

2026-11-09. Supersedes the "QMI bypass surface EXHAUSTED" verdict of the
original EXP-035 row. Fold-in of the mtd9 breakthrough chain (overseer's
MTD9-CP-LPA.md + UIM-LPA-INVENTORY.md, independently verified in this lane's
pristine extraction — see MTD9-EFS-POLICY-MAP.md).

## The mission question, answered

**"Where is the ISD-R access-control check?"** — Three layers (behaviorally
characterized live in EXP-035), ALL driven by provisioned EFS files, none
compiled:

| Layer (observed live) | EFS file (provisioned policy) |
|---|---|
| L1: channel-open deny for ISD-R AID ≥7 bytes (QMI err 82) | `/nv/item_files/modem/qmi/uim/apdu_security_restrictions` + `apdu_security_aid_list` |
| L3: APDU payload scan dropping SELECTs carrying the GSMA RSP RID | same `apdu_security_aid_list` |
| L2: fabricated card SWs on ISD-R-resolved channels | same policy family (exact file TBC during EFS read; behaviorally same-class) |
| (AT layer: CSIM/CCHO universal ERROR) | ATCoP surface, separate coarser block — unchanged verdict |

The static-RE prediction of EXP-034 §5 — "no compiled AID comparison exists;
the policy must be runtime data (NV/EFS), hence likely changeable without
firmware patching" — is **confirmed exactly**, with the file names.

## The modem is eSIM-capable by design

The live B12 CP (AMSS MDM9650.LE.1.2-10295 / MPSS.AT.2.5.1-00628) contains a
**resident SGP.22 LPA** (`lpa_task_init`, full rsp1+rsp2 ES9+ client, driven
via `qmi_uim_m2m_euicc.c`, gated by `uim/lpa/lpa_support`) and **UIM-Remote
machinery** (`uim/remote/uim_remote_service_enable`, policy-gated off —
reopens the remote-SIM door EXP-032 closed). Reframe accepted: the ISD-R
"Access denied" is plausibly standard LPA-owns-ISD-R reservation.

## Unlock routes (owner-gated, reversibility ordered)

- **Route A (supported)**: EFS-write `lpa_support=1` → native LPA via QMI.
- **Route B (raw)**: edit `apdu_security_restrictions`/`aid_list` → open
  ISD-R channels for lpac-on-router (fallback).
- **Route C (bonus)**: `uim_remote_service_enable` → UIM-Remote (new option).

All three are single-file EFS edits (undo = write-back), far below firmware
patching on the risk ladder. Full-backup preconditions already satisfied.

## Artifacts

- `dumps/mtd9.img` pristine (efd0b8a6…) + `dumps/mtd9-files/` (191-file tree)
- `MTD9-EFS-POLICY-MAP.md` (this lane's verification + full UIM EFS map)
- `LPA-CONTROL-SURFACE.md` (updated with confirmation + read list)
- Overseer: `/tmp/opencode/b12diff/{MTD9-CP-LPA,UIM-LPA-INVENTORY,B02-B12-DIFF}.md`
- Wire/behavioral spec + probe tooling: `TESTPLAN-live-b12.md`, `qmiuim.c`
