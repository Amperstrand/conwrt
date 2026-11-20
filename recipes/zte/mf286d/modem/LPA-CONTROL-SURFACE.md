# LPA Control Surface — MF286D B12 (MDM9650) — `-lpad` hunt results

EXP-034/035 continuation, 2026-11-09. Author: mf286d-fwre lane. Sources:
pristine mtd9 (`mtd9.img`, sha256 efd0b8a6…) UBI vol0 extraction (`vol0-pristine.bin`,
185/240 LEBs — the 55 unwritten LEBs are factory-blank flash, NOT missing data),
mtd16 rootfs (`mtd16-extract/375765971/rootfs`), B02↔B12 diff (overseer, /tmp/opencode/b12diff/),
Zyxel prior art (conwrt PR #666 §3b/§3c).

## What the `-lpad` thing actually is

`-lpad/1.1.0` is the **HTTP User-Agent string** of an SGP.22 LPA client
statically linked into the Hexagon (MPSS) image. The complete ES9+ download
client is present in vol0 @≈0x2AA6000:

- HTTP machinery: `"Sending post for uri=%s"`, `application/json`,
  `X-Admin-Protocol`, `gsma/rsp1` (GSMA RSP cert URI path), `User-Agent:
  -lpad/1.1.0`, base64 tables
- SGP.22 objects: `dpSigned1`, `euiccCiPKIdToB`, `filePackage`,
  `DownloadResponse`, `asn1_dec_isdr_PK` (ISD-R key ASN.1 decoder!)
- LPA state machine: `AUTH_OBTAINED … READY/UNKNOWN`
- `euicc_defaultaddr_fqdn` (default SM-DS/SM-DP+ address), `scws.c` source path
- Build leak: `/Soft4_P82M_H3GSEMF286D_uSDK/…qualcomm/mdm9xxx…` (ZTE Soft4 SDK)

**It is NOT a resident daemon with a string-rich API.** No SGP.22 API field
names (`matchingId`, `confirmCode`, `activationCode`, `euiccInfo2`) exist
anywhere in vol0 — the client is library-linked into the baseband stack
(mmgsdi/euicc), consistent with the modem's UIM monopoly (EXP-035 three-layer
block guards exactly this).

## Where the control surface is NOT (all verified)

| Candidate | Verdict | Evidence |
|---|---|---|
| AT commands (live table) | **ABSENT** | live ATCoP table @vol0 0x2F54ABF: `$QCSIMSTAT $QCPBM $QCSIMA $QCINSTA ^SYSINFO ^MODE ^SPN +ZNVBA…` — no ESIM/ZESIM/QESIM family; B12 diff confirms none in the AT layer |
| Modem-Linux web (WEBSERVER/) | **ABSENT** | QCMAP UI only (Firewall/WWAN/IPV6/Account); `usr/zte_web` empty |
| mcm_ril_service | **ABSENT** | 0 esim/euicc/lpa strings |
| zte_adapter_sim (B12) | **NO LPA ops** | has new QMI-UIM-IDL layer (uim_register, REFRESH_IND) — plumbing only |
| init.d / spawn-on-demand (Zyxel §3c pattern) | **NOT FOUND in mtd16** | B12 diff: no lpad/esim strings anywhere in mtd16; caller-hunt on router side is parent lane |
| QMI service enumeration | **PENDING (device-side)** | needs live `qmicli --get-versions` sweep for a euicc/LPA service when device recovers |

## Ranked trigger candidates (what to probe, read-only)

1. **DM/DIAG probe matrix** (overseer already running): if any ZTE subsystem
   responds under DIAG_SUBSYS_CMD_F, factory diag may include eSIM ops.
   My static diagpkt-table extraction of `zte_topsw_diag` hit an optimized
   binary (tables not in scannable form); empirical probing wins. The
   registered-handler name list IS known: card_test_ram/rom, LCD backlight,
   key test, touchUI, wifi calibration backup/restore/query, therm —
   factory tests only, **no eSIM-looking handler names**.
2. **QMI service sweep** on recovery: `qmicli --device-open-qmi
   --uim-… / --dms-…` full version list; look for nonstandard service
   (e.g. a vendor euicc service next to 0x0B UIM).
3. **efs2 NV/FS contents** (efsbak mtd5 copy in hand, pristine): grep for
   `euicc_defaultaddr` / lpa config / SM-DP+ URLs — the LPA's activation-code
   and matchingID inputs must persist somewhere; efsbak is the offline copy.
   **This is now the highest-value offline target** for the LPA question.
4. **Router-side goform→modem chain** (parent lane): Zyxel §3c pattern would
   put the caller in the goform/WEBSERVER layer — B12 mtd16 has no lpad, but
   the ROUTER's stock firmware (our BD_TELIAMF286D B09/B12 router images,
   mtd8 web) should be grepped for esim/lpa goform handlers that then reach
   the modem via AT/QMI — that check belongs to the router-image lane.

## Honest assessment

The `-lpad` client is most plausibly the modem's *internal* RSP capability
used (if ever) via ZTE carrier flows (QR activation in some market variant),
with no host-drivable surface in this build — matching the three-layer ISD-R
monopoly. The efsbak/efs2 contents sweep (offline, we hold the image) and the
QMI service enumeration (on device recovery) are the two remaining checks
that could change this verdict; neither requires new device risk.

## Artifact map

- `dumps/mtd9.img` — pristine MPSS (UBI, vol "modem" = 185 LEBs)
- `dumps/vol0-pristine.bin` + `vol0p-strings.txt` — extracted volume + strings
- `dumps/mtd9.img.corrupt-shellcat` — original transport-corrupted pull (forensics)
- LPA string cluster: vol0-pristine @ 0x2AA6287-0x2AA6800; QMI-UIM name table
  @ 0x3013000-0x3014000; ATCoP table @ 0x2F54ABF; mmgsdi feature files @ 0x52F4B4+

---

## UPDATE 2026-11-09 (post-overseer breakthrough): CONFIRMED + EXPANDED

Overseer's MTD9-CP-LPA.md verified against my pristine extraction — every
claim reproduces (see MTD9-EFS-POLICY-MAP.md for the table). The `-lpad` is
the AMSS-resident LPA task (`lpa_task_init`, full rsp1+rsp2 ES9+ client,
driven via `qmi_uim_m2m_euicc.c`), gated by
`/nv/item_files/modem/uim/lpa/lpa_support`.

**My addition — the L1/L3 gate files found**: `apdu_security_aid_list` +
`apdu_security_restrictions` (+sap/auth variants, gba fqdn white/black lists
as the naming-pattern precedent) — the runtime AID policy class EXP-034 §5
predicted, now with names. If the ISD-R AID sits in `apdu_security_aid_list`,
that file IS the observed blocklist, and both the "raw channel" and "modem
LPA" paths are EFS-file flips away.

Reconciliation: B02-kit (Marvell) vs live B12 (Qualcomm AMSS) = different
codebases; my §3/§5 offset maps are kit-relative. Amss `Ver_Info`:
MDM9650.LE.1.2-10295 / MPSS.AT.2.5.1-00628, 2021-07-10.

Priority EFS read list (device ladder): apdu_security_aid_list →
apdu_security_restrictions → lpa_support → uim_passthrough_mode → sap/auth
restrictions.
