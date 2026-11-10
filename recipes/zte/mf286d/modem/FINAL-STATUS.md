# MF286D Modem Firmware — Complete Findings & Status

Final document for EXP-034/035/036. Species-level (unit identifiers excluded).
This supersedes all prior analysis documents. 2026-11-10.

---

## Executive summary

**Question**: Can the MF286D modem firmware be made to allow in-device eSIM (ISD-R) management?

**Answer**: **No, not through any safe path on this firmware.** The ISD-R
access block is **compiled into the Qualcomm AMSS baseband code** (three-layer
defense: channel-open deny, fabricated card responses, APDU payload scanning).
It is NOT an EFS-configurable carrier policy as initially hypothesized. The
modem contains a full SGP.22 LPA client internally but provides no
host-drivable interface to it in this build. EFS policy files
(`apdu_security_aid_list`, `lpa_support`) are supplementary controls that
operate on top of the compiled base — zeroing them does not remove the base
ISD-R reservation.

**Device status**: Unit 1 is **fully functional** (QMI, AT, DM, cellular
registration, data). The only limitation is eSIM management (ISD-R access).

---

## 1. Hardware & firmware architecture (corrected)

### Two modem generations exist

| Generation | SoC | Firmware | Found in |
|---|---|---|---|
| Marvell/ASR (2019 kit) | PXA1826 "Nezha3" | ZTE ASRMICRO (TIM/OSLO/ARBI) | B02 service-kit FBF only |
| **Qualcomm (live units)** | **MDM9650** | **AMSS MDM9650.LE.1.2-10295 / MPSS.AT.2.5.1-00628** | All live B12+ units |

The B02 kit describes a different modem generation — all B02-kit offset maps
and architecture diagrams are **species-relative**, not live-unit truth.

### Live unit architecture

```
Router (OpenWrt 25.12, IPQ4019)
  └─ USB 19d2:1485
       ├─ ttyUSB0 = DM/DIAG port (EFS/NV access)
       ├─ ttyUSB1-2 = AT ports (ATCoP)
       ├─ cdc-wdm0 = QMI (UIM/NAS/WDS/DMS/WMS)
       └─ iface 1.6 = ADB (root, no auth, auto-start)

Modem (MDM9650, single chip):
  ├─ a5 Linux (kernel 3.18.31, UBIFS rootfs on mtd16)
  │   ├─ adbd (root shell)
  │   ├─ zte_topsw_* daemons (factory/test)
  │   └─ QCMAP web (no eSIM pages)
  └─ Hexagon Q6 MPSS (mtd9, 71MB UBI):
      ├─ AMSS with mmgsdi/UIM stack
      ├─ Resident SGP.22 LPA (-lpad/1.1.0)
      └─ Three-layer ISD-R defense (COMPILED)
```

### NAND partition map (live unit /proc/mtd)

| Partition | Size | Content | Readable |
|---|---|---|---|
| mtd0 sbl | 2.5MB | Secure boot loader | ✅ backed up |
| mtd1 mibib | 2.5MB | NAND partition table | ❌ CRASHER (char+block) |
| mtd2 efs2 | 11MB | EFS2 filesystem (NV/items) | ❌ CRASHER (char+block) |
| mtd3 tz | 3.5MB | TrustZone | ✅ backed up |
| mtd4 rpm | 3.25MB | RPM firmware | ✅ backed up |
| mtd5 efsbak | 11MB | EFS backup | ✅ factory-blank |
| mtd6 aboot | 1MB | Android boot | ✅ backed up |
| mtd7 boot | 15MB | Boot image | ✅ backed up |
| mtd9 modem | 71MB | MPSS/AMSS | ✅ pristine backup |
| mtd10 misc | 1.5MB | Misc | ✅ blank |
| mtd11 recovery | 15MB | Recovery | ✅ backed up |
| mtd13 recoveryfs | 40MB | Recovery rootfs | ✅ extracted |
| mtd16 system | 168MB | Modem Linux rootfs | ✅ extracted |

---

## 2. The ISD-R access-control mechanism (fully characterized)

### Three-layer defense (all COMPILED, not EFS-configurable)

| Layer | Mechanism | Bypass? |
|---|---|---|
| **L1: Channel-open deny** | QMI UIM OPEN_LOGICAL_CHANNEL with ISD-R AID ≥7 bytes → error 82 (AccessDenied). <7-byte partials pass (card resolves to ISD-R via FCI). | 6-byte partial opens the channel |
| **L2: Fabricated card responses** | On channels whose open-FCI revealed ISD-R, ALL APDUs get fake SWs (SELECT→6A82, STATUS→6D00, STORE DATA→6A80). Card never sees the APDU. | None found |
| **L3: APDU payload scan** | Any SEND-APDU whose data contains a SELECT with GSMA RSP RID (≥4 bytes) is dropped QMI-level, even on unflagged channels. | None found |
| **Basic channel (0)** | All host APDUs rejected (modem-reserved). | None |
| **AT layer** | +CSIM="not supported", +CCHO=ERROR for ALL AIDs (separate, coarser block). | None |

### Proof that it's compiled, not EFS

| Test | Result |
|---|---|
| `apdu_security_aid_list` (512B) zeroed + reboot | All three layers UNCHANGED |
| `lpa_support=1` created + reboot | File confirmed, no behavior change |
| USIM channel control test | Opens fine, real APDU responses (transport clean) |
| Differential (ISD-R vs USIM vs garbage) | Unchanged from pre-write baseline |

### The EFS policy files (what they actually control)

| File | Role | Effect of modification |
|---|---|---|
| `apdu_security_aid_list` | Additional per-AID restrictions ON TOP of compiled base | Zeroing removes extras, NOT the base ISD-R deny |
| `apdu_security_restrictions` | Policy flags for additional restrictions | Same |
| `lpa_support` | Gates whether the AMSS LPA task initializes | Enables the LPA internally, but no host interface |
| `uim_passthrough_mode` | APDU passthrough mode | Absent on our unit |
| `uim_remote_service_enable` | UIM-Remote machinery gate | Absent |

---

## 3. The internal LPA (present but unreachable)

The modem contains a **complete SGP.22 LPA client** statically linked into
the Hexagon AMSS:

- Task: `lpa_task_init` → `-lpad/1.1.0` User-Agent
- Driver: `qmi_uim_m2m_euicc.c` (registered in AMSS source manifest)
- Full ES9+ client: rsp1 AND rsp2 endpoints (`initiateAuthentication`,
  `getBoundProfilePackage`, `authenticateClient`, `handleNotification`)
- eUICC protocol: `euiccChallenge`, `asn1_dec_isdr_PK`, `filePackage`,
  `DownloadResponse`, `authenticate_server`, `activation_code_from_user`
- State machine: `LPA:READY`, `AUTH_OBTAINED`
- Config: `euicc_defaultaddr_fqdn` (default SM-DP+)
- Build: ZTE Soft4 SDK `/Soft4_P82M_H3GSEMF286D_uSDK/`

**No host-drivable interface exists in this build:**
- No QMI UIM euicc messages in libqmi 1.36 (public implementation)
- No AT commands for eSIM (full ATCoP table scan — zero matches)
- No web UI pages (QCMAP minimal only)
- No diag subsystem commands found
- The proprietary QMI M2M message IDs are not documented anywhere public

---

## 4. Service outage (root cause + resolution)

**What happened**: mtd1/mtd2 reads triggered whole-SoC resets → one reset
interrupted an in-flight NAND write → transient SMEM/IPC state corruption →
QMI/AT services dead, DM alive, persisted across warm reboots.

**Root cause**: Transient power/SMEM state, NOT flash corruption. A true
cold power cycle (10-min, PMIC "cold") fully recovered all services.

**Lesson learned**: The crasher partitions (mtd1/mibib, mtd2/efs2) cause
instant whole-SoC reboots when read from Linux — community-confirmed on this
exact modem (eko.one.pl MF286D thread). Access EFS through the DM/DIAG
port instead, never through Linux mtd.

---

## 5. Tooling & techniques developed

| Tool | Purpose | Location |
|---|---|---|
| `qmiuim.c` + unit tests | Custom QMI UIM client (persistent channel, APDU chain, differential probes) | PR #664 |
| `qfenix` (deployed) | Full EFS/NV/DIAG management from DIAG port | router:/tmp/qfenix |
| `qcdm-efs2` | Lightweight Python EFS client (fallback) | reference only |
| FBF parsers | Marvell-kit container extraction | evidence/modem-fw-re/ |
| `at3.sh`/`at4.sh` | AT command helpers (echo-tolerant, ttyUSB2) | router:/tmp/ |
| UBI/UBIFS extraction | mtd9 → vol0 → file tree (191 files) | evidence/modem-fw-re/dumps/ |
| `TESTPLAN-live-b12.md` | Full behavioral spec + probe procedures | PR #664 |

### QMI wire format (validated by unit tests)

```
Frame: [01][len16LE=total-1][qmux_flags][svc][cid][qmi_flags][txn][msg16LE][tlvlen16LE][TLVs]
TLV:   [type u8][len16LE][value]
CTL txn: u8; Service txn: u16 LE
CRC:   crcmod.mkCrcFun(0x11021, initCrc=0, xorOut=0xFFFF)
```

---

## 6. What works vs what doesn't (device 1, current state)

### ✅ Fully functional
- Cellular registration (4G/LTE, network time sync)
- QMI data (WDS)
- AT commands (all standard + ZTE proprietary set)
- SIM card operations (PIN, IMSI, phonebook via QMI UIM)
- Logical channel opens to non-ISD-R applets (USIM etc.)
- APDU send/receive on non-ISD-R channels
- DM/DIAG port (EFS read/write, NV read/write, modem restart)
- ADB root shell

### ❌ Blocked (by design, compiled)
- ISD-R channel open (≥7-byte AID)
- ISD-R APDU exchange (fabricated responses on any ISD-R-resolved channel)
- AT+CSIM, AT+CCHO (universal block, coarser than QMI)
- Host-side eSIM profile management (no LPA interface)

---

## 7. Remaining research questions

| Question | Priority | Approach |
|---|---|---|
| ~~Does B14 wire the LPA to a host interface?~~ | **ANSWERED (EXP-038): NO** | B14-GENEALOGY-REPORT.md |
| ~~Did any older firmware (B02+) lack the LPA/ISD-R block?~~ | **ANSWERED (EXP-038): NO — LPA present since B02; B10=B11=B12; B13 never existed** | B14-GENEALOGY-REPORT.md |
| What are the proprietary QMI M2M euicc message IDs? | HIGH | Hexagon RE of mtd9, or QXDM tool |
| Can the MPSS binary be patched to remove ISD-R deny? | MEDIUM | Hexagon RE → find compare → patch → hash re-sign |
| Does a newer Qualcomm generic firmware remove the deny? | LOW | Would require cross-flashing (risky; B14 already proven useless for eSIM) |
| Does UIM-Remote (policy-gated off) provide an alternate path? | MEDIUM | Enable via EFS → enumerate remote UIM interface |
| What does mtd15-zterw (145MB, unread) contain? | LOW | Pull via block-mode canary (factory staging area) |

**NOTE (EXP-038)**: Do NOT flash B14 — zero eSIM benefit (LPA chunks copied
byte-identical from B12) and it breaks QMI under OpenWrt (community-verified).

---

## 8. Proven eSIM management paths (alternatives)

| Path | Status | Notes |
|---|---|---|
| NR7101 + lpac | ✅ Production-proven | Same 9eSIM card, ifd-modemifd + lpac |
| USB CCID reader + lpac | ✅ Deterministic | Card moves to reader, full control |
| MF286D modem | ❌ Not possible on B12 | This document |

---

## 9. Evidence inventory

All artifacts in `~/mf286d-work/evidence/modem-fw-re/`:
- `dumps/mtd9.img` — pristine MPSS (74.7MB, sha256 efd0b8a6…)
- `dumps/mtd9-files/` — 191-file AMSS extraction
- `dumps/vol0-pristine.bin` — UBI volume 0 raw
- `dumps/efs-*.bin` — pre/post EFS write snapshots
- `dumps/efs-full-backup.tar` — 555-file EFS + 338 NV items (XQCN XML format)
- `dumps/mtd16-extract/` — modem Linux rootfs
- `dumps/recovfs-out/` — recovery filesystem
- Analysis docs: ANALYSIS.md, EXP035-ANSWER-ADDENDUM.md, MTD9-EFS-POLICY-MAP.md,
  LPA-CONTROL-SURFACE.md, EFSBAK-ZTERW-FINDINGS.md, RECOVERY-RESEARCH.md,
  TOOL-VERIFICATION.md
- Test plans: TESTPLAN-live-b12.md (behavioral spec + probes)
- Tools: qmiuim.c (unit-tested QMI client), arm_annot.py, extract_fbf.py, etc.

GitHub: PR #664 (all docs + code), Issues #672 (session plan + results)

---

## 10. Roadmap (future testing)

### Immediate (device 1, read-only)
1. **B14 firmware diff**: Download TELIA_MF286DV1.0.0B12-TELIA_MF286DV1.0.1B02.up
   → BSDIFF40 split → diff modem partition against pristine B12 → look for
   new AT commands, QMI handlers, or LPA interface wiring
2. **zterw (mtd15) pull**: Block-mode canary → 145MB staging area → look for
   staged update remnants, ZTE config, LPA provisioning scripts
3. **UIM-Remote enable**: EFS write `uim_remote_service_enable=1` → reboot →
   enumerate QMI UIM Remote interface (service 0x32 was absent, may appear)

### Medium-term (requires Hexagon RE)
4. **Hexagon disassembly of mtd9**: Ghidra + Hexagon module → find the L1/L2/L3
   compare in the UIM/mmgsdi code → document exact patch site
5. **QMI M2M message enumeration**: Find the proprietary QMI UIM message IDs
   that drive the internal LPA (from the handler table in the AMSS binary)

### Long-term (risky, last resort)
6. **MPSS binary patch**: Remove the ISD-R deny from compiled code → hash
   re-sign → flash via firehose (full backups exist, but modem brick risk)
7. **Cross-flash generic Qualcomm firmware**: Would lose ZTE features, unknown
   compatibility

---

*Document closes the modem firmware RE arc (EXP-034/035/036). Device 1 is
healthy and daily-usable; eSIM management through the modem is conclusively
not available on this firmware generation.*
