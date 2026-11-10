# The eSIM Ecosystem Map — existing work we can build on

Researched 2026-11-10 after the v8 crasher incident made one thing clear: **we were
trial-and-error probing a device that an entire open-source ecosystem has already
mapped from other angles.** This document is the map: what exists, where it lives,
what it gives us, and how it changes the MF286D plan. Species-level facts only.

## The one-paragraph summary

Host-side eSIM provisioning is a **solved problem** for modems with an unlocked UIM
APDU path: [lpac](https://github.com/estkme-group/lpac) implements the full GSMA
SGP.22 LPA (profile list/download/enable/disable/delete, EID, notifications) and
speaks **three standard QMI UIM messages** to the card. Routers with locked APDU
paths (our MF286D) are the remaining frontier — and for those, Quectel documented
the vendor "built-in LPA" control surface (`AT+QESIM`), which is the same
architectural family as ZTE's internal LPA that we reverse-engineered. The end
goal — "flash any old router, provision silent.link/nadanada, cellular up" —
assembles from existing parts: conwrt (flash/configure) + lpac (provisioning) +
an APDU transport that works on the target modem.

## The ecosystem, piece by piece

### 1. lpac / libeuicc — the provisioning engine (solved)

- Repo: `estkme-group/lpac` (C, MIT/libeuicc; AGPL for lpac CLI)
- Full SGP.22 consumer LPA: chip info (EID), profile list/download/enable/disable/
  delete, notifications, ES9+ HTTPS to SM-DP+ over its own HTTP stack
- **APDU backends** (`driver/apdu/`): PC/SC, **QMI**, **QRTR**, MBIM, AT (`AT+CSIM`),
  stdio, gbinder (Android)
- The QMI backend (`driver/apdu/qmi.c` + `qmi_common.c`) is the reference
  implementation of host-side APDU exchange. It uses libqmi-glib and exactly:
  - `QMI_UIM_GET_CARD_STATUS` (0x2F) — find USIM
  - `QMI_UIM_GET_SLOT_STATUS` (0x47) / `QMI_UIM_SWITCH_SLOT` (0x46) — select slot
    (Dell DW5829e: eUICC lives on **slot 2**, lpac switches to it)
  - `QMI_UIM_OPEN_LOGICAL_CHANNEL` (0x42) with the ISD-R AID
    (`a0000005591010ffffffff890000010000`)
  - `QMI_UIM_SEND_APDU` (0x3B) — all SGP.22 APDUs over the open channel
  - `QMI_UIM_LOGICAL_CHANNEL` (0x3F) — close
- **Proven in the wild**: SIM7600E-H with sysmoEUICC test card (lpac issue #221);
  Dell DW5829e / DW5821e production fleet since May 2026 (see below)

### 2. libqmi — the standard message definitions (documented)

- The standard UIM APDU trio was **added to libqmi 1.36 (2024)** by Fairphone/
  Sartura engineers specifically for lpac: `Send APDU` = 0x3B, `Logical Channel`
  (close) = 0x3F, `Open Logical Channel` = 0x42
- `data/qmi-service-uim.json` in the libqmi repo = machine-readable TLV layouts
  for every standard UIM message — cross-validate any hand-crafted probe against
  this before sending it
- Implication for MF286D: our extended-message sweep covered 0x2b–0x6f; the
  standard trio (0x3B/0x3F/0x42) sits inside that block and 0x3B answered as
  "externally present" in EXP-041. **The community's "front door is locked"
  verdict predates lpac's QMI backend — they tried AT+CCHO; the QMI APDU path
  was not testable with public tooling until 2024.**

### 3. wwand — OpenWrt-native eSIM management (the router-side pattern)

- Repo: `ddimension/wwand` (OpenWrt, ucode, GPL-2.0)
- `wwand-esim` implements **ES10c (SGP.22 profile management) on the router** in
  ucode: BER-TLV codec, STORE DATA over the ISD-R channel, EID/profile list/
  enable/disable/delete
- Architecture note (their own header): *"management only; the SM-DP+ download
  runs host-side through lpac; wwand only provides the APDU transport"*
- APDU backends: `qmi` / `mbim` / `at`
- ubus API: `wwand modem_esim '{"modem":"m0","op":"download","activation_code":
  "LPA:1$smdp.example.com$ABC-123"}'`
- **This is the conwrt profile-layer pattern for cellular**: router daemon =
  transport + management; lpac = download engine; activation code in = profile
  installed. silent.link and nadanada both issue standard activation codes.

### 4. Quectel `AT+QESIM` — the vendor "built-in LPA" control surface (the key)

- Document: *RG50xQ&RM5xxQ Series eSIM LPA Application Note v1.0* (2022-09-20,
  Quectel, archived: web.archive.org/web/20231222190957 if the forum link dies)
- Quectel SDX-family modules ship the **modem-internal LPA** (same Qualcomm
  `qmi_uim_m2m_euicc` ancestry we found in MDM9650) and expose it via AT:
  - `AT+QESIM="lpa_enable"` — **enable/disable the built-in LPA**
  - `AT+QESIM="eid"` — query EID
  - `AT+QESIM="profile_brief"` / `"profile_detail"` — list profiles
  - `AT+QESIM="enable_profile"` / `"disable_profile"` / `"delete_profile"` /
    `"nickname"` / `"def_svr_addr"` (default SM-DP+ address!)
- **The `lpa_enable` operation is the client-state gate concept we've been
  hunting**: the built-in LPA's commands return errors until the LPA is enabled.
  Our MF286D 0x65 (GetEID) INTERNAL error may mean "LPA not enabled", not
  "permanently locked".
- ZTE's analogous surface exists in OUR modem firmware (see MF286D leads below).

### 5. Dell DW5821e/DW5829e production notes — same modem family, working eSIM

- Repo: `freedomcomedelivery/dell-dw5821e-dw5829e-esim-linux` (MIT, in production
  since May 2026 — Freedom Checker fleet)
- DW5829e = Snapdragon X20 modem (MDM9250 family — **same generation as
  MF286D's modem**), eUICC on **UIM slot 2**, lpac QMI backend + qmi-proxy
- Production pitfalls documented: ModemManager must be masked (grabs the device);
  profile switch requires DMS reset / `AT+CFUN=0,1` for the modem to re-read the
  eUICC; interrupted CFUN leaves the radio off; APN attach quirks after switch
- Proof that the X20-class baseband's eUICC-over-QMI path works when the vendor
  doesn't lock it down — the lock is vendor/carrier config, not silicon

### 6. osmocom eUICC developer manual — the canonical reference

- URL: `euicc-manual.osmocom.org`
- Known LPA solutions, known eUICC cards, ATR database, profile transfer
  standards, MEP (multiple enabled profiles), test profiles, PKI/CIs, Android
  OMAPI/TelephonyManager, LPAd list (including Qualcomm LPAd)
- Harald Welte's ELCE 2025 talk "Open Source for eSIM Integration" covers QMI
  transport on Qualcomm modems — slides:
  `static.sched.com/hosted_files/osseu2025/b4/elce2025-open_source_for_esim_integration.pdf`

### 7. Other pieces worth knowing

- **OpenEUICC / EasyEUICC** — open-source Android LPA; the SGP.22 state machine
  reference (what APDU sequence a real LPA sends, in what order)
- **ModemManager eSIM support** — gitlab issue #485 (open since 2022); MBIM
  (Microsoft MBIMEx 2.0 eSIM extensions) is the documented path there
- **sysmoEUICC / ESTKme / eSIM.me** — programmable eUICC cards in physical SIM
  form factor. A router with only a physical SIM slot (MF286D) becomes an eSIM
  router by inserting one of these; the LPA (host or modem) writes profiles to it
- **ZTE GPL kernel releases** — `opensource.ztedevices.com` (worth pulling the
  MF286D kernel source for QMI header cross-referencing)

## What this changes for MF286D (issue #621/#677)

1. **Try the standard path first, exactly as lpac does it.** The QMI APDU trio
   (0x42/0x3B/0x3F) with the ISD-R AID was likely never tested on this device —
   the tooling didn't exist when the community gave its verdict. Low risk (all
   well-formed standard requests), high information value. With a plain SIM in
   the slot, expect "channel not found"-class errors either way; a definitive
   AID-denial (AccessDenied) on the QMI path would confirm the compiled lock
   applies there too.
2. **The EID gate may be an enable-gate, not a lock.** Cross-reference our
   extended-message IDL (PR #664) against Quectel's documented QESIM operations:
   `profile_brief/detail` ↔ our 0x34–0x37 family, `eid` ↔ 0x65, enable/disable
   ↔ 0x5x. Whatever `AT+QESIM="lpa_enable",1` invokes internally (likely a QMI
   euicc message in our 35-message reachable set) is the prime candidate for the
   client-state creation the research lane is hunting.
3. **ZTE's own surface is in our dumps (zero-risk local RE):**
   - `AT*EUICC` — ZTE-proprietary AT command in the modem's atcmdsrv
     (`at-table.txt` line 90, handler `atEUICC` at 0x4483c; query path returns
     `*EUICC: <int>` cached state; set path returns error 4 in this build)
   - `CI_SIM_PRIM_DOWNLOADPROFILE_REQ/CNF` — internal command-interface
     primitives: **ZTE's profile download path exists in the modem firmware**
   - `STK_DownloadMeProfile` — STK/BIP-mediated profile download machinery
   - `sac_dev_euicc` region (0x65d9000–0x65e4000) in the arbi/SAC daemon —
     the euicc device layer of ZTE's SIM access control
   - All four are unexplored leads in our existing artifacts; the research lane
     has the Ghidra project + Qshrink DB to run them down without touching the
     device.
4. **A programmable eUICC card is needed for end-to-end provisioning.** The
   MF286D has no soldered eUICC; the tollgate-cellular pipeline needs an
   ESTKme/sysmoEUICC-class card in the slot, then lpac (or the modem LPA) writes
   silent.link/nadanada profiles to it.

## The conwrt pipeline this enables ("tollgate for cellular")

```
any old router
  → conwrt detect/flash/recover (existing)
  → conwrt configure profile "cellular" (existing modem bring-up)
  → conwrt esim provision:
        transport = modem-dependent:
          unlocked modem  → lpac QMI backend (0x42/0x3B/0x3F)
          ZTE-locked      → modem-internal LPA (extended messages, in research)
        lpac profile download --activation-code LPA:1$smdp...$...   (silent.link / nadanada)
        → modem re-read (DMS reset / CFUN cycle — production-proven recipe)
        → data session on the new profile
```

Every box except "ZTE-locked transport" exists today in open source. That's the
remaining research delta, and it's ours.

## Safety lessons from the ecosystem (adopted policy)

- **Reference implementations before crafted probes.** libqmi's JSON message
  definitions and lpac's backend source are the ground truth for TLV formats —
  never hand-craft a message that one of them already defines.
- **Standard messages first.** A message documented in libqmi is a well-formed
  surface other vendors test against; a message only present in our IDL decode
  is experimental territory (crash risk).
- **The Quectel/Dell docs are the closest thing to a "working LPA session"
  transcript** — use them to know what success looks like before probing.

Refs: #621 #672 #675 #676 #677 #682
