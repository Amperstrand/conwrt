# Prompt: MF286D modem (MDM9650) live access & probing runbook

Species-level. Written after EXP-034/035 (2026-11-09). Everything below was
verified live on a B12 unit unless marked otherwise.

## What the modem is (correction of prior belief)

The live MF286D modem card is a **Qualcomm MDM9650** (soc_id 283, rev 1.1),
running ZTE-customized Qualcomm firmware `BD_TELIAMF286DV1.0.0B12` (kernel
3.18.31, built 2021-07-10). It is NOT the Marvell PXA1826 of the 2019 B02
service-kit FBF (`asrmod/`) — that kit describes the earlier modem
generation. USB idProduct `19d2:1485`; interfaces: 1.0/1.1 ECM-data,
1.2–1.4 `option` → ttyUSB0–2, 1.5 `qmi_wwan` → cdc-wdm0, **1.6 = ADB
(ff/42/01)**.

## Access path

```
# from a host with SSH to the bench (resolve via registry):
ssh -i <key> root@<unit-IP>   # resolve from the registry (lab.yaml / labgrid place)      # router (OpenWrt 25.12)
adb devices                                                 # modem = MF286DZTED000000
adb shell id                                                # uid=0 — adbd 5.0.2, NO AUTH
```
`adb-enablemodem` package is installed and kept enabled (survives reboots).
adb protocol version is old (client 1.0.32 works; if a future router apk
updates adb and it complains, use `adb kill-server` first).

## The three interfaces

- **ADB (root shell on modem Linux)** — best surface. Modem partition map
  (`/proc/mtd`): sbl, mibib, efs2 (NV!), tz, rpm, efsbak, aboot, boot,
  scrub, **modem (mtd9, 0x4700000 = MPSS/AMSS)**, misc, recovery, fota,
  recoveryfs, ztefile, zterw, system (rootfs, mtd16, UBIFS).
- **AT** — ttyUSB0 = DM (silent), ttyUSB1/2 = AT (ttyUSB1 accumulates echo
  garbage easily; prefer ttyUSB2). Router busybox lacks `timeout`/`stty`;
  use an `exec 3<>/dev/ttyUSB2` + `read -t 1` loop helper (see
  `/tmp/at3.sh` pattern in session logs). Only ONE reader per port, ever.
- **QMI** — `qmicli` (apk: qmi-utils) and the campaign's own client
  `qmiuim` (source: `recipes/zte/mf286d/modem/qmiuim.c`; unit-tested golden
  frames; build: `arm-linux-gnueabihf-gcc -O2 -static`). Deploy to the
  router `/tmp`, run against `/dev/cdc-wdm0`.

## qmiuim usage

```
/tmp/quv4 <aid-hex> [apdu-hex | geteid | isdrbattery | calib]...
/tmp/quv4 ch0 <apdu-hex>...        # basic channel (rejected by this fw for all APDUs)
```
- opens a logical channel to `<aid>` then sends each APDU on it.
- TLV wire facts (validated by unit tests): APDU TLV 0x02 = `[u16 LE len][apdu]`;
  response APDU+SW in TLV 0x10 = `[u16 len][data…SW]`, SW-only answers look
  like `0200XXXX`. QMUX: len = total−1, qmi_flags byte present, txn = u8 (CTL)
  / u16 LE (services).

## Operational rules (learned the hard way)

1. **Channel budget**: every qmiuim run leaks its channel (close-logical-channel
   TLV still wrong — error 0x47). ~2–3 opens per modem boot, then error 0x44.
   Recovery: `adb reboot` (~2.5 min). Batch your APDUs into one run.
2. **Never hammer locked partitions**: reading `/dev/mtd2ro` (efs2) while the
   modem is warm *destabilizes adb* (device drops). One cold attempt after a
   modem reboot is the plan; do not repeat on failure. mtd9 read fine.
3. `dd`/`head -c` on ttys/cdc-wdm block forever — always `read -t` or select().
4. Modem reboots are safe; nothing in these flows writes to flash.

## The ISD-R policy you will hit (three layers, all in MPSS)

- L1: QMI open-logical-channel with ISD-R AID ≥7 bytes (`A0000005 591010…`)
  → error 82. <7-byte partials open; card FCI then reveals the full ISD-R AID.
- L2: on channels whose open-FCI revealed ISD-R, the modem **fabricates card
  responses** (SELECT MF→6A82, STATUS→6D00, STORE DATA→6A80). Proven by
  differential: identical APDUs on a USIM channel give real answers.
- L3: APDU **payload scanner**: any SELECT-by-DF-name carrying the GSMA RSP
  RID (≥4 bytes `A0 00 00 05`) is dropped QMI-level even on unflagged channels.
- Basic channel (0): all host APDUs rejected (modem-reserved) — not ISD-R-specific.
- AT layer: `+CSIM` "operation not supported", `+CCHO` ERROR for every AID.

Net: the QMI/AT surface is closed by design; see prompt `modem-fw-02` for the
offline RE path that locates this code in the mtd9 image.
