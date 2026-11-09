# EXP-034 Live Test Plan & Verification Checklist (MDM9650 B12)

Device: MF286D unit 1 @ 192.168.34.1 (via ai-legion, `ssh -i ~/.ssh/google_compute_engine root@192.168.34.1`)
Modem: Qualcomm MDM9650, BD_TELIAMF286DV1.0.0B12, 19d2:1485, ADB iface 2-1:1.6 (ff/42/01)
Tooling on router: /tmp/quq (qmiuim), qmicli 1.36, adb, /tmp/at3.sh (AT on ttyUSB2)

## A. VERIFIED FACTS (do not re-test; cite these)

| # | Fact | Evidence |
|---|------|----------|
| F1 | Live modem = Qualcomm MDM9650 soc 283 rev 1.1 (NOT the Marvell PXA1826 of the B02 kit) | adb shell /sys/devices/soc0/*, kernel SMD threads |
| F2 | ADB root, no auth (`adb shell id` = uid=0) | live 2026-11-09 |
| F3 | AT: `AT+CCHO` → plain ERROR for ALL AIDs (ISD-R full/partial, USIM, garbage) — AT layer blocks channel opens UNIVERSALLY | ttyUSB2 runs 2026-11-09 |
| F4 | AT: `AT+CSIM` → "+CME ERROR: operation not supported" | ttyUSB2 |
| F5 | AT: `AT*EUICC?`→ERROR, `AT+QESIM=?`→"operation not supported", `AT*PROD?`→ERROR (set-only), ttyUSB0 = silent (DM) | ttyUSB2 |
| F6 | QMI UIM alive (v10, card status OK, slot1 app1 provisioned) | qmicli --uim-get-card-status |
| F7 | **QMI channel-open differential**: full ISD-R AID (16B) → error 82 AccessDenied; USIM A0000000871002 → channel OPENS; garbage → error 80 SimFileNotFound; 4-byte A0000005 → 80 | qmicli 2026-11-09 |
| F8 | **PARTIAL-AID BYPASS**: 6-byte A00000055910 → channel OPENS; card FCI returns full ISD-R AID `A0000005591010FFFFFFFF8900000100` SW=9000 | qmicli -v capture + qmiuim FCI |
| F9 | 7-byte A0000005591010 → 82 AccessDenied (deny threshold = ≥7-byte ISD-R prefix) | qmicli |
| F10 | Deny thresholds: 5-byte A000000559 → OPENS (card-side prefix match ok); 6-byte ETSI A000000087 → OPENS | qmicli |
| F11 | Channel ownership: send-apdu from a client that did NOT open the channel → 82 AccessDenied | qmicli |
| F12 | qmicli is single-UIM-action per run; channels leak per client; ~3 opens then error 0x44 (channel exhaustion) until modem reboot | observed |
| F13 | qmiuim (own client) full flow works: CTL cid → open(6B partial) → APDU → close. APDU result=QMI success; card SW returned in TLV 0x10 | qmiuim debug |
| F14 | Card answered **6A80** to GetEID `81E2910005BF3E035C015A` (correct lpac encoding) on the ISD-R channel | qmiuim 2026-11-09 |
| F15 | QMUX wire format (golden): req `[01][len16LE=total-1][qmux_flags][svc][cid][qmi_flags][txn: ctl u8 / svc u16LE][msg16LE][tlvlen16LE][TLVs]`; TLVs `[type][len16LE][value]`; SEND_APDU TLV 0x02 value = `[u16LE len][apdu]`; APDU response TLV 0x10; card SW TLV 0x11 | captured frames |
| F16 | close-logical-channel from qmiuim returns error 0x47 (INVALID_CHANNEL_ID?) — channel leaks anyway | qmiuim debug |

## B. OPEN QUESTIONS → TESTS (numbered, one modem reboot per batch when channel-bound)

| # | Question | Test | Expected outcomes / decision |
|---|----------|------|------------------------------|
| T1 | What is TLV 0x10 layout in send-apdu responses? | Open USIM channel (A0000000871002), send STATUS `81F2000000`?? or SELECT MF `81A40000023F00`; dump TLV 0x10 raw | Calibrates [ch?][len?][data][SW]. Compare TLV len vs SW presence. |
| T2 | **Does the modem rewrite CLA before the card?** (explains F14's 6A80) | On USIM channel: send `81A40000023F00` (correct CLA) AND `80A40000023F00` (wrong CLA) — compare SWs. On ISD-R channel: `81E2910005BF3E035C015A` vs `80E2910005BF3E035C015A` | If wrong-CLA succeeds → modem rewrites CLA (then 6A80 has another cause). If wrong-CLA gives 6A80/6E00 and correct also 6A80 on ISD-R only → card rejects our STORE DATA for another reason. |
| T3 | Does the ISD-R accept STORE DATA with different P1/P2? | Battery on ISD-R channel: P1∈{91,81,11,01} P2=00, and P1=91 P2∈{00,01}; all with data BF3E035C015A | Any response ≠6A80 (e.g. 61xx/9000/BF3E…) = winner; log matrix. |
| T4 | Does the ISD-R need Le (expected response length)? | Variant of GetEID with Le=xx appended (APDU len 12: `81E2910005BF3E035C015A00`) | 9000/61xx expected if Le required. |
| T5 | Is 6A80 card-global or ISD-R-specific on partial-opened channels? | On 6-byte-opened ISD-R channel send a benign `81A4040400` (hmm—SELECT by DF w/ Le) or STATUS; see if ANY command succeeds on this channel | If nothing works → partial-open leaves applet unselectable-state; if STATUS works → app fine, STORE DATA blocked. |
| T6 | Does the QMI open-logical-channel carry a P2/control TLV we can set (e.g. select-next-occurrence, or AID match mode)? | qmicli -v the open; look for optional TLVs in its request (0x10 aid, 0x01 slot seen; check libqmi uim.json for 'File Control'/'Control' TLV 0x11?) | If selectable P2 → maybe full-AID open via alternate control bypasses deny too. |
| T7 | What EXACTLY does the modem deny-match? (≥7 bytes? prefix A0000005 591010? or full 16?) | 7-byte non-ISD-R e.g. A0000000871002 (7B, opens? YES=F10) — already answered: prefix-specific. Try 8B `A0000005591010FF` (8-byte prefix of ISD-R) → expect DENY (≥7). Try 7B `A0000005591011` (non-matching app byte) → expect NotFound (card) not deny | Confirms matcher = first-7-bytes AND len≥7. |
| T8 | Where does the deny live (MPSS code vs NV)? | Post-ADB: `strings /dev/... mtd9` pull modem image → grep A0000005 591010; check /efs via diag later | Static grep on pulled mtd9 modem partition (71MB, adb cat /dev/mtd9ro). |
| T9 | Is the deny maybe in the MODEM LINUX (qmuxd-side)? | adb: ps full list (missed earlier runs) + strings of any qmi/uim daemon | If a userspace daemon proxies UIM → userspace patch possible. |
| T10 | ADB: modem full partition dump for offline RE | adb shell cat /dev/mtd9ro > /tmp/modem.img (71MB) etc. | Evidence for T8; do once. |

## C. BUGS/LESSONS (encode in tools)
- L1: qmiuim close fails (F16) → every run leaks 1 channel; budget ~2 runs per modem boot; FIX close TLV (compare vs qmicli -v close capture).
- L2: cdc-wdm read returns PARTIAL frames → accumulate until 1+len (fixed in qmiuim).
- L3: dd/head -c on ttys and wdm BLOCK forever; use read -t loops / select().
- L4: qmicli -v truncates RAW prints at 12 bytes — use "translated" sections + tail of frame.
- L5: multiple readers on one tty = garbage (coordination rule with parent session).
- L6: `timeout`/`sleep 0.3`/`stty` absent on router busybox — integer sleeps, own binaries.
- L7: QMUX len = total−1 (counts len-field itself); CTL txn u8, svc txn u16 LE, qmi_flags byte present.

## D. NEXT-SESSION RUNBOOK (after modem reboot)
1. `/tmp/quq A0000000871002 calib` (T1/T2 on USIM channel: correct/wrong CLA + STATUS)
2. `/tmp/quq A00000055910 isdrbattery` (T3/T4/T5: P1/P2/Le matrix, ~6 APDUs, ONE channel)
3. Reboot modem; `/tmp/quq A0000005591011` + `A0000005591010FF` (T7)
4. adb pull mtd9 (T10) → offline grep (T8) — no device contention
5. Full ps dump + /usr/bin inventory (T9)
