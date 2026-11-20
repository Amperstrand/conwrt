# MF286D Modem Crash-Loop Recovery Options (host-side research, zero device access)

Context: MDM9650 modem crash-loops (~80s/cycle) during m2m_euicc service
init due to corrupted EFS state. QMI alive ~40s windows, DIAG dead.
Need alternatives to physical EDL boot-point short.

---

## (A) QMI live-window intervention

### A1: QMI DMS Offline/Reset (already proven)
- **QMI DMS SET OPERATING MODE (0x002A)** to OFFLINE (0x06) → stops the
  modem task, potentially preventing m2m_euicc init
- **QMI DMS RESET (0x0000)** — already worked (temporary fix)
- Problem: the modem restarts and hits the same corrupted EFS on next boot

### A2: QMI service disable via subsystem restart
- The MF286D's modem Linux (a5 core) manages the Q6 via the remoteproc/
  subsystem_restart framework
- `/sys/class/remoteproc/remoteproc*/state` — can `echo stop > state` to
  halt the Q6 and `echo start` to restart it
- BUT: on the MF286D, the modem Linux runs INSIDE the modem SoC, not on
  the router — the router (IPQ4019) doesn't have remoteproc/sysfs access
  to the MDM9650's Q6 core
- The modem's own Linux (armv7l) DOES have this but we'd need ADB to reach it

### A3: Repeated QMI DMS resets in a loop
- A script that monitors QMI availability and sends DMS RESET every time
  the modem comes up could keep the modem in a reset cycle that avoids
  the m2m_euicc crash point — but this is a band-aid, not a fix

**VERDICT**: QMI alone cannot fix corrupted EFS — it can only restart the
modem, which will hit the same bad data.

---

## (B) Modem Linux intervention (ADB during boot window)

### B1: ADB access timing
- The modem Linux (a5 core) boots BEFORE the Q6 baseband
- ADB interface comes up when the modem Linux USB driver registers
- **In the ~40s QMI-alive window, ADB may also be alive**
- From our EXP-034 work: `adb-enablemodem` package on the router →
  ADB to modem Linux at 192.168.34.1 (or USB ADB interface)

### B2: What to do if ADB is reachable
- `adb shell` → check `/dev/mtd*` → the EFS2 partition (mtd2) contains
  the corrupted data
- **DANGER**: reading mtd2 previously crashed the whole SoC (EXP-034)!
- Better: use the modem Linux's own EFS tools if any exist
- Or: write a cleanup script that deletes specific EFS files via the
  modem Linux EFS driver (not direct mtd read)

### B3: Boot sequence order (from our rootfs analysis)
```
rcS.d/S30usb → USB gadget up (ADB + AT + DIAG ports)
rcS.d/S38init_sys_mss → modem subsystem bring-up
rcS.d/S39start_QCMAP_ConnectionManager_le → QMI userspace
rcS.d/S40start_qti_le → QTI (QMI data interface)
rc2.d/S45netmgrd, S45qmi_shutdown_modemd, etc.
```
The modem Linux boots fully BEFORE the Q6 starts hitting m2m_euicc.
**ADB is alive during the QMI window.**

### B4: Proposed ADB intervention
```bash
# From the router (192.168.34.1):
adb connect <modem-ip>:5555  # or USB ADB
adb shell "mount | grep efs"  # find the EFS mount
adb shell "ls /nv/item_files/"  # check if readable via VFS
adb shell "rm /nv/item_files/qmi/uim/..."  # delete corrupted item
adb shell "reboot"  # clean restart
```
**KEY QUESTION**: does the modem Linux expose EFS as a filesystem?
From EXP-035: the modem Linux has `/dev/mtd2` (efs2) but direct reads
crashed it. However, the EFS **driver** may mount it at `/nv/` or
similar — need to check the modem Linux boot logs.

**VERDICT**: ADB + modem Linux is the MOST PROMISING path if EFS is
mounted as a filesystem. Need to verify in the QMI-alive window.

---

## (C) QMI messages that write EFS

### C1: QMI EFS via DIAG (proven tooling exists)
- **qfenix** (already deployed on our router!) has full EFS management:
  - `qfenix efsls /` — list EFS directories
  - `qfenix efsrm -r /nv/item_files/...` — delete corrupted items
  - `qfenix efspush` — write files
  - `qfenix efsrestore backup.tar` — restore from backup
- qfenix uses the DIAG port (not QMI) — **DIAG is dead in our crash loop**
- BUT: qfenix also has `diag2edl` — switches from DIAG to EDL mode

### C2: QMI EFS service
- There is NO standard QMI EFS service in libqmi/qmicli
- EFS operations go through the DIAG protocol, not QMI
- rmtfs (remote file system) is the QRTR/QMI-based EFS alternative on
  newer platforms (SDX55+) — MDM9650 may use it
- The modem Linux's `rmtfs` service (if present) provides EFS access
  via QMI service 14 (RMTFS)

### C3: QMI DMS Restore Factory Defaults (0x002A sub-command)
- `qmicli --dms-restore-factory-defaults` exists
- This could potentially clear the corrupted EFS state
- **Risk**: it would also wipe calibration data (IMEI, RF cal) — but
  we have a full EFS backup from EXP-035!
- Could be sent during the QMI-alive window

**VERDICT**: DMS restore-factory-defaults + our saved EFS backup
restore via qfenix is a viable recovery path IF DIAG comes up.

---

## (D) Preventing m2m_euicc from loading

### D1: EFS items that gate service startup
From our MTD9-EFS-POLICY-MAP.md:
- `modem/uim/remote/uim_remote_service_enable` — gates UIM Remote
- `modem/qmi/uim/lpa_support` — gates the LPA task (we wrote this in EXP-035)
- There may be an item that gates m2m_euicc specifically

### D2: Our EXP-035 EFS write created the problem
We wrote `lpa_support=1` which enabled the LPA/m2m_euicc subsystem.
The subsequent QMI probes (0x67 register with u64) corrupted state
within the now-active m2m_euicc service.

### D3: Fix by reverting lpa_support
- If we can delete/zero `lpa_support` from EFS, the LPA/m2m_euicc
  subsystem won't initialize on next boot → crash loop broken
- Can be done via qfenix (DIAG) or modem Linux (ADB)

### D4: Fastboot approach
From the MF268 unlock guide (Msprg's gist):
- The MF286D can enter a mode where `fastboot` commands work
- `fastboot flash modem mdm9650-NON-HLOS.ubi` reflashes the modem firmware
- This would NOT fix EFS (it's a separate partition) but might give
  us a stable boot while we work on EFS

**VERDICT**: Reverting `lpa_support` via EFS is the most targeted fix.

---

## (E) USB composition switching

### E1: ZTE USB mode switching (documented)
From community research (eko.one.pl, MF297D, MF823/MF830):

| Mode | PID | Description |
|---|---|---|
| 0 | 0016 | ZTE download mode (AT+ZCDRUN=E) |
| 1 | 1225 | Mass Storage (default) |
| 3/4 | 1403 | RNDIS + MSD (normal work mode) |
| 5 | 1405 | CDC/ECM (Linux auto) |
| **6** | **1404** | **RNDIS + DIAG + 2 COM + MSD + ADB** |
| **7** | **1244** | **CDC + DIAG + 2 COM + MSD + ADB** |
| **8** | **1402** | **DIAG + 2 COM + WWAN + MSD + ADB** |
| 9 | 9994 | MBIM + DIAG + 2 COM + ADB |

**The MF286D normally runs in mode 8 (PID 1402 = DIAG + COM + WWAN + ADB)**

### E2: Switching to mode 6/7 exposes DIAG earlier
- Mode 6/7 includes DIAG + ADB simultaneously
- If we can force the modem into mode 6/7 during the QMI window,
  DIAG port becomes available for qfenix EFS operations
- **Problem**: the mode switch command goes through the web UI or AT
  port — AT is dead, but QMI DMS may have a USB composition message

### E3: QMI USB composition
- Some Qualcomm modems support QMI DMS SET USB COMPOSITION
- Not in standard libqmi/qmicli but may be in the DMS extended set
- Check: our decoded DMS messages (the modem-Linux DMS has 65 messages!)

### E4: Via web UI (if router is up)
- The router at 192.168.34.1 has the ZTE web interface
- USB mode switch URLs are documented:
  `http://192.168.0.1/goform/goform_set_cmd_process?goformId=USB_MODE_SWITCH&usb_mode=6`
- But the MF286D runs OpenWrt now — the ZTE web UI is gone

### E5: Via modem Linux (ADB)
- The modem Linux controls the USB gadget configuration
- If ADB is alive, we can change `/sys/class/android_usb/android0/` or
  run the usb_composition_switch binary (we saw it in the rootfs)
- **This is the most practical path if ADB works during the QMI window**

**VERDICT**: ADB + usb_composition_switch during the boot window could
expose DIAG for qfenix EFS repair.

---

## (F) Community solutions for Qualcomm modem crash loops

### F1: EDL mode via DIAG command (not hardware short)
From bkerler/edl and the MF268 unlock guide:
```
# From DIAG port:
qcommand.exe -pCOM -e -c "c 4b 65 1 0"
# Or from Python:
diag.send(b"\x4b\x65\x01\x00")
```
This is the DIAG-to-EDL switch command. **Requires a working DIAG port.**
Our DIAG is dead during the crash loop.

### F2: ADB reboot to EDL
```
adb shell "reboot edl"
```
Some Qualcomm devices support this — sends the reboot-to-EDL flag.
Works on the modem Linux if ADB is reachable.

### F3: Fastboot mode (MF286D-specific)
From Msprg's MF268 unlock guide:
1. Enter DIAG mode via DL.exe or DIAG port
2. Use qdload/qcommand to enter EDL (9008)
3. Erase boot partition → device enters fastboot
4. `fastboot flash modem mdm9650-NON-HLOS.ubi`
This is a FULL reflash — nuclear option but proven on this hardware.

### F4: Partition-level: erase EFS2 (mtd2) from modem Linux
```
adb shell "flash_eraseall /dev/mtd2"
adb shell "reboot"
```
This wipes the corrupted EFS. The modem will re-create minimal EFS
structure on boot (but lose calibration/IMEI). Our EXP-035 backup
has the full EFS and can be restored via qfenix after recovery.

### F5: EFS "golden copy" recovery
Qualcomm modems have a fsg (golden copy) partition and fsc (checksum).
From the GSM Alphabet research:
```
1. When modemst1 reads/writes abnormally → clear modemst1
2. When modemst1 is empty → copy fsg to modemst1 for recovery
```
If the MF286D has this mechanism, simply erasing mtd2 (efs2) might
trigger automatic recovery from the golden copy on next boot.

---

## PRIORITY-ORDERED RECOVERY PLAN

### Tier 1: QMI-window ADB + EFS file deletion (safest)
1. During the ~40s QMI-alive window, try `adb connect` to modem
2. If ADB works: `adb shell "ls /nv/item_files/qmi/uim/"`
3. Delete the corrupted files: `adb shell "rm -f /nv/item_files/qmi/uim/lpa_support"`
   (or zero the file)
4. `adb shell "reboot"` — clean restart
5. If modem boots normally → DONE

### Tier 2: QMI-window + QMI DMS factory reset
1. During QMI window: `qmicli -d /dev/cdc-wdm0 -p --dms-restore-factory-defaults=<spc>`
2. This wipes EFS to factory state (loses cal but breaks the loop)
3. Restore calibration from our EXP-035 EFS backup via qfenix

### Tier 3: ADB reboot edl + full EFS reflash
1. During QMI window: `adb shell "reboot edl"`
2. Device enters EDL (Qualcomm 9008 mode)
3. Use qfenix/edl to flash a clean EFS image
4. Restore from our backup

### Tier 4: Physical EDL boot-point short (last resort)
1. Open the MF286D case
2. Short the test point to ground during power-on
3. Device enters EDL 9008 mode
4. Flash clean firmware + EFS from backup

---

## TOOLCHAIN READY

- **qfenix** on router (EXP-035): full EFS management via DIAG
- **EFS backup** (EXP-035): 555 files + 338 NV items in XQCN/TAR format
- **uim_bitmap** (EXP-042): QMI probe tool for the QMI window
- **Modem Linux rootfs analysis** (EXP-039): boot sequence mapped
- **adb-enablemodem** package: already on the router

## KEY UNKNOWN

Whether ADB is reachable during the QMI-alive window. The modem Linux
boots before the Q6 crash, so ADB SHOULD be up — but the USB composition
may not include ADB by default on the MF286D (mode 8 = DIAG + COM + WWAN
+ MSD + ADB — it does include ADB!).

The MF286D's normal USB composition (19d2:1485) is **mode 8 equivalent**
— it already includes ADB. So ADB should be alive whenever USB is up.
