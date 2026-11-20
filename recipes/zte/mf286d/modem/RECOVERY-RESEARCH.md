# Recovery research — tools, best practices, and the recommended session plan

2026-11-10. Web + zread research into Qualcomm modem EFS corruption recovery,
safe repair procedures, and the specific tools applicable to our MDM9650.

## Tools discovered (all Linux/DIAG-port, no QPST needed)

### qfenix (github.com/iamromulan/qfenix) — BEST FIT
Full DIAG-port modem management:
- `efsls` / `efspull` / `efspush` / `efsrm` (delete!) / `efsstat` / `efsmkdir`
- `efsbackup -o .xqcn` (QPST-compatible) or `-t .tar` — full EFS backup
- `efsrestore` — restore from either format
- `nvread` / `nvwrite` — NV item access
- `diag2edl` — switch to EDL/flash mode
- Runs over the DIAG serial port directly

### qcdm-efs2 (git.gec.im/grmrgecko/qcdm-efs2) — LIGHTEST
Single-file Python + pyserial (perfect for the router's ttyUSB0 bridge):
- `efs2.py {ls,stat,pull,push,backup}`
- push does delete→recreate→write→read-back-verify (the read-back is the
  safety net against truncated writes)

### qcom-efs-browser (github.com/catxeon/qcom-efs-browser) — REFERENCE
Documents the complete EFS2 DIAG packet set:
- Read/write/delete/mkdir/chmod/unlink/rename/symlink — all over DIAG subsys
- **Modem restart: `4b 25 03 00`** (DIAG frame, with journal sync first)
- **Journal sync: opcodes 48/49** (SYNC_NOWAIT / SYNC_GET_STATUS)
- EFS2 is journalled — unsynced changes can roll back across restart

## Key protocol facts for the session

| Operation | DIAG frame/packet |
|-----------|------------------|
| EFS2 file ops | `[0x4B][subsys][cmd_lo][cmd_hi][body]`, subsys 0x13 (standard) or 0x3E (Quectel) |
| Journal sync | opcode 48 (start) then 49 (poll status) |
| **Modem/baseband restart** | **`4b 25 03 00`** (with sync first, then reconnect after ~8s) |
| NV read/write | 0x26/0x27 (or indexed 0x4B 0x30 0x01/0x02) |
| SPC unlock for NV writes | 0x41 (Service Programming Code) |

## Best-practice recovery order (community consensus)

From XDA forums, eko.one.pl (this exact modem!), qfenix docs, QCN guides:

1. **Full EFS backup FIRST** — `efsbackup` or `backup /` before ANY write
   - Our NV sweep + pristine mtd9 do NOT cover EFS file-level state
   - Without this, a bad write could lose IMEI/calibration permanently
2. **Read the priority files** — look for present-but-garbage (not missing)
   - Missing = benign (compiled defaults kick in, per our AMSS analysis)
   - Garbage = service death (reader accepts it as a valid feature bitmask)
3. **If garbage found: DELETE the file** (`efsrm`) → journal sync → restart
   - Deletion is cleaner than trying to write correct values
   - On restart, the reader hits "file not found" → falls back to defaults
4. **Restart via `4b 25 03 00`** (not adb reboot, not DLOAD) — the designed
   modem-restart path with journal sync, service reconnection
5. **Verify QMI services return** — `qmicli --uim-get-card-status` etc.
6. **Only then: ISD-R flips** (apdu_security, lpa_support) — the dual-purpose
   payload of the same session

## Community confirmation of our crasher partitions

eko.one.pl forum (MF286D modem thread, 2022):
> "I was able to dump all of the partitions on my modem, **except for EFS
> and MIBIB**, trying to dump which caused instant reboot, and for some
> models even reset to QDLoader (9008) mode."

This is EXACTLY our mtd1/mtd2 experience — species-confirmed.

## The flash-recovery backstop (if EFS repair fails)

Community-proven on this exact modem:
1. QPST "Software Download" SB3.0 mode with a modified `contents.xml`
2. Or: fastboot flash of individual partitions (boot/system/modem/recovery)
3. Or: the ZAS/dload tooling we already have (EXP-015/016/020)

All paths covered by our pristine backups + firehose tooling.

## Session plan (recommended)

```
Phase 1: Connect qcdm-efs2 (or qfenix) to router ttyUSB0
Phase 2: efs2.py backup / ./efs-full-backup    # FULL backup first
Phase 3: Read priority-8 files (hex dump each)  # damage inspection
Phase 4: If garbage found → efsrm <file>        # targeted delete
         → journal sync (opcode 48)              # commit
         → restart (4b 25 03 00)                 # modem restart
Phase 5: Verify QMI services return              # qmicli checks
Phase 6: ISD-R policy reads + flips              # the unlock
```
