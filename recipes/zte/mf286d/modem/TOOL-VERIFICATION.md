# Tool verification — qfenix, qcdm-efs2, QCSuper EFS write (session-ready)

2026-11-10. Systematic verification of the three candidate tools for the EFS
repair + ISD-R unlock session (issue #672). All studied from source.

## Verdict: qfenix is THE tool. Pre-built static ARM binary ready to deploy.

### qfenix (github.com/iamromulan/qfenix) — RECOMMENDED PRIMARY

**Verified from source + release binary:**
- **Pre-built static armv7 binary**: `qfenix-linux-arm.tar.gz` from the latest
  release (v2.5.10-qfenix-0.1.0, 2026-03-08) — 5.4MB, static-pie, runs on the
  OpenWrt router directly. Downloaded and tested: `qfenix --help` works on x280.
- **Serial transport**: opens `/dev/ttyUSB*` at 115200 raw mode with
  termios — exactly our router-side ttyUSB0 DM port. No USB/libusb dependency
  for DIAG commands (only EDL needs libusb).
- **Complete EFS command set** (verified in `qdl.c`):
  - `efsbackup -o backup.tar` or `-o backup.xqcn` — full EFS backup
  - `efsls /nv/item_files/modem/uim/` — tree listing
  - `efspull /nv/item_files/...` — file read
  - `efspush local_file /nv/item_files/...` — file write
  - `efsrm /nv/item_files/...` — file delete (-r for dirs)
  - `efsdump` — factory image dump
  - `nvread` / `nvwrite` — NV item access
- **EFS2 subsystem**: auto-detects method 0x3E (Quectel alt) then 0x13 (std)
  via a HELLO probe — exactly the right sequence for our modem.
- **Item file interface**: `GET/PUT` opcodes (39/38) for `/nv/item_files/`
  paths — bypasses file-level ACLs, atomic writes, handles the
  item-file-vs-regular-file distinction automatically (`is_item_path()`).
- **Modem restart**: uses `DIAG_CONTROL_F` (0x29) with mode=2 (RESET):
  ```
  frame = 29 02 00 <CRC16-LE> 7E
  ```
  This is the DIAG mode-change mechanism, verified in `diag.c:685-700`.
  After sending, it closes the port, waits 10s, retries open for 30 attempts.
  **This supersedes the `4b 25 03 00` I cited earlier** (that's a different,
  subsystem-specific restart path — both should work; qfenix's is proven).
- **Journal sync**: EFS2_DIAG_SYNC_NO_WAIT (48) + SYNC_GET_STATUS (49) before
  any restart — implemented correctly.

**Key source details (for session planning):**
- PUT (write) is limited to 6KB per frame (HDLC constraint); larger files use
  chunked open/write/close. Our target files (NV items, feature lists) are
  all well under 6KB — PUT path will be used.
- O_AUTODIR flag on PUT auto-creates parent directories.
- The tool includes a `list` command that auto-discovers connected DIAG/EDL/AT
  devices — useful for initial port discovery.

### qcdm-efs2 (grmrgecko/qcdm-efs2) — FALLBACK (simplest)

Single-file Python, 358 lines, pyserial-only. Verified:
- `ls`, `stat`, `pull`, `push` (with read-back verify), `backup`
- Uses DIAG subsys 0x4B, EFS2 DIAG opcodes
- HDLC framing with the correct CRC (0x11021/init=0/xor=0xFFFF)
- **No delete, no NV, no restart** — read + write + backup only
- **No item-file GET/PUT interface** — uses file-level OPEN/WRITE only
- Good as a lightweight backup/pull tool on the router (no compilation needed)

### QCSuper EFS shell — NOT SUITABLE

- `put.py` confirmed: file-level open/write/close only (no item-file interface)
- Requires Python 3 + pyserial + crcmod on the target (router or legion)
- No delete, no backup, no restart
- The `get.py` module may work for reads, but qfenix does everything better

## Recommended session toolchain

| Phase | Tool | Why |
|-------|------|-----|
| Port discovery | `qfenix list` | Auto-detects DIAG port |
| Full EFS backup | `qfenix efsbackup -o /tmp/efs-full.tar` | Complete, TAR format |
| File reads | `qfenix efpull <path>` or `efsls` | Item-file GET for /nv/ |
| Damage inspection | `qfenix efspull` each priority file, hex-dump | Look for garbage |
| Delete damaged | `qfenix efsrm <path>` | Falls back to defaults |
| Write/flip | `qfenix efspush <local> <remote>` | Atomic item-file PUT |
| Journal sync | built into efspush/efsrm | Automatic |
| Modem restart | built into restart flow (DIAG_CONTROL_F mode=2) | After changes |
| NV read | `qfenix nvread <item>` | For NV sweep |
| Backup restore | `qfenix efsrestore backup.tar` | If we need to undo |

## What we DON'T yet know (honest gaps)

1. **apdu_security_aid_list file format**: binary TLV? Simple AID array?
   Unknown — will be discovered on first read.
2. **lpa_support value type**: boolean byte? u32? Unknown.
3. **Whether the degraded modem still serves EFS reads correctly**: DM works,
   EFS NV reads work, but file-level EFS (opendir/readfile) is untested.
4. **Whether deleting a features_status_list actually restores service**:
   theory says yes (absence → defaults), but not proven on this unit.
5. **Whether the EFS corruption theory is correct at all**: the alternative
   is mibib damage (which would need reflash, not EFS repair). The EFS
   inspection will distinguish: if EFS files are clean, the damage is elsewhere.

## Session risk assessment

- Phase 1 (backup): ZERO risk (read-only)
- Phase 2 (inspection): ZERO risk (read-only)
- Phase 3 (delete): LOW risk (undo = restore from backup; absence = defaults)
- Phase 5 (flip): LOW risk (undo = write-back original value)
- Backstop: pristine full partition backups + firehose tooling = guaranteed
  recoverable, community-proven on this exact modem model
