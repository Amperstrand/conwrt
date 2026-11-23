# MF286D modem DM/DIAG protocol — the open channel (2026-11-09)

Species-level. Discovered live on B12; the DM channel is the modem's
management backdoor that survives everything (no AT, no crashers).

## Transport

- Router `/dev/ttyUSB0` (USB if2 — the port mute to AT; PR #85 pins it as
  untagged/DIAG-presumed: **now CONFIRMED as the DM channel**)
- 115200 8N1 raw; HDLC-lite framing: `0x7E <payload> <crc16 LE> 0x7E`,
  escape `0x7D c` for 0x7E/0x7D inside; responses OMIT the opening 0x7E.
- **CRC variant (the key discovery)**: NOT the community-table
  reflected-0x8408/init-0xFFFF (crc(00)=0x87F0). This device uses the
  variant reproduced by `crcmod.mkCrcFun(0x11021, initCrc=0, xorOut=0xFFFF)`
  — crc(00)=**0xF078**. Validated: all captured RX frames verify. With the
  WRONG CRC the device answers `0x13 DIAG_BAD_CMD_F` + echo of your frame
  (looks like lockdown; is not). Corrected VERNO frame: `7E 00 78 F0 7E`.

## Confirmed command set (B12, live)

| Cmd | Name | Result |
|---|---|---|
| 0x00 | DIAG_VERNO_F | build date string ×2 ("Jul 10 2021 00:33:56…") |
| 0x1C | DIAG_DIAG_VER_F | `08 00 3A 28` (proto 8.0.58-ish) |
| 0x7C | DIAG_EXT_BUILD_ID_F | full MPSS build: **MPSS.AT.2.5.1-00628-9655_GEN…** |
| 0x26 | NV_READ_F `{26, item_lo, item_hi, 00}` | 135-B responses (128-B item buffer) |
| 0x0C | DIAG_STATUS_F | BAD_CMD |
| 0x4B+0F/46 | subsystem dispatch | BAD_CMD (those subs only) |

## NV sweep result (2026-11-09)

All items 0–4095 swept via `dm_sweep` (below): **4096/4096 answered,
0 errors**. Harvest: `~/mf286d-work/evidence/modem-fw-re/live-b12/nv/
nvsweep-4096.txt` (sha256 `b121cc75…`). Item 550 (NV_UE_IMEI_I) carries
the IMEI payload. **This is the QCN-equivalent of the efs2 content —
extracted with zero raw-flash reads.** efs2/efsbak raw partitions remain
locked (crasher class both char+block paths; efsbak verified erased).

## Tooling (this dir, static armv7 builds via ai-legion
`arm-linux-gnueabihf-gcc -O2 -static`; deploy via scp -O to router /tmp)

- `dm_probe.c` — first-contact probe (bad-CRC era, kept for the record)
- `dm_probe2.c` — corrected-CRC probe matrix (validated responses)
- `dm_sweep.c` + `nv_crcs.h` — full NV sweep (embedded precomputed CRC
  table; no runtime CRC needed)
- response grammar + vectors inline above

## AT stack note (separate, 2026-11-09)

After crash-reboots, `MCM_atcop_svc` fails to start: init script writes
`/sys/class/tty/smd8/open_timeout` under `set -e`, but the smd8 **tty
class sysfs dir never appears** (device node does). Persists across `adb
reboot`; direct daemon start also fails. Data path unaffected (QCMAP +
netmgrd run; QMI on cdc-wdm0 unaffected). **Fix path: cold power cycle.**
DM port is unaffected and is the preferred management surface anyway.
