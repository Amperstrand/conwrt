# External Review Request: AP3915i OpenWrt Flash Plan (Unit 2)

**Purpose**: This document is structured for an external LLM to review and challenge
our flash plan before execution. We bricked the first AP3915i and want to avoid repeating
that mistake. Please be critical — look for gaps, wrong assumptions, and hidden risks.

**Device**: Extreme Networks WS-AP3915i-ROW (second unit, S/N 1918Y-1083600000)
**Goal**: Flash OpenWrt 24.10.2 without serial cable, via network only

---

## Background: What Went Wrong on Unit 1

We successfully flashed OpenWrt 24.10.2 onto the first AP3915i. The firmware was correct.
The flash was correct. But we set the wrong U-Boot `bootcmd` variable, causing a boot loop
that requires serial cable to fix.

### The Chain of Mistakes (Unit 1):

1. **`rdwr_boot_cfg` was broken** on Unit 1 (exit 255 "unable to find config blocks")
   — This forced us into raw MTD writes (higher risk approach)

2. **We set `bootcmd=run boot_flash`** instead of `bootcmd=run boot_openwrt`:
   - `run boot_flash` → `source boot_kernel` → stock boot script with watchdog timers
   - Stock script expects stock uImage format, not OpenWrt FIT
   - Script fails, watchdog fires, boot loop
   - The CORRECT value was `run boot_openwrt` which does: `sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000`

3. **We wrote to BOTH config blocks** (CFG1 and CFG2) — eliminated the CRC-fail fallback

4. **No fallback** in bootcmd — should have used `run boot_openwrt || run boot_net`

5. **Source of the error**: PR #13370's instructions said `bootcmd="run boot_flash"` but
   that was for a different scenario (going BACK through stock firmware). We didn't read
   David Bauer's original commit e16a0e7 which had the correct `boot_openwrt` command.

---

## Unit 2 Hardware Details

### Confirmed Identity
```
MODEL=AP3915i-ROW (from config block)
SERIAL#=1918Y-1083600000
DTS compatible: qcom,ipq40xx-apdk04.1
SoC: Qualcomm IPQ4019 (4x Cortex-A7)
RAM: 512MB
MAC: DC:B8:08:XX:XX:XX (Extreme Networks OUI)
```

### Flash Layout
```
This unit has BOTH SPI-NOR (32MB) AND NAND (512MB).
NAND holds UBIFS rootfs — IRRELEVANT for OpenWrt (uses SPI-NOR only).

SPI-NOR partitions (IDENTICAL to Unit 1):
  CFG1     64KB   — U-Boot env block 1 (mtd1)
  BootBAK  448KB  — Backup U-Boot (read-only)
  WINGCFG1 64KB   — WiNG config
  ART      64KB   — Radio calibration (IRREPLACEABLE)
  BootPRI  448KB  — Primary U-Boot + boot_kernel script
  WINGCFG2 64KB   — WiNG config
  FS       512KB  — JFFS2 filesystem
  PriImg   ~15MB  — Primary kernel at flash offset 0x280000 (FIT image, d0 0d fe ed)
  SecImg   ~15MB  — Secondary kernel at flash offset 0x1130000 (FIT image)
  CFG2     64KB   — U-Boot env block 2 (mtd10)
```

### Key Difference: bootcmd
```
Unit 1 default: bootcmd=run boot_flash
Unit 2 default: bootcmd=bootx

BOOTX IS EQUIVALENT TO RUN BOOT_FLASH. Confirmed from BootPRI partition:
  "bootx - equivalent to the command: run boot_flash"
```

### TFTP Boot Variables (existing, not modified)
```
boot_net = tftpboot 0x83600000 vmlinux.gz.uImage.3912; bootm 0x83600000
```

### rdwr_boot_cfg Status
```
Binary exists: /usr/sbin/rdwr_boot_cfg (4824 bytes)
read_all: returned empty (needs investigation)
read_var: NOT YET TESTED
write_var: NOT YET TESTED
```

---

## Proposed Flash Plan

### Topology
```
[Mac 192.168.1.X] ---en5--- [OpenWrt Zyxel GS1900-8HP 192.168.1.2]
                                    |
                                    | lan5 (PoE to AP)
                                    |
                               [AP3915i 192.168.1.X]
```

All 8 switch ports on bridge VLAN1 — no filtering, all traffic visible on Mac's en5.

### Phase 0: Verify rdwr_boot_cfg (CRITICAL — must do first)
```bash
ssh admin@192.168.1.X
rdwr_boot_cfg read_var bootcmd        # Does this work?
rdwr_boot_cfg read_var boot_net       # Can we read individual vars?
rdwr_boot_cfg read_var boot_flash     # Verify stock values
rdwr_boot_cfg read_all                 # Try again — maybe needs different invocation
```

**If read_var works**: Proceed with rdwr_boot_cfg approach (safer than raw MTD)
**If read_var fails**: Fall back to raw MTD write approach (kmod-mtd-rw + flashcp from initramfs)

### Phase 1: Save Current Config (read-only, zero risk)
```bash
rdwr_boot_cfg read_all > /tmp/unit2-bootcfg-backup.txt
# Also raw-dump both config blocks
dd if=/dev/mtd1 of=/tmp/cfg1_backup.bin    # CFG1
dd if=/dev/mtd10 of=/tmp/cfg2_backup.bin   # CFG2
# Pull to Mac via SCP
```

### Phase 2: Stabilize (safe — doesn't change boot path)
```bash
cset sshtimeout 0 && capply && csave       # Prevent SSH timeout reboots
rdwr_boot_cfg write_var WATCHDOG_COUNT=0   # Disable watchdog count
rdwr_boot_cfg write_var WATCHDOG_LIMIT=0   # Disable watchdog limit
# Verify:
rdwr_boot_cfg read_var WATCHDOG_COUNT
rdwr_boot_cfg read_var WATCHDOG_LIMIT
```

### Phase 3: Set TFTP Boot (changes boot path — SAFE because TFTP is recoverable)
```bash
rdwr_boot_cfg write_var AP_MODE=0
rdwr_boot_cfg write_var MOSTRECENTKERNEL=0
rdwr_boot_cfg write_var AP_PERSONALITY=identifi
rdwr_boot_cfg write_var serverip=192.168.1.X   # Mac's IP
rdwr_boot_cfg write_var ipaddr=192.168.1.X
rdwr_boot_cfg write_var bootcmd="run boot_net"
# Verify ALL:
rdwr_boot_cfg read_var bootcmd       # MUST be "run boot_net"
rdwr_boot_cfg read_var serverip      # MUST be 192.168.1.X
rdwr_boot_cfg read_var boot_net      # MUST show tftpboot command
```

**Safety**: `bootcmd=run boot_net` means if AP reboots, it tries TFTP. As long as Mac
is running TFTP server with initramfs, AP boots into OpenWrt. This is the "known safe" state.

### Phase 4: TFTP Boot Initramfs
```bash
# Terminal 1: tcpdump on Mac
sudo tcpdump -i en5 -w /tmp/ap3915i-unit2-flash.pcap host 192.168.1.X or port 69

# Terminal 2: TFTP server on Mac
sudo python3 scripts/tftp-server.py data/extreme-ap3915i/ 192.168.1.X
# Must serve: vmlinux.gz.uImage.3912 (symlink to initramfs-uImage.itb)

# Terminal 3: Reboot AP
ssh admin@192.168.1.X "reboot"
# Wait ~90 seconds. Watch tcpdump for:
#   1. ARP requests from AP (192.168.1.X looking for 192.168.1.X)
#   2. TFTP read request for vmlinux.gz.uImage.3912
#   3. TFTP data transfer (~10MB)
#   4. ARP/DHCP from OpenWrt after boot
```

### Phase 5: Connect to OpenWrt Initramfs
```bash
ssh root@192.168.1.X   # No password — OpenWrt defaults
# Verify:
uname -a                  # Should show OpenWrt kernel
cat /proc/mtd             # Check partition layout
cat /etc/board.json       # Confirm device identification
```

### Phase 6: Backup MTD Partitions
```bash
# On AP:
mkdir -p /tmp/backup
for i in 0 1 2 3 4 5 6 7 8 9 10 11; do
  dd if=/dev/mtd${i} of=/tmp/backup/mtd${i}.bin 2>/dev/null
done
# Pull to Mac:
scp -r root@192.168.1.X:/tmp/backup/ data/extreme-ap3915i-unit2/
```

### Phase 7: Sysupgrade
```bash
# Upload firmware
scp data/extreme-ap3915i/openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-squashfs-sysupgrade.bin \
    root@192.168.1.X:/tmp/sysupgrade.bin

# Verify SHA256 on AP
ssh root@192.168.1.X "sha256sum /tmp/sysupgrade.bin"

# Flash
ssh root@192.168.1.X "sysupgrade -n /tmp/sysupgrade.bin"
# AP reboots. bootcmd is still "run boot_net" → TFTP boots initramfs again
# This is EXPECTED — sysupgrade doesn't change U-Boot env
```

### Phase 8: Set Final bootcmd (DANGER ZONE)

After sysupgrade, AP TFTP-boots into initramfs again. Now we need to set the final bootcmd.

**Option A: If rdwr_boot_cfg is available in initramfs** — unlikely (it's a stock tool)

**Option B: Raw MTD write from initramfs (proven approach)**
```bash
ssh root@192.168.1.X

# Install MTD read-write bypass
opkg update && opkg install kmod-mtd-rw
insmod mtd-rw i_want_a_brick=1

# Build correct config block with Python (on Mac)
# Config block format:
#   [4-byte LE CRC32 of block[5:]] [1-byte flag (0x01=active)] [KV pairs null-separated, padded with 0xFF to 65536 bytes]
# CRC algorithm: struct.pack('<I', zlib.crc32(data[5:]))
#
# Variables to include (all existing vars PLUS new ones):
#   boot_openwrt=sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000
#   bootcmd=run boot_openwrt || run boot_net    <-- WITH FALLBACK!
#   WATCHDOG_COUNT=0
#   WATCHDOG_LIMIT=0
#   MOSTRECENTKERNEL=0
#   serverip=192.168.1.X    <-- For TFTP fallback
#   ipaddr=192.168.1.X
#   (preserve all other existing vars)

# Upload and write
scp correct_cfg.bin root@192.168.1.X:/tmp/
flashcp /tmp/correct_cfg.bin /dev/mtd1    # CFG1
flashcp /tmp/correct_cfg.bin /dev/mtd10   # CFG2 (both blocks — acceptable because of fallback)
```

**Option C: Set boot_openwrt from stock firmware BEFORE first TFTP boot**
```bash
# Do this BEFORE Phase 3 (before changing bootcmd to run boot_net):
rdwr_boot_cfg write_var boot_openwrt="sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000"
rdwr_boot_cfg write_var serverip=192.168.1.X
rdwr_boot_cfg write_var WATCHDOG_COUNT=0
rdwr_boot_cfg write_var WATCHDOG_LIMIT=0
# Then set bootcmd for TFTP:
rdwr_boot_cfg write_var bootcmd="run boot_net"
# After sysupgrade, from initramfs, write final bootcmd:
rdwr_boot_cfg write_var bootcmd="run boot_openwrt || run boot_net"
# PROBLEM: rdwr_boot_cfg doesn't exist in OpenWrt initramfs
```

**Recommended: Hybrid approach (Option C modified)**
1. From stock: write `boot_openwrt`, `serverip`, `WATCHDOG_*` via `rdwr_boot_cfg`
2. From stock: set `bootcmd=run boot_net` (temporary, for TFTP boot)
3. TFTP boot → initramfs → backup → sysupgrade
4. After sysupgrade, AP TFTP-boots into initramfs again
5. From initramfs: use `kmod-mtd-rw` + `flashcp` to write ONLY `bootcmd=run boot_openwrt || run boot_net`
   - The other vars (boot_openwrt, serverip, WATCHDOG_*) were already set in step 1
   - Only need to change bootcmd from "run boot_net" to "run boot_openwrt || run boot_net"
   - **CRITICAL**: Keep `|| run boot_net` fallback!

### Phase 9: Reboot and Verify
```bash
# From initramfs, after writing final bootcmd:
reboot
# Keep TFTP server running during first flash boot (for fallback)
# Watch tcpdump for:
#   1. NO TFTP request (means boot_openwrt worked)
#   2. ARP from OpenWrt at 192.168.1.X
#   3. SSH becomes available

ssh root@192.168.1.X
# Verify:
iw phy                     # WiFi radios
hexdump -C /dev/mtd4 | head  # ART partition integrity
cat /etc/board.json          # Correct device identification
```

---

## Safety Measures (Lessons from Unit 1)

| Measure | Why |
|---------|-----|
| `bootcmd` includes `\|\| run boot_net` fallback | If flash boot fails, TFTP catches it |
| Keep TFTP server running during first flash boot | Fallback actually works |
| Verify EVERY `rdwr_boot_cfg write_var` with `read_var` | Catch typos before reboot |
| Save full config block dump BEFORE any writes | Rollback reference |
| Backup ALL MTD partitions from initramfs | Irreplaceable data (ART, BootPRI) |
| NEVER use `run boot_flash` or `bootx` as bootcmd | These run stock boot_kernel — incompatible |
| Write boot_openwrt + serverip BEFORE changing bootcmd | Other vars are in place before boot path changes |
| Test `rdwr_boot_cfg read_var` first | Confirm the tool works before relying on it |

---

## Open Questions for Reviewer

1. **Address conflict**: `sf read 0x88000000` loads at 0x88000000 but `fdt_high=0x87000000`.
   Does `bootm` correctly extract the FDT from the FIT blob and place it below 0x87000000?
   The FIT blob at 0x88000000 contains kernel + FDT + rootfs. `bootm` should parse the FIT,
   relocate FDT below fdt_high, and boot the kernel. Is this correct?

2. **NAND interference**: This device has NAND with UBIFS rootfs. When OpenWrt boots from
   SPI-NOR, will it try to mount the NAND UBIFS? Could this cause issues? The OpenWrt DTS
   for ws-ap3915i defines only SPI-NOR partitions — it shouldn't even know about the NAND.

3. **Same OpenWrt image**: The OpenWrt image (extreme-networks_ws-ap3915i-initramfs-uImage.itb
   and sysupgrade.bin) was built for the IPQ4029 ws-ap3915i. This unit has IPQ4019.
   The IPQ4019 and IPQ4029 are the same silicon with different feature enables — the DTS
   uses `qcom,ipq4029` for both. Is the image compatible?

4. **rdwr_boot_cfg write_var writes BOTH blocks**: We learned that writing both blocks
   with the same wrong value is dangerous (eliminates fallback). But rdwr_boot_cfg does
   this atomically. Is the `|| run boot_net` fallback sufficient protection, or should we
   try to write only one block?

5. **Config block format**: The CRC covers `block[5:]` (skips 4-byte CRC + 1-byte flag).
   Flag 0x01 = active, 0x00 = backup. Both blocks have 0x01 in our dump. When writing,
   should we set both to 0x01? Or set one to 0x00? U-Boot tries block with flag=0x01 first.

6. **PriImg size**: The OpenWrt sysupgrade image is ~9MB (IMAGE_SIZE := 30080k = ~29.4MB).
   The PriImg partition is 0xeb0000 = ~14.6MB. The OpenWrt DTS firmware partition is
   0x1d60000 = ~29.4MB (merged PriImg + SecImg). sysupgrade writes to the DTS firmware
   partition. Does OpenWrt's `default_do_upgrade` handle this correctly on this hardware?

7. **Traffic capture through switch**: All ports are on bridge VLAN1. Will tcpdump on the
   Mac's en5 interface see the TFTP requests from the AP? The switch should flood unknown
   unicasts and forward broadcasts. TFTP uses UDP broadcast or unicast — should be visible.

8. **bootcmd=bootx in config block**: The current bootcmd is `bootx`, not `run boot_flash`.
   When we write `bootcmd=run boot_net || run boot_openwrt`, this replaces `bootx`. The
   variable `boot_flash=source boot_kernel` remains in the config block (harmless). Is
   there any scenario where U-Boot falls back to a compiled-in default bootcmd that uses
   bootx or boot_flash?

---

## Source References

| Source | URL | What it confirms |
|--------|-----|-------------------|
| David Bauer commit e16a0e7 | https://github.com/openwrt/openwrt/commit/e16a0e7e8876df0a92ec4779fe766de1a943307a | Correct boot_openwrt command, firmware offset 0x280000, load address 0x88000000 |
| PR #13370 | https://github.com/openwrt/openwrt/pull/13370 | rdwr_boot_cfg usage, credentials admin/new2day, bootcmd="run boot_flash" (WRONG for our use case) |
| OpenWrt wiki | https://openwrt.org/toh/extreme_networks_ws_ap391x | Device support page |
| OpenWrt DTS | target/linux/ipq40xx/dts/qcom-ipq4029-ws-ap3915i.dts | Partition layout, firmware at 0x280000 |
| OpenWrt generic.mk | target/linux/ipq40xx/image/generic.mk | Device/FitImage, IMAGE_SIZE := 30080k |
| PR #17305 | https://github.com/openwrt/openwrt/pull/17305 | BLOCKSIZE fix (merged in 24.10.2) |

---

## Files for Reference

- `recipes/extreme-networks/ws-ap3915i/SESSION-WRITEUP.md` — Full Unit 1 session notes with mistakes analysis
- `recipes/extreme-networks/ws-ap3915i/UNIT2-AP3915i-ROW.md` — Unit 2 hardware details
- `recipes/extreme-networks/ws-ap3915i/no-serial-openwrt.md` — Technical documentation
- `recipes/extreme-networks/ws-ap3915i/SEMI-AUTO-FLASH.md` — Semi-auto flash procedure
- `models/extreme-networks-ws-ap3915i.json` — Device model definition
