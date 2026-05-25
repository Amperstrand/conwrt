# External Review Request: AP3915i OpenWrt Flash Plan (Unit 2) — REVISED v2

**Purpose**: This document is structured for an external LLM to review and challenge
our flash plan before execution. We bricked the first AP3915i and want to avoid repeating
that mistake. Please be critical — look for gaps, wrong assumptions, and hidden risks.

**Device**: Extreme Networks WS-AP3915i-ROW (second unit, S/N AP3915i-ROW-S/N)
**Goal**: Flash OpenWrt 24.10.2 without serial cable, via network only

**v2 Changes**: Incorporates feedback from external LLM review (see Appendix A).

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

4. **No fallback** in bootcmd — should have used `run boot_openwrt; run boot_net`

5. **Source of the error**: PR #13370's instructions said `bootcmd="run boot_flash"` but
   that was for a different scenario (going BACK through stock firmware). We didn't read
   David Bauer's original commit e16a0e7 which had the correct `boot_openwrt` command.

---

## Unit 2 Hardware Details

### Confirmed Identity
```
MODEL=AP3915i-ROW (from config block)
SERIAL#=AP3915i-ROW-S/N
DTS compatible: qcom,ipq40xx-apdk04.1
SoC: Qualcomm IPQ4019 (4x Cortex-A7, same as IPQ4029 — different feature enables only)
RAM: 512MB
MAC: DC:B8:08:XX:XX:XX (Extreme Networks OUI)
U-Boot: 2012.07.19-r00020.1 (Jul 17 2017) — older than Unit 1 (2012.07.22)
```

### Flash Layout — CRITICAL MAPPING

**Stock firmware /proc/mtd** (WiNG OS kernel partition table — NOT in physical order):
```
mtd0:  512MB NAND  "nand_flash"     — UBIFS rootfs/config
mtd1:  64KB  NOR   "CFG1"           — U-Boot env block 1
mtd2:  448KB NOR   "BootBAK"        — Backup U-Boot
mtd3:  64KB  NOR   "WINGCFG1"       — WiNG config
mtd4:  64KB  NOR   "ART"            — Radio calibration (IRREPLACEABLE)
mtd5:  448KB NOR   "BootPRI"        — Primary U-Boot + boot_kernel script
mtd6:  64KB  NOR   "WINGCFG2"       — WiNG config
mtd7:  512KB NOR   "FS"             — JFFS2 filesystem
mtd8:  ~15MB NOR   "PriImg"         — Primary kernel (FIT, d0 0d fe ed)
mtd9:  ~15MB NOR   "SecImg"         — Secondary kernel (FIT)
mtd10: 64KB  NOR   "CFG2"           — U-Boot env block 2
mtd11: ~500MB NAND "nand_flash"     — UBIFS (mounted at /flash)
```

**OpenWrt DTS partition table** (from `qcom-ipq4029-ws-ap3915i.dts`):
```
mtd0: "CFG1"      @ 0x0e0000  (64KB)   read-only
mtd1: "BootBAK"   @ 0x0f0000  (448KB)  read-only
mtd2: "WINGCFG1"  @ 0x160000  (64KB)   read-only
mtd3: "ART"       @ 0x170000  (64KB)   read-only
mtd4: "BootPRI"   @ 0x180000  (448KB)  read-only
mtd5: "WINGCFG2"  @ 0x1f0000  (64KB)   read-only
mtd6: "FS"        @ 0x200000  (512KB)  read-only
mtd7: "firmware"  @ 0x280000  (30,080KB)  writable
mtd8: "CFG2"      @ 0x1fe0000 (64KB)   read-only
```

**CRITICAL**: Stock mtd1 (CFG1) and OpenWrt mtd0 (CFG1) are the SAME physical block at 0xe0000.
Evidence: On Unit 1, writes to stock mtd1 persisted when read from OpenWrt mtd0 after boot.

**IMPLICATION**: The DTS marks ALL config partitions as `read-only`. Writing to CFG1/CFG2 from
OpenWrt initramfs requires bypassing the read-only flag. kmod-mtd-rw is NOT available in
OpenWrt 24.10.2 (it was in 23.05.x but not rebuilt for kernel 6.6).

**RESOLUTION**: Write ALL config block changes from STOCK FIRMWARE, where the partitions are
writable. Design the plan so no initramfs MTD writes are needed.

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

### Fallback Syntax Analysis
```
The U-Boot uses hush shell (confirmed: boot_kernel script uses if/then/else/fi syntax).
Hush shell supports || operator, but the SAFER fallback is semicolon:

  bootcmd=run boot_openwrt; run boot_net

Why semicolon is safer:
  - If bootm succeeds → kernel boots, never returns → run boot_net never executes
  - If sf read fails → bootm not reached, returns → run boot_net executes
  - If bootm fails → returns → run boot_net executes
  - Does NOT depend on || operator support
  - Functionally identical to || for this use case
```

### rdwr_boot_cfg Status
```
Binary exists: /usr/sbin/rdwr_boot_cfg (4824 bytes)
read_all: returned empty (needs investigation)
read_var: NOT YET TESTED
write_var: NOT YET TESTED

WARNING: rdwr_boot_cfg write_var writes BOTH config blocks atomically.
This is a risk — see "One-Block-At-A-Time" strategy below.
```

### Firmware Verification
```
AP3915i initramfs: 75e105a3b4f9a8c6f8e5c7ff9bd2ee6607e6fe5da144bba8bfe7f1d0f21296d3
AP3915i sysupgrade: 38ca385660e46aa084017b80e620ab07fb30716a07bcaab8f3d5435bc88bf848

AP391x initramfs:  5e19c02b7c466ced36d0a5e3c66b6c0491f3befa9fd4410bacfd84ce01807eb5
AP391x sysupgrade:  67807ce9abf23d102251260096d39898f88d57f13f82d1549b28c59fbdb8a98b

⚠️ AP391x images are adjacent in the download directory and have similar sizes.
The AP391x uses a SPLIT firmware layout (two ~15MB slots, IMAGE_SIZE := 15040k).
The AP3915i uses a MERGED layout (one ~30MB slot, IMAGE_SIZE := 30080k).
Using the wrong image will cause sysupgrade to fail or write incorrectly.
ABORT if filename contains "ws-ap391x" instead of "ws-ap3915i".
```

---

## Proposed Flash Plan (v2 — Revised)

### Key Design Principles (from external review)

1. **No initramfs MTD writes** — All config block changes from stock firmware
2. **One block at a time** — Write CFG1 only, leave CFG2 as fallback
3. **Semicolon fallback** — `run boot_openwrt; run boot_net` (not `||`)
4. **Set boot_openwrt FIRST** — Before changing bootcmd
5. **Name-based MTD lookup** — Use `/proc/mtd` by name, not index
6. **Pre-staged tooling** — Verify all tools exist before danger zone
7. **IP discovery** — Don't assume OpenWrt comes up at 192.168.1.X
8. **/proc/mtd gate** — Verify partition layout from initramfs before sysupgrade

### Topology (REQUIRED — through switch)
```
[Mac 192.168.1.X] ---en5--- [OpenWrt Zyxel GS1900-8HP 192.168.1.2]
                                    |
                                    | lan5 (PoE to AP)
                                    |
                               [AP3915i 192.168.1.X]
```

All 8 switch ports on bridge VLAN1 — no filtering, all traffic visible on Mac's en5.

**IMPORTANT**: The AP must be connected through the switch, NOT direct to Mac. The AP's stock firmware requires DHCP to bring up SSH. The switch's dnsmasq DHCP server provides the lease (192.168.1.X). Direct-connect via PoE injector does NOT work — the AP ignores DHCP offers from both Python DHCP servers and macOS bootpd, falls back to auto-IP 192.168.1.20, but never starts SSH. Factory reset does not help — the AP still needs DHCP.

**Model JSON updated for this topology**:
- `stock_default_ip`: 192.168.1.X (AP's DHCP-assigned IP from switch)
- `openwrt_client_ip`: 192.168.1.X (Mac's en5 IP — TFTP server)
- `openwrt_ip`: 192.168.1.1 (OpenWrt initramfs default IP after TFTP boot)

**Before starting**: Run `sudo arp -d -a` to clear stale ARP entries.

### Phase 0: Verify rdwr_boot_cfg (CRITICAL — must do first)
```bash
ssh admin@192.168.1.X
rdwr_boot_cfg read_var bootcmd        # Does this work?
rdwr_boot_cfg read_var boot_net       # Can we read individual vars?
rdwr_boot_cfg read_var boot_flash     # Verify stock values
rdwr_boot_cfg read_all                 # Try again — maybe needs different invocation

# Also verify flashcp is available:
which flashcp
flashcp --help 2>&1 | head -3
```

**Decision tree**:
- If `read_var` works → Use `rdwr_boot_cfg write_var` for all changes
- If `read_var` fails → Use `flashcp` for raw MTD write (proven on Unit 1)
- If both fail → **STOP**. Cannot safely modify boot path.

### Phase 1: Save Current Config (read-only, zero risk)
```bash
# Raw-dump BOTH config blocks AND critical partitions
dd if=/dev/mtd1 of=/tmp/cfg1_backup.bin     # CFG1 (U-Boot env 1)
dd if=/dev/mtd10 of=/tmp/cfg2_backup.bin    # CFG2 (U-Boot env 2)
dd if=/dev/mtd5 of=/tmp/bootpri_backup.bin  # BootPRI (boot scripts)
dd if=/dev/mtd4 of=/tmp/art_backup.bin      # ART (IRREPLACEABLE calibration)
dd if=/dev/mtd3 of=/tmp/wingcfg1_backup.bin # WINGCFG1
dd if=/dev/mtd6 of=/tmp/wingcfg2_backup.bin # WINGCFG2

# Record /proc/mtd for reference
cat /proc/mtd > /tmp/proc_mtd.txt

# Pull to Mac via SCP
mkdir -p data/extreme-ap3915i/unit2-stock-backups/
scp admin@192.168.1.X:/tmp/*_backup.bin data/extreme-ap3915i/unit2-stock-backups/
scp admin@192.168.1.X:/tmp/proc_mtd.txt data/extreme-ap3915i/unit2-stock-backups/
```

### Phase 2: Stabilize (safe — doesn't change boot path)
```bash
cset sshtimeout 0 && capply && csave       # Prevent SSH timeout reboots

# Verify: keep a stopwatch. The stock shell may still auto-reboot after ~5 minutes
# without a controller. Work quickly through subsequent phases.

# If rdwr_boot_cfg works:
rdwr_boot_cfg write_var WATCHDOG_COUNT=0   # Disable watchdog count
rdwr_boot_cfg write_var WATCHDOG_LIMIT=0   # Disable watchdog limit
rdwr_boot_cfg read_var WATCHDOG_COUNT      # Verify
rdwr_boot_cfg read_var WATCHDOG_LIMIT      # Verify
```

### Phase 3: Set Final bootcmd (from stock firmware — BEFORE TFTP boot)

**This is the key insight from v2**: Set the FINAL bootcmd from stock firmware,
not from initramfs. The bootcmd tries flash first, falls back to TFTP. Before
sysupgrade, flash has no firmware, so it falls through to TFTP. After sysupgrade,
flash has firmware and boots successfully. No initramfs MTD writes needed.

```bash
# Step 3a: Set boot_openwrt variable FIRST (before changing bootcmd)
rdwr_boot_cfg write_var boot_openwrt="sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000"
rdwr_boot_cfg read_var boot_openwrt  # VERIFY: must show exact command above

# Step 3b: Set serverip for TFTP fallback
rdwr_boot_cfg write_var serverip=192.168.1.X
rdwr_boot_cfg read_var serverip  # VERIFY: must be 192.168.1.X

# Step 3c: Keep AP's IP address configured
rdwr_boot_cfg write_var ipaddr=192.168.1.X
rdwr_boot_cfg read_var ipaddr  # VERIFY

# Step 3d: NOW set bootcmd with flash-first + TFTP fallback
rdwr_boot_cfg write_var bootcmd="run boot_openwrt; run boot_net"
rdwr_boot_cfg read_var bootcmd  # VERIFY: must be "run boot_openwrt; run boot_net"
```

**⚠️ rdwr_boot_cfg writes BOTH blocks.** This is a risk. If bootcmd is wrong,
BOTH blocks are wrong. Mitigation:
- The semicolon fallback guarantees TFTP catch (no matter what's on flash)
- TFTP server must be running when AP reboots
- If TFTP also fails, U-Boot drops to console (needs serial — but so does any failure)

**Alternative (if flashcp is preferred for single-block write)**:
```bash
# Build config block with Python on Mac:
python3 -c "
import struct, zlib

# Read existing CFG1 to preserve all vars
with open('data/extreme-ap3915i/unit2-stock-backups/cfg1_backup.bin', 'rb') as f:
    block = bytearray(f.read())

# Parse existing vars (skip 4-byte CRC + 1-byte flag)
payload = block[5:]
vars = {}
pos = 0
while pos < len(payload):
    end = payload.index(0, pos) if 0 in payload[pos:] else len(payload)
    if end == pos:
        break
    kv = payload[pos:end].decode('ascii', errors='replace')
    if '=' in kv:
        k, v = kv.split('=', 1)
        vars[k] = v
    pos = end + 1

# Set new vars
vars['boot_openwrt'] = 'sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000'
vars['bootcmd'] = 'run boot_openwrt; run boot_net'
vars['serverip'] = '192.168.1.X'
vars['ipaddr'] = '192.168.1.X'
vars['WATCHDOG_COUNT'] = '0'
vars['WATCHDOG_LIMIT'] = '0'

# Rebuild payload
new_payload = b'\x00'.join(f'{k}={v}'.encode() for k, v in vars.items())
new_payload = new_payload.ljust(65531, b'\xff')

# Build block: [flag=0x01] + [payload]
data = b'\x01' + new_payload
crc = struct.pack('<I', zlib.crc32(data) & 0xFFFFFFFF)
block = crc + data

with open('/tmp/correct_cfg1.bin', 'wb') as f:
    f.write(block)
print(f'Wrote {len(block)} bytes, {len(vars)} vars')
"

# Upload and write to CFG1 ONLY (leave CFG2 untouched)
scp /tmp/correct_cfg1.bin admin@192.168.1.X:/tmp/correct_cfg1.bin
ssh admin@192.168.1.X "flashcp /tmp/correct_cfg1.bin /dev/mtd1"

# VERIFY: read back and compare
ssh admin@192.168.1.X "dd if=/dev/mtd1 bs=65536 count=1 | md5sum"
md5sum /tmp/correct_cfg1.bin
# Hashes MUST match. If not, DO NOT REBOOT.
```

### Phase 4: TFTP Boot Initramfs
```bash
# Terminal 1: tcpdump on Mac (capture all traffic)
sudo tcpdump -i en5 -w /tmp/ap3915i-unit2-flash.pcap host 192.168.1.X or port 69

# Terminal 2: TFTP server on Mac
# Create symlink: vmlinux.gz.uImage.3912 → initramfs image
cd data/extreme-ap3915i/
ln -sf openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-initramfs-uImage.itb \
      vmlinux.gz.uImage.3912
cd /Users/macbook/src/conwrt
sudo python3 scripts/tftp-server.py data/extreme-ap3915i/ 192.168.1.X

# Terminal 3: Reboot AP
ssh admin@192.168.1.X "reboot"
# Watch tcpdump for:
#   1. ARP requests from AP (192.168.1.X looking for 192.168.1.X)
#   2. TFTP read request for vmlinux.gz.uImage.3912
#   3. TFTP data transfer (~10MB)
#   4. No further TFTP requests (means flash boot failed as expected, TFTP caught it)
```

### Phase 5: Connect to OpenWrt Initramfs

**⚠️ IP discovery**: OpenWrt initramfs may come up at 192.168.1.1 (DHCP server mode),
NOT 192.168.1.X. U-Boot `ipaddr` is a bootloader address; the initramfs kernel
uses its own network config. Watch tcpdump/ARP to find the actual IP.

```bash
# Watch for ARP/DHCP from initramfs:
sudo tcpdump -i en5 -n arp or port 67 or port 68

# Try common addresses:
ssh root@192.168.1.1      # OpenWrt default
ssh root@192.168.1.X    # U-Boot ipaddr
ssh root@192.168.1.X    # unlikely but check

# Once connected, VERIFY:
uname -a                  # Should show OpenWrt kernel
cat /proc/mtd             # MUST match DTS partition layout

# /proc/mtd GATE (abort if wrong):
# Expected: CFG1, BootBAK, WINGCFG1, ART, BootPRI, WINGCFG2, FS, firmware, CFG2
# firmware size must be ~30,080KB (0x1d60000) — NOT ~15,000KB
# If firmware is ~15,000KB → WRONG IMAGE (AP391x), ABORT

# NAND VERIFICATION (sanity check):
# Unit 2 has 512MB NAND, but OpenWrt DTS disables the NAND controller.
# /proc/mtd should list ONLY SPI-NOR partitions (mtd0-mtd8, 9 total).
# If NAND partitions appear → DTS mismatch, investigate before proceeding.
dmesg | grep -i nand      # Should show nothing or 'disabled'
cat /proc/mtd | wc -l     # Should be ~9 lines (header + 9 partitions)

cat /etc/board.json       # Confirm device identification
```

### Phase 6: Backup MTD Partitions
```bash
# On AP:
mkdir -p /tmp/backup
# Use name-based lookup, not index
for name in CFG1 BootBAK WINGCFG1 ART BootPRI WINGCFG2 FS firmware CFG2; do
  dev=$(cat /proc/mtd | grep "\"$name\"" | awk -F: '{print "/dev/"$1}')
  if [ -n "$dev" ]; then
    dd if=$dev of=/tmp/backup/${name}.bin 2>/dev/null
    echo "Backed up $name from $dev"
  fi
done

# Verify ART backup (irreplaceable):
ls -la /tmp/backup/ART.bin  # Should be 65536 bytes

# Pull to Mac:
scp -r root@OPENWRT_IP:/tmp/backup/ data/extreme-ap3915i/unit2-initramfs-backups/
```

### Phase 7: Sysupgrade
```bash
# Upload firmware
scp data/extreme-ap3915i/openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-squashfs-sysupgrade.bin \
    root@OPENWRT_IP:/tmp/sysupgrade.bin

# Verify SHA256 on AP — MUST match pinned hash:
ssh root@OPENWRT_IP "sha256sum /tmp/sysupgrade.bin"
# Expected: 38ca385660e46aa084017b80e620ab07fb30716a07bcaab8f3d5435bc88bf848
# If different → ABORT, wrong image

# Flash
ssh root@OPENWRT_IP "sysupgrade -n /tmp/sysupgrade.bin"
# AP reboots.
# bootcmd is "run boot_openwrt; run boot_net"
# → boot_openwrt tries sf read from 0x280000 → NOW firmware exists → bootm succeeds
# → OpenWrt boots from flash!
# → run boot_net never executes (bootm doesn't return on success)
```

### Phase 8: Verify Flash Boot

**Keep TFTP server running during first flash boot** — if something is wrong with the
firmware partition, bootm will fail and the semicolon fallback catches it.

```bash
# Watch tcpdump for:
#   1. NO TFTP request (means boot_openwrt worked — firmware found and booted)
#   2. ARP from OpenWrt at some IP (likely 192.168.1.1)
#   3. SSH becomes available

ssh root@OPENWRT_IP
# Verify:
iw phy                     # WiFi radios present
ART_DEV=$(cat /proc/mtd | grep '"ART"' | awk -F: '{print "/dev/"$1}')
hexdump -C $ART_DEV | head  # ART partition integrity (name-based, avoids MTD index confusion)
cat /etc/board.json          # Correct device identification
cat /proc/mtd                # Partition layout matches DTS

# If boot_openwrt FAILED and TFTP caught it:
# - AP is back in initramfs
# - Problem is likely the firmware partition (sysupgrade didn't write correctly)
# - Can re-attempt sysupgrade from initramfs
# - bootcmd still has TFTP fallback, so always recoverable
```

### Phase 9: (Optional) Converge CFG2

After verified successful flash boot, optionally write CFG2 to match CFG1:
- Only do this AFTER confirming OpenWrt boots from flash reliably
- Use the same method as Phase 3 (rdwr_boot_cfg or flashcp)
- This is LOW PRIORITY — the device works fine with only CFG1 updated

---

## Safety Measures Summary

| Measure | Why | Phase |
|---------|-----|-------|
| `bootcmd` uses `;` not `\|\|` | Semicolon fallback doesn't depend on \|\| support in U-Boot | 3 |
| Keep TFTP server running during ALL reboots | Fallback actually works when needed | 4, 7, 8 |
| Write CFG1 only, leave CFG2 untouched | CFG2 has original bootcmd as fallback | 3 |
| Read-back verify after every config write | Catch write errors before reboot | 3 |
| Set `boot_openwrt` before `bootcmd` | Other vars in place before boot path changes | 3 |
| Initramfs MTD writes possible but risky | kmod-mtd-rw IS available in 24.10.2 (used successfully on Unit 2), but stock firmware writes preferred | 3 |
| Name-based `/proc/mtd` lookup | MTD indices differ between stock and OpenWrt kernels | 6 |
| Pin firmware SHA256 hashes | Prevent AP3915i vs AP391x confusion | 7 |
| Check `/proc/mtd` firmware size | AP3915i has ~30MB firmware; AP391x has ~15MB | 5 |
| Don't assume initramfs IP | Watch ARP; try 192.168.1.1 first | 5 |
| Backup ART before any writes | Radio calibration is irreplaceable | 1 |
| Work quickly after Phase 2 | Stock shell may auto-reboot ~5 min without controller | 2-3 |

---

## What Changed from v1 (External Review Feedback)

See Appendix A for the full external review. Key changes:

1. **Removed Phase 8 MTD writes from initramfs** — The DTS marks CFG partitions as
   read-only. Original assumption: kmod-mtd-rw was not rebuilt for kernel 6.6 and unavailable
   in 24.10.2, so the entire "write bootcmd from initramfs" approach was impossible.
   **UPDATE (2026-05-24)**: This assumption was wrong. kmod-mtd-rw is an out-of-tree kernel
   module in the `packages` feed (`kernel/mtd-rw/`), built by OpenWrt's build system for every
   target with MTD support (excluded only: x86, bcm27xx, octeontx). On ipq40xx with kernel
   6.6.93 it installs and loads fine: `opkg install kmod-mtd-rw && insmod mtd-rw i_want_a_brick=1`.
   The actual Unit 2 flash used this approach as a fallback when stock firmware's rdwr_boot_cfg
   was broken. Writing from stock firmware is still preferred (fewer failure modes) but the
   initramfs path is viable.

2. **Semicolon fallback instead of `||`** — While the hush shell likely supports `||`,
   the semicolon approach (`run boot_openwrt; run boot_net`) is functionally equivalent
   and doesn't depend on operator support.

3. **Set FINAL bootcmd from stock firmware** — Since boot_openwrt fails gracefully
   (returns error when no firmware at 0x280000), the semicolon falls through to TFTP.
   After sysupgrade, firmware exists and boot_openwrt succeeds. No second MTD write needed.

4. **One config block at a time** — rdwr_boot_cfg writes both blocks, which is risky.
   The flashcp alternative writes only CFG1, leaving CFG2 as known-good fallback.

5. **Pre-staged tool verification** — Verify flashcp/rdwr_boot_cfg before Phase 3.
   No assumption that opkg works from initramfs (it doesn't — no internet).

6. **IP discovery for initramfs** — OpenWrt initramfs likely comes up at 192.168.1.1,
   not 192.168.1.X. Added ARP watching and multi-IP probing.

7. **Pinned firmware hashes** — Explicit SHA256 for both AP3915i and AP391x images.
   Abort if hash doesn't match.

8. **/proc/mtd gate** — Verify from initramfs that firmware partition is ~30MB (AP3915i),
   not ~15MB (AP391x). Abort if wrong layout.

---

## Open Questions for Reviewer (updated)

1. ~~**Address conflict**: `sf read 0x88000000` vs `fdt_high`~~
   **RESOLVED**: This is David Bauer's proven command from commit e16a0e7. `bootm`
   extracts the FDT from the FIT blob and places it below `fdt_high`. The FIT blob
   at 0x88000000 stays intact. Note: `fdt_high=0x80100000` in the config block (verified
   from Unit 1 backup). The BootPRI's boot_kernel script overrides this to `0x87000000`,
   but our `boot_openwrt` doesn't run boot_kernel so the config block value applies.
   Either value is safe — FDT at 0x80100000 is well below FIT at 0x88000000.

2. ~~**NAND interference**~~
   **RESOLVED**: OpenWrt DTS for AP3915i defines only SPI-NOR partitions. NAND is
   not exposed. Low risk. Should still check `dmesg | grep -i nand` from initramfs.

3. ~~**IPQ4019 vs IPQ4029**~~
   **RESOLVED**: Same silicon, different feature enables. DTS uses `qcom,ipq4029` for
   both variants. OpenWrt image profile is `extreme-networks_ws-ap3915i` with
   `SOC := qcom-ipq4029`. Compatible.

4. ~~**rdwr_boot_cfg writes both blocks**~~
   **RESOLVED v2**: If using flashcp, write CFG1 only. If using rdwr_boot_cfg,
   accept the risk because the semicolon fallback guarantees TFTP catch regardless
   of what's in the blocks.

5. ~~**Config block format**~~
   **RESOLVED**: CRC covers bytes [5:], flag 0x01=active, 0x00=backup.
   Algorithm: `struct.pack('<I', zlib.crc32(data[5:])) + flag_byte + kv_payload.ljust(65531, b'\xff')`

6. ~~**Firmware partition size**~~
   **RESOLVED**: OpenWrt DTS defines single `firmware` partition at 0x280000, size 0x1d60000
   (30,080KB). sysupgrade writes to this partition. The AP391x has a DIFFERENT DTS with
   split firmware/firmware2 layout (~15MB each). Using the wrong image would be caught by
   the `/proc/mtd` gate.

7. **Remaining risk: U-Boot env semantics**
   The DTS uses `u-boot,env-redundant-bool` compatible. The exact redundant env selection
   algorithm (which block U-Boot tries first, how it handles flag bytes) is not fully
   documented for this specific U-Boot build. Our assumption: U-Boot tries block with
   valid CRC + flag=0x01 first, falls back to the other block if CRC fails. This should
   be tested in Phase 0 by reading both blocks and comparing their flag bytes.

8. **Remaining risk: cset sshtimeout 0 effectiveness**
   The upstream install notes warn about automatic reboot after ~5 minutes without a
   controller. `cset sshtimeout 0` may only affect SSH session timeout, not the watchdog.
   Plan should assume ~5 minute window for Phases 2-3. Keep operations short and verifiable.

---

## Appendix A: External LLM Review Feedback (verbatim summary)

**Source**: External LLM review of v1 plan
**Key issues identified**:

1. **MTD numbering wrong**: Plan's Phase 8 wrote to `/dev/mtd1` and `/dev/mtd10` from
   initramfs using stock firmware MTD numbers. OpenWrt has different numbering.
   **Fix**: No initramfs MTD writes needed with v2 approach.

2. **`||` syntax unverified**: U-Boot might not support `||` in bootcmd.
   **Fix**: Changed to semicolon fallback.

3. **Fallback logic incomplete**: "If rdwr_boot_cfg fails, fall back to kmod-mtd-rw from
   initramfs" is circular — can't reach initramfs without bootcmd change.
   **Fix**: Both rdwr_boot_cfg and flashcp work from stock firmware. No circular dependency.

4. **Don't write both config blocks**: Repeats Unit 1 failure mode.
   **Fix**: flashcp writes CFG1 only. rdwr_boot_cfg risk accepted with fallback safety net.

5. **Pre-stage kmod-mtd-rw and flashcp**: opkg won't work in initramfs (no internet).
   **Fix**: v2 doesn't need any initramfs package installs.

6. **Pin firmware hashes**: Explicit abort if wrong image.
   **Fix**: Added pinned SHA256 hashes and abort conditions.

7. **Don't assume initramfs IP**: OpenWrt likely comes up at 192.168.1.1.
   **Fix**: Added IP discovery via ARP watching.

8. **Add /proc/mtd gate**: Verify layout before sysupgrade.
   **Fix**: Added partition name and firmware size verification.

9. **Back up more before changing boot path**: At minimum, dump ART, BootPRI, CFG1, CFG2.
   **Fix**: Phase 1 now dumps 6 partitions plus /proc/mtd.

10. **cset sshtimeout 0 unproven**: May not disable the controller-less reboot watchdog.
    **Fix**: Added warning about ~5 min window.

---

## Source References

| Source | URL | What it confirms |
|--------|-----|-------------------|
| David Bauer commit e16a0e7 | https://github.com/openwrt/openwrt/commit/e16a0e7e8876df0a92ec4779fe766de1a943307a | Correct boot_openwrt command, firmware offset 0x280000, load address 0x88000000 |
| PR #13370 | https://github.com/openwrt/openwrt/pull/13370 | rdwr_boot_cfg usage, credentials admin/new2day, bootcmd="run boot_flash" (WRONG for our use case) |
| OpenWrt wiki | https://openwrt.org/toh/extreme_networks_ws_ap391x | Device support page |
| OpenWrt DTS | `target/linux/ipq40xx/files-6.6/arch/arm/boot/dts/qcom/qcom-ipq4029-ws-ap3915i.dts` | Partition layout, read-only flags, firmware at 0x280000 |
| OpenWrt generic.mk | `target/linux/ipq40xx/image/generic.mk` | Device/FitImage, IMAGE_SIZE := 30080k |
| PR #17305 | https://github.com/openwrt/openwrt/pull/17305 | BLOCKSIZE fix (merged in 24.10.2) |
| OpenWrt ipq40xx Makefile | `target/linux/ipq40xx/Makefile` | `uboot-envtools` is a default package |

---

## Files for Reference

- `recipes/extreme-networks/ws-ap3915i/SESSION-WRITEUP.md` — Full Unit 1 session notes with mistakes analysis
- `recipes/extreme-networks/ws-ap3915i/UNIT2-AP3915i-ROW.md` — Unit 2 hardware details
- `recipes/extreme-networks/ws-ap3915i/no-serial-openwrt.md` — Technical documentation
- `recipes/extreme-networks/ws-ap3915i/SEMI-AUTO-FLASH.md` — Semi-auto flash procedure
- `models/extreme-networks-ws-ap3915i.json` — Device model definition
- `data/extreme-ap3915i/openwrt-backups/` — Unit 1 MTD backups (mtd0_CFG1.bin etc.)
