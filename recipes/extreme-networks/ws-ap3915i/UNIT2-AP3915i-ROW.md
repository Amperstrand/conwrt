# AP3915i-ROW — Second Unit Hardware Notes

Device: WS-AP3915i-ROW (Rest of World variant)
Serial: 1918Y-1083600000
MAC: DC:B8:08:XX:XX:XX
IP: 192.168.1.1 (OpenWrt, DHCP disabled via overlay)
Date: 2026-05-22
Status: **OpenWrt 24.10.2 running from SPI-NOR flash** (flashed 2026-05-22, DHCP disabled 2026-05-23)

## Hardware Identity

```
MODEL=AP3915i-ROW
SERIAL#=1918Y-1083600000
DTS compatible: qcom,ipq40xx-apdk04.1, qcom,ipq40xx
SoC: Qualcomm IPQ4019 (4x Cortex-A7 rev 5)
RAM: 495800 kB (~512MB DDR3)
Ethernet: 1x GbE (eth0, DC:B8:08:XX:XX:XX, PoE+ data)
WiFi: ath10/ath12/ath13/ath15/ath18 (multiple VAPs configured)
Kernel: 3.14.43--10.51.24.0003 (stock Extreme WiNG firmware)
U-Boot: 2012.07.19-r00020.1 (Jul 17 2017) — OLDER than unit 1 (2012.07.22)
```

## Flash Layout (from /proc/cmdline)

```
mtdparts=nand2:64k@896k(CFG1),448k(BootBAK)ro,64k(WINGCFG1),64k(ART),448k(BootPRI),64k(WINGCFG2),512k(FS),15040k(PriImg),15040k(SecImg),64k(CFG2)
```

### MTD Partitions

```
mtd0:  20000000 (512MB) NAND    "nand_flash"    — UBIFS rootfs/config
mtd1:  00010000 (64KB)  NOR     "CFG1"          — U-Boot env block 1
mtd2:  00070000 (448KB) NOR     "BootBAK"       — Backup U-Boot (read-only)
mtd3:  00010000 (64KB)  NOR     "WINGCFG1"      — WiNG config 1
mtd4:  00010000 (64KB)  NOR     "ART"           — Atheros radio calibration
mtd5:  00070000 (448KB) NOR     "BootPRI"       — Primary U-Boot + boot_kernel script
mtd6:  00010000 (64KB)  NOR     "WINGCFG2"      — WiNG config 2
mtd7:  00080000 (512KB) NOR     "FS"            — JFFS2 filesystem (/flashBAK)
mtd8:  00eb0000 (~15MB) NOR     "PriImg"        — Primary kernel image (FIT, d0 0d fe ed)
mtd9:  00eb0000 (~15MB) NOR     "SecImg"        — Secondary kernel image (FIT, d0 0d fe ed)
mtd10: 00010000 (64KB)  NOR     "CFG2"          — U-Boot env block 2
mtd11: 1e5d4000 (~500MB) NAND   "nand_flash"    — UBIFS (mounted at /flash)
```

### Key Difference from Unit 1

Unit 1 had **SPI-NOR only** (32MB Macronix MX25L25635E). This unit (Unit 2) has
**both SPI-NOR and NAND** (512MB). However:

- The **SPI-NOR partition layout is IDENTICAL** (same offsets, same names)
- PriImg=0x280000, SecImg=0x1130000 (same as Unit 1)
- The NAND is used for UBIFS rootfs and WiNG application data
- OpenWrt writes to SPI-NOR only (squashfs on NOR) — NAND is irrelevant for OpenWrt
- Both PriImg and SecImg contain FIT images (d0 0d fe ed header)

## Config Block Contents (raw dump from /dev/mtd1)

```
CRC: 24 bd 7c 4c (LE) Flag: 0x01 (active)
```

Key variables extracted from CFG1:

| Variable | Value | Notes |
|----------|-------|-------|
| MODEL | AP3915i-ROW | Confirms model |
| SERIAL# | 1918Y-1083600000 | |
| AP_MODE | 0 | Normal mode |
| AP_PERSONALITY | identifi | Controller-managed |
| BOOT_BOOTROM | "U-Boot 2012.07.19-r00020.1 (Jul 17 2017)" | |
| BOOT_KERNEL | primary | |
| MOSTRECENTKERNEL | 0 | PriImg first |
| WATCHDOG_COUNT | (not set in visible dump) | |
| WATCHDOG_LIMIT | 3 | **NOT zero — watchdog active** |
| NUM_ANTENNAS | 4 | |
| PriImg | 0x280000 | Same as Unit 1 |
| SecImg | 0x1130000 | Same as Unit 1 |
| RADIOADDR0 | DC:B8:08:XX:XX:XX | 2.4GHz radio MAC |
| RADIOADDR1 | DC:B8:08:XX:XX:XX | 5GHz radio MAC |
| baudrate | 115200 | Serial console speed |
| bootcmd | bootx | **NOT run boot_flash** |
| boot_flash | source boot_kernel | Stock boot script |
| boot_net | tftpboot 0x83600000 vmlinux.gz.uImage.3912; bootm 0x83600000 | TFTP boot |
| bootargs | console=ttyMSM0,115200n81 ubi.mtd=0 panic=30 nohlt ro BOOT_KERNEL=primary ... | |
| REGION | NA | North America |
| HW_RELEASE | AM | Hardware revision |
| SERVICEATTRS | ac_manager,ru_manager | |
| SERVICETYPE | siemens | Was managed by Siemens/Extreme controller |

## bootx — The Critical Discovery

From BootPRI partition (U-Boot binary strings at offset ~0x49f50):

```
bootx - equivalent to the command: run boot_flash
```

**`bootx` IS `run boot_flash`**. It's a Qualcomm/QCA custom U-Boot command (from
`cmd_bootqca.c`) that runs the stock boot_kernel script. This is the EXACT same
mechanism that bricked Unit 1 when we set `bootcmd=run boot_flash`.

The BootPRI also contains:
- `bootipq` — another custom command, "boot from flash device"
- `set fdt_high 0x87000000` — boot_kernel overrides config block value (0x80100000) to 0x87000000
- The full boot_kernel script with watchdog, dual-image failover, nboot logic

## boot_kernel Script (extracted from BootPRI)

The script implements:
1. If AP_MODE=3 or 4: load from NAND (UBIFS recovery mode)
2. MOSTRECENTKERNEL selects which image (PriImg vs SecImg) to try first
3. WATCHDOG_LIMIT/WATCHDOG_COUNT: if watchdog reset detected, swap boot order
4. nboot loads from SPI-NOR at PriImg (0x280000) or SecImg (0x1130000) offset
5. Kernel authentication check (fails for OpenWrt FIT — but continues anyway)
6. Hardware watchdog setup

## Address Map

| Purpose | Address | Notes |
|---------|---------|-------|
| TFTP load (boot_net) | 0x83600000 | Same as Unit 1 |
| SPI-NOR read (boot_openwrt) | 0x88000000 | From David Bauer commit e16a0e7 |
| FDT high limit | 0x80100000 (config block) / 0x87000000 (boot_kernel override) | FDT placed below this; safe at either value |
| PriImg flash offset | 0x280000 | Same as Unit 1 |
| SecImg flash offset | 0x1130000 | Same as Unit 1 |
| Firmware size | 0xc00000 (12MB) | From David Bauer commit |
| SPI-NOR total | ~32MB | 0xE0000 offset + all partitions |

## rdwr_boot_cfg Behavior

```
# Exists at /usr/sbin/rdwr_boot_cfg (4824 bytes, Nov 16 2022)
# Usage:
#   rdwr_boot_cfg read_all         — read entire active block (returned empty!)
#   rdwr_boot_cfg read_var <var>   — read single variable
#   rdwr_boot_cfg write_var <var=val> — write to BOTH blocks (handles CRC)
#   rdwr_boot_cfg rm_var <var>     — delete from both blocks

# read_all returned empty — needs investigation (maybe different firmware version)
# read_var NOT YET TESTED
# write_var NOT YET TESTED
```

## Stock Firmware Quirks

- SSH requires legacy key types: `-o HostKeyAlgorithms='+ssh-rsa,ssh-dss' -o KexAlgorithms='+diffie-hellman-group1-sha1'`
- Device reboots periodically without controller (watchdog) — disable with `cset sshtimeout 0 && capply && csave`
- `cset`/`capply`/`csave` produce "Error in obtaining the tty" warnings — these are harmless
- Device was previously in production (REDACTED_SSID_1, REDACTED_SSID_2, REDACTED_SSID_4, REDACTED_SSID_3 VAPs configured)
- WEB GUI at http://192.168.1.X (not tested)

## DTS Partition Layout (from OpenWrt qcom-ipq4029-ws-ap3915i.dts)

The OpenWrt DTS defines a DIFFERENT partition table than the stock firmware. Key differences:

```
OpenWrt DTS (qcom-ipq4029-ws-ap3915i.dts):
  CFG1      @ 0x0e0000  (64KB)   read-only   — same physical block as stock mtd1
  BootBAK   @ 0x0f0000  (448KB)  read-only
  WINGCFG1  @ 0x160000  (64KB)   read-only
  ART       @ 0x170000  (64KB)   read-only
  BootPRI   @ 0x180000  (448KB)  read-only
  WINGCFG2  @ 0x1f0000  (64KB)   read-only
  FS        @ 0x200000  (512KB)  read-only
  firmware  @ 0x280000  (30,080KB)  writable  — merged PriImg + SecImg
  CFG2      @ 0x1fe0000 (64KB)   read-only   — same physical block as stock mtd10
```

**CRITICAL**: Stock mtd1 (CFG1) and OpenWrt mtd0 (CFG1) are the SAME physical block at
offset 0xe0000. Evidence: On Unit 1, writes to stock mtd1 persisted when read from OpenWrt
mtd0 after boot. The stock kernel's /proc/mtd does NOT list partitions in physical offset
order — NAND partitions (mtd0, mtd11) interleave with NOR partitions.

**IMPLICATION**: ALL partitions except `firmware` are marked `read-only` in the DTS.
Writing to CFG1/CFG2 from OpenWrt initramfs requires bypassing the read-only flag.
kmod-mtd-rw IS available in 24.10.2 (contrary to earlier notes): package
`kmod-mtd-rw_6.6.93.2021.02.28~e8776739-r1_arm_cortex-a7_neon-vfpv4.ipk` from the official
OpenWrt repo. Requires `insmod mtd-rw i_want_a_brick=1` to activate. This was used
successfully to write CFG1 on Unit 2.

**fw_setenv**: The AP3915i is NOT in the uboot-envtools board list
(`package/boot/uboot-envtools/files/ipq40xx`). fw_env.config is NOT auto-generated.
Even if manually configured, fw_setenv cannot write to read-only MTD partitions.

## Flash Strategy (v2 — revised after external review)

**Key insight**: Set the FINAL bootcmd from stock firmware (not initramfs).

```
bootcmd=run boot_openwrt; run boot_net
boot_openwrt=sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000
```

Before sysupgrade: boot_openwrt fails (no firmware at 0x280000) → falls through to boot_net → TFTP
After sysupgrade: boot_openwrt succeeds (firmware exists) → boots from flash → done

No initramfs MTD writes needed. The semicolon fallback is safer than `||` because:
- If bootm succeeds → kernel boots, never returns → boot_net never runs
- If bootm fails → returns → boot_net runs (TFTP catch)

**One block at a time**: Use flashcp (not rdwr_boot_cfg) to write CFG1 only.
Leave CFG2 untouched as known-good fallback.

---

## Flash Session Log (2026-05-22)

### What We Did

1. **Stock firmware TFTP boot setup**: Used `rdwr_boot_cfg write_var bootcmd=run boot_net`
   from stock firmware to set TFTP boot. Configured Mac as DHCP+TFTP server on en5 (USB ethernet).
   Watchdog reboot triggered TFTP boot of OpenWrt initramfs.

2. **Initramfs verification**: OpenWrt 24.10.2 initramfs booted at 192.168.1.1. Verified kernel,
   RAM, MTD layout, SSH. All 10 MTD partitions backed up to
   `data/extreme-ap3915i/unit2-stock-backups/`.

3. **Env write approach**: `fw_setenv` failed with "environment overflow" due to 0xFF padding
   in stock env (fw_setenv scans past env data into padding). Pivoted to raw binary env block
   built with Python: CRC32 + flag byte + env data + padding. Verified CRC matches U-Boot's
   algorithm exactly.

4. **kmod-mtd-rw installation**: Installed `kmod-mtd-rw` from official OpenWrt 24.10.2 repo
   (contrary to our earlier notes, it IS available). `insmod mtd-rw i_want_a_brick=1` sets
   MTD_WRITEABLE flag on all partitions. Verified CFG1 flags changed from 0x800 to 0xC00.

5. **Env write to CFG1**: Built env block with Python containing:
   - `boot_openwrt=sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000`
   - `bootcmd=run boot_openwrt; run boot_net` (flash first, TFTP fallback)
   - All 65 original env variables preserved unchanged
   - CRC32 calculated with `zlib.crc32()` (verified matching U-Boot)
   - 0xFF padding (matching stock format)
   - Flag=0x02 (higher than CFG2's 0x01, making CFG1 active)
   - Written via `mtd write /tmp/cfg1_new.bin CFG1`
   - **CFG2 left untouched** as safety net (bootcmd=run boot_net)

6. **Sysupgrade**: `sysupgrade -n /tmp/sysupgrade.bin` wrote 9.1 MB OpenWrt squashfs to
   firmware partition (mtd7). AP rebooted automatically.

7. **Verification**: OpenWrt 24.10.2 booted from SPI-NOR flash. Kernel 6.6.93, squashfs rootfs,
   jffs2 overlay on rootfs_data (mtd10). SSH working. Reboot test passed — permanent flash boot.

### What Worked

- **kmod-mtd-rw + mtd write**: The mechanism for writing env from initramfs. Flawless.
- **Raw Python env block builder**: CRC32 correct, flag semantics correct, all vars preserved.
- **David Bauer's boot_openwrt command**: `sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000`
  — worked perfectly on first try.
- **One-block strategy**: Only writing CFG1, leaving CFG2 as fallback. Didn't need the fallback
  but the safety net was critical for confidence.
- **Semicolon fallback**: `boot_openwrt; boot_net` — if flash boot fails, TFTP catches it.

### What Didn't Work

- **fw_setenv**: "environment overflow" on every attempt. Root cause: stock env uses 0xFF
  padding, fw_setenv scans past the env data into the padding and thinks the env is full.
  Raw binary write was the workaround.
- **rdwr_boot_cfg** (from stock firmware): `read_all` returned empty. Not reliable on this firmware.

### Lessons for Future Flashes

1. **kmod-mtd-rw IS available in OpenWrt 24.10.2** despite our earlier notes saying it wasn't.
   The package is in the official repo for kernel 6.6.93.
2. **fw_setenv is unreliable with stock env format** (0xFF padding). Always use raw binary
   env blocks for reliability.
3. **Build env blocks with Python**: `struct.pack('<I', zlib.crc32(env_data)) + flag_byte + env_data`
   — simple, verifiable, repeatable.
4. **Test `mtd write` with round-trip** before committing: dump partition, write same data back,
   verify hash matches.
5. **Keep TFTP server running** throughout the process as safety net.
6. **Never write both config blocks** — Unit 1 bricked because the same wrong value went to both.
7. **Do env write + sysupgrade in one SSH session** — if AP reboots with new bootcmd but old
   firmware, boot_openwrt succeeds with stock FIT → stock firmware → watchdog loop.
8. **The stock bootargs `ubi.mtd=0` causes kernel error on boot** — kernel tries to attach CFG1 as
   UBI, fails with `ubi0 error: failed to attach mtd0, error -22`. Functional but should be cleaned
   up by updating bootargs env variable (see todo below).

### Current State

```
Device: Extreme Networks WS-AP3915i (AP3915i-ROW)
Serial: 1918Y-1083600000
MAC: DC:B8:08:XX:XX:XX
IP: 192.168.1.1 (br-lan, static default)
SSH: root@192.168.1.1 (no password, key auth)
Firmware: OpenWrt 24.10.2 r28739-d9340319c6
Kernel: 6.6.93 armv7l (ipq40xx/generic)
Boot: SPI-NOR flash (boot_openwrt → sf read → bootm)
Rootfs: squashfs on mtd9 (read-only) + jffs2 overlay on mtd10 (read-write)
RAM: 506 MB
Storage: 4.3 MB squashfs + 20.8 MB overlay
WiFi: QCA4019 detected (phy0) — not yet configured
LEDs: green:system=ON (solid), green:wlan24/wlan5=phy0tpt/phy1tpt (blink on traffic)
```

### MTD Layout (OpenWrt view)

```
mtd0:  00010000 "CFG1"       — U-Boot env block 1 (flag=0x02, active, has boot_openwrt)
mtd1:  00070000 "BootBAK"    — Backup U-Boot (read-only)
mtd2:  00010000 "WINGCFG1"   — WiNG config 1 (read-only)
mtd3:  00010000 "ART"        — Atheros radio calibration (read-only)
mtd4:  00070000 "BootPRI"    — Primary U-Boot + boot_kernel script (read-only)
mtd5:  00010000 "WINGCFG2"   — WiNG config 2 (read-only)
mtd6:  00080000 "FS"         — JFFS2 filesystem (read-only)
mtd7:  01d60000 "firmware"   — OpenWrt squashfs-sysupgrade (writable)
mtd8:  00490000 "kernel"     — FIT kernel (auto-split from firmware)
mtd9:  018df440 "rootfs"     — squashfs rootfs (auto-split from firmware)
mtd10: 014d0000 "rootfs_data" — jffs2 overlay (auto-split, writable)
mtd11: 00010000 "CFG2"       — U-Boot env block 2 (flag=0x01, backup, bootcmd=run boot_net)
```

### Env Variables (Critical)

```
bootcmd=run boot_openwrt; run boot_net
boot_openwrt=sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000
boot_net=tftpboot 0x83600000 vmlinux.gz.uImage.3912; bootm 0x83600000
bootdelay=2
serverip=192.168.1.X
ipaddr=192.168.1.1
```

### Known Issues

- **Harmless dmesg error**: `ubi0 error: failed to attach mtd0, error -22` — caused by
  stock bootargs `ubi.mtd=0`. Kernel ignores unknown params. Can be fixed by updating
  bootargs env variable.
- **WiFi not configured**: OpenWrt default doesn't enable WiFi radios. Need `uci set wireless.radio0.disabled=0` etc.
- **No pcap monitoring during flash**: We did not capture the boot sequence with tcpdump.
  Would be valuable for documentation but the flash succeeded without it.

### Todo

- [ ] Enable and configure WiFi radios
- [ ] Clean up bootargs (remove `ubi.mtd=0` and stock params)
- [ ] Set root password for production use
- [ ] Configure firewall rules
- [ ] Re-enable Mac PF firewall properly
