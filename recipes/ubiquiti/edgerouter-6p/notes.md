# Ubiquiti EdgeRouter 6P (ER-e300) -- Notes

## Hardware
- SoC: Cavium Octeon III CN7130 @ 1 GHz (mips64)
- RAM: 1 GiB DDR3
- Flash: SPI NOR (boot0/boot1 2MB each + 64KB eeprom) + internal eMMC 4GB
- Ethernet: 5x GbE (eth0-eth4) + 1x SFP (eth5)
- USB: 1x USB 3.0 (front panel)
- Console: RJ45 front panel, 115200 8N1
- Reset: Recessed button on front panel

## eMMC Partition Layout (observed on EdgeOS v2.0.9-hotfix.7)
```
/dev/mmcblk0      ~3.8GB total
/dev/mmcblk0p1     145MB  VFAT (boot: vmlinux.64 + vmlinux.64.md5)
/dev/mmcblk0p2    ~3.5GB  ext3  (rootfs: EdgeOS squashfs+overlay)
/dev/mmcblk0boot0  2MB    eMMC boot partition 0
/dev/mmcblk0boot1  2MB    eMMC boot partition 1
/dev/mmcblk0rpmb   512KB  RPMB
```

SPI NOR flash (separate from eMMC):
```
mtd0 (boot0)   2MB    U-Boot bootloader slot 0
mtd1 (boot1)   2MB    U-Boot bootloader slot 1
mtd2 (eeprom)  64KB   board EEPROM
```

## Boot Chain
```
SPI NOR (boot0/boot1) -> U-Boot
  -> mounts /dev/mmcblk0p1 (VFAT)
  -> reads vmlinux.64 + vmlinux.64.md5
  -> boots kernel from /dev/mmcblk0p1
  -> rootfs on /dev/mmcblk0p2
```

U-Boot bootargs (observed):
```
root=/dev/mmcblk0p2 rootdelay=10 rw rootsqimg=squashfs.img rootsqwdir=w
mtdparts=spi32766.0:2048k(boot0),2048k(boot1),64k(eeprom)
console=ttyS0,115200 rootwait rootflags=data=journal
```

Note: `rootsqimg` and `rootsqwdir` are EdgeOS-specific parameters that OpenWrt
ignores. OpenWrt squashfs kernel auto-detects the filesystem on mmcblk0p2.
`rootflags=data=journal` is an ext3 option that squashfs ignores.

## OpenWrt
- Target: `octeon/generic`
- Device: `ubnt,edgerouter-6p`
- Profile: `ubnt_edgerouter-6p`
- Board name: `ubnt,edgerouter-6p`
- Architecture: mips64 (Cavium Octeon III)
- Default IP: 192.168.1.1 (after flash)
- Tested version: 25.12.4

### OpenWrt Port Mapping
OpenWrt maps ER-6P ports differently from EdgeOS:
- Physical eth0 -> lan0 (WAN in default config)
- Physical eth1 -> lan1 (LAN)
- Physical eth2 -> lan2 (LAN)
- Physical eth3 -> lan3 (LAN)
- Physical eth4 -> lan4 (LAN)
- SFP (eth5)   -> lan5 (LAN)

**IMPORTANT**: After OpenWrt initramfs boots, you must connect to physical eth1-eth4 (LAN),
NOT physical eth0 (which is WAN). This is the #1 gotcha.

### Firmware Files (OpenWrt 25.12.4)
```
openwrt-25.12.4-octeon-generic-ubnt_edgerouter-6p-initramfs-kernel.bin   (28MB, RAM boot)
SHA256: e369ec1653197661c14fe0e1d1d35ed568cdb7f690b49a76bda0876dd57bf1ae

openwrt-25.12.4-octeon-generic-ubnt_edgerouter-6p-squashfs-sysupgrade.tar (16MB, permanent)
SHA256: c497bcf7bc1ad30e2e7bd6748767ed45ab8c27a1bf352089512af6c915084f2f
```

Sysupgrade tar contents:
```
sysupgrade-ubnt_edgerouter-6p/kernel   12,361,160 bytes (12MB, squashfs kernel)
sysupgrade-ubnt_edgerouter-6p/root      3,693,568 bytes (3.5MB, squashfs rootfs)
```

Download URL pattern:
```
https://downloads.openwrt.org/releases/{version}/targets/octeon/generic/openwrt-{version}-octeon-generic-ubnt_edgerouter-6p-{artifact}
```

## Flash Methods

### edgeos-kernel-swap + manual-dd (no serial cable required)

This is a two-stage process that exploits the fact that U-Boot boots whatever
is at `/dev/mmcblk0p1:/vmlinux.64`. By replacing the EdgeOS kernel with the
OpenWrt initramfs kernel, we can boot OpenWrt from RAM and then manually write
the squashfs kernel and rootfs to eMMC.

**IMPORTANT: Do NOT use `sysupgrade` from initramfs.** The sysupgrade command
requires ubus/procd orchestration that does not work properly in the initramfs
environment. See "Why sysupgrade fails from initramfs" below for details.

**Prerequisites:**
1. EdgeOS running and accessible via SSH (default: ubnt/ubnt at 192.168.1.1)
2. Bootloader version 003+ (has TFTP recovery support via reset button)
3. Two OpenWrt images: initramfs-kernel.bin + squashfs-sysupgrade.tar
4. Physical access to reset button (for recovery fallback)
5. Cable currently connected to physical eth0

**Stage 1: Kernel swap from EdgeOS**

```bash
# On the host machine (macOS/Linux):

# 1. Verify connectivity
ping -c 2 192.168.1.1

# 2. SCP the initramfs to EdgeOS /tmp
sshpass -p 'ubnt' scp -O \
  openwrt-*-initramfs-kernel.bin \
  ubnt@192.168.1.1:/tmp/openwrt-initramfs.bin

# 3. SSH into EdgeOS and perform the kernel swap
sshpass -p 'ubnt' ssh ubnt@192.168.1.1 bash -s <<'SWAP'
  set -x

  # Mount boot partition
  mkdir -p /tmp/boot
  mount -t vfat /dev/mmcblk0p1 /tmp/boot

  # Verify boot files exist
  test -f /tmp/boot/vmlinux.64 || { echo "ERROR: vmlinux.64 not found"; exit 1; }
  test -f /tmp/boot/vmlinux.64.md5 || { echo "ERROR: vmlinux.64.md5 not found"; exit 1; }

  # Backup original EdgeOS kernel
  cp -a /tmp/boot/vmlinux.64 /tmp/boot/vmlinux.64.edgeos.bak
  cp -a /tmp/boot/vmlinux.64.md5 /tmp/boot/vmlinux.64.md5.edgeos.bak

  # Write OpenWrt initramfs as new boot kernel
  cp /tmp/openwrt-initramfs.bin /tmp/boot/vmlinux.64

  # Generate correct MD5 sidecar (OpenWrt format: just hash + newline)
  md5sum /tmp/boot/vmlinux.64 | cut -d ' ' -f1 > /tmp/boot/vmlinux.64.md5

  # Verify
  echo "=== New boot files ==="
  ls -la /tmp/boot/vmlinux.64 /tmp/boot/vmlinux.64.md5
  echo "=== MD5 file content ==="
  cat /tmp/boot/vmlinux.64.md5
  echo "=== MD5 file size (expect ~33 bytes) ==="
  wc -c /tmp/boot/vmlinux.64.md5

  # Sync and unmount
  sync
  umount /tmp/boot
  echo "Kernel swap complete. Rebooting..."
  reboot
SWAP
```

**After reboot, the device will boot OpenWrt initramfs from RAM.**

IMPORTANT: After reboot, move ethernet cable from physical eth0 to physical eth1.
OpenWrt maps eth0 as WAN, eth1-eth4 as LAN.

**Stage 2: Manual dd from initramfs (NOT sysupgrade)**

Wait 60-90 seconds for initramfs to boot, then:

```bash
# Reconfigure host IP for LAN side
# Try DHCP first, fall back to static
sudo ipconfig set en6 DHCP
sleep 5
# Or: sudo ifconfig en6 192.168.1.2 netmask 255.255.255.0

# SCP sysupgrade tar to initramfs (use -O for Dropbear compatibility)
scp -O -o StrictHostKeyChecking=no \
  openwrt-*-squashfs-sysupgrade.tar \
  root@192.168.1.1:/tmp/sysupgrade.tar

# SSH into initramfs and manually flash (same as OpenWrt's platform_do_flash)
ssh -o StrictHostKeyChecking=no root@192.168.1.1 bash -s <<'FLASH'
  set -ex

  # Verify the tar is valid
  tar tf /tmp/sysupgrade.tar | head -5

  # Mount boot partition
  mkdir -p /boot
  mount -t vfat /dev/mmcblk0p1 /boot

  # Backup current initramfs kernel
  [ -f /boot/vmlinux.64 ] && mv /boot/vmlinux.64 /boot/vmlinux.64.previous
  [ -f /boot/vmlinux.64.md5 ] && mv /boot/vmlinux.64.md5 /boot/vmlinux.64.md5.previous

  # Write squashfs kernel (NOT initramfs -- this is the permanent kernel)
  tar xf /tmp/sysupgrade.tar sysupgrade-ubnt_edgerouter-6p/kernel -O > /boot/vmlinux.64
  md5sum /boot/vmlinux.64 | cut -f1 -d " " > /boot/vmlinux.64.md5

  # Verify kernel write
  echo "=== Kernel written ==="
  ls -la /boot/vmlinux.64 /boot/vmlinux.64.md5
  echo "=== Kernel size (expect ~12MB) ==="
  du -h /boot/vmlinux.64
  echo "=== MD5 ==="
  cat /boot/vmlinux.64.md5

  # Write squashfs rootfs directly to mmcblk0p2
  echo "Flashing rootfs to /dev/mmcblk0p2..."
  tar xf /tmp/sysupgrade.tar sysupgrade-ubnt_edgerouter-6p/root -O | dd of=/dev/mmcblk0p2 bs=4096

  # Sync and unmount
  sync
  umount /boot

  echo "Flash complete. Rebooting into permanent OpenWrt..."
  reboot -f
FLASH
```

After reboot, device boots permanent OpenWrt from eMMC.
Reconnect cable to any LAN port (eth1-eth4). OpenWrt at 192.168.1.1, root, no password.

## Why sysupgrade fails from initramfs

**DO NOT use `sysupgrade` from initramfs on octeon. It will fail.**

Root cause analysis from source code:

1. `/sbin/sysupgrade` calls `ubus call system sysupgrade "$(json_dump)"` as its
   ONLY upgrade mechanism (no fallback path for ubus failure)
2. This ubus call tells procd to: pivot to ramdisk, run `/lib/upgrade/do_stage2`,
   which calls `platform_do_upgrade()` -> `platform_do_flash()`
3. In initramfs, ubus/procd infrastructure is not fully functional
4. The call fails with "Command failed: ubus call system sysupgrade ... (Connection failed)"
5. The sysupgrade script has no error handling for this case -- it just exits
6. If procd partially started the upgrade, the kernel may have been written to
   mmcblk0p1 but rootfs NOT written to mmcblk0p2 -> kernel panic

Evidence:
- OpenWrt issue #9492: ubusd non-functional in initramfs environments
- OpenWrt issue #14190: identical "Connection failed" on rockchip from initramfs
- sysupgrade source: package/base-files/files/sbin/sysupgrade (line 453)
- octeon platform: target/linux/octeon/base-files/lib/upgrade/platform.sh

The manual dd approach executes the exact same `platform_do_flash()` operations
(mount VFAT, write kernel, dd rootfs, sync, unmount) but without the ubus/procd
orchestration layer that fails in initramfs.

**Future upgrades (OpenWrt -> OpenWrt)**: sysupgrade WILL work because the device
is then running from squashfs (not initramfs) with full procd/ubus infrastructure.

## Recovery

### TFTP Recovery (button-based, no serial cable required)

The bootloader (v003+) has a built-in TFTP recovery mode. It ONLY accepts
cryptographically signed `.img.signed` files -- unsigned files (including raw
kernels and OpenWrt images) are rejected with "Firmware check failed".

**Recovery image download:**
```
https://dl.ubnt.com/firmwares/edgemax/v2.0.x/ER-e300.recovery.v2.0.6.5208554.190708.0611.16de5fdde.img.signed
Size: ~112MB (117,637,316 bytes)
Format: UBNT.EDGEOS signed binary (starts with "UBNT.EDGEOS" header)
Installs: EdgeOS v2.0.6 (does NOT change bootloader)
```

SHA256 of the upgrade tar for verification (not the recovery image):
```
ER-e300.v2.0.6.5208554.tar: 4231f221a2b5f22cf6b453e7a91c6e65564465f63971084f3a6aad4ffff36d82
```

**Procedure:**
1. Connect laptop to physical eth0
2. Set laptop IP: `sudo ifconfig en6 192.168.1.10 netmask 255.255.255.0`
3. Hold reset button, plug in power, continue holding ~30 seconds until all LEDs light up
4. Release reset -- device enters TFTP recovery at 192.168.1.20
5. Verify: `ping -c 1 192.168.1.20`
6. Send signed recovery image:
   ```
   echo -e "binary\nput /path/to/ER-e300.recovery.v2.0.6.img.signed\nquit" | tftp 192.168.1.20
   ```
7. Wait ~2 minutes for flash + reboot
8. Device reboots into EdgeOS v2.0.6 at 192.168.1.1 (default: ubnt/ubnt)

**TFTP timeout:** The device stays in TFTP mode for a limited time. If it drops
out, redo the reset-button procedure. Transfer takes ~73 seconds for 112MB.

### Serial Console Recovery (manual TFTP with console cable)

If button-based TFTP doesn't work, you can use serial console for manual recovery.
This method uses `.vmlinux.64` files (NOT `.img.signed`):

```
Octeon ubnt_e300# setenv ipaddr 192.168.1.20
Octeon ubnt_e300# setenv serverip 192.168.1.10
Octeon ubnt_e300# setenv ethact octeth1        # octeth1 = eth0 on ER-6P
Octeon ubnt_e300# tftpboot 0 ER-e300.recovery.v2.0.6.5208554.190708.0611.16de5fdde.vmlinux.64
Octeon ubnt_e300# bootoctlinux 0
```

### Rollback (before reboot, from EdgeOS)
If you haven't rebooted yet and want to abort:
```bash
ssh ubnt@192.168.1.1
mount -t vfat /dev/mmcblk0p1 /tmp/boot
cp -a /tmp/boot/vmlinux.64.edgeos.bak /tmp/boot/vmlinux.64
cp -a /tmp/boot/vmlinux.64.md5.edgeos.bak /tmp/boot/vmlinux.64.md5
sync && umount /tmp/boot && reboot
```

## Bootloader

### Observed on this unit
- Bootloader version: e301_003_6be37
- TFTP recovery: YES (version 003+)
- EdgeOS version: v2.0.9-hotfix.7 (was v2.0.6 after recovery, then updated)

### Checking bootloader version
```bash
ssh ubnt@192.168.1.1 '/opt/vyatta/bin/vyatta-op-cmd-wrapper show system boot-image'
```

### Updating bootloader (if needed)
```bash
ssh ubnt@192.168.1.1
/opt/vyatta/bin/vyatta-op-cmd-wrapper add system boot-image
reboot
```

EdgeOS v2.0.4+ and v1.10.10+ include bootloader v003 with TFTP recovery for e300.

## Preflight Checklist

Before starting the kernel swap, verify ALL of these:

| Check | Command | Expected |
|-------|---------|----------|
| Hardware model | `show version` | "EdgeRouter 6P" |
| Bootloader version | `show system boot-image` | e301_003 or newer |
| Boot partition VFAT | `mount -t vfat /dev/mmcblk0p1 /tmp/boot && ls /tmp/boot` | vmlinux.64 + vmlinux.64.md5 |
| MD5 format | `wc -c /tmp/boot/vmlinux.64.md5` | ~33 bytes |
| Root partition | `cat /proc/cmdline` | root=/dev/mmcblk0p2 |
| OpenWrt images | `sha256sum openwrt-*` | Matches known hashes |
| SSH access | `sshpass -p ubnt ssh ubnt@192.168.1.1 echo ok` | "ok" |
| Recovery ready | Physical access to reset button + stock recovery image | Available |

## Gotchas

### sysupgrade does NOT work from initramfs
The sysupgrade command requires ubus/procd which is non-functional in initramfs.
Use manual dd instead (see Stage 2 above). This is a known OpenWrt limitation,
not a bug. Future upgrades (OpenWrt -> OpenWrt) will work with sysupgrade.

### Port mapping difference
OpenWrt maps physical eth0 as WAN (lan0). After initramfs boots, connect to
physical eth1-eth4 for LAN access. If the device appears "dead" after reboot,
try a different physical port before assuming brick.

### initramfs first boot access
OpenWrt initramfs may expose telnet, SSH, or only local console on first boot.
Be prepared for any of these. Default root access, no password.

### VFAT case sensitivity
The boot partition is VFAT. File names like vmlinux.64 are case-sensitive in
the U-Boot config but VFAT is case-insensitive. Use exact case matching.

### md5sum format
U-Boot reads vmlinux.64.md5 which should contain only the hex md5 hash followed
by a newline (~33 bytes total). This matches the format produced by:
`md5sum file | cut -d ' ' -f1 > file.md5`

### SCP requires -O flag
OpenWrt's Dropbear doesn't include sftp-server. Always use `scp -O` for file
transfers to OpenWrt targets.

### TFTP recovery requires signed images
The bootloader's button-based TFTP recovery ONLY accepts `.img.signed` files.
Unsigned kernels, OpenWrt images, and even genuine EdgeOS kernels are rejected
with "Firmware check failed". The signed recovery image is ~112MB and available
from dl.ubnt.com (no auth required).

### No WiFi
The ER-6P has no WiFi hardware. Do not attempt WiFi STA/AP configuration.

### eMMC, not NAND
The ER-6P uses eMMC for OS storage, not NAND flash. Flash methods that write
raw NAND images (like some other Ubiquiti devices) do not apply here.

### Squashfs vs initramfs kernel
The initramfs kernel (28MB) boots entirely from RAM. The squashfs kernel (12MB)
from the sysupgrade tar expects rootfs on mmcblk0p2. They are different files
for different purposes. Stage 1 uses initramfs; Stage 2 writes squashfs.

## Lessons Learned (2026-05-19 session)

### Mistake #1: Used sysupgrade from initramfs (bricked device)

**What happened:** Ran `sysupgrade -n /tmp/sysupgrade.tar` from the OpenWrt initramfs
environment. Got "Commencing upgrade. Closing all shell sessions." then ubus
"Command failed... (Connection failed)". Device became unresponsive on all ports.

**Root cause:** OpenWrt's `/sbin/sysupgrade` calls `ubus call system sysupgrade`
as its ONLY upgrade mechanism. In initramfs, the ubus/procd infrastructure is
non-functional. The script has no error handling or fallback path for this case.

**Worse:** sysupgrade likely wrote the kernel to mmcblk0p1 before the ubus call
failed, but never wrote rootfs to mmcblk0p2. Result: squashfs kernel with no
rootfs = kernel panic. Device had solid link lights but no boot loop.

**Recovery cost:** Full TFTP recovery required (30+ minutes of reset-button TFTP,
researching signed recovery image URLs, downloading 112MB image, re-doing Stage 1).

**What we should have done:** Researched the flash path BEFORE attempting it.
Reading `target/linux/octeon/base-files/lib/upgrade/platform.sh` and
`package/base-files/files/sbin/sysupgrade` would have revealed the ubus dependency
in 5 minutes. The manual dd approach does the exact same thing without ubus.

**Prevention for conwrt:** If the flash method involves initramfs, NEVER use
sysupgrade. Always extract and dd manually. Add a check: if `/proc/1/cmdline`
shows initramfs, refuse sysupgrade and use manual dd.

---

### Mistake #2: Didn't test recovery path before flashing

**What happened:** We had a backup of the EdgeOS kernel but NOT the signed
recovery image. When sysupgrade bricked the device, we had to scramble to find
the correct `.img.signed` file while the device sat unresponsive.

**What went wrong during recovery:**
1. Tried TFTP with OpenWrt initramfs (28MB) → rejected ("Firmware check failed")
2. Tried TFTP with backed-up EdgeOS kernel (6.7MB) → rejected (not signed)
3. Had to research the signed recovery image URL, download 112MB, then retry

**What we should have done:** Downloaded the signed recovery image AND verified
TFTP recovery works BEFORE starting any flash operation. Recovery is a path,
not a plan. If you haven't walked it, you don't have it.

**Prevention for conwrt:** Before any flash, verify the recovery path:
- Download the recovery image
- Confirm the image format is accepted (signed vs unsigned)
- Document the exact reset-button procedure with timing
- Know which physical port recovery uses

---

### Mistake #3: Port mapping surprise

**What happened:** After initramfs booted, the device appeared "dead" because
the cable was on physical eth0. OpenWrt maps physical eth0 as WAN (firewall
blocks all inbound). We spent time diagnosing before realizing the port mapping
difference.

**Root cause:** EdgeOS uses all ports equally by default. OpenWrt maps eth0 as
WAN with firewall filtering. This is documented in OpenWrt wiki but we didn't
check before flashing.

**What finally worked:** Moved cable from physical eth0 to physical eth1.
DHCP immediately assigned 192.168.1.X, SSH to 192.168.1.1 worked.

**Prevention for conwrt:** Document port mapping in model JSON before flashing.
If the model has `port_swap_required: true`, include explicit instructions to
move cable after initramfs boot.

---

### What finally worked: edgeos-kernel-swap + manual dd

**Stage 1 (kernel swap):** Worked perfectly on first attempt and second attempt.
Replace `/dev/mmcblk0p1:/vmlinux.64` with OpenWrt initramfs kernel, generate
correct MD5 sidecar, reboot. Simple, reliable, reversible (backup the original
kernel first).

**Stage 2 (manual dd):** After initramfs booted on LAN port:
1. SCP sysupgrade.tar to initramfs (use `scp -O` for Dropbear)
2. Mount mmcblk0p1, extract squashfs kernel to `/boot/vmlinux.64`
3. Generate MD5 sidecar
4. Extract squashfs rootfs and dd directly to `/dev/mmcblk0p2`
5. Sync, unmount, reboot

The rootfs is only 3.5MB — writes in <1 second, making interruption virtually
impossible. The kernel is 12MB — also fast. Total flash time: ~5 seconds of
actual I/O.

**Total time for successful flash: ~7 minutes**
(30s kernel swap + 75s reboot + 30s manual dd + 75s reboot)

**Key insight:** The manual dd approach executes the EXACT SAME operations as
OpenWrt's `platform_do_flash()`:
1. Mount VFAT boot partition
2. Write squashfs kernel to vmlinux.64
3. Write md5sum sidecar
4. dd rootfs to mmcblk0p2
5. Sync and unmount

The only difference is we skip the broken ubus/procd orchestration layer.

---

### Session timeline

| Step | Result | Time |
|------|--------|------|
| Preflight checks | ✅ All passed | 5 min |
| EdgeOS backup | ✅ squashfs.img + kernel + config | 5 min |
| Stage 1: Kernel swap (1st attempt) | ✅ Initramfs booted | 2 min |
| sysupgrade from initramfs | ❌ Bricked (ubus broken) | 1 min |
| Diagnosis + research | Found root cause | 15 min |
| TFTP recovery | ✅ EdgeOS v2.0.6 restored | 30 min |
| Research: manual dd approach | ✅ Found correct method | 20 min |
| Stage 1: Kernel swap (2nd attempt) | ✅ Initramfs booted | 2 min |
| Cable swap eth0 → eth1 | ✅ LAN access obtained | 1 min |
| Stage 2: Manual dd | ✅ Permanent OpenWrt | 1 min |
| **Total session** | **Success on 2nd attempt** | **~82 min** |

**Time lost to mistakes:** ~45 minutes (sysupgrade failure + TFTP recovery + research)
**Time for correct approach:** ~7 minutes (kernel swap + cable swap + manual dd)

---

### Reference: OpenWrt octeon sysupgrade source

The relevant source files (for conwrt automation):
- `target/linux/octeon/base-files/lib/upgrade/platform.sh` -- platform_do_flash()
- `package/base-files/files/sbin/sysupgrade` -- main sysupgrade script (ubus call at line 453)

## Timing (observed)

| Phase | Duration |
|-------|----------|
| EdgeOS boot after reset | ~60-90 seconds |
| Kernel swap (SCP + SSH) | ~30 seconds |
| Reboot to initramfs | ~60-90 seconds |
| Manual dd (SCP tar + flash) | ~30 seconds |
| Reboot to permanent OpenWrt | ~60-90 seconds |
| TFTP recovery (full restore) | ~3-4 minutes (73s transfer + 2min flash) |
| **Total end-to-end (kernel-swap + dd)** | **~5-7 minutes** |

## Serial Console (if available)

For debugging or manual U-Boot interaction:
- RJ45 front panel port (NOT an ethernet port)
- Settings: 115200 baud, 8N1, no flow control
- Use a USB-to-RJ45 console cable (Cisco-compatible pinout)
- U-Boot prompt: `Octeon ubnt_e300#`
- Interrupt autoboot by pressing any key during "Hit any key to stop autoboot"

## Final Result (2026-05-19)

**SUCCESS.** OpenWrt 25.12.4 permanently installed on EdgeRouter 6P.

- OpenWrt 25.12.4 r32933-4ccb782af7
- Kernel: Linux 6.12.87 mips64 (Cavium Octeon III)
- Board: ubnt,edgerouter-6p (Ubiquiti EdgeRouter 6P)
- MAC: 74:83:c2:XX:XX:XX (eth0/lan0)
- Rootfs: squashfs 3.5MB on /rom, overlay 3.4GB writable on /overlay
- RAM: 974MB total, ~37MB used
- Ports: eth0(WAN), eth1-eth4(LAN), eth5(SFP/LAN)
- Uptime: immediate after flash

**Method used:**
1. Stage 1: Kernel swap (EdgeOS -> initramfs via VFAT replacement)
2. Stage 2: Manual dd (squashfs kernel to mmcblk0p1, squashfs rootfs to mmcblk0p2)
3. Recovery: TFTP with signed .img.signed (needed after initial failed sysupgrade attempt)

**Total time for successful flash: ~7 minutes** (30s kernel swap + 75s reboot + 30s manual dd + 75s reboot)

## OpenWrt Default Packages (octeon target)
- dropbear (SSH)
- firewall4
- dnsmasq
- odhcpd-ipv6only
- netifd, ubus, uci
- NO LuCI by default
- NO WiFi packages (no WiFi hardware)

## Upstreaming Path: Getting ER-6P PoE into OpenWrt / Linux

Our PoE implementation is currently standalone: out-of-tree kernel module + userspace scripts. Here's the path to getting it into OpenWrt and potentially the Linux kernel.

### What We Have

| Component | Location | Status |
|-----------|----------|--------|
| `er6p-poe` kernel module | `recipes/.../er6p-poe/src/` | v0.5.0, tested on hardware |
| ISL28022 hwmon driver | Mainline Linux (`drivers/hwmon/isl28022.c`) | Already upstream, not enabled for octeon |
| `poe.init` procd init script | `recipes/.../userspace/poe.init` | Tested, module loading + ISL28022 registration |
| `poe-ubus` CLI | `recipes/.../userspace/poe-ubus` | Tested, ubus interface |
| `poe` CLI tool | `recipes/.../userspace/poe` | Tested |
| `er6p_poe.lua` Prometheus collector | `recipes/.../userspace/prometheus-collectors/` | Tested, follows official pattern |
| UCI config | `recipes/.../userspace/poe.config` | realtek-poe standard format |

### Step 1: Enable ISL28022 in OpenWrt Octeon Kernel Config

The ISL28022 driver is already in mainline Linux. OpenWrt's octeon target just doesn't enable it.

**Action**: Add `CONFIG_SENSORS_ISL28022=m` to `target/linux/octeon/config-*` in openwrt/openwrt.

Current octeon config already has the prerequisites:
- `CONFIG_I2C=y`, `CONFIG_I2C_OCTEON=y` (I2C bus driver)
- `CONFIG_REGMAP=y`, `CONFIG_REGMAP_I2C=y` (regmap framework)
- `CONFIG_HWMON` not explicitly set but likely available

**Blocker**: The ER-6P device tree has no ISL28022 node. Currently we register the device manually via `echo isl28022 0x40 > /sys/bus/i2c/devices/i2c-1/new_device`. A proper DT node would make this automatic.

### Step 2: Device Tree Patch for ER-6P

Add ISL28022 node to the ER-6P DTS in OpenWrt:

```dts
/* In twsi1 (I2C bus 1) node */
isl28022@40 {
    compatible = "renesas,isl28022";
    reg = <0x40>;
    shunt-resistor-micro-ohms = <10000>;  /* 10mΩ default, needs hardware verification */
};
```

**Location**: `target/linux/octeon/files/arch/mips/boot/dts/cavium-octeon/ubnt_edgerouter-6p.dts` (or wherever OpenWrt keeps the ER-6P DTS overlay).

### Step 3: Kernel Module — Three Options (Ascending Effort)

#### Option A: Target Patch (Easiest, OpenWrt-only)

Add `er6p-poe` as a patch/module to OpenWrt's octeon target:
- `target/linux/octeon/modules.mk` — add package definition
- `target/linux/patches-*/` or `target/linux/octeon/files/` — module source
- `target/linux/octeon/config-*` — enable `CONFIG_ER6P_POE=m`

**Pros**: Quick, no upstream kernel process needed. OpenWrt targets commonly have board-specific modules.
**Cons**: Only available for OpenWrt's octeon builds, not mainline Linux.

**Precedent**: Other OpenWrt targets ship board-specific GPIO/platform drivers (e.g., `target/linux/ath79/` has many board-specific hacks).

#### Option B: Extend gpio-octeon Driver (Medium)

The existing `gpio-octeon` driver (`drivers/gpio/gpio-octeon.c`) is already in mainline Linux and enabled in OpenWrt (`CONFIG_GPIO_OCTEON=y`). Our module does direct register writes to the same GPIO controller.

We could add a platform driver that:
1. Gets GPIO descriptors from DT (`gpios = <&gpio 4 0>, <&gpio 10 0>, <&gpio 16 0>`)
2. Exposes PoE control via regulator framework or sysfs
3. No more `ioremap` of raw GPIO registers — use the kernel GPIO API

**Pros**: Clean kernel API usage, DT-driven, no hardcoded register addresses.
**Cons**: Need to verify `gpio-octeon` supports all the BIT_CFG manipulation we need.

#### Option C: PSE Subsystem Integration (Hardest, Most Correct)

Linux has a PSE (Power Sourcing Equipment) subsystem at `drivers/net/pse-pd/`:
- Exposes PoE control via `ethtool` (`ethtool --show-pse eth1`)
- DT bindings at `Documentation/devicetree/bindings/net/pse-pd/`
- `pse_controller_ops` structure for driver callbacks

Write a `gpio-pse` driver that:
1. Takes GPIO descriptors from DT
2. Registers as a PSE controller
3. Maps each PSE port to a netdev (eth1, eth3, eth4)
4. Control via `ethtool --set-pse eth1 --pse 1`

**Concern**: The PSE subsystem is designed for 802.3af/at (active PoE with negotiation). Passive 24V GPIO toggle might not fit the abstraction well. No existing "gpio-pse" driver exists in mainline — we'd be defining a new pattern.

### Step 4: Userspace Package (OpenWrt packages feed)

Create an OpenWrt package for the ER-6P PoE userspace tools, following the realtek-poe pattern:

**Option A — Separate package** (`openwrt/packages` PR):
- `net/er6p-poe/Makefile` — package definition
- `net/er6p-poe/files/etc/init.d/poe` — init script
- `net/er6p-poe/files/etc/config/poe` — UCI config
- `net/er6p-poe/files/usr/sbin/poe-ubus` — ubus provider
- `net/er6p-poe/files/usr/sbin/poe` — CLI tool

**Option B — Target base-files** (simpler):
- Add scripts directly to `target/linux/octeon/base-files/` for ER-6P only
- Simpler but less discoverable

### Step 5: Prometheus Collector (openwrt/packages PR)

The easiest upstream contribution — one Lua file, follows an established pattern:
- PR to `openwrt/packages` adding `prometheus-node-exporter-lua-er6p-poe` sub-package
- Pattern: identical to existing `prometheus-node-exporter-lua-realtek-poe`
- Depends on `prometheus-node-exporter-lua` + `er6p-poe`
- No special Lua dependencies (uses `io.popen` not `nixio.fs`)

### Recommended Path (Phased)

1. **ISL28022 enablement** — one-line kernel config change + small DT patch. Low risk, high value.
2. **Prometheus collector PR** — easiest contribution, follows existing pattern exactly.
3. **Kernel module as target patch** (Option A) — gets PoE working for all OpenWrt octeon users.
4. **Userspace package** — once kernel module is in the target.
5. **PSE subsystem integration** (Option C) — long-term, only if we want mainline Linux acceptance.

### Blockers & Open Questions

- **Shunt resistor value**: Driver defaults to 10mΩ. Actual value unknown without board inspection or multimeter verification. DT property `shunt-resistor-micro-ohms` allows override, but we need the correct value.
- **Port testing**: Only eth1 tested with live PoE load. eth3/eth4 verified at GPIO level but not with real devices. Upstream may require all ports tested.
- **Port restrictions**: Our module has an allowlist (eth1/eth3/eth4 only). Upstream would need to support all 5 ports or explain the restriction via DT.
- **No upstream ER-6P PoE precedent**: Nobody has done passive PoE via GPIO on Octeon in OpenWrt before. We'd be defining the pattern.
