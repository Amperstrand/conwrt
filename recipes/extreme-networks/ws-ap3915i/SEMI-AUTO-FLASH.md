# Extreme Networks WS-AP3915i — Semi-Automatic Flash Procedure

## Prerequisites

- A computer with ethernet (macOS or Linux)
- An ethernet cable
- The AP3915i powered on, running stock firmware
- `sshpass` installed (`brew install sshpass` or `apt install sshpass`)
- A TFTP server (conwrt's built-in one works)

## Files (already downloaded)

```
data/extreme-ap3915i/
├── initramfs-uImage.itb          # OpenWrt initramfs (9.6 MB)
├── sysupgrade.bin                # OpenWrt sysupgrade (8.7 MB)
├── vmlinux.gz.uImage.3912        # Symlink/copy of initramfs — TFTP boot expects this filename
└── sha256sums                    # Official checksums (verified)
```

## Network Setup

```
[Your Laptop] ---ethernet--- [AP3915i GE1 port]
  192.168.1.2                  192.168.1.1
```

Configure your laptop ethernet to:
- IP: 192.168.1.2
- Subnet: 255.255.255.0
- No gateway, no DNS needed

## Step-by-Step Procedure

### Phase 0: Verify Stock Access

```bash
# Test SSH to stock firmware
sshpass -p 'new2day' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@192.168.1.1

# If that doesn't work, try alternate password:
# sshpass -p 'admin123' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@192.168.1.1
```

Once logged in, immediately save the current U-Boot environment:

```bash
rdwr_boot_cfg read_all
```

**COPY THIS OUTPUT SOMEWHERE SAFE.** This is your rollback reference.

Then disable the SSH timeout (prevents the stock shell from kicking you out):

```bash
cset sshtimeout 0
capply
csave
```

### Phase 1: Write U-Boot Variables for TFTP Boot

Run these commands on the AP via SSH. Each one writes to BOTH boot config blocks:

```bash
rdwr_boot_cfg write_var AP_MODE=0
rdwr_boot_cfg write_var MOSTRECENTKERNEL=0
rdwr_boot_cfg write_var WATCHDOG_COUNT=0
rdwr_boot_cfg write_var WATCHDOG_LIMIT=0
rdwr_boot_cfg write_var AP_PERSONALITY=identifi
rdwr_boot_cfg write_var serverip=192.168.1.2
rdwr_boot_cfg write_var ipaddr=192.168.1.1
rdwr_boot_cfg write_var bootcmd="run boot_net"
```

Verify each one:

```bash
rdwr_boot_cfg read_all
```

Confirm: `bootcmd` should be `run boot_net`, `serverip` should be `192.168.1.2`.

**WARNING**: From this point forward, if the AP reboots it will try to TFTP boot. If no TFTP server is running, it may hang. Do NOT power off or lose network until Phase 3.

### Phase 2: Start TFTP Server and Reboot AP

On your laptop, start the TFTP server serving the initramfs:

```bash
# From the conwrter repo root:
sudo python3 scripts/tftp-server.py data/extreme-ap3915i/ 192.168.1.2
```

Note: TFTP uses port 69 which requires root/sudo on most systems.

The TFTP server must be serving `vmlinux.gz.uImage.3912` (the renamed initramfs).

Verify it's accessible:
```bash
# In another terminal:
ls data/extreme-ap3915i/vmlinux.gz.uImage.3912
# Should be 10110420 bytes
```

Now reboot the AP from the SSH session:

```bash
reboot
```

The SSH connection will drop. The AP will:
1. Load U-Boot
2. Execute `run boot_net`
3. TFTP-fetch `vmlinux.gz.uImage.3912` from 192.168.1.2
4. Boot into OpenWrt initramfs
5. Start SSH at 192.168.1.1 (root, no password)

**Wait ~90 seconds** for the boot to complete.

### Phase 3: Connect to OpenWrt Initramfs

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@192.168.1.1
```

You should see the OpenWrt banner. No password needed.

**Optional but recommended**: Backup the MTD partitions:

```bash
# On the AP (OpenWrt initramfs):
cat /proc/mtd
mkdir -p /tmp/conwrt-backup
cat /proc/mtd > /tmp/conwrt-backup/proc_mtd.txt
dmesg > /tmp/conwrt-backup/dmesg.txt
mount > /tmp/conwrt-backup/mount.txt

# Backup each MTD partition (adjust based on cat /proc/mtd output)
# dd if=/dev/mtd0 of=/tmp/conwrt-backup/mtd0.bin bs=64k
# dd if=/dev/mtd1 of=/tmp/conwrt-backup/mtd1.bin bs=64k
# ... etc for each partition ...
```

### Phase 4: Upload and Flash Sysupgrade

From your laptop, upload the sysupgrade image:

```bash
scp -O data/extreme-ap3915i/sysupgrade.bin root@192.168.1.1:/tmp/sysupgrade.bin
```

Verify the upload on the AP:

```bash
# On the AP:
sha256sum /tmp/sysupgrade.bin
# Expected: 38ca385660e46aa084017b80e620ab07fb30716a07bcaab8f3d5435bc88bf848
ls -la /tmp/sysupgrade.bin
# Expected: ~9175666 bytes
```

Flash it:

```bash
# On the AP:
sysupgrade -n /tmp/sysupgrade.bin
```

The AP will flash and reboot. Wait ~2 minutes.

### Phase 5: Restore bootcmd to Flash Boot

After the AP reboots into permanent OpenWrt, restore the bootcmd so it boots from flash instead of TFTP.

> **NOTE**: `fw_setenv` does NOT work on this device — there is no `/etc/fw_env.config` in the
> ipq40xx base-files. Use one of the methods below instead.

**Option A: U-Boot serial console** (recommended, requires serial cable)
```
# At U-Boot prompt (press 's' during boot, login admin/new2day):
setenv boot_openwrt "sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000"
setenv bootcmd "run boot_openwrt || run boot_net"
setenv serverip 192.168.1.2
saveenv
boot
```

**Option B: Raw MTD write from OpenWrt** (no serial needed, requires kmod-mtd-rw)
```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@192.168.1.1

# Install MTD read-write bypass
opkg update && opkg install kmod-mtd-rw
insmod mtd-rw i_want_a_brick=1

# Build and write correct config block (see no-serial-openwrt.md for config block builder)
# Must include: boot_openwrt=sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000
#               bootcmd=run boot_openwrt || run boot_net
#               WATCHDOG_COUNT=0, WATCHDOG_LIMIT=0, MOSTRECENTKERNEL=0
# Write to: /dev/mtd0 (CFG1) and /dev/mtd8 (CFG2)
```

### Phase 6: Verify

```bash
ssh root@192.168.1.1
cat /etc/openwrt_release
# Should show OpenWrt 24.10.2

# Check wifi
wifi status
# Configure as needed
```

## Rollback (if something goes wrong)

If the AP won't boot after Phase 4 and you have serial console access:
1. Interrupt U-Boot at boot (press `s`)
2. Set `setenv bootcmd "run boot_net"; saveenv; boot` to TFTP boot
3. Or set `setenv boot_openwrt "sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000"; setenv bootcmd "run boot_openwrt"; saveenv; boot`

If you don't have serial and the AP is bricked:
- You need a serial cable. The AP3915i has a serial header inside the case.
- Serial settings: 115200 8N1

## Troubleshooting

| Problem | Solution |
|---------|----------|
| SSH to stock fails | Try password `admin123` instead of `new2day` |
| `rdwr_boot_cfg` not found | Device may not be on stock Extreme firmware — check with `which rdwr_boot_cfg` |
| AP reboots during Phase 1 | The watchdog fired. SSH timeout wasn't disabled. Reconnect and try again faster. |
| TFTP boot fails | Check TFTP server is running on 192.168.1.2, file is named exactly `vmlinux.gz.uImage.3912` |
| No SSH after reboot | Wait longer (up to 5 min). Check your ethernet link. Try power cycling the AP. |
| `fw_setenv` not found | The initramfs may not have it. Use the sysupgraded OpenWrt instead. |
