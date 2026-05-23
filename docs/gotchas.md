# Gotchas — Hard-Won Knowledge

Lessons learned from real device interactions. Read before touching a router.

## OpenWrt BusyBox Limitations

### No chpasswd
BusyBox on OpenWrt does not include `chpasswd`. Any uci-defaults script using `echo 'root:pw' | chpasswd` will fail silently.

**Fix:** `printf '%s\n%s\n' 'pw' 'pw' | passwd root`

### No sftp-server
OpenWrt's dropbear doesn't include sftp-server. Modern OpenSSH SCP defaults to SFTP, which fails with `ash: /usr/libexec/sftp-server: not found`.

**Fix:** Always use `scp -O` (legacy SCP protocol) when copying to OpenWrt.

## uci-defaults Script Rules

### No set -eu
Using `set -eu` in uci-defaults scripts is dangerous. If any command fails (like chpasswd above), the entire script aborts. Later commands like firewall rules never execute, potentially leaving the router unreachable.

**Fix:** Let each command run independently. Handle failures explicitly where needed. The `exit 0` at the end must always be reached so OpenWrt deletes the script.

### Script self-deletion
OpenWrt deletes uci-defaults scripts only on successful `exit 0`. If a script fails partway, it remains in `/etc/uci-defaults/` and runs again on next boot. Check with `ls /etc/uci-defaults/` after first boot.

## ASU (Attended Sysupgrade) API

### User-Agent blocking
The ASU server at sysupgrade.openwrt.org returns HTTP 403 for Python's default `Python-urllib/3.x` User-Agent.

**Fix:** Set `User-Agent: your-tool/1.0` on all requests.

### Image availability
Built images are stored temporarily on the ASU server. Download immediately — don't rely on them being available later.

## SCP/SSH with OpenWrt

### sysupgrade kills SSH
`sysupgrade -n` reboots the router, killing the SSH connection mid-command. This is normal. Exit code 246 means "connection dropped by remote" — expected behavior, not an error.

### Password-less root
Vanilla OpenWrt has no root password by default. SSH as root with no password works on LAN. This changes if you set a password or configure dropbear differently.

## U-Boot Recovery

### D-Link COVR-X1860: LAN port works for recovery
Recovery mode works on both WAN and LAN ports (validated 2026-05-12). The recovery HTTP server at 192.168.0.1 is accessible regardless of which ethernet port the cable is plugged into.

### D-Link COVR-X1860: Skip power cycle if already in recovery
If the device is already in recovery mode (recovery HTTP live), conwrt detects this and skips the power-off/reset-button sequence, going straight to firmware upload.

### GL.iNet LED patterns differ by model
- AR-150/AR300M: red LED blinks, release on 6th blink, green LED = ready
- MT3000: blue LED flashes 6x, then solid white = ready

### U-Boot upload field names
The HTTP form field for firmware upload is "firmware" (validated on MT3000 and AR300M). Some older documentation mentions "gl_firmware" but this is from an older U-Boot version for AR750S only.

### Browser requirements
Use Chrome or Edge for U-Boot web UI. Firefox has known issues that may brick the device during upload.

## Device Identity

### board.json is firmware identity, NOT hardware identity

`/etc/board.json` reflects what firmware was *flashed onto the device*, not what the device physically is. If someone previously force-flashed the wrong firmware (e.g., x1860 image on ex5700 hardware), board.json will lie.

**The sysupgrade hardware validation check is the authoritative source of truth.** It reads from firmware metadata that is set at build time and verified against the actual device. When sysupgrade says "Device X not supported by this image, supported devices: Y", it means the hardware is X and the image is for Y.

**Incident (2026-05-18):** A Zyxel EX5700 had been previously flashed with D-Link COVR-X1860 firmware. `board.json` reported `dlink,covr-x1860-a1`. conwrt auto-detected it as x1860 and sysupgraded successfully (first flash). On the second manual sysupgrade attempt, sysupgrade's hardware check correctly identified `zyxel,ex5700-telenor` and rejected the x1860 image. The operator used `sysupgrade -F` to force-flash anyway, writing x1860 firmware to ex5700 hardware — bricking the device.

**Lesson:** Never override sysupgrade's device validation. If the device identity doesn't match the image, STOP and investigate. The check exists to prevent exactly this class of failure.

### How to verify real hardware identity

1. `sysupgrade -n /tmp/firmware.bin` without `-F` — the error message tells you the real device
2. `cat /tmp/sysinfo/board_name` — another source of device identity from the running firmware
3. Physical inspection — labels, MAC OUI, case markings
4. Match MAC OUI prefixes against `models/*.json` — each model has `mac_oui_prefixes` defined

## Security

### SSH key mismatch: ASU bake vs. SSH/SCP connection
When config.toml has multiple SSH keys, ASU bakes the **first** key into the firmware's authorized_keys. But `_detect_ssh_key_path()` may resolve to a different private key for SCP/SSH connections. If the keys don't match, the device rejects the connection after flashing.

**Fix:** Ensure the first key in `config.toml` `keys` array has a corresponding private key on the host machine. The private key is resolved from the public key path (strip `.pub`) or auto-detected from `~/.ssh/`.

### Don't accidentally modify the upstream router
When your development machine has SSH access to both the test router AND the upstream/main router, verify the IP address before running ANY command. Commands like `passwd` run without confirmation.

## Initramfs sysupgrade is broken (octeon, possibly others)

### sysupgrade requires ubus, which is non-functional in initramfs

On octeon (Cavium Octeon III) targets, `sysupgrade` calls `ubus call system sysupgrade` as its ONLY upgrade mechanism. In the initramfs environment, ubus/procd infrastructure is not fully functional. The call fails with "Command failed: ubus call system sysupgrade ... (Connection failed)" and sysupgrade has NO fallback path.

**Worse:** sysupgrade may partially write the kernel to the boot partition before the ubus call fails, leaving the device in a broken state (kernel without matching rootfs = kernel panic).

**Incident (2026-05-19, ER-6P):** Ran `sysupgrade -n /tmp/sysupgrade.tar` from initramfs. Got "Connection failed" error. Device became unresponsive — OpenWrt squashfs kernel on mmcblk0p1 but no rootfs on mmcblk0p2. Required full TFTP recovery with signed EdgeOS image.

**Fix:** Use manual dd from initramfs instead. Extract kernel and rootfs from the sysupgrade tar and write them directly:
```bash
tar xf /tmp/sysupgrade.tar sysupgrade-DEVICE/kernel -O > /boot/vmlinux.64
tar xf /tmp/sysupgrade.tar sysupgrade-DEVICE/root -O | dd of=/dev/mmcblk0p2 bs=4096
```
This executes the exact same operations as OpenWrt's `platform_do_flash()` without the broken ubus layer.

**Future upgrades (OpenWrt -> OpenWrt):** sysupgrade WILL work because the device is then running from squashfs with full procd/ubus.

### OpenWrt issues referencing this bug
- #9492: ubusd non-functional in initramfs
- #14190: identical "Connection failed" on rockchip from initramfs

## Port mapping differs between stock and OpenWrt

### ER-6P: Physical eth0 is WAN in OpenWrt

The EdgeRouter 6P maps ports differently in OpenWrt vs EdgeOS:
- Physical eth0 → lan0 (WAN in default config, firewall blocks SSH)
- Physical eth1-eth4 → lan1-lan4 (LAN, DHCP server active)
- SFP (eth5) → lan5 (LAN)

**Incident (2026-05-19):** After initramfs booted, device appeared "dead" because cable was on physical eth0. IPv6 link-local confirmed device was alive and DHCP discover packets showed MAC on WAN, but all TCP ports (22/23/80) were filtered by firewall.

**Fix:** Always move cable from physical eth0 to physical eth1+ after initramfs boots. If device seems unresponsive after a flash, try a different physical port before assuming brick.

**General lesson:** Always verify the OpenWrt port mapping for your specific device BEFORE flashing. Many devices remap WAN/LAN differently from stock firmware.

## TFTP recovery requires signed images

### EdgeRouter bootloader rejects unsigned files

The EdgeRouter 6P bootloader (v003+) has a button-activated TFTP recovery mode, but it ONLY accepts cryptographically signed `.img.signed` files. Unsigned kernels, OpenWrt images, and even genuine EdgeOS kernels are all rejected with "Firmware check failed".

**Incident (2026-05-19):** Tried to TFTP an OpenWrt initramfs kernel (28MB) and a backed-up EdgeOS kernel (6.7MB). Both rejected. Had to research and download the 112MB signed recovery image from dl.ubnt.com.

**Fix:** Always download the vendor's signed recovery image BEFORE starting any flash operation. For EdgeRouter, these are at `dl.ubnt.com/firmwares/edgemax/`. No authentication required.

**General lesson:** Some bootloaders validate firmware signatures during recovery. Test your recovery path (have the right image, know the procedure) BEFORE you start flashing. A recovery image that you haven't verified is not a recovery path.

## SCP to OpenWrt requires -O flag

### Dropbear lacks sftp-server

OpenWrt's Dropbear SSH server doesn't include sftp-server. Modern OpenSSH SCP defaults to SFTP protocol, which fails with `ash: /usr/libexec/sftp-server: not found`.

**Fix:** Always use `scp -O` (legacy SCP protocol) when copying files to OpenWrt targets. This applies to both initramfs and permanent OpenWrt installations.

## EdgeOS SSH requires sudo for mount operations

The EdgeOS SSH session (ubnt user) requires `sudo` for mounting partitions and writing to the boot partition. All mount/cp commands in the kernel swap procedure need `sudo` prefix or be run via `sudo bash`.

## md5sum sidecar format matters for U-Boot

U-Boot reads `vmlinux.64.md5` which should contain ONLY the hex MD5 hash followed by a newline (~33 bytes total). The correct format is produced by: `md5sum file | cut -d ' ' -f1 > file.md5`

Do NOT use `md5 -r` (macOS) which produces a different format. Do NOT include the filename after the hash.

## Research before flashing unfamiliar targets

### The 20-minute research rule

**Incident (2026-05-19):** First attempt used sysupgrade from initramfs, which failed and required a full TFTP recovery (30+ minutes of work). 20 minutes of source code research would have revealed that ubus is broken in initramfs and manual dd is the correct approach.

**Lesson:** When flashing an unfamiliar target or using a method you haven't validated, spend the extra time researching the specific flash path through source code, issue trackers, and community reports. The cost of a failed flash (recovery time) almost always exceeds the cost of research time.

### What to research specifically
1. How does `sysupgrade` work on this target? (Read `target/linux/$ARCH/base-files/lib/upgrade/platform.sh`)
2. Does the method work from initramfs? (Check for ubus/procd dependencies)
3. What does the recovery path look like? (Signed images? Serial only?)
4. Are there device-specific gotchas in OpenWrt issue tracker?
5. What is the exact partition layout? (Boot partition format, rootfs location)

## OpenWrt Dropbear SSH Quirks

### authorized_keys location

OpenWrt's Dropbear reads `authorized_keys` from **`/etc/dropbear/authorized_keys`**, NOT `~/.ssh/authorized_keys`. The Dropbear init script (`/etc/init.d/dropbear`) explicitly references this path via `file_verify /etc/dropbear/authorized_keys`.

**Incident (2026-05-23):** Pushed SSH public key to `~/.ssh/authorized_keys` on an AP3915i. Key auth failed. Discovered the correct path by grepping the init script. Key worked immediately after copying to `/etc/dropbear/authorized_keys`.

**Note:** conwrt already handles this correctly — its SSH key management code writes to `/etc/dropbear/authorized_keys`. The gotcha is when doing manual post-flash setup outside of conwrt.

### Dropbear private key format incompatible with openssh-client

Keys generated by `dropbearkey` are in Dropbear's own format, which openssh-client cannot read. Attempting to use a Dropbear-format key with openssh SSH produces: `Load key: error in libcrypto: unsupported`.

**Fix:** Use `dbclient` (Dropbear's native SSH client) for key-based auth from OpenWrt-to-OpenWrt, or use password auth via `sshpass`. To convert: `dropbearconvert dropbear openssh ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.openssh` (if `dropbearconvert` is available).

### DROPBEAR_PASSWORD for non-interactive auth

Dropbear's `dbclient` accepts passwords via the `DROPBEAR_PASSWORD` environment variable for non-interactive auth. This works when `sshpass` is unavailable on the OpenWrt host.

```bash
DROPBEAR_PASSWORD='thepassword' dbclient -y root@target 'command'
```

### SSH algorithm negotiation failures

Modern openssh-client (9.x+) may fail to connect to older Dropbear servers due to disabled legacy algorithms. Symptoms: "no matching host key type found. Their offer: ssh-rsa,ssh-dss" or "no matching algo kex".

**Fix:** Add explicit algorithm flags:
```bash
ssh -o HostKeyAlgorithms=+ssh-rsa,ssh-ed25519 \
    -o KexAlgorithms=+curve25519-sha256,diffie-hellman-group14-sha256 \
    -o Ciphers=+aes128-ctr,aes256-ctr \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-ed25519 \
    root@target
```

## Extreme AP3915i Boot Commands

### boot_openwrt vs boot_flash — CRITICAL

These are fundamentally different commands. Using the wrong one bricks the device:

| Variable | Value | What It Does |
|----------|-------|-------------|
| `boot_openwrt` | `sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000` | Direct SPI-NOR read of OpenWrt FIT image. **CORRECT** for OpenWrt. |
| `boot_flash` | `source boot_kernel` | Runs stock Extreme boot script with watchdog + dual-image failover. **INCOMPATIBLE** with OpenWrt FIT. |

**Incident (2026-05-22):** Wrote `bootcmd=run boot_flash` instead of `bootcmd=run boot_openwrt` to both CFG blocks. AP entered boot loop (stock boot_kernel script tried nboot, set watchdog, failed on FIT image). Required switch-initiated TFTP recovery and raw MTD rewrite.

**Correct final bootcmd:** `run boot_openwrt; run boot_net` (semicolon provides TFTP fallback — if bootm succeeds it never returns, if it fails, boot_net catches via TFTP).

**Source:** David Bauer's original commit e16a0e7 in openwrt/openwrt.

### Never change bootcmd away from a working state

If `bootcmd=run boot_net` (TFTP boot) is working, do NOT change it until flash boot is verified. Keep the TFTP fallback: `bootcmd=run boot_openwrt; run boot_net`.

### Write CFG1 only, never both blocks simultaneously

U-Boot tries CFG1 first; if CRC is invalid, it falls back to CFG2. Writing the same wrong value to both eliminates the fallback. Always write CFG1 first, verify boot, then mirror to CFG2.

### Set SSH keys BEFORE setting a password

Vanilla OpenWrt allows root SSH login without a password. Once you set a password, passwordless SSH stops working. If you're setting up access through a jump host (switch → AP), push SSH keys to `/etc/dropbear/authorized_keys` FIRST, then set the password.

### ubi.mtd=0 in bootargs causes kernel failure

Stock Extreme firmware CFG blocks may contain `ubi.mtd=0` or `static_bootargs` with `ubi.mtd=0`. This causes the OpenWrt kernel to attempt UBI attach on the CFG1 partition, which fails. Remove `ubi.mtd=0` from bootargs when writing CFG blocks for OpenWrt.

## U-Boot Config Block Format (Extreme AP391x)

### CFG block CRC32 covers bytes[5:], not bytes[4:]

The config block format is:
```
Bytes 0-3:  Little-endian CRC32 of bytes [5:end]
Byte 4:     Block flag (0x01 = active/primary, 0x00 = backup)
Bytes 5+:   Null-separated KEY=VALUE pairs, padded with 0xFF to 65536 bytes
```

**Common mistake:** Computing CRC over `block[4:]` instead of `block[5:]`. The 1-byte flag at offset 4 is NOT included in the CRC. Three failed attempts before getting this right.

**Verification:** `zlib.crc32(block[5:]) & 0xFFFFFFFF` should match `struct.unpack('<I', block[:4])[0]`.

### flashcp, not dd, for NOR flash writes

`dd` does not erase NOR flash sectors before writing. Use `flashcp` (available on stock Extreme firmware and OpenWrt) which handles erase+write correctly:

```bash
flashcp /tmp/cfg1.bin /dev/mtd0
```

### kmod-mtd-rw bypasses DTS read-only protection

OpenWrt's device tree marks CFG partitions as read-only. The `kmod-mtd-rw` kernel module bypasses this: `insmod mtd-rw.ko i_want_a_brick=1`. Available from OpenWrt package repos for most targets. Must be loaded before any MTD writes to read-only partitions.

## Switch-Initiated Flashing (Router-to-Router)

### PoE power control as safety mechanism

OpenWrt-managed PoE switches (like GS1900-8HP) can power-cycle target devices via software:

```bash
ubus call poe set_port_config '{"port":"lan5","enable":false}'  # Kill power
ubus call poe set_port_config '{"port":"lan5","enable":true}'   # Restore power
```

This is the primary safety mechanism for switch-initiated flashing — instant power cut if anything goes wrong.

### PoE re-enable may require switch reboot

Disabling and re-enabling PoE via software sometimes fails (port stays "unknown"). A full switch reboot always recovers PoE functionality.

### Secondary IP for cross-subnet access

When the target device is on a different subnet (e.g., AP at 192.168.1.1, switch at 192.168.13.2), add a secondary IP to the switch:

```bash
ip addr add 192.168.1.2/24 dev switch.1
```

Remove after flash is complete. Consider changing the target's IP to the switch's subnet instead (avoids the secondary IP entirely).

### dnsmasq as TFTP server on OpenWrt

OpenWrt's dnsmasq can serve TFTP without additional packages:

```bash
dnsmasq --port=0 --no-daemon --tftp-root=/tmp/tftpboot --user=root --listen-address=192.168.1.2 &
```

The `--port=0` disables DNS. Bind to specific interface/IP to avoid interfering with existing DHCP.

## Backup before flashing

### Always pull a full backup before writing anything

**Incident (2026-05-19):** Pulled EdgeOS backup (squashfs.img, kernel, config overlay) BEFORE the kernel swap. This proved critical during recovery — we knew exactly what the original state looked like.

**Lesson:** Always backup the stock firmware, kernel, and configuration BEFORE starting any flash operation. Store backups on the host machine, not on the device. The backup should include:
- Boot partition contents (kernel + any sidecar files)
- Rootfs / squashfs image
- Device configuration
- SSH keys
- Boot partition format and mount options
