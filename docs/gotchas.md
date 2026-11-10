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

OpenWrt's device tree marks some partitions (CFG, bootloader, calibration) as read-only. The `kmod-mtd-rw` kernel module removes the `MTD_WRITEABLE` flag from all MTD partitions: `insmod mtd-rw.ko i_want_a_brick=1`.

**How it's built:** Out-of-tree kernel module in the `packages` feed at `kernel/mtd-rw/`. Source is a single C file (`mtd-rw.c`, ~100 lines) from [github.com/jclehner/mtd-rw](https://github.com/jclehner/mtd-rw). OpenWrt's build system cross-compiles it against each target's kernel headers. It's excluded only for targets without MTD support (x86, bcm27xx, octeontx). For ipq40xx, realtek, mediatek, etc. it's always available.

**Verifying availability for a target:** Check the OpenWrt downloads server for the target's kmods directory, or just try `opkg install kmod-mtd-rw` — if the target has MTD support, it's there.

```bash
opkg update && opkg install kmod-mtd-rw
insmod mtd-rw i_want_a_brick=1
```

**Key behaviors:**
- The `i_want_a_brick=1` parameter is **required** — the module refuses to load without it (safety measure).
- Reverts on reboot (module is not loaded again unless re-installed or added to `/etc/modules.d/`).
- Must be loaded BEFORE any MTD writes to read-only partitions.
- In OpenWrt 24.10.x, kernel modules are in a separate kmods feed. On official images, the kmods feed is auto-configured in `/etc/opkg/distfeeds.conf`.

**Common misconception:** "kmod-mtd-rw was removed in OpenWrt 24.10.x." This is false — it was never in the main OpenWrt tree. It's always been in the `packages` feed (`openwrt/packages/kernel/mtd-rw/`). As long as the target has MTD support and the kmods feed is configured, it installs fine. Verified on ipq40xx (kernel 6.6.93) and realtek (kernel 6.6.x).

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

When the target device is on a different subnet (e.g., AP at 192.168.1.1, switch at (switch management IP)), add a secondary IP to the switch:

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

## UBIFS Overlay Persistence

### File writes lost on `network restart` or unclean power loss

OpenWrt devices with UBIFS overlays (NAND flash, common on ipq40xx, mediatek, etc.) have a write-back cache that is NOT flushed by `sync` alone. `uci commit` persists because it does an explicit `fsync()`, but regular file writes (`echo >`, `cp`, `passwd`) sit in UBIFS buffers and are lost if the device restarts without a clean shutdown.

**What persists:**
- `uci commit` — always persists (explicit fsync)
- Regular file writes — only persist after `sync; sync; reboot` (clean shutdown flushes UBIFS)

**What does NOT persist:**
- File writes after `network restart` — UBIFS buffers not flushed
- File writes after unclean power loss (unplugging) — no shutdown, no flush

**Incident (2026-05-28, ASUS Lyra MAP-AC2200):** Configured lyra2 with SSH key, password, hostname. Used `network restart` to change IP. SSH key and password were lost (UBIFS write-back not committed). UCI changes (IP, hostname) survived because `uci commit` does its own fsync. Device became unreachable — key auth failed and password was gone.

**Safe pattern:**
1. Write all files (authorized_keys, passwd)
2. `sync; sync`
3. `reboot` (clean shutdown — NOT `network restart`)
4. Wait for device to come back
5. Verify persistence (check authorized_keys exists, key auth works)
6. **Only then** disable password auth

**NEVER:**
- Use `network restart` to apply file-level changes on UBIFS overlays
- Disable password auth before verifying SSH key survives reboot
- Unplug a device after writing config without `sync; sync` first

**Detection:** Check `mount | grep ubifs` — if the overlay is UBIFS, this gotcha applies. JFFS2 overlays may behave differently but the safe pattern (sync + reboot) works for both.

## Backup before flashing

### Shell variable expansion in uci commands (CRITICAL)

**Incident (2026-05-29, ASUS Lyra MAP-AC2200):** `builder.py` generated shell scripts with single quotes around uci values containing shell variables:

```bash
uci set network.lan.ipaddr='10.231.9.$_host'   # BUG: $_host never expands
uci set system.@system[0].hostname='lyra_$_suffix'  # BUG: $_suffix never expands
```

Single quotes prevent ALL variable expansion in shell. The device literally stored `10.231.9.$_host` as its IP address and `lyra_$_suffix` as its hostname. After reboot, netifd couldn't parse the invalid IP → device became unreachable on all protocols (IPv4, IPv6, ARP).

**Recovery**: Physical failsafe mode (hold reset during power cycle → boots at 192.168.1.1 ignoring overlay) → `firstboot -y && reboot` → re-run `conwrt configure`.

**Fix**: Always use double quotes when shell variables must expand:
```bash
uci set network.lan.ipaddr="10.231.9.$_host"   # Correct: $_host expands
uci set system.@system[0].hostname="lyra_$_suffix"  # Correct: $_suffix expands
```

**Lesson**: Any shell script that constructs uci values from variables MUST use double quotes. Single quotes are only safe for literal strings with no variable interpolation. This applies to both post-flash SSH scripts and ASU first-boot scripts.

### Python and shell must use the same hash algorithm

**Incident (2026-05-29):** `mac_hash.py` used `sha256` to derive the MAC-hash host byte, but the on-device shell script used `md5sum` (because sha256sum isn't guaranteed on all BusyBox builds). Python predicted IP `10.231.9.199`, device actually computed `10.231.9.48`.

**Fix**: Both must use the same algorithm. Since BusyBox always has `md5sum` but may not have `sha256sum`, Python should use md5:
```python
# Python (matches BusyBox md5sum)
h = hashlib.md5(mac_clean.encode()).hexdigest()
val = int(h[:8], 16)
```

**Lesson**: Any hash/digest computed on-device MUST match what Python computes off-device. Prefer md5 for BusyBox compatibility — it's not a security context.

### Use eth0 MAC, not br-lan MAC, for stable device identity

**Incident (2026-05-29):** MAC-hash IP and hostname scripts read from `/sys/class/net/br-lan/address`. After `firstboot`, br-lan gets a **random MAC** (different each time). The MAC-hash IP would change after every factory reset.

**Fix**: Read from `eth0` instead — this always has the **factory MAC** from the hardware (stable across reboots and resets):
```bash
_mac=$(cat /sys/class/net/eth0/address 2>/dev/null)
```

**Lesson**: For any identifier derived from MAC (hostname, IP, inventory), use the factory/base MAC (eth0), never the bridge MAC (br-lan). br-lan MAC is randomized after `firstboot`.

### echo adds newline — tail -c6 includes it

**Incident (2026-05-29):** Hostname suffix script:
```bash
_suffix=$(echo "$_mac" | tr -d ':' | tail -c6)
```

`echo` appends a newline. `tail -c6` includes that newline as one of the 6 characters, producing only 5 hex digits visible in the hostname (`lyra_2f319` instead of `lyra_12f319`).

**Fix**: Strip newlines in the `tr` command:
```bash
_suffix=$(echo "$_mac" | tr -d ':\n' | tail -c6)
```

**Lesson**: When piping through `tail -cN`, account for trailing newlines from `echo`. Use `tr -d ':\n'` or `printf '%s'` instead of `echo`.

### Test shell commands manually before automating

This incident could have been avoided by following the new AGENTS.md "Test Before You Commit" rule. The exact sequence that would have caught all four bugs:

1. SSH to device, run the MAC-hash IP script manually → verify `uci get network.lan.ipaddr` returns a valid IP (not `$_host` literal)
2. Run the hostname script manually → verify `uci get system.@system[0].hostname` returns `lyra_12f319` (not `$_suffix`)
3. Verify the IP matches what Python predicts → would have caught sha256 vs md5 mismatch
4. Reboot, verify persistence, verify reachable on the new IP

Step 1 alone would have caught the single-quote bug before it was committed to the overlay.

## Backup before flashing

### Newly flashed devices hijack DHCP (rogue DHCP)

Freshly flashed OpenWrt devices boot with DHCP server enabled on br-lan by default. If conwrt is running on an OpenWrt **switch or router** with other devices on the same network, the freshly flashed device competes for DHCP clients — potentially hijacking the default gateway.

**When this happens:** Switch-to-device flashing (e.g. GS1900-8HP → AP3915i via PoE). The switch and other devices share br-lan. The newly booted device's dnsmasq answers DHCP requests faster than the real DHCP server.

**When this does NOT happen:** Direct macOS → device flashing (USB ethernet or direct connect). The Mac is the only device on the link — there's no other DHCP client to hijack.

**Incident (2026-05-23):** Flashed an AP3915i via GS1900-8HP switch. After boot, the AP's DHCP server handed the Mac a lease with itself as gateway, breaking internet access. The Mac's real gateway was replaced by the AP (192.168.1.1).

**Prevention approaches (in order of effectiveness):**

1. **VLAN port isolation** (best): Isolate the target port into a separate VLAN before powering on the device. DHCP offers cannot escape the isolated VLAN. See `port_isolation` in `models/zyxel-gs1900-8hp-a1.json`.

2. **Sysupgrade overlay** (good): Inject a sysupgrade `-f` overlay that sets `dhcp.lan.ignore=1` before first boot. Works for sysupgrade and tftp+initramfs paths. See `scripts/profile/overlay.py`. Only active when conwrt runs on an OpenWrt device.

3. **Post-flash SSH disable** (too late): SSH in and `uci set dhcp.lan.ignore=1`. Race window between boot and SSH — other devices may already have rogue leases.

**Fix when hit:** Release and renew DHCP on affected machines. On macOS: `sudo ipconfig set en0 DHCP`.

### Always pull a full backup before writing anything

**Incident (2026-05-19):** Pulled EdgeOS backup (squashfs.img, kernel, config overlay) BEFORE the kernel swap. This proved critical during recovery — we knew exactly what the original state looked like.

**Lesson:** Always backup the stock firmware, kernel, and configuration BEFORE starting any flash operation. Store backups on the host machine, not on the device. The backup should include:
- Boot partition contents (kernel + any sidecar files)
- Rootfs / squashfs image
- Device configuration
- SSH keys
- Boot partition format and mount options
