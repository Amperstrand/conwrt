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
