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

### GL.iNet LED patterns differ by model
- AR-150/AR300M: red LED blinks, release on 6th blink, green LED = ready
- MT3000: blue LED flashes 6x, then solid white = ready

### U-Boot upload field names
The HTTP form field for firmware upload is "firmware" (validated on MT3000 and AR300M). Some older documentation mentions "gl_firmware" but this is from an older U-Boot version for AR750S only.

### Browser requirements
Use Chrome or Edge for U-Boot web UI. Firefox has known issues that may brick the device during upload.

## Security

### Don't accidentally modify the upstream router
When your development machine has SSH access to both the test router AND the upstream/main router, verify the IP address before running ANY command. Commands like `passwd` run without confirmation.
