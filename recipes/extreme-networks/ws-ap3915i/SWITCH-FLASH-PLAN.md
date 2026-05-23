# Switch-Initiated AP3915i Flash Plan — Milestones

> **STATUS: ALL MILESTONES COMPLETE (2026-05-23).** AP3915i boots OpenWrt 24.10.2 from
> SPI-NOR flash. Overlay persisted through reboot. IP changed to 192.168.13.253.
> See post-flash status in `no-serial-openwrt.md`.

**Goal**: Flash OpenWrt onto the AP3915i, orchestrated entirely from the GS1900-8HP
switch running OpenWrt 25.12.1. No laptop required during the flash.

**Device topology** (post-flash):
```
[Ubuntu 192.168.13.218]---WiFi---[GS1900-8HP 192.168.13.2]---lan5(PoE)---[AP3915i 192.168.13.253]
         (observer)                   (orchestrator)                        (target)
[Ubuntu 192.168.1.2]---enp5s0---[ZyXEL stock switch 192.168.1.1]
         (separate network, unrelated to flash)
```

**Safety mechanisms**:
- PoE per-port control: `ubus call poe manage '{"port":"lanX","enable":false}'` kills power instantly
- `uci set poe.@port[N].enable=0` for persistent off (survives switch reboot)
- All milestones are independently verifiable and reversible (except M6)
- Mac remains on the network for monitoring/backup throughout

**Shortcut policy**: First iteration may use brute-force approaches (openssh-client
instead of Dropbear rebuild, shell script instead of conwrt.py). Document everything.
Improve later.

---

## Milestone 0: Reconnaissance (Zero risk, read-only)

**Goal**: Discover what the AP actually is, what state it's in, and what the switch can do.

### 0a: Verify switch access and baseline

```bash
# From Mac:
ssh root@192.168.1.2 "uname -a; cat /etc/openwrt_release; free -m; df -h /overlay"
ssh root@192.168.1.2 "ubus call poe info"        # PoE status all ports
ssh root@192.168.1.2 "ls /etc/config/poe"         # PoE config exists
ssh root@192.168.1.2 "dbclient -h 2>&1 | head"   # Dropbear SSH client options
ssh root@192.168.1.2 "which sshpass curl scp"     # Available tools
ssh root@192.168.1.2 "opkg list-installed"        # Installed packages
```

**Safety gate**: Confirm switch is reachable and stable. Confirm PoE control works.

### 0b: Identify which port the AP is on

```bash
# On switch: check PoE status to see which port is delivering power
ssh root@192.168.1.2 "ubus call poe info"
# Look for a port showing "Delivering power" — that's the AP

# Alternative: cycle PoE on suspected port and watch
# (AP will reboot — do this only if we can't identify by power draw)
```

**Safety gate**: Identify the exact port (lanX) the AP is connected to. Record it.

### 0c: Discover AP state

```bash
# From Mac (known-good SSH client):
# Try stock firmware credentials
sshpass -p 'new2day' ssh -o StrictHostKeyChecking=no \
  -o HostKeyAlgorithms='+ssh-rsa' \
  -o KexAlgorithms='+diffie-hellman-group1-sha1' \
  admin@192.168.13.2 'hostname; uname -a; cat /proc/mtd' 2>&1

# Try alternate password
sshpass -p 'admin123' ssh ... admin@192.168.13.2 'hostname'

# Try OpenWrt (maybe already flashed?)
ssh root@192.168.13.2 'cat /etc/openwrt_release' 2>&1

# Try HTTP (stock ZyXEL? stock Extreme?)
curl -s --max-time 5 http://192.168.13.2/ | head -20

# ARP scan from Mac to verify device exists
arp -a | grep 192.168.13
```

**Expected outcomes**:
- Stock Extreme firmware → proceed with extreme-rdwr-tftp method
- OpenWrt already → just sysupgrade (trivial)
- Dead/unresponsive → serial recovery needed, different plan

**Safety gate**: KNOW what device we're dealing with before proceeding.

### 0d: Verify Dropbear legacy SSH support (the big unknown)

```bash
# On switch: check if dbclient supports legacy algorithms
ssh root@192.168.1.2 "dbclient -h 2>&1"
# Look for: -c cipherlist, -m MAClist options

# Try a direct connection from switch to AP:
ssh root@192.168.1.2 "sshpass -p 'new2day' ssh -o StrictHostKeyChecking=no \
  -o HostKeyAlgorithms='+ssh-rsa' \
  -o KexAlgorithms='+diffie-hellman-group1-sha1' \
  admin@192.168.13.2 'hostname'" 2>&1
```

If this fails, check if it's a connectivity issue vs algorithm issue:
```bash
# Can switch reach AP at all?
ssh root@192.168.1.2 "ping -c 3 192.168.13.2"

# Is it a routing issue? (192.168.13.x vs 192.168.1.x)
ssh root@192.168.1.2 "ip addr show br-lan"
ssh root@192.168.1.2 "ip route"
```

**Decision tree**:
- Dropbear works with legacy algos → proceed to M1 (no openssh needed)
- Dropbear rejects legacy algos → install openssh-client on switch (M1 shortcut)
- Can't reach AP → fix routing first (M2 early)

**Rollback**: Nothing to roll back — all read-only.

**Time estimate**: 15 minutes.

---

## Milestone 1: Tool Installation (Low risk, reversible)

**Goal**: Install the minimum tools on the switch to orchestrate the flash.

### 1a: Check available flash space

```bash
ssh root@192.168.1.2 "df -h /overlay"
ssh root@192.168.1.2 "df -h /tmp"
# /overlay = persistent flash storage
# /tmp = RAM (tmpfs, 128MB available)
```

### 1b: Install SSH client (if Dropbear can't do legacy)

```bash
# Shortcut: install openssh-client (~2MB)
ssh root@192.168.1.2 "opkg update"
ssh root@192.168.1.2 "opkg install openssh-client"

# Verify
ssh root@192.168.1.2 "ssh -V"  # Should show OpenSSH
```

### 1c: Install sshpass

```bash
ssh root@192.168.1.2 "opkg install sshpass"
ssh root@192.168.1.2 "which sshpass"
```

### 1d: Install TFTP server

```bash
# Option A: atftpd (smallest, ~50KB)
ssh root@192.168.1.2 "opkg install atftpd"

# Option B: Use dnsmasq TFTP-only (already installed, just needs config)
# No install needed — just configure in M2
```

**Decision**: Prefer dnsmasq TFTP-only mode since dnsmasq is already on the switch.
Avoid adding packages unless necessary.

### 1e: Verify toolchain

```bash
# From switch, test SSH to AP (the critical test):
ssh root@192.168.1.2 "sshpass -p 'new2day' ssh \
  -o StrictHostKeyChecking=no \
  -o HostKeyAlgorithms='+ssh-rsa' \
  -o KexAlgorithms='+diffie-hellman-group1-sha1' \
  admin@192.168.13.2 'hostname; which rdwr_boot_cfg'"
```

**Safety gate**: SSH from switch to AP stock firmware works. If it doesn't,
STOP and debug before proceeding.

**Rollback**: `opkg remove openssh-client sshpass atftpd`

**Time estimate**: 10 minutes.

---

## Milestone 2: Network Configuration (Medium risk, reversible)

**Goal**: Ensure the switch can reach the AP AND the Mac can still reach the switch.

### 2a: Current routing check

```bash
# Is the AP already reachable from the switch?
ssh root@192.168.1.2 "ping -c 3 192.168.13.2"

# If yes: the switch already has a route (br-lan is a bridge, all ports see all traffic)
# If no: we need to add an IP alias
```

### 2b: Add IP alias if needed (AP on different subnet)

```bash
# Only if AP is on 192.168.13.x and switch is on 192.168.1.x:
ssh root@192.168.1.2 "ip addr add 192.168.13.1/24 dev br-lan"

# Verify:
ssh root@192.168.1.2 "ip addr show br-lan"
# Should show both 192.168.1.2/24 and 192.168.13.1/24

# Verify Mac still reaches switch:
ssh root@192.168.1.2 "echo 'management access preserved'"
# If this fails, the alias broke something — remove it:
# ssh root@192.168.1.2 "ip addr del 192.168.13.1/24 dev br-lan"
```

### 2c: Verify full path

```bash
# Mac → Switch → AP
ssh root@192.168.1.2 "ping -c 3 192.168.13.2"

# From switch, SSH to AP:
ssh root@192.168.1.2 "sshpass -p 'new2day' ssh [...] admin@192.168.13.2 'hostname'"
```

### 2d: Test PoE control (power cycle the AP)

```bash
# Identify the AP's port number (from M0b)
# Assuming port lan5 for this example:

# Turn off PoE on the AP's port:
ssh root@192.168.1.2 "ubus call poe manage '{\"port\":\"lan5\",\"enable\":false}'"
# Wait 10 seconds
# Verify AP is off: ping should fail
ping -c 3 192.168.13.2  # From Mac — should fail

# Turn PoE back on:
ssh root@192.168.1.2 "ubus call poe manage '{\"port\":\"lan5\",\"enable\":true}'"
# Wait 60-90 seconds for AP boot
# Verify AP comes back: ping should succeed
ping -c 3 192.168.13.2

# Confirm AP still has stock firmware:
ssh root@192.168.1.2 "sshpass -p 'new2day' ssh [...] admin@192.168.13.2 'hostname'"
```

**Safety gate**:
- [ ] Mac can reach switch at 192.168.1.2
- [ ] Switch can reach AP at 192.168.13.2
- [ ] PoE control works (verified power cycle)
- [ ] SSH from switch to AP stock firmware works

**Rollback**: `ip addr del 192.168.13.1/24 dev br-lan` (removes alias)

**Time estimate**: 10 minutes.

---

## Milestone 3: Firmware Staging (Low risk, no hardware interaction)

**Goal**: Get the firmware images onto the switch's /tmp (RAM).

### 3a: Identify firmware files needed

From the model JSON:
- Initramfs: `openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-initramfs-uImage.itb` (~10MB)
- Sysupgrade: `openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-squashfs-sysupgrade.bin` (~9MB)
- TFTP name: `vmlinux.gz.uImage.3912` (symlink to initramfs)

### 3b: Transfer firmware to switch

```bash
# Option A: SCP from Mac (Mac has the files already)
scp -O data/extreme-ap3915i/openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-initramfs-uImage.itb \
  root@192.168.1.2:/tmp/initramfs.itb

scp -O data/extreme-ap3915i/openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-squashfs-sysupgrade.bin \
  root@192.168.1.2:/tmp/sysupgrade.bin

# Option B: wget from ASU or HTTP server if Mac serves files
# ssh root@192.168.1.2 "wget -O /tmp/initramfs.itb http://192.168.1.100:8000/initramfs.itb"
```

### 3c: Verify checksums on the switch

```bash
# On switch: verify SHA256 matches pinned hashes
ssh root@192.168.1.2 "sha256sum /tmp/initramfs.itb"
# Expected: 75e105a3b4f9a8c6f8e5c7ff9bd2ee6607e6fe5da144bba8bfe7f1d0f21296d3

ssh root@192.168.1.2 "sha256sum /tmp/sysupgrade.bin"
# Expected: 38ca385660e46aa084017b80e620ab07fb30716a07bcaab8f3d5435bc88bf848

# ABORT if hashes don't match.
```

### 3d: Set up TFTP root

```bash
ssh root@192.168.1.2 "mkdir -p /tmp/tftpboot"
ssh root@192.168.1.2 "ln -sf /tmp/initramfs.itb /tmp/tftpboot/vmlinux.gz.uImage.3912"
ssh root@192.168.1.2 "ls -la /tmp/tftpboot/"
```

### 3e: Test TFTP server (from Mac)

```bash
# Start TFTP on switch (dnsmasq TFTP-only, no DNS/DHCP interference):
ssh root@192.168.1.2 "dnsmasq --port=0 --no-daemon --tftp-root=/tmp/tftpboot \
  --user=root --listen-address=192.168.13.1 &"

# Test TFTP download from Mac:
# (Mac needs a TFTP client: brew install tftp || atftp)
atftp -g -r vmlinux.gz.uImage.3912 -l /tmp/test-tftp.bin 192.168.13.1 69
# Compare:
sha256sum /tmp/test-tftp.bin
# Should match initramfs hash

# Clean up test:
rm /tmp/test-tftp.bin
# Kill test TFTP server on switch:
ssh root@192.168.1.2 "killall dnsmasq"
```

**Safety gate**:
- [ ] Both firmware files on switch /tmp with correct SHA256
- [ ] TFTP symlink correct
- [ ] TFTP download test passed

**Rollback**: `rm /tmp/initramfs.itb /tmp/sysupgrade.bin /tmp/tftpboot` (free RAM)

**Time estimate**: 10 minutes.

---

## Milestone 4: Stock Firmware Validation (Low risk, read-only from AP)

**Goal**: Verify we can interact with the AP's stock firmware from the switch,
test rdwr_boot_cfg, and create full backups.

### 4a: Stock firmware inventory

```bash
# All commands run FROM the switch TO the AP via SSH
# Define a helper alias for the SSH command:
SSH_AP="sshpass -p 'new2day' ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms='+ssh-rsa' -o KexAlgorithms='+diffie-hellman-group1-sha1' admin@192.168.13.2"

# Collect device info:
ssh root@192.168.1.2 "$SSH_AP 'hostname'"
ssh root@192.168.1.2 "$SSH_AP 'cat /proc/mtd'"
ssh root@192.168.1.2 "$SSH_AP 'uname -a'"
ssh root@192.168.1.2 "$SSH_AP 'which rdwr_boot_cfg flashcp'"
```

### 4b: Test rdwr_boot_cfg

```bash
ssh root@192.168.1.2 "$SSH_AP 'rdwr_boot_cfg read_all'"
# Possible outcomes:
#   1. Returns env variables → rdwr_boot_cfg works, use it
#   2. Returns empty → broken like Unit 2, try read_var
#   3. Exit 255 → completely broken like Unit 1, use flashcp

# Try individual reads:
ssh root@192.168.1.2 "$SSH_AP 'rdwr_boot_cfg read_var bootcmd'"
ssh root@192.168.1.2 "$SSH_AP 'rdwr_boot_cfg read_var boot_net'"
ssh root@192.168.1.2 "$SSH_AP 'rdwr_boot_cfg read_var serverip'"
```

**Decision tree**:
- `read_var` works → use `write_var` for U-Boot changes (safest)
- `read_var` fails → use `flashcp` for raw MTD write (proven on Units 1 & 2)

### 4c: Disable watchdog

```bash
ssh root@192.168.1.2 "$SSH_AP 'cset sshtimeout 0 && capply && csave'"
# Expect "Error in obtaining the tty" warnings — harmless
```

### 4d: Essential backup (ART + CFG1 only)

We don't back up the full flash to the switch — it's a 128MB RAM device, not
a storage server. The firmware images (PriImg/SecImg) are ~15MB each and
replaceable from OpenWrt downloads. Only two partitions matter:

| Partition | Size | Why | Replaceable? |
|-----------|------|-----|-------------|
| ART (mtd4) | 64KB | Radio calibration data | **NO — unique per device** |
| CFG1 (mtd1) | 64KB | U-Boot env (boot variables) | Yes (factory defaults work) |

```bash
# Pull ONLY the small critical partitions directly to Mac (skip the switch):
mkdir -p data/extreme-ap3915i/unit3-stock-backups/

# ART — the one irreplaceable partition
ssh root@192.168.1.2 "sshpass -p 'new2day' ssh [...] admin@192.168.13.2 \
  'dd if=/dev/mtd4 bs=65536 count=1 2>/dev/null | base64'" \
  | base64 -d > data/extreme-ap3915i/unit3-stock-backups/ART.bin
ls -la data/extreme-ap3915i/unit3-stock-backups/ART.bin  # Must be 65536 bytes

# CFG1 — for reference, shows current U-Boot env
ssh root@192.168.1.2 "sshpass -p 'new2day' ssh [...] admin@192.168.13.2 \
  'dd if=/dev/mtd1 bs=65536 count=1 2>/dev/null | base64'" \
  | base64 -d > data/extreme-ap3915i/unit3-stock-backups/CFG1.bin

# Also save /proc/mtd and device info for documentation:
ssh root@192.168.1.2 "sshpass -p 'new2day' ssh [...] admin@192.168.13.2 \
  'cat /proc/mtd; echo ---; hostname; echo ---; uname -a'" \
  > data/extreme-ap3915i/unit3-stock-backups/device-info.txt
```

**Safety gate**:
- [ ] rdwr_boot_cfg status known (works/partially broken/completely broken)
- [ ] ART partition backed up to Mac (65536 bytes, verify size)
- [ ] Watchdog disabled

**Rollback**: Nothing to roll back — all read-only operations.

**Time estimate**: 15 minutes.

---

## Milestone 5: Dry Run (Low risk, no AP mutation)

**Goal**: Walk through every step of the flash procedure without actually changing
the AP's boot configuration or rebooting it. Verify each command individually.

### 5a: Build the config block (if flashcp needed)

```bash
# On Mac: build the modified CFG1 block with Python
python3 -c "
import struct, zlib
# Read the backup we just made:
with open('data/extreme-ap3915i/unit3-stock-backups/ap-mtd1-backup.bin', 'rb') as f:
    block = bytearray(f.read())

# Parse and modify
payload = block[5:]
vars = {}
pos = 0
while pos < len(payload):
    end = payload.index(0, pos) if 0 in payload[pos:] else len(payload)
    if end == pos: break
    kv = payload[pos:end].decode('ascii', errors='replace')
    if '=' in kv:
        k, v = kv.split('=', 1)
        vars[k] = v
    pos = end + 1

# Print current vars for verification
for k, v in sorted(vars.items()):
    print(f'  {k}={v}')

# Set flash variables (but DO NOT write yet)
print(f'\\nWould set:')
print(f'  boot_openwrt=sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000')
print(f'  bootcmd=run boot_openwrt; run boot_net')
print(f'  serverip=192.168.13.1')
print(f'  ipaddr=192.168.13.2')
print(f'  WATCHDOG_COUNT=0')
print(f'  WATCHDOG_LIMIT=0')
"
```

### 5b: Test each SSH command individually (DO NOT REBOOT)

```bash
# Test: can we read the config block?
ssh root@192.168.1.2 "$SSH_AP 'dd if=/dev/mtd1 bs=65536 count=1 | md5sum'"

# Test: can we upload a file to AP's /tmp?
echo "test" > /tmp/test-upload.txt
scp -O /tmp/test-upload.txt root@192.168.1.2:/tmp/
ssh root@192.168.1.2 "scp -O /tmp/test-upload.txt $SSH_AP_USER@192.168.13.2:/tmp/test.txt"
# Actually this won't work easily with sshpass. Test the upload path:
ssh root@192.168.1.2 "sshpass -p 'new2day' scp -o StrictHostKeyChecking=no \
  -o HostKeyAlgorithms='+ssh-rsa' \
  -o KexAlgorithms='+diffie-hellman-group1-sha1' \
  /tmp/test-upload.txt admin@192.168.13.2:/tmp/test.txt"

# Verify on AP:
ssh root@192.168.1.2 "$SSH_AP 'cat /tmp/test.txt'"

# Clean up:
ssh root@192.168.1.2 "$SSH_AP 'rm /tmp/test.txt'"
```

### 5c: Verify TFTP readiness

```bash
# Start TFTP server on switch (will stay running for actual flash):
ssh root@192.168.1.2 "dnsmasq --port=0 --no-daemon --tftp-root=/tmp/tftpboot \
  --user=root --listen-address=192.168.13.1 &"

# Verify file is accessible:
ssh root@192.168.1.2 "ls -la /tmp/tftpboot/vmlinux.gz.uImage.3912"
```

### 5d: Document the exact command sequence

Write down every command that will run in M6, in order, with expected output.
This becomes the flash script.

**Safety gate**:
- [ ] Every individual command tested and works
- [ ] File upload path verified (switch → AP via SCP)
- [ ] TFTP server verified serving correct file
- [ ] Config block contents verified (printed, not written)
- [ ] Written command sequence for M6 ready

**Rollback**: Kill TFTP server: `ssh root@192.168.1.2 "killall dnsmasq"`

**Time estimate**: 20 minutes.

---

## Milestone 6: The Flash (High risk, irreversible)

**Goal**: Execute the flash procedure. This is the point of no return.

### Pre-flight checklist (all must be ✅ before proceeding)

- [ ] M0-M5 all passed their safety gates
- [ ] Mac is connected and can monitor (tcpdump on en5)
- [ ] MTD backups exist on Mac at `data/extreme-ap3915i/unit3-stock-backups/`
- [ ] Firmware SHA256 hashes verified on switch
- [ ] TFTP server running on switch
- [ ] Serial cable available? (Y/N — affects recovery options)
- [ ] PoE control tested — can kill AP power if needed

### 6a: Set up monitoring

```bash
# Terminal 1 (Mac): capture all traffic
sudo tcpdump -i en5 -w /tmp/ap3915i-unit3-flash.pcap host 192.168.13.2 or port 69

# Terminal 2 (Mac): watch ARP/DHCP
sudo tcpdump -i en5 -n arp or port 67 or port 68
```

### 6b: Write U-Boot variables to AP (from switch)

**If rdwr_boot_cfg works**:
```bash
# Set the FINAL bootcmd from stock firmware
# Key insight from Unit 2: set boot_openwrt FIRST, then bootcmd
ssh root@192.168.1.2 "sshpass -p 'new2day' ssh [...] admin@192.168.13.2 '
  rdwr_boot_cfg write_var WATCHDOG_COUNT=0 &&
  rdwr_boot_cfg write_var WATCHDOG_LIMIT=0 &&
  rdwr_boot_cfg write_var boot_openwrt=\"sf probe\; sf read 0x88000000 0x280000 0xc00000\; bootm 0x88000000\" &&
  rdwr_boot_cfg write_var serverip=192.168.13.1 &&
  rdwr_boot_cfg write_var ipaddr=192.168.13.2 &&
  rdwr_boot_cfg write_var bootcmd=\"run boot_openwrt\; run boot_net\"
'"
```

**If rdwr_boot_cfg broken**: Use flashcp with pre-built config block (see M5a).

### 6c: Reboot AP and TFTP boot initramfs

```bash
# Reboot from switch SSH:
ssh root@192.168.1.2 "sshpass -p 'new2day' ssh [...] admin@192.168.13.2 'reboot'"

# Watch tcpdump on Mac for:
# 1. AP goes offline (ARP stops)
# 2. AP sends ARP for 192.168.13.1 (U-Boot trying TFTP)
# 3. TFTP read request for vmlinux.gz.uImage.3912
# 4. TFTP data transfer (~10MB, ~30 seconds)
# 5. AP boots initramfs (ARP for new IP, DHCP requests)

# Wait ~90 seconds
```

### 6d: Connect to initramfs

```bash
# Initramfs default IP is 192.168.1.1 (OpenWrt default)
# But AP was configured with ipaddr=192.168.13.2 — U-Boot may use this
# Try both:

# From switch:
ssh root@192.168.1.2 "ssh -o StrictHostKeyChecking=no root@192.168.13.2 'uname -a'"
ssh root@192.168.1.2 "ssh -o StrictHostKeyChecking=no root@192.168.1.1 'uname -a'"

# If neither works, check ARP:
ssh root@192.168.1.2 "ip neigh show | grep -v FAILED"
# Also from Mac:
arp -a | grep -i "192.168"
```

### 6e: Upload sysupgrade and flash

```bash
# SCP from switch to AP initramfs:
ssh root@192.168.1.2 "scp -o StrictHostKeyChecking=no /tmp/sysupgrade.bin root@<INITRAMFS_IP>:/tmp/sysupgrade.bin"

# Verify on AP:
ssh root@192.168.1.2 "ssh -o StrictHostKeyChecking=no root@<INITRAMFS_IP> 'sha256sum /tmp/sysupgrade.bin'"
# Expected: 38ca385660e46aa084017b80e620ab07fb30716a07bcaab8f3d5435bc88bf848

# FLASH:
ssh root@192.168.1.2 "ssh -o StrictHostKeyChecking=no root@<INITRAMFS_IP> 'sysupgrade -n /tmp/sysupgrade.bin'"
```

### 6f: Wait for flash boot

```bash
# Watch tcpdump:
# 1. AP goes offline (sysupgrade reboot)
# 2. U-Boot runs boot_openwrt → sf read → bootm
# 3. If bootm succeeds: NO TFTP request (flash boot worked!)
# 4. If bootm fails: TFTP request (fallback catches it — try again)
# 5. OpenWrt boots, sends ARP/DHCP

# Wait ~120 seconds, then try SSH:
ssh root@192.168.1.2 "ssh -o StrictHostKeyChecking=no root@192.168.1.1 'cat /etc/openwrt_release'"
```

### 6g: Verify

```bash
ssh root@192.168.1.2 "ssh -o StrictHostKeyChecking=no root@192.168.1.1 '
  uname -a
  cat /proc/mtd
  cat /etc/board.json
  iw phy
'"
```

### Recovery if flash boot fails

1. **TFTP fallback catches it**: AP boots initramfs via TFTP → re-try sysupgrade
2. **TFTP also fails**: AP hangs at U-Boot → serial cable needed
3. **Nuclear option**: Power cycle AP via PoE control → watch for TFTP on reboot

**PoE power cycle procedure**:
```bash
ssh root@192.168.1.2 "ubus call poe manage '{\"port\":\"lan5\",\"enable\":false}'"
sleep 10
ssh root@192.168.1.2 "ubus call poe manage '{\"port\":\"lan5\",\"enable\":true}'"
```

**Time estimate**: 30 minutes (including waiting for reboots).

---

## Post-Flash: Cleanup

1. Kill TFTP server on switch: `ssh root@192.168.1.2 "killall dnsmasq"`
2. Remove firmware from RAM: `ssh root@192.168.1.2 "rm -rf /tmp/tftpboot /tmp/initramfs.itb /tmp/sysupgrade.bin"`
3. Remove IP alias if added: `ssh root@192.168.1.2 "ip addr del 192.168.13.1/24 dev br-lan"`
4. Document results in `UNIT3-AP3915i-FLASH-LOG.md`
5. Update model JSON with new tested_hardware entry

---

## Milestone Dependency Graph

```
M0 (recon) ──→ M1 (tools) ──→ M2 (network) ──→ M3 (firmware)
     │                                                    │
     └──→ M4 (stock validation) ←────────────────────────┘
                           │
                           └──→ M5 (dry run) ──→ M6 (flash)
```

M0 must be first. M1-M3 can be partially parallelized. M4 depends on M2 + M3.
M5 depends on M4. M6 depends on M5.

## Total Time Estimate

| Milestone | Time | Risk |
|-----------|------|------|
| M0: Recon | 15 min | Zero |
| M1: Tools | 10 min | Low |
| M2: Network | 10 min | Medium |
| M3: Firmware | 10 min | Low |
| M4: Validation | 15 min | Low |
| M5: Dry run | 20 min | Low |
| M6: Flash | 30 min | **High** |
| **Total** | **~2 hours** | |

## Notes

- **PoE control is the safety net**: If anything goes wrong during M6, we can instantly
  kill power to the AP and take time to plan recovery.
- **Mac is the observer**: Throughout all milestones, Mac watches traffic and holds backups.
  Mac is NOT required to be the orchestrator.
- **Shortcut for first iteration**: Use openssh-client if Dropbear can't handle legacy SSH.
  Rebuild the switch firmware later with proper Dropbear config.
- **Document everything**: Each milestone should produce a log. Final state goes in
  `UNIT3-AP3915i-FLASH-LOG.md`.
