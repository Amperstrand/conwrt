<!--
  conwrt — serial-05-configure
  DISCLAIMER: Serial-based device configuration. You MUST have legal authority
  to modify the target device. This step changes device settings (IP, SSH, auth).
-->

# Serial 05: Configure Device via Serial Console

**Role**: You are a serial console operator configuring an OpenWrt device that has
booted but is inaccessible via network (wrong IP, no SSH key, IP conflict).

**Use case**: The device booted OpenWrt (initramfs or stock) but its LAN IP
conflicts with another device on your network. You need to change the IP,
install an SSH key, and enable SSH — all via serial, without network access.

---

## ⚠️ Safety Rules

- **VERIFY** you are connected to the correct device before changing settings
- **DO NOT** flash firmware in this step (use serial-04 for flashing)
- **DO NOT** erase partitions or run firstboot/factory reset
- **DO** verify each change with `uci get` before committing
- **DO** record the new IP and recovery procedure after configuration

---

## Prerequisites

- serial-01 completed: device identified, serial connection established
- Device has booted into OpenWrt (either initramfs or permanent install)
- Serial console shows `root@OpenWrt:~#` prompt (press Enter to activate)

**If device has NOT booted OpenWrt**: Return to serial-04 (flash via bootloader).

---

## Procedure

### Step 1: Activate Serial Console

After OpenWrt boots, the serial console may need activation:

```bash
# Via serial-boot-capture.py command FIFO:
printf 'ENTER' > /tmp/conwrt-serial-cmd

# Or via direct pyserial:
python3 -c "
import serial, time
s = serial.Serial('/dev/cu.usbserial-XXXX', 57600, timeout=1)
s.write(b'\r\n')
time.sleep(1)
print(s.read(4096).decode('ascii', errors='replace'))
s.close()
"
```

If the console is in a continuation prompt (`>`), send Ctrl-C:
```python
s.write(b'\x03')  # Ctrl-C breaks out of quote/continuation
time.sleep(0.5)
s.write(b'\r\n')
```

### Step 2: Identify Current State

```bash
python3 scripts/serial-configure.py /dev/cu.usbserial-XXXX 57600 --show-firmware --show-config
```

Or via direct commands:
```
cat /etc/openwrt_release      # Firmware version
uci show network.lan          # Current LAN config
uci show dropbear             # SSH config
cat /proc/mtd                 # Partition layout
ip addr show                  # Network interfaces
```

### Step 3: Change LAN IP

When the device's default IP (192.168.1.1) conflicts with another router:

```bash
python3 scripts/serial-configure.py /dev/cu.usbserial-XXXX 57600 --set-ip 192.168.5.1
```

Or via direct commands:
```
uci set network.lan.ipaddr='192.168.5.1'
uci commit network
ifup lan
```

**VERIFY** before proceeding:
```
uci get network.lan.ipaddr    # Must return the new IP
```

### Step 4: Install SSH Key

Install a public key for passwordless SSH access:

```bash
python3 scripts/serial-configure.py /dev/cu.usbserial-XXXX 57600 --install-key ~/.ssh/id_ed25519.pub
```

Or via direct commands (be careful with long keys over serial):
```
mkdir -p /etc/dropbear
echo 'ssh-ed25519 AAAA...' > /etc/dropbear/authorized_keys
chmod 600 /etc/dropbear/authorized_keys
```

**Pitfall**: Long SSH keys may wrap across serial lines, causing the shell to
enter continuation mode (`>`). If this happens, send Ctrl-C and retry with
a shorter method (e.g., download via wget after enabling network).

### Step 5: Enable/Disable Password Auth

For initial access (enable password auth temporarily):
```bash
python3 scripts/serial-configure.py /dev/cu.usbserial-XXXX 57600 --enable-password
```

After SSH key is installed (disable password for security):
```bash
python3 scripts/serial-configure.py /dev/cu.usbserial-XXXX 57600 --disable-password
```

### Step 6: Verify and Record

After configuration:
```
uci get network.lan.ipaddr         # Verify new IP
uci get dropbear.@dropbear[0].PasswordAuth  # Verify auth mode
cat /etc/dropbear/authorized_keys | wc -c   # Verify key installed
```

Record for inventory:
- New LAN IP
- MAC address (from `cat /sys/class/net/br-lan/address` or `ip link`)
- Firmware version
- Recovery procedure (how to revert if needed)

### Step 7: Connect via SSH

Once the device is configured and ethernet is connected:

```bash
# Add IP alias on your ethernet interface to reach the device
sudo ifconfig enX inet 192.168.5.2/24 alias

# SSH to the device
ssh root@192.168.5.1
```

After SSH access is confirmed, proceed to sysupgrade with a permanent image.

---

## Output Contract

Write `$STEP_DIR/findings.json`:

```json
{
  "step": "serial-05-configure",
  "device_state_before": {
    "firmware": "OpenWrt 25.12.4",
    "lan_ip": "192.168.1.1",
    "ssh_accessible": false,
    "ip_conflict": true
  },
  "changes_made": [
    {"setting": "network.lan.ipaddr", "old": "192.168.1.1", "new": "192.168.5.1"},
    {"setting": "dropbear.PasswordAuth", "old": "off", "new": "on"},
    {"setting": "dropbear.authorized_keys", "action": "installed", "key_type": "ssh-rsa"}
  ],
  "device_state_after": {
    "lan_ip": "192.168.5.1",
    "ssh_accessible": true,
    "ssh_key_installed": true
  },
  "next_step_input": {
    "recommendation": "sysupgrade",
    "parameters": {
      "lan_ip": "192.168.5.1",
      "image": "ASU custom sysupgrade with baked IP"
    }
  }
}
```
