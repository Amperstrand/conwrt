# Switch-Initiated Flash — Using an OpenWrt PoE Switch to Flash Devices

**Status**: Manual process documented. Automation script not yet implemented.
**Tested on**: GS1900-8HP A1 (OpenWrt) → NR7101 (zycast), AP3915i (TFTP)

## Overview

An OpenWrt PoE switch (e.g., ZyXEL GS1900-8HP) can autonomously flash devices
connected to its ports. The switch controls PoE power, serves firmware via TFTP
or sends it via zycast multicast, and verifies the flash via SSH.

This is the MOST RELIABLE flash method because:
- Switch has stable networking (no macOS IP removal issues)
- Switch controls PoE power cycling precisely (software-triggered)
- Switch is on the same L2 segment as the target device
- No laptop needed during the flash process

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Laptop (optional)                               │
│  conwrt flash --via-switch 192.168.13.2          │
│  ┌────────────────────────────────────────────┐  │
│  │ SSH to switch, orchestrate flash remotely  │  │
│  └────────────────────────┬───────────────────┘  │
└───────────────────────────┼──────────────────────┘
                            │ SSH
┌───────────────────────────┼──────────────────────┐
│  OpenWrt PoE Switch                              │
│  ┌────────────────────────────────────────────┐  │
│  │ 1. Disable PoE on target port (power off)  │  │
│  │ 2. Stage firmware + TFTP/zycast config     │  │
│  │ 3. Enable PoE on target port (power on)    │  │
│  │ 4. Serve firmware via TFTP or zycast       │  │
│  │ 5. Wait for SSH from flashed device        │  │
│  │ 6. Backup partitions (dd via SSH)          │  │
│  │ 7. Sysupgrade to permanent image           │  │
│  │ 8. Post-flash config (SSH key, IP, etc.)   │  │
│  └────────────────────────────────────────────┘  │
└───────────────────────────┬──────────────────────┘
                            │ PoE ethernet
                    ┌───────┴───────┐
                    │  Target Device │
                    │  (NR7101, etc) │
                    └───────────────┘
```

## Prerequisites

- OpenWrt PoE switch (GS1900-8HP A1 tested)
- `realtek-poe` package for PoE port control
- Target device connected to a PoE port on the switch
- Correct firmware images for the target device

## Method A: Zycast Flash (ZyXEL Devices)

Best for ZyXEL devices with Z-Loader bootloader that supports multicast flash.

### Step 1: Cross-compile zycast for MIPS

```bash
# On laptop
GOOS=linux GOARCH=mips GOMIPS=softfloat go build -ldflags="-s -w" ./cmd/zycast/
scp -O zycast root@switch:/tmp/
```

### Step 2: Upload firmware to switch

```bash
scp -O initramfs-recovery.bin root@switch:/tmp/
```

### Step 3: Configure switch network for flash

```bash
ssh root@switch
# Create VLAN interface for the target port (e.g., lan2)
ip link add link switch name switch.1002 type vlan id 1002
ip addr add 192.168.2.2/24 dev switch.1002
ip addr add 192.168.1.2/24 dev switch.1002  # secondary IP for post-flash access
ip link set switch.1002 up
```

### Step 4: Flash

```bash
# On the switch
/tmp/zycast flash -i switch.1002 --poe-port lan2 --loops 3 \
    --boot-ip 192.168.1.1 /tmp/initramfs-recovery.bin
```

The Go binary handles everything:
- PoE power cycle (7-10s off)
- Multicast send (repeated for the requested number of loops)
- Ping-based boot detection at the specified IP

### Step 5: Verify and sysupgrade

```bash
# Wait for SSH (device boots OpenWrt at 192.168.1.1)
ssh root@192.168.1.1 'cat /etc/openwrt_release'

# SCP sysupgrade image
scp -O sysupgrade.bin root@192.168.1.1:/tmp/

# Flash permanent image
ssh root@192.168.1.1 'sysupgrade -n /tmp/sysupgrade.bin'
```

### Key timing (NR7101, verified)

- Power-on to first ping: ~20s
- SSH available: ~60s after power-on
- Zycast transmission: ~75s per loop (7438 chunks at 10ms)
- PoE power-off delay: 7-10s

## Method B: TFTP Flash (U-Boot Devices)

Best for devices with U-Boot that supports TFTP boot (Extreme AP3915i, etc.).

### Step 1: Configure TFTP server on switch

```bash
ssh root@switch
# Configure dnsmasq as TFTP server
uci set dhcp.@dnsmasq[0].enable_tftp=1
uci set dhcp.@dnsmasq[0].tftp_root=/tmp/tftpboot
uci set dhcp.@dnsmasq[0].dhcp_boot=vmlinux.gz.uImage.3912
uci commit dhcp
/etc/init.d/dnsmasq restart
mkdir -p /tmp/tftpboot
cp /tmp/initramfs.itb /tmp/tftpboot/vmlinux.gz.uImage.3912
```

### Step 2: Power cycle device into U-Boot recovery

```bash
# Disable PoE (power off device)
ubus call poe set_port_config '{"port":"lan5","enable":false}'
sleep 8

# Enable PoE (device boots into U-Boot recovery)
ubus call poe set_port_config '{"port":"lan5","enable":true}'
```

### Step 3: Wait for TFTP boot + SSH

```bash
# Monitor for TFTP request
tcpdump -i br-lan -nn port 69

# Wait for SSH from initramfs
# ... (poll for SSH availability)
```

## PoE Port Control

On the GS1900-8HP with `realtek-poe`:

```bash
# Check PoE status
ubus call poe info

# Disable PoE on a port
ubus call poe set_port_config '{"port":"lan2","enable":false}'

# Enable PoE on a port
ubus call poe set_port_config '{"port":"lan2","enable":true}'

# Power cycle (soft reset)
ubus call poe set_port_config '{"port":"lan2","enable":false}'
sleep 8
ubus call poe set_port_config '{"port":"lan2","enable":true}'
```

**Gotcha**: PoE re-enable delay: the BCM59121 controller needs 5-10s to
renegotiate after disable/enable cycle. Don't set the delay shorter than 7s.

## Model Schema for Switch Flash

Add to model JSON:

```json
"switch_flash": {
    "poe_control": {
        "disable_cmd": "ubus call poe set_port_config {\"port\":\"lan5\",\"enable\":false}",
        "enable_cmd": "ubus call poe set_port_config {\"port\":\"lan5\",\"enable\":true}",
        "re_enable_delay_seconds": 8
    },
    "network": {
        "flash_subnet": "192.168.1.0/24",
        "host_ip": "192.168.1.2"
    },
    "tftp": {
        "server": "dnsmasq",
        "bootfile": "vmlinux.gz.uImage.3912"
    }
}
```

## Known Gotchas

1. **SCP requires `-O` flag** — OpenWrt dropbear lacks SFTP server
2. **dnsmasq must run as root** on OpenWrt for TFTP (`--user=root`)
3. **PoE daemon crashes** during long operations — recovery: `killall -9 realtek-poe; sleep 1; /etc/init.d/poe start`
4. **Monitor both old and new IPs** after flashing — OpenWrt changes from stock IP to 192.168.1.1
5. **Secondary IP on br-lan** works alongside existing IPs for post-flash access
6. **Kill zycast after flash** — bootloader listens on every boot

## Planned CLI Interface

```bash
# From switch: flash device on port lan5
conwrt-lite flash --port lan5 --model-id zyxel-nr7101 \
    --image /tmp/firmware.bin --tftp-image /tmp/initramfs.bin

# From laptop: tell switch to flash (via SSH to switch)
conwrt flash --via-switch 192.168.13.2 --port lan5 \
    --model-id zyxel-nr7101 --image firmware.bin
```

Not yet implemented. The manual process above is proven and documented.
