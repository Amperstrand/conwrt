# ZyXEL Multicast Flash Protocol (zycast)

## 1. Overview

Zycast is ZyXEL's proprietary multicast protocol for flashing firmware to devices over Ethernet, used by the "Multiboot client" in ZyXEL bootloaders (Z-Loader). It sends firmware images as UDP multicast packets to `225.0.0.0:5631`, split into 1024-byte chunks with a 30-byte header per packet. No authentication whatsoever.

The primary use case is flashing devices without serial access. Tested on NR7101 (MT7621AT, MIPS) connected through a Zyxel GS1900-8HP OpenWrt switch with PoE control. The bootloader accepts multicast on every boot, so the firmware gets written without any prior configuration on the target device.

The protocol was reverse-engineered by Bjorn Mork and published as `zycast.c` in OpenWrt's `firmware-utils` under GPL-2.0. Conwrt provides three implementations (Go, C, Python), all derived from this reference.

## 2. Implementations

| Feature | Go (`cmd/zycast/`) | C (via `scripts/zycast.py`) | Python (`scripts/zycast.py` fallback) |
|---------|-------------------|---------------------------|--------------------------------------|
| **Status** | **TESTED on hardware** | Reference, untested on our hardware | Untested |
| **Binary size** | 3.1 MB (stripped, MIPS) | ~50 KB | N/A (interpreted) |
| **Cross-compile** | Single command | Requires C compiler on host | No compilation |
| **Dependencies** | None (static) | C compiler + socket headers | Python 3 stdlib only |
| **PoE control** | Built-in (`poe` subcommand) | None | None |
| **Boot detection** | Built-in (`flash` subcommand pings target) | None | None |
| **Platforms** | MIPS, ARM, x86_64 (any Go target) | Linux/macOS (needs MSG_MORE or `-DMSG_MORE=0`) | Any Python 3 |
| **Interface binding** | SO_BINDTODEVICE with IP_MULTICAST_IF fallback | SO_BINDTODEVICE | SO_BINDTODEVICE with IP_MULTICAST_IF fallback |

**Recommendation**: Use the Go binary. It is the only implementation tested on real hardware, includes PoE control and boot detection, and produces a single static binary that runs on any OpenWrt switch.

## 3. Compiling the Go Binary

```bash
# From conwrt repository root
cd /home/ubuntu/src/conwrter

# MIPS (for Zyxel GS1900-8HP OpenWrt switch)
GOOS=linux GOARCH=mips GOMIPS=softfloat go build -ldflags="-s -w" -o conwrt-zycast ./cmd/zycast/

# ARM (for Raspberry Pi, etc.)
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o conwrt-zycast ./cmd/zycast/

# x86_64 (for Linux laptop)
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o conwrt-zycast ./cmd/zycast/

# macOS (for development/testing)
go build -ldflags="-s -w" -o conwrt-zycast ./cmd/zycast/
```

## 4. Compiling the C Binary (alternative)

The Python script `scripts/zycast.py` handles this automatically:

```bash
python3 scripts/zycast.py  # downloads zycast.c, compiles, caches at ~/.cache/conwrt/zycast
```

Or compile manually:

```bash
cc -o zycast zycast.c                # Linux
cc -DMSG_MORE=0 -o zycast zycast.c  # macOS
```

## 5. Flashing via a Zyxel Switch with PoE

This is the tested workflow for flashing NR7101 devices connected to a Zyxel GS1900-8HP switch running OpenWrt.

**Prerequisites**:
- OpenWrt switch with PoE (Zyxel GS1900-8HP tested)
- Target device connected via Ethernet to a switch port
- Firmware image (initramfs-recovery for zycast)
- Go zycast binary compiled for switch architecture

**Step 1: Upload to switch**

```bash
# From your machine
scp -O conwrt-zycast root@switch-ip:/tmp/z
scp -O firmware.bin root@switch-ip:/tmp/fw.bin
```

**Step 2: Set up VLAN interface**

```bash
# On the switch -- replace 1002 with your VLAN ID
ip link add link switch name switch.1002 type vlan id 1002
ip addr add 192.168.2.2/24 dev switch.1002     # for initial access
ip addr add 192.168.1.2/24 dev switch.1002     # for post-flash OpenWrt access
ip link set switch.1002 up
```

**Step 3: Flash**

```bash
# Full automated workflow (PoE cycle + multicast + boot detection)
/tmp/z flash -i switch.1002 --poe-port lan2 --loops 3 --boot-ip 192.168.1.1 /tmp/fw.bin

# Or manual steps:
/tmp/z poe off lan2       # power off device
sleep 7                   # wait for discharge
/tmp/z poe on lan2        # power on (bootloader starts)
/tmp/z send -i switch.1002 -t ras --loops 3 /tmp/fw.bin  # send firmware
# Wait ~20s, then check if device responds
ping -c 1 192.168.1.1
```

**Step 4: Verify**

```bash
ssh root@192.168.1.1        # if directly reachable
# OR through the switch:
ssh root@switch-ip
ssh root@192.168.1.1
```

## 6. Protocol Details

Header format (30 bytes, big-endian):

```
Offset  Size  Field
0       4     magic        0x7A797800 ("zyx\0")
4       2     checksum     byte sum of payload, folded to 16-bit
6       4     packet_id    sequential chunk number
10      4     payload_len  length of this chunk (max 1024)
14      4     file_len     total firmware size
18      2     unused       0
20      1     type         image type bitmap (0x04 = RAS)
21      1     images       same as type (target partition bitmap)
22      2     country      "FF" (default)
24      1     flags        0x01 (FLAG_SET_DEBUG)
25      5     reserved     zeros
```

Image type bitmap:

- 0x01 = bootbase (bootloader)
- 0x02 = ROM (data)
- 0x04 = RAS (kernel, default for firmware images)
- 0x08 = ROMD
- 0x10 = backup (kernel2)

Timing: 10ms inter-packet delay, roughly 75 seconds per complete loop for a 7.6 MB image.

The bootloader accepts multicast on every boot. If zycast keeps running, it will reflash the device on every power cycle. Stop zycast after a successful flash.

On devices with dual-image layout (NR7101), zycast writes to both firmware slots. The stock firmware cannot be preserved.

## 7. Troubleshooting

**Device does not respond after zycast**:
- Monitor BOTH the old IP and 192.168.1.1. The IP changes after flashing to OpenWrt default.
- Check if 192.168.1.0/24 conflicts with your local network. If it does, SSH through the switch instead.
- Increase `--loops` (try 5 or more).
- Verify the VLAN interface is up and has an IP address.
- Check PoE status: `ubus call poe info` on the switch. The port should show "Delivering power".

**PoE daemon crashes**: Run `killall -9 realtek-poe; sleep 1; /etc/init.d/poe start` on the switch. This resets all PoE ports.

**VLAN interfaces lost after PoE restart**: Recreate them. PoE daemon restarts can drop VLAN interfaces on some switches.
```
ip link add link switch name switch.1002 type vlan id 1002
ip addr add 192.168.2.2/24 dev switch.1002
ip addr add 192.168.1.2/24 dev switch.1002
ip link set switch.1002 up
```

**Device reflashes on every boot**: Kill the zycast process after a successful flash. The bootloader listens for multicast packets on every boot, not just the first one.

**Wrong port assignment**: Verify which physical port the target is connected to. On the GS1900-8HP, `lan2` is PoE port 2. Check with `ubus call poe info` to see which ports show "Delivering power".
