# NR7101 Flash Runbook

> **⚠️ WARNING: This procedure permanently overwrites both firmware slots.**
> Stock firmware cannot be recovered from the device after zycast flash.
> If you make a mistake during serial wiring (wrong pins, 5V on 3.3V UART),
> you can damage the device irreparably. Read this entire guide before starting.

Tested procedure for flashing a Zyxel NR7101 with OpenWrt via serial-triggered zycast.

## Hardware Required

- USB-serial adapter (FTDI FT232R, CP2102, or CH340) at **3.3V**
- Ethernet cable + 802.3at PoE injector
- Mac with USB GigE adapter (en8 or similar)

## NR7101 Serial Header (J5)

```
Pin 1: GND  ──── adapter GND
Pin 2: (key — no pin, alignment only)
Pin 3: RX   ──── adapter TX
Pin 4: TX   ──── adapter RX
Pin 5: 3.3V ──── DO NOT CONNECT (device powered by PoE)
```

**Baud: 57600 8N1** (NOT 115200 — confirmed from OpenWrt device tree)

**Access**: The NR7101 is an IP68 outdoor enclosure. To access the PCB:
1. Unscrew the front cover (4 screws behind the rubber gasket)
2. Remove the SIM/button/LED cover (clips off gently)
3. Remove the WLAN button assembly
4. Remove 12 screws holding the PCB to the heatsink
5. Carefully lift the PCB — J5 is near the ethernet connector, labeled on the silkscreen

## Step-by-Step

### 1. Verify Adapter Health

```bash
python3 scripts/serial-console.py --diagnose
```

Confirms adapter detected, identifies chip type, checks signal lines.

### 2. Loopback Test (optional but recommended)

Bridge TX→RX on the adapter with a jumper wire:

```bash
python3 scripts/serial-console.py /dev/cu.usbserial-XXXX --loopback
```

All 4 test patterns must echo. If fail → adapter is broken.

### 3. Connect Serial + Ethernet

1. Connect adapter to J5: GND→GND, adapter TX→J5 pin 3 (RX), adapter RX→J5 pin 4 (TX)
2. Connect ethernet: PoE injector "PoE OUT" → NR7101, PoE injector "DATA IN" → Mac
3. Set up Mac interface:
   ```bash
   sudo ifconfig en8 inet 192.168.2.10/24 alias
   sudo route add -host 192.168.1.1 -interface en8
   ```

### 4. Start Serial Monitor

```bash
python3 scripts/serial-console.py /dev/cu.usbserial-XXXX \
  --baud 57600 --monitor --session nr7101-flash
```

Logs to `serial/nr7101-flash/` (console.log, console.raw, session.json).

### 5. Start Zycast Sender (separate terminal)

```bash
python3 scripts/zycast_macos.py \
  images/openwrt-25.12.4-ramips-mt7621-zyxel_nr7101-initramfs-recovery.bin \
  192.168.2.10
```

This continuously sends multicast firmware on 225.0.0.0:5631.

### 6. Power On NR7101

Plug in PoE injector power. The serial monitor should show:

```
BOOT STAGE: unknown → zloader      ← Z-Loader banner detected
[RX] Z-LOADER V1.30
[RX] Press any key to enter debug mode
```

### 7. Interrupt Bootloader (send Escape)

When "Press any key" appears, immediately send Escape:

```bash
printf 'ESCAPE' > /tmp/conwrt-serial-cmd
```

Z-Loader should enter multicast listen mode:

```
[RX] Multiboot Listening...
```

### 8. Wait for Flash (~3 minutes)

Zycast sends firmware in ~75s loops. Z-Loader needs 2-3 complete loops.
Watch serial for:

```
BOOT STAGE: zloader → kernel      ← Flash succeeded, kernel booting
[RX] [    0.000000] Linux version 5.15.xxx
```

### 9. Kill Zycast Immediately

```bash
pkill -f zycast_macos
```

The bootloader listens on every Z-Loader entry — running zycast will reflash.

### 10. Wait for OpenWrt Boot

```
BOOT STAGE: kernel → openwrt      ← OpenWrt userspace starting
[RX] Starting OpenWrt...
```

Device appears at **192.168.1.1** (~20s after kernel starts).

### 11. Verify SSH

```bash
ssh -o StrictHostKeyChecking=no root@192.168.1.1
cat /etc/openwrt_release
```

### 12. Run conwrt configure

```bash
python3 scripts/conwrt.py configure \
  --model-id zyxel-nr7101 \
  --interface en8 \
  --lan-ip-mode mac-hash \
  --wifi-disable
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Zero serial data | RX/TX swapped, no GND, or wrong baud | Swap RX/TX wires, verify GND, use `--auto-baud` |
| Garbage on serial | Wrong baud rate | Use `--auto-baud` to sweep rates |
| No "Press any key" prompt | Device boots too fast | Send Escape repeatedly during early boot |
| Z-Loader but no "Multiboot Listening" | Zycast not reaching device | Verify multicast on en8: `sudo tcpdump -i en8 udp port 5631` |
| Flash but no kernel boot | Image wrong or corrupt | Verify image: `ls -la images/openwrt-*-initramfs-recovery.bin` |
| Device at wrong IP after flash | 192.168.1.0/24 conflict with main network | Use host route: `sudo route add -host 192.168.1.1 -iface en8` |

## What Zycast Overwrites

- **mtd3** (Kernel) — overwritten with OpenWrt initramfs
- **mtd5** (Kernel2) — overwritten (dual-image, both slots)
- **mtd2** (Factory) — **NOT touched** (MAC, serial, calibration preserved)

Stock firmware cannot be recovered from the device after zycast flash.
