# ASUS Lyra MAP-AC2200 — OpenWrt Migration

## Hardware

| Field | Value |
|-------|-------|
| **SoC** | Qualcomm IPQ4019 (quad-core Cortex-A7) @ 717MHz |
| **Flash** | 128MB NAND (Macronix) |
| **RAM** | 256MB DDR3 (Nanya NT5CC128M16IP-DI) |
| **WiFi** | Tri-band: IPQ4019 2.4GHz b/g/n + IPQ4019 5GHz a/n/ac (ch36-64) + QCA9886 5GHz a/n/ac (ch100-140) |
| **Ethernet** | 2x GbE via QCA8072 switch |
| **Bluetooth** | Atheros AR3012 |
| **LED** | Single RGB LED via TI LP5523 (9-channel, 3 channels per color bonded for max current) |
| **Serial** | Header J35, 2mm spacing, 115200 8N1, pinout: 3.3v-RX-TX-GND (square=VCC) |
| **Buttons** | WPS, Reset |
| **Power** | 12 VDC, 2.0A via barrel connector |

### Port labeling

The two ethernet ports are labeled identically, but:
- **Port next to power connector = LAN** (eth1 in OpenWrt, swport4)
- **Other port = WAN** (eth0 in OpenWrt, gmac)

For initial flashing from stock firmware, use the **LAN port** (next to power).

### LED behavior (stock firmware)

| Color | Meaning |
|-------|---------|
| Solid white | Ready for setup |
| Random breathing | Booting up or applying settings |
| Light cyan | Everything is good |
| Red | Loss connection to primary Lyra |
| Orange | Loss connection to internet |
| Blue breathing → blink → steady | Booting OpenWrt initramfs (after mtd-write) |

## OpenWrt Support

| Field | Value |
|-------|-------|
| **Target** | ipq40xx/generic |
| **Device name** | `asus,map-ac2200` |
| **ASU profile** | `asus_map-ac2200` |
| **Board name** | `asus,map-ac2200` |
| **Supported since** | 19.07.0 |
| **Current release** | 24.10.4 |
| **DTS** | `qcom-ipq4019-map-ac2200.dts` |
| **Support commit** | 9ad3967f140b |

### Hardware revision note

The OpenWrt support does not distinguish between hardware revisions (A1, B1, etc.). The DTS and flash layout are the same across revisions. HW B1 is confirmed working with the standard images.

### NVMEM-on-UBI migration (24.10.x+)

Recent commits (7381901) switched MAC and calibration data lookup to NVMEM-on-UBI. The Factory UBI volume provides:
- `precal@1000` — IPQ4019 wifi0 calibration
- `macaddr@1006` — base MAC (WAN = base+1, LAN = base+3)
- `precal@5000` — IPQ4019 wifi1 calibration
- `precal@9000` — QCA9886 wifi2 calibration

## Flashing Procedure

### Prerequisites

1. Factory-reset the device (hold reset button 10+ seconds)
2. Complete the initial setup wizard via web UI (required to enable SSH)
3. Connect ethernet to the **LAN port** (next to power connector)
4. Stock firmware default IP: `192.168.1.1`

### Method: Stock SSH + mtd-write (two-stage)

This is the **only reliable non-serial flash method**. The device does NOT have a push-button TFTP recovery.

#### Stage 1: Write initramfs via stock SSH

```bash
# Stock SSH uses same credentials as web UI login
# After factory reset + wizard, login credentials are what you set during setup
INITRAMFS="openwrt-24.10.4-ipq40xx-generic-asus_map-ac2200-initramfs-uImage.itb"

# 1. SCP initramfs to device
scp -O "$INITRAMFS" admin@192.168.1.1:/tmp/

# 2. SSH in, unlock and write to linux partition
ssh admin@192.168.1.1
mtd-unlock -d linux
mtd-write -d linux -i /tmp/$INITRAMFS
reboot -f
```

**Important:** Do NOT power off during this process. Wait at least 5 minutes for the reboot. The LED will breathe multiple colors, blink blue, then go steady blue when OpenWrt initramfs is ready.

#### Stage 2: Sysupgrade from OpenWrt initramfs

```bash
# OpenWrt initramfs is at 192.168.1.1, root, no password
SYSUPGRADE="openwrt-24.10.4-ipq40xx-generic-asus_map-ac2200-squashfs-sysupgrade.bin"

# 1. SCP sysupgrade image
scp -O "$SYSUPGRADE" root@192.168.1.1:/tmp/

# 2. Sysupgrade
ssh root@192.168.1.1
sysupgrade -n /tmp/$SYSUPGRADE
```

Wait for reboot (up to 10 minutes for NAND first boot). After reboot, OpenWrt is at `192.168.1.1`, root, no password.

### Backup stock firmware (before flashing)

If you want to back up the stock firmware before overwriting:

```bash
# From stock firmware SSH:
ssh admin@192.168.1.1

# List MTD partitions
cat /proc/mtd

# Back up all partitions (via SCP or netcat)
for part in $(cat /proc/mtd | awk -F: '{print $1}' | grep mtd); do
  dd if=/dev/$part of=/tmp/$part.backup 2>/dev/null
done

# Or dump specific critical partitions:
dd if=/dev/mtd0 of=/tmp/mtd0-bootloader.backup
dd if=/dev/mtd1 of=/tmp/mtd1-Factory.backup   # calibration data!
dd if=/dev/mtd2 of=/tmp/mtd2-linux.backup      # kernel + rootfs

# SCP them off:
# From your workstation:
scp -O admin@192.168.1.1:/tmp/*.backup ./stock-backup/
```

**Critical:** The `Factory` partition contains WiFi calibration data and MAC addresses. Without it, WiFi may not work after any future flash.

### Debricking

- **ASUS Firmware Restore tool**: Use ASUS's official firmware restore utility for soft-bricked devices
  - https://www.asus.com/support/faq/1000814/
- **Serial TFTP**: Requires opening the case and attaching to header J35
  - Set TFTP server at 192.168.1.70 (device is at 192.168.1.1)
  - Name firmware as `MAP-AC2200.trx` (bootloader default `bootfile`)
  - Interrupt U-Boot by pressing `1` at boot
  - Select "1: Load System code to SDRAM via TFTP"
- **No push-button recovery**: Cannot enter TFTP mode without serial. Rescue mode (hold reset on power-up) runs a TFTP server that only accepts valid ASUS TRX firmware — it cannot flash OpenWrt images directly.

## Firmware Download

```
# Initramfs (factory install)
https://downloads.openwrt.org/releases/24.10.4/targets/ipq40xx/generic/openwrt-24.10.4-ipq40xx-generic-asus_map-ac2200-initramfs-uImage.itb

# Sysupgrade (permanent install)
https://downloads.openwrt.org/releases/24.10.4/targets/ipq40xx/generic/openwrt-24.10.4-ipq40xx-generic-asus_map-ac2200-squashfs-sysupgrade.bin

# OEM stock firmware
https://www.asus.com/Networking/Lyra/HelpDesk_BIOS/
```

## Known Issues

- **No push-button TFTP recovery**: Debricking requires serial console or ASUS firmware restore tool
- **TFTP filename**: U-Boot expects `HIVESPOT.trx` as the TFTP filename (or the initramfs name must contain `asus_map-ac2200-initramfs-fit-uImage.itb`)
- **UBI partitioning**: OEM and OpenWrt differ in UBI partition layout. Push-button TFTP recovery cannot deal with changed UBI partitioning.
- **LED controller**: LP5523 driver had issues in some releases (22.03.x). Fixed in later versions with updated device tree.
- **WiFi channels**: First 5GHz radio (IPQ4019) limited to ch36-64. Second 5GHz radio (QCA9886) limited to ch100-140. This matches OEM firmware and is an ART data constraint.
- **Setup wizard required**: Stock firmware SSH is only available after completing the initial setup wizard via web UI.
- **mtd-unlock**: Some firmware versions may require `mtd-unlock -d linux` before `mtd-write`. Run it before the write step.

## WiFi Radio Map

| Radio | Hardware | Band | Channels | OpenWrt name |
|-------|----------|------|----------|-------------|
| wifi0 | IPQ4019 | 2.4GHz | 1-13 | radio0 (2g) |
| wifi1 | IPQ4019 | 5GHz | 36-64 | radio1 (5g, low) |
| wifi2 | QCA9886 | 5GHz | 100-140 | radio2 (5g, high) |

## References

- OpenWrt Wiki: https://openwrt.org/toh/asus/lyra_map-ac2200
- Original support patch: https://lists.infradead.org/pipermail/openwrt-devel/2018-December/020864.html
- NVMEM-on-UBI commit: https://github.com/openwrt/openwrt/commit/73819013eebca620944673e333dc47fb36bec95c
- LED issue #9851: https://github.com/openwrt/openwrt/issues/9851
- ASUS firmware restore: https://www.asus.com/support/faq/1000814/
