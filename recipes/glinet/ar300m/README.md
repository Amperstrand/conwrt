# GL.iNet AR-300M Family — conwrt Recipe

## Hardware

| Spec | Value |
|---|---|
| SoC | QCA9531 @ 650MHz |
| RAM | 128MB DDR2 |
| Flash | 16MB NOR + optional 128MB NAND (variant-dependent) |
| WiFi | 2.4GHz 802.11b/g/n, 300Mbps (+ 5GHz on AR300MD) |
| USB | 1× USB 2.0 |
| Power | Micro USB 5V/2A |

## Variant Matrix

| Variant | NAND | Ethernet Ports | Antenna | 5GHz | OpenWrt Device |
|---|---|---|---|---|---|
| AR300M | 128MB | WAN + LAN | Internal PCB | No | glinet,gl-ar300m-nand |
| AR300M-Ext | 128MB | WAN + LAN | External RP-SMA | No | glinet,gl-ar300m-nand |
| AR300M16 | None | WAN + LAN | Internal | No | glinet,gl-ar300m-lite |
| AR300M16-Ext | None | WAN + LAN | External RP-SMA | No | glinet,gl-ar300m-lite |
| AR300M-Lite | None | WAN only | Internal | No | glinet,gl-ar300m-lite |
| AR300MD | 128MB | WAN + LAN | Internal | Yes (QCA9887) | glinet,gl-ar300m-nand |

## Physical Identification

⚠️ All AR-300M variants share FCC ID **2AFIW-AR300M**. You cannot tell them apart by looking at the FCC label.

### What to check

| Check | What to look for | Tells you |
|---|---|---|
| Bottom label | Printed model name: GL-AR300M, GL-AR300M16, or GL-AR300M-Lite | Rough variant group |
| Ethernet jack count | 1 port = Lite, 2 ports = others | Lite vs non-Lite |
| External antenna connectors | RP-SMA jacks on sides | -Ext variant |
| 5GHz module | QCA9887 chip visible inside | AR300MD |

### What you cannot determine physically

- Whether NAND is present (AR300M vs AR300M16)
- Exact OpenWrt target without booting or SSH

## Network Identification

| Property | Value |
|---|---|
| MAC OUI | 94:83:C4 (shared across ALL GL.iNet products) |
| Default IP (stock) | 192.168.8.1 |
| Default IP (OpenWrt) | 192.168.1.1 |
| Default SSID | GL-AR300M-XXXX |
| Default WiFi password | `goodlife` |
| Open ports (stock) | 22 (SSH), 80 (HTTP), 83 (GL.iNet remote admin) |

⚠️ MAC OUI and SSID are identical across all six variants. Network-only identification cannot distinguish AR300M from AR300M16 from AR300M-Lite. SSH access is required for exact identification.

## SSH Variant Identification

SSH into the device on 192.168.8.1 (stock) or 192.168.1.1 (OpenWrt), then run these checks in order.

### 1. Flash layout (most definitive)

```bash
cat /proc/mtd
```

| Output | Meaning |
|---|---|
| 6 partitions (mtd0 through mtd5, includes "kernel" and "ubi") | Dual-flash: AR300M, AR300M-Ext, or AR300MD |
| 4 partitions (mtd0 through mtd3, only "firmware") | NOR-only: AR300M16, AR300M16-Ext, or AR300M-Lite |

### 2. Port count

```bash
ls /sys/class/net/ | grep eth
```

| Output | Meaning |
|---|---|
| `eth0` only | AR300M-Lite (single WAN port) |
| `eth0` and `eth1` | All other variants |

### 3. 5GHz module check

```bash
dmesg | grep -i "ath10k\|9887\|5g"
```

| Output | Meaning |
|---|---|
| Matches found | AR300MD (has QCA9887 5GHz radio) |
| No matches | All other variants |

### 4. OpenWrt board name (final confirmation)

```bash
cat /tmp/sysinfo/board_name
```

| Board Name | Variant |
|---|---|
| `glinet,gl-ar300m-lite` | AR300M-Lite or AR300M16 (same image) |
| `glinet,gl-ar300m-nor` | AR300M booted from NOR partition |
| `glinet,gl-ar300m-nand` | AR300M or AR300MD booted from NAND |

### Decision flow

```
cat /proc/mtd
├─ 4 partitions → NOR-only
│   └─ ls eth ports
│       ├─ eth0 only → AR300M-Lite
│       └─ eth0+eth1 → AR300M16 or AR300M16-Ext (check for external antenna)
└─ 6 partitions → Dual-flash
    └─ dmesg | grep ath10k
        ├─ Found → AR300MD
        └─ Not found → AR300M or AR300M-Ext (check for external antenna)
```

## OpenWrt Targets

| Variant | Target | Device Name | Firmware Filename |
|---|---|---|---|
| AR300M-Lite | ath79/generic | glinet,gl-ar300m-lite | `openwrt-{ver}-ath79-generic-glinet_gl-ar300m-lite-squashfs-sysupgrade.bin` |
| AR300M16 | ath79/generic | glinet,gl-ar300m-lite | Same as AR300M-Lite |
| AR300M16-Ext | ath79/generic | glinet,gl-ar300m-lite | Same as AR300M-Lite |
| AR300M (NAND) | ath79/nand | glinet,gl-ar300m-nand | `openwrt-{ver}-ath79-nand-glinet_gl-ar300m-nand-squashfs-sysupgrade.bin` |
| AR300M (NOR) | ath79/nand | glinet,gl-ar300m-nor | `openwrt-{ver}-ath79-nand-glinet_gl-ar300m-nor-squashfs-sysupgrade.bin` |
| AR300MD (NAND) | ath79/nand | glinet,gl-ar300m-nand | Same as AR300M NAND |

NOR-only models (AR300M16, AR300M16-Ext, AR300M-Lite) all use the same firmware image. Dual-flash models have separate NAND and NOR images.

## Boot States

| State | IP | Detection Method | What You See |
|---|---|---|---|
| U-Boot safe mode | 192.168.1.1 (static, no DHCP) | `curl -sI` returns `Server: uIP/0.9` | Left green LED only, upload page at http://192.168.1.1 |
| GL.iNet stock | 192.168.8.1 (DHCP) | GL.iNet web UI responds, port 83 open | Normal boot LEDs |
| OpenWrt | 192.168.1.1 (DHCP) | LuCI page or `openwrt` in response body | Normal OpenWrt boot sequence |
| OpenWrt failsafe | 192.192.192.1 | Serial console required | Power LED blinks rapidly |

### Dual-Flash Boot Behavior (AR300M / AR300M-Ext / AR300MD)

U-Boot always tries NAND first. After **3 consecutive NAND boot failures** it falls back to NOR automatically. This is a built-in safety net: if NAND gets corrupted, the device still boots.

Quick detection:

```bash
# Check for U-Boot
HEADER=$(curl -sI --max-time 3 http://192.168.1.1/ 2>/dev/null)
echo "$HEADER" | grep -q "uIP/0.9" && echo "U-BOOT SAFE MODE"

# Check for stock firmware
curl -s --max-time 3 http://192.168.8.1/ | grep -q "GL.iNet" && echo "STOCK FIRMWARE"
```

## Button Operations

| Operation | Button | Timing | LED Pattern | Result |
|---|---|---|---|---|
| U-Boot safe mode | Reset | Hold reset, apply power, release on **6th blink** (after 5 red blinks) | Red blinks → left green LED only | HTTP upload server at 192.168.1.1 |
| OpenWrt failsafe | `f` key | Press during boot on serial console | Power LED blinks rapidly | Failsafe shell at 192.192.192.1 |
| Factory reset | Reset | Hold 10+ seconds while powered on | LEDs flash | Returns to GL.iNet stock defaults |
| NAND/NOR toggle | Side switch (on newer U-Boot, Mar 2017+) | Flip while powered off | N/A | Left = NAND, Right = NOR |

### Side Toggle Switch (Dual-Flash Models Only)

The physical toggle switch on the side of dual-flash units selects the boot device. This only works on U-Boot versions from March 2017 and later.

| Switch Position | Boot Device | Requirement |
|---|---|---|
| Left | NAND | Default, no config needed |
| Right | NOR | Requires `fw_setenv boot_dev on` |

Enable the toggle switch first:

```bash
fw_setenv boot_dev on
```

### Reset Hold Timing

| Hold Duration | Result |
|---|---|
| ~5 seconds | Web failsafe mode (HTTP server on port 80) |
| ~8 seconds | U-Boot serial console |
| ~10+ seconds | Netconsole (UDP port 6666) |

## Dual-Flash Boot Behavior

On AR300M, AR300M-Ext, and AR300MD, U-Boot manages two flash chips:

1. **Normal boot**: NAND first (larger, faster)
2. **After 3 NAND failures**: automatic fallback to NOR
3. **Force NOR from SSH**:

```bash
# Option A: increment boot failure counter
fw_setenv bootcount 3 && reboot

# Option B: use GL.iNet helper
glinet_set_next_boot_nor && reboot
```

⚠️ Flashing to NOR first is the recommended approach. The NOR firmware includes NAND drivers, so you can flash NAND later. If NAND gets bricked, the NOR fallback means the device is always recoverable.

For NOR-only models (AR300M16, AR300M16-Ext, AR300M-Lite), none of this applies. They have a single flash chip and boot normally.

## Recovery

### U-Boot HTTP Recovery

1. Enter U-Boot safe mode (hold reset, apply power, release on 6th blink)
2. Set PC to 192.168.1.2/24
3. Browse to http://192.168.1.1
4. Upload firmware using the form (field name: `firmware`)
5. Wait 10-30 seconds (NOR) or up to 3 minutes (NAND)
6. Device reboots automatically

⚠️ The U-Boot page also exposes `uboot` and `art` upload fields. Do not touch these. Flashing the wrong U-Boot or ART partition will brick the device permanently. Only use the `firmware` field.

### Dual-Flash Recovery

If NAND is bricked, the device is still recoverable:

1. Force NOR boot: `fw_setenv bootcount 3 && reboot` (if you still have SSH)
2. If SSH is gone, enter U-Boot safe mode and flash the NOR image
3. Once booted from NOR, flash NAND from within OpenWrt

### TFTP Recovery

```bash
# Set PC to 192.168.1.2/24
# Filename MUST contain "tftp" or U-Boot ignores it
tftp -i 192.168.1.1 put firmware-tftp.bin
```

| Parameter | Value |
|---|---|
| TFTP server IP (router) | 192.168.1.1 |
| Client IP (your PC) | 192.168.1.2 |
| Filename requirement | Must contain "tftp" |
| Port | UDP/69 |

### Serial Recovery

For devices where U-Boot is unresponsive:

- Pinout: standard QCA9531 UART header (3.3V, TX, RX, GND)
- Baud: 115200
- Format: 8N1
- Flash via U-Boot command line with TFTP

⚠️ If the ART partition (WiFi calibration data) is corrupted, the device becomes wired-only. ART data is unique per unit and cannot be regenerated.

## Post-Flash Configuration

After flashing vanilla OpenWrt, the conwrt pipeline applies:

| Setting | Value |
|---|---|
| WiFi STA radio | `radio0` (2.4GHz) |
| WiFi STA interface | `phy0-sta0` (used as WAN) |
| Hostname | First 12 chars of `sha256(MAC_UPPERCASE_WITH_COLONS)` |
| SSH | Key auth only, password auth disabled |
| Dropbear | `PasswordAuth=off`, `RootPasswordAuth=off` |

```bash
# After sysupgrade, device is at 192.168.1.1
ssh root@192.168.1.1  # no password on fresh OpenWrt
```
