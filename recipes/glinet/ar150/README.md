# GL.iNet AR-150 — conwrt Recipe

## Hardware

| Spec | Value |
|---|---|
| SoC | Atheros AR9331 @ 400MHz |
| RAM | 64MB DDR2 |
| Flash | 16MB NOR (W25Q128) |
| Ethernet | 1 WAN + 1 LAN (10/100) |
| WiFi | 2.4GHz 802.11b/g/n, 150Mbps |
| USB | 1× USB 2.0 |
| Power | Micro USB 5V/2A |
| Dimensions | 58×58×25mm white cube |

## Variants

All four variants run the same firmware. The differences are physical (antenna type, PoE support).

| Variant | Antenna | PoE | Notes |
|---|---|---|---|
| AR150 | Internal PCB | No | Base model |
| AR150-Ext | External RP-SMA | No | Screw-on antenna connectors |
| AR150-PoE | Internal PCB | Yes | Powered over ethernet |
| AR150-Ext-PoE | External RP-SMA | Yes | External antenna + PoE |

One firmware image covers all four. No variant-specific flashing needed.

## Physical Identification

- Bottom label: model name printed as **GL-AR150** (or variant name)
- Form factor: small white plastic cube, 58×58×25mm
- 2 ethernet ports on one side (no port labels on older units)
- Micro USB power port
- Single orange WiFi LED on front

## Network Identification

| Property | Value |
|---|---|
| MAC OUI | 94:83:C4 (all GL.iNet devices share this) |
| Default IP (stock) | 192.168.8.1 |
| Default IP (OpenWrt) | 192.168.1.1 |
| Default SSID | GL-XXXXX-xxx |
| Default WiFi password | `goodlife` |
| Open ports (stock) | 22 (SSH), 80 (HTTP), 83 (GL.iNet remote admin) |

⚠️ MAC OUI 94:83:C4 is shared across every GL.iNet device. It confirms the vendor but not the model. Use the SSID pattern or bottom label to confirm you have an AR-150.

## OpenWrt Target

```
Target:    ath79/generic
Device:    glinet,gl-ar150
Board:     glinet,gl-ar150
Arch:      mips_24kc
Firmware:  openwrt-{version}-ath79-generic-glinet_gl-ar150-squashfs-sysupgrade.bin
URL:       https://downloads.openwrt.org/releases/{version}/targets/ath79/generic/
```

U-Boot accepts the sysupgrade image directly. No factory image needed.

## Boot States

| State | IP | Detection Method | What You See |
|---|---|---|---|
| U-Boot safe mode | 192.168.1.1 (static, no DHCP) | `curl -sI` returns `Server: uIP/0.9` | Left green LED only, upload page at http://192.168.1.1 |
| GL.iNet stock | 192.168.8.1 (DHCP) | GL.iNet web UI responds, port 83 open | Normal boot LEDs |
| OpenWrt | 192.168.1.1 (DHCP) | LuCI page or `openwrt` in response body | Normal OpenWrt boot sequence |
| OpenWrt failsafe | 192.192.192.1 | Serial console required | Power LED blinks rapidly |

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

### U-Boot Safe Mode Procedure

1. Connect ethernet from PC to either AR-150 port
2. Set PC to static IP 192.168.1.2/24
3. Unplug AR-150 power
4. Hold reset button, plug in power
5. Watch for red LED blinks (there will be 5)
6. Release reset on the **6th** blink
7. Left green LED lights up alone = success
8. Open http://192.168.1.1 in browser

### Reset Hold Timing

| Hold Duration | Result |
|---|---|
| ~5 seconds | Web failsafe mode (HTTP server on port 80) |
| ~8 seconds | U-Boot serial console |
| ~10+ seconds | Netconsole (UDP port 6666) |

## Recovery

### U-Boot HTTP Recovery

1. Enter U-Boot safe mode (see above)
2. Browse to http://192.168.1.1
3. Upload firmware using the form (field name: `firmware`)
4. Wait 10-30 seconds for flash and reboot
5. Device comes up on 192.168.1.1 (OpenWrt) or 192.168.8.1 (stock)

⚠️ The U-Boot page also exposes `uboot` and `art` upload fields. Do not touch these. Flashing the wrong U-Boot or ART partition will brick the device permanently. Only use the `firmware` field.

### TFTP Recovery

If HTTP upload fails, TFTP works as a fallback:

```bash
# Set PC to 192.168.1.2/24
# Start TFTP server serving the firmware file
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

For truly bricked devices where U-Boot is unresponsive:

- Pinout: standard AR9331 UART header (3.3V, TX, RX, GND)
- Baud: 115200
- Format: 8N1
- Flash via U-Boot command line with TFTP

⚠️ If the ART partition (WiFi calibration data) is corrupted, the device becomes a wired-only router. ART data is unique per unit and cannot be regenerated.

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
