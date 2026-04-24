# GL.iNet Research Notes — AR-150 & AR-300 Family

Device identification, variant differentiation, and boot-state detection for automated
OpenWrt provisioning via conwrt.

---

## 1. Device Overview

Unlike the Linksys Velop WHW03 (stock → OpenWrt migration), GL.iNet routers **ship with
OpenWrt-based firmware**. The pipeline is reconfigure/sysupgrade, not factory-flash.

| | AR-150 | AR-300 | AR-300M family |
|---|---|---|---|
| **SoC** | Atheros AR9331 @ 400MHz | Atheros AR9344 @ 560MHz | QCA9531 @ 650MHz |
| **RAM** | 64MB DDR2 | 128MB DDR2 | 128MB DDR2 |
| **Flash** | 16MB NOR (W25Q128) | 16MB NOR | 16MB NOR + optional 128MB NAND |
| **Ethernet** | 1 WAN + 1 LAN (10/100) | 1 WAN + 4 LAN (10/100) | 1–2 ports (variant-dependent) |
| **WiFi** | 2.4GHz 802.11b/g/n 150Mbps | 2.4GHz 300Mbps | 2.4GHz 300Mbps (+ 5GHz on AR300MD) |
| **USB** | 1× USB 2.0 | 2× USB 2.0 + MicroSD | 1× USB 2.0 |
| **Power** | Micro USB 5V/2A | 12V/2A barrel | Micro USB 5V/2A |
| **OpenWrt target** | ath79/generic | ath79/generic | ath79/generic (NOR) or ath79/nand |
| **OpenWrt device** | glinet,gl-ar150 | gl-ar300 (legacy) | glinet,gl-ar300m-lite / -nand / -nor |
| **Status** | Active | Discontinued | Active |

---

## 2. AR-300M Variant Matrix

All AR-300M variants share FCC ID **2AFIW-AR300M**, MAC OUI **94:83:C4**, and default
SSID pattern **GL-AR300M-XXXX**. Network-only identification cannot distinguish them — SSH
required.

| Variant | NOR | NAND | Ethernet | Antenna | 5GHz | Notes |
|---|---|---|---|---|---|---|
| AR300M | 16MB | 128MB | WAN + LAN | Internal PCB | No | Original, dual-flash |
| AR300M-Ext | 16MB | 128MB | WAN + LAN | External RP-SMA | No | External antenna connectors |
| AR300M16 | 16MB | None | WAN + LAN | Internal | No | Cost-reduced, NAND removed |
| AR300M16-Ext | 16MB | None | WAN + LAN | External RP-SMA | No | Cost-reduced + ext antenna |
| AR300M-Lite | 16MB | None | **WAN only** | Internal | No | Budget, single port |
| AR300MD | 16MB | 128MB | WAN + LAN | Internal | Yes (QCA9887) | AR300M + 5GHz module |

### Distinguishing Variants via SSH

```bash
# Flash type — most definitive
cat /proc/mtd
#   6 partitions (mtd0-mtd5, includes "kernel"+"ubi") → dual-flash (AR300M/AR300MD)
#   4 partitions (mtd0-mtd3, only "firmware") → NOR-only (AR300M16/Lite)

# Port count
ls /sys/class/net/ | grep eth
#   eth0 + eth1 → AR300M16 or AR300M (2 ports)
#   eth0 only → AR300M-Lite (1 port)

# 5GHz module
dmesg | grep -i "ath10k\|9887\|5g"
#   Present → AR300MD

# OpenWrt board name
cat /tmp/sysinfo/board_name
#   glinet,gl-ar300m-lite → AR300M-Lite or AR300M16 (same image)
#   glinet,gl-ar300m-nor → AR300M booted from NOR
#   glinet,gl-ar300m-nand → AR300M booted from NAND
```

### Boot Behavior (Dual-Flash Models)

U-Boot always tries NAND first. After **3 consecutive NAND boot failures** it falls back to
NOR. Force NOR boot from SSH:

```bash
fw_setenv bootcount 3 && reboot
# or
glinet_set_next_boot_nor && reboot
```

Side toggle switch on newer U-Boot (Mar 2017+): Left = NAND, Right = NOR
(requires `fw_setenv boot_dev on`).

---

## 3. Identification Signatures

### 3.1 MAC OUI Prefixes

| OUI | Organization | Notes |
|---|---|---|
| **94:83:C4** | GL Technologies (Hong Kong) Limited | Primary, all current GL.iNet devices |
| **E4:95:6E** | Possibly GL.iNet | Reported for some AR-150 (DeviWiki), unconfirmed |

**All GL.iNet devices share 94:83:C4** — cannot distinguish models by OUI alone.

### 3.2 Default Network Behavior

| Firmware State | IP | SSH (22) | HTTP (80) | HTTPS (443) | DHCP Server |
|---|---|---|---|---|---|
| **GL.iNet stock** | 192.168.8.1 | Yes (root) | GL.iNet UI | Yes | Yes |
| **OpenWrt (vanilla)** | 192.168.1.1 | Yes (root, no pw) | LuCI | No | Yes |
| **U-Boot safe mode** | 192.168.1.1 | **No** | uIP/0.9 | No | **No** |

### 3.3 Default SSID & WiFi Password

| Device | SSID Pattern | Default Password |
|---|---|---|
| AR-150 | GL-XXXXX-xxx | `goodlife` |
| AR-300M family | GL-AR300M-XXXX | `goodlife` |

### 3.4 Passive Detection

**Can be detected via:**
- MAC OUI 94:83:C4 → GL.iNet device
- SSID pattern GL-* → GL.iNet (confirm model from SSID)
- Port 83 open (GL.iNet-specific remote admin with serial number auth)

**Cannot distinguish via passive means:**
- No LLDP by default
- No mDNS by default
- No SSDP/UPnP by default
- DHCP vendor class is generic `udhcpc` (BusyBox)

### 3.5 Default Credentials

| | Username | Password | Notes |
|---|---|---|---|
| GL.iNet web UI | admin | Set during first-run wizard (or device label) | |
| SSH (stock) | root | Same as web UI password | May need `HostkeyAlgorithms +ssh-rsa` |
| SSH (OpenWrt) | root | None | First login sets password |
| Port 83 (WAN) | admin | Password + serial number | GL.iNet-specific |

---

## 4. Boot-State Detection

Critical for automation: the script must know whether the device is in U-Boot, GL.iNet stock,
or already running OpenWrt.

### 4.1 Detection Matrix

| Check | U-Boot Safe Mode | GL.iNet Stock | OpenWrt |
|---|---|---|---|
| `curl -sI http://192.168.1.1/` | `Server: uIP/0.9` | Timeout / connection refused | LuCI / openwrt in body |
| `curl -sI http://192.168.8.1/` | Timeout | GL.iNet UI response | Timeout |
| `ssh root@IP` | Connection refused | Password auth | Key or password auth |
| DHCP server | None | Active (192.168.8.x) | Active (192.168.1.x) |
| Ping 192.168.1.1 | Responds | May respond | Responds |
| Ping 192.168.8.1 | No response | Responds | No response |

### 4.2 U-Boot Detection (Definitive)

The **`Server: uIP/0.9`** HTTP header is unique to GL.iNet U-Boot. No other firmware produces
this signature.

```bash
# Detect U-Boot safe mode
HEADER=$(curl -sI --max-time 3 http://192.168.1.1/ 2>/dev/null)
if echo "$HEADER" | grep -q "uIP/0.9"; then
    echo "U-BOOT SAFE MODE DETECTED"
fi

# Confirm by checking content
BODY=$(curl -s --max-time 3 http://192.168.1.1/ 2>/dev/null)
if echo "$BODY" | grep -q "FIRMWARE UPDATE"; then
    echo "U-Boot firmware upload form confirmed"
fi
```

### 4.3 U-Boot HTTP Server Details

Source: `gl-inet/uboot-for-qca95xx` repository — `src/httpd/vendors/httpd.c`

```
IP:       192.168.1.1 (static, no DHCP)
Port:     TCP/80
Server:   uIP/0.9
Content:  Simple HTML form with file upload

Upload endpoints:
  name="firmware" → firmware upgrade
  name="uboot"    → U-Boot bootloader upgrade
  name="art"      → ART partition (WiFi calibration)

Firmware format:
  AR-150:  accepts sysupgrade.bin directly (no factory image needed)
  AR-300M: accepts NOR sysupgrade.bin or NAND factory.img
```

### 4.4 U-Boot Entry Procedure

| Step | AR-150 | AR-300M |
|---|---|---|
| 1. Connect ethernet to PC | Either port | Either port |
| 2. Set PC IP | 192.168.1.2/24 | 192.168.1.2/24 |
| 3. Unplug power | Yes | Yes |
| 4. Hold reset, apply power | Yes | Yes |
| 5. Count red LED blinks | Release on **6th** blink | Release on **6th** blink |
| 6. Success indicator | Left green LED only | Left green LED only |
| 7. Access | http://192.168.1.1 | http://192.168.1.1 |

**Reset hold timing** (from reverse engineering):
- ~5 seconds → web failsafe mode (HTTP server on port 80)
- ~8 seconds → U-Boot serial console
- ~10+ seconds → netconsole (UDP port 6666)

### 4.5 TFTP Recovery (Alternative)

```
TFTP server IP:   192.168.1.1 (router)
Client IP:        192.168.1.2 (your PC)
Filename:         Must contain "tftp" in filename
Port:             UDP/69
```

```bash
# From PC with TFTP client
tftp -i 192.168.1.1 put firmware-tftp.bin
```

---

## 5. OpenWrt Target & Firmware Mapping

### AR-150

```
Target:    ath79/generic
Device:    glinet,gl-ar150
Board:     glinet,gl-ar150
Compat:    qca,ar9330
Arch:      mips_24kc
Firmware:  openwrt-{version}-ath79-generic-glinet_gl-ar150-squashfs-sysupgrade.bin
URL:       https://downloads.openwrt.org/releases/{version}/targets/ath79/generic/
```

### AR-300M Family

```
Target:    ath79/generic (NOR-only models)
           ath79/nand    (dual-flash models)
Devices:   glinet,gl-ar300m-lite  (AR300M-Lite, AR300M16 — NOR only)
           glinet,gl-ar300m-nand   (AR300M booted from NAND)
           glinet,gl-ar300m-nor    (AR300M booted from NOR, NAND-aware)

NOR-only firmware:
  openwrt-{version}-ath79-generic-glinet_gl-ar300m-lite-squashfs-sysupgrade.bin

NAND firmware:
  openwrt-{version}-ath79-nand-glinet_gl-ar300m-nand-squashfs-sysupgrade.bin
  openwrt-{version}-ath79-nand-glinet_gl-ar300m-nor-squashfs-sysupgrade.bin
```

### AR-300 (Discontinued)

```
Target:    ath79/generic (legacy ar71xx)
Device:    gl-ar300
Firmware:  openwrt-{version}-ath79-generic-gl-ar300-squashfs-sysupgrade.bin
```

---

## 6. Flash Procedure

### 6.1 GL.iNet Stock → Vanilla OpenWrt (Sysupgrade)

Since GL.iNet already runs OpenWrt, the simplest path is sysupgrade via SSH:

```bash
# 1. Copy firmware to device
scp firmware.bin root@192.168.8.1:/tmp/

# 2. Sysupgrade
ssh root@192.168.8.1 "sysupgrade -n /tmp/firmware.bin"

# -n flag: do not preserve configuration (clean slate)
# Device reboots, IP changes to 192.168.1.1
```

### 6.2 GL.iNet Web UI Upgrade

```
1. Browse to http://192.168.8.1
2. More Settings → Upgrade
3. Select "Local Upgrade"
4. Upload .bin file
5. Uncheck "Keep settings" for clean slate
6. Wait 2-3 minutes
7. IP changes to 192.168.1.1
```

### 6.3 U-Boot Recovery (If Bricked)

```
1. Enter U-Boot safe mode (see §4.4)
2. Browse to http://192.168.1.1
3. Upload firmware .bin file
4. Wait 10-30 seconds (AR-150) or up to 3 minutes (AR-300M NAND)
5. Device reboots automatically
```

### 6.4 AR-300M Dual-Flash Considerations

For AR-300M with dual flash (NAND + NOR):

1. **Recommended**: Flash to NOR (recovery partition), keep NAND as stock backup
2. NOR firmware includes NAND drivers, so NAND can be flashed later
3. `glinet_set_next_boot_nor` forces NOR boot if NAND is active
4. 3 failed NAND boots → auto-fallback to NOR (safety net)

---

## 7. Post-Flash Configuration

### 7.1 Conwrt Standard Config

The standard conwrt pipeline configures:
1. Hostname = first 12 chars of `sha256(MAC_UPPERCASE_WITH_COLONS)`
2. SSH key in `/etc/dropbear/authorized_keys`
3. WiFi STA on radio0 (2.4GHz) as WAN
4. Dropbear: PasswordAuth=off, RootPasswordAuth=off

### 7.2 GL.iNet-Specific Differences from WHW03

| Setting | WHW03 | GL.iNet AR-150/AR-300M |
|---|---|---|
| Default LAN IP | 192.168.1.1 | 192.168.8.1 (stock) or 192.168.1.1 (OpenWrt) |
| WiFi STA radio | radio1 | radio0 |
| WiFi STA interface | phy1-sta0 | phy0-sta0 |
| SSH on fresh OpenWrt | root, no password | root, no password (same) |
| Stock identification | JNAP API | SSH + board_name |
| Flash method | JNAP /jcgi/ upload | sysupgrade or web UI |
| Stock credentials | admin:admin | root / device-password |

---

## 8. Recovery Reference

### Boot States & Recovery

| State | Symptom | Recovery |
|---|---|---|
| Normal operation | Web UI at 192.168.8.1 or 192.168.1.1 | N/A |
| Bad config | Boots but misbehaving | OpenWrt failsafe: press `f` during boot |
| Corrupt firmware | No boot, U-Boot still works | U-Boot safe mode → reflash |
| Corrupt U-Boot | No response | Serial UART (115200 8N1) → TFTP flash |
| Corrupt ART | WiFi broken | **Cannot recover** (unique calibration data) |

### Brick Risk Assessment

| Device | Risk Level | Why |
|---|---|---|
| AR-150 | **Low** | U-Boot safe mode always works, single flash is simple |
| AR-300M (NOR-only) | **Low** | Same as AR-150 |
| AR-300M (dual-flash) | **Low-Medium** | NOR fallback provides safety net, but dual-boot adds complexity |

---

## 9. Automated Detection Flowchart

```
Device appears on ethernet
│
├─ Ping 192.168.1.1 → responds?
│   ├─ YES → curl -sI http://192.168.1.1/
│   │   ├─ Server: uIP/0.9 → U-BOOT SAFE MODE
│   │   │   → Upload firmware via HTTP POST (name="firmware")
│   │   │
│   │   ├─ LuCI / openwrt in body → OPENWRT (vanilla or GL.iNet flashed)
│   │   │   → SSH in, check board_name, configure
│   │   │
│   │   └─ GL.iNet UI / no match → GL.iNet STOCK at wrong IP?
│   │       → Try SSH, check /etc/gl_version
│   │
│   └─ NO → Ping 192.168.8.1 → responds?
│       ├─ YES → curl http://192.168.8.1/
│       │   ├─ GL.iNet UI detected → GL.iNet STOCK FIRMWARE
│       │   │   → SSH root@192.168.8.1, sysupgrade
│       │   │
│       │   └─ No match → Unknown device
│       │
│       └─ NO → Device not ready or not connected
│           → Wait and retry (stock boot takes 60-90s)
```

---

## 10. GL-MT3000 (Beryl AX) — WiFi 6 Travel Router

### 10.1 Hardware Overview

The MT3000 is a significant architectural departure from the AR-150/AR-300M family. It uses
MediaTek's Filogic platform (aarch64) instead of Qualcomm Atheros (mips).

| | MT3000 | AR-150 | AR-300M |
|---|---|---|---|
| **SoC** | MediaTek MT7981B dual-core Cortex-A53 @ 1.3GHz | Atheros AR9331 @ 400MHz | QCA9531 @ 650MHz |
| **Arch** | aarch64_cortex-a53 | mips_24kc | mips_24kc |
| **RAM** | 512MB DDR4 | 64MB DDR2 | 128MB DDR2 |
| **Flash** | 128MB NAND | 16MB NOR | 16MB NOR + optional 128MB NAND |
| **WiFi** | 2.4GHz + 5GHz WiFi 6 (MT7981B + MT7976C) | 2.4GHz 802.11b/g/n | 2.4GHz 802.11b/g/n |
| **Ethernet** | 1x WAN (2.5G) + 1x LAN (1G) | 1 WAN + 1 LAN (10/100) | 1-2 ports (variant-dependent) |
| **USB** | USB 3.0 | USB 2.0 | USB 2.0 |
| **Power** | USB-C 5V/3A | Micro USB 5V/2A | Micro USB 5V/2A |
| **OpenWrt target** | mediatek/filogic | ath79/generic | ath79/generic or ath79/nand |
| **OpenWrt device** | glinet_gl-mt3000 | glinet_gl-ar150 | glinet_gl-ar300m-* |
| **Default IP (stock)** | 192.168.8.1 | 192.168.8.1 | 192.168.8.1 |
| **Default IP (OpenWrt)** | 192.168.1.1 | 192.168.1.1 | 192.168.1.1 |
| **MAC OUI** | 94:83:C4 | 94:83:C4 | 94:83:C4 |

### 10.2 Boot-State Detection

Same detection matrix as AR-150/AR-300M. The uIP/0.9 U-Boot signature works identically:

| Check | U-Boot Safe Mode | GL.iNet Stock | OpenWrt |
|---|---|---|---|
| `curl -sI http://192.168.1.1/` | `Server: uIP/0.9` | Timeout | LuCI / openwrt in body |
| `curl -sI http://192.168.8.1/` | Timeout | GL.iNet UI response | Timeout |
| SSH | Connection refused | Password auth | Key or password auth |

### 10.3 U-Boot Entry Procedure

The MT3000 has a **different LED pattern** from the AR-150/AR-300M family:

| Step | MT3000 | AR-150 / AR-300M |
|---|---|---|
| 1. Connect ethernet to PC | Either port | Either port |
| 2. Set PC IP | 192.168.1.2/24 | 192.168.1.2/24 |
| 3. Unplug power | Yes | Yes |
| 4. Hold reset, apply power | Pinhole on side | Regular button |
| 5. LED pattern | Blue flashes ~6x, then **solid white** = ready | Red blinks, release on 6th, **green LED** = ready |
| 6. Access | http://192.168.1.1 | http://192.168.1.1 |

Upload field name is `firmware` (same as AR-150/AR-300M). Flash takes ~3 minutes (NAND).

Use Chrome or Edge for U-Boot web UI. Firefox has known issues that may brick the device.

Headless alternative:
```bash
curl -sk --max-time 300 -F firmware=@image.bin http://192.168.1.1/
```

### 10.4 Flash Procedure

**Sysupgrade (from GL.iNet stock):**
```bash
scp -O firmware.bin root@192.168.8.1:/tmp/firmware.bin
ssh root@192.168.8.1 "sysupgrade -n /tmp/firmware.bin"
# Exit code 246 is expected (SSH killed by reboot)
```

**U-Boot recovery (if bricked):**
```
1. Enter U-Boot safe mode (see 10.3)
2. Upload firmware via HTTP POST (name="firmware")
3. Wait ~3 minutes
4. Device reboots automatically
```

### 10.5 Post-Flash Configuration Differences

| Setting | MT3000 | AR-150 / AR-300M |
|---|---|---|
| WiFi STA radio | radio0 | radio0 |
| WiFi STA interface | phy0-sta0 | phy0-sta0 |
| OpenWrt target | mediatek/filogic | ath79/generic or ath79/nand |
| Default packages | fitblk, wpad-basic-mbedtls, libopenssl3 | Standard ath79 packages |
| LuCI included | No | No |
| openssl-util | No | No |

Key MT3000-specific packages from default install:
- `fitblk` — MT7981 boot partition helper (essential, do not remove)
- `wpad-basic-mbedtls` — WPA supplicant (mbedtls backend, NOT openssl)
- `libopenssl3` / `libustream-mbedtls` — TLS libraries only, no CLI tools

### 10.6 Default OpenWrt Firmware

```
Target:    mediatek/filogic
Device:    glinet_gl-mt3000
Arch:      aarch64_cortex-a53
Firmware:  openwrt-{version}-mediatek-filogic-glinet_gl-mt3000-squashfs-sysupgrade.bin
URL:       https://downloads.openwrt.org/releases/{version}/targets/mediatek/filogic/
```

---

## 11. Sources

- OpenWrt Wiki: https://openwrt.org/toh/gl.inet/gl-ar150
- GL.iNet AR-150 specs: https://docs.gl-inet.com/router/en/2/hardware/ar150/
- GL.iNet AR-300M specs: https://docs.gl-inet.com/router/en/2/hardware/ar300m/
- GL.iNet U-Boot source: https://github.com/gl-inet/uboot-for-qca95xx
- GL.iNet U-Boot docs: https://docs.gl-inet.com/router/en/3/dev/uboot/
- GL.iNet debrick guide: https://docs.gl-inet.com/router/en/3/tutorials/debrick/
- OpenWrt AR-300M NAND support commit: `55e6c903ae` in openwrt/openwrt
- AR-300M16 flashing guide: https://lowtek.ca/roo/2023/gl-inet-gl-ar300m16-with-openwrt-22-03-05/
- AR-150 DTS: `target/linux/ath79/dts/ar9330_glinet_gl-ar150.dts` in openwrt/openwrt
- MAC OUI lookup: https://www.netify.ai/resources/macs/brands/gl-inet
