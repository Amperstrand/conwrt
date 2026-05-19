# Zyxel NR7101 — Validated Notes

## Hardware
- SoC: MediaTek MT7621A dual-core MIPS 1004Kc @ 880MHz
- RAM: 256MB DDR3
- Flash: SPI NAND 256MB
- Ethernet: 1x GigE (PoE 802.3at, single port)
- WiFi: none (5G/NR modem only)
- Modem: Quectel RG502Q-EA (5G NR Sub-6, NSA/SA, integrated USB)
- Serial: UART internal header, 115200 8N1
- Enclosure: IP68 outdoor, PoE powered
- Board revision: A1 (board_name: `zyxel,nr7101`)
- MAC OUI observed: `4C:C5:3E`

## OpenWrt
- Target: `ramips/mt7621`
- Device: `zyxel,nr7101`
- Supported since: 22.03.0
- Default IP: 192.168.1.1
- LuCI available on port 80 (redirect `/` → `/cgi-bin/luci/`)
- SSH: root@192.168.1.1, no password by default
- No DHCP server on LAN by default (unlike most routers)

## Modem (Quectel RG502Q-EA)

### USB topology
The modem appears as a single USB device with 5 interfaces:
- Interface 0 → `/dev/ttyUSB0` (DIAG)
- Interface 1 → `/dev/ttyUSB1` (AT commands)
- Interface 2 → `/dev/ttyUSB2` (AT commands — primary)
- Interface 3 → `/dev/ttyUSB3` (AT commands)
- Interface 4 → `/dev/cdc-wdm0` (QMI control) + `wwan0` (network data)

Driver: `option1` for serial ports, `qmi_wwan` for cdc-wdm0/wwan0.

### AT command interface
AT commands work on `/dev/ttyUSB2` regardless of network configuration state. This is the reliable path — uqmi via cdc-wdm0 fails when the WAN interface is not configured (e.g. after `sysupgrade -n`).

On OpenWrt (busybox ash), use file descriptors for reliable AT communication:
```sh
# Flush stale data first
cat /dev/ttyUSB2 > /dev/null 2>&1 & D=$!; sleep 1; kill $D 2>/dev/null; wait $D 2>/dev/null

# Send command and read response
exec 3<>/dev/ttyUSB2
printf "AT+CPIN?\r\n" >&3
sleep 3
for i in 1 2 3 4 5; do
    read -t 2 LINE <&3 2>/dev/null || break
    case "$LINE" in
        "AT+CPIN?"|"") continue ;;   # skip echo and empty lines
        OK|ERROR*) echo "$LINE"; break ;;
        *) echo "$LINE" ;;
    esac
done
exec 3>&-
```

The `sleep` values matter — the modem needs 2-3 seconds between command and response. The `case` filter skips the command echo and blank lines that the modem sends.

**Pitfall**: busybox `sleep` only accepts integers — `sleep 0.5` fails with "invalid number". Use `sleep 1` minimum.

**Pitfall**: After aggressive AT command sequences (especially `AT+CEMODE` or `AT+COPS` with manual network selection), the modem's QMI service can crash. Recovery requires a device reboot. Don't send rapid-fire commands — wait 3+ seconds between each.

### Key AT commands (modem inventory)
| Info | Command | Response example |
|------|---------|-----------------|
| Model | `ATI` | Quectel / RG502Q-EA / Revision: RG502QEAACR13A03M4G_ZYXEL |
| SIM status | `AT+CPIN?` | `+CPIN: READY` |
| ICCID | `AT+CCID` | `+CCID: 89470715000046815804` |
| IMSI | `AT+CIMI` | `242140003511580` |
| Operator | `AT+COPS?` | `+COPS: 0,0,"ice+",13` |
| Signal | `AT+CSQ` | `+CSQ: 19,99` (RSSI 19 = ~-77 dBm) |
| Serving cell | `AT+QENG="servingcell"` | LTE FDD, MCC/MNC, EARFCN, RSRP, RSRQ, SNR |
| USB mode | `AT+QCFG="usbnet"` | `0` = QMI (default) |

### uqmi interface
uqmi works via `/dev/cdc-wdm0` but only when the WAN interface is properly configured:
```sh
uqmi -d /dev/cdc-wdm0 --get-signal-info       # signal strength
uqmi -d /dev/cdc-wdm0 --get-serving-system     # operator, registration
uqmi -d /dev/cdc-wdm0 --get-data-status        # "connected" or "disconnected"
```

After `sysupgrade -n`, uqmi returns `"Failed to connect to service"` until the WAN interface is configured. AT commands always work.

## Cellular WAN Configuration

### Default state after sysupgrade
OpenWrt 25.12.4 ships with a QMI WAN interface pre-configured:
```
config interface 'wan'
    option device '/dev/cdc-wdm0'
    option proto 'qmi'
    option apn 'auto'
```
The APN is set to `auto` which attempts to detect the APN from the SIM. This may or may not work depending on carrier. For ice+ Norway, manual APN is required.

### Setting up cellular data (ice+ Norway, verified working 2026-05-19)
```sh
# Set the APN for ice+ Norway
uci set network.wan.apn='ice.net'
uci commit network
ifup wan
```

Wait ~15 seconds, then verify:
```sh
ifstatus wan          # "up": true
ip addr show wwan0    # should show an IP like 100.x.x.x/30
ping -c 3 8.8.8.8     # should work
```

### ice+ Norway carrier details (verified)
| Setting | Value |
|---------|-------|
| APN | `ice.net` |
| Authentication | none |
| MCC/MNC | 242/14 |
| Network | LTE FDD |
| Band | 3 (1800 MHz) |
| DNS (observed) | XXX.XXX.XXX.X, XXX.XXX.XXX.X |

The SIM registers as "home" on ice+ (not roaming). Data roaming does not need to be enabled for domestic use. ice+ recommends enabling data roaming in Norway for best coverage (roams on Telenor/Telia where ice+ has no own coverage).

### Performance (LTE Band 3, indoor)
- Download: ~56 Mbps (10MB Cloudflare test, 1.43s)
- Latency: ~43ms to 8.8.8.8
- Signal: RSRP -74 dBm (good), RSRQ -13 dB, SINR 9 dB
- These are LTE-only measurements; 5G NR performance is untested

### Troubleshooting

**SIM not detected (`+CME ERROR: 13`)**
- Reseat the SIM card in the outdoor enclosure
- Reboot the device: `reboot`
- Wait for full modem init (~30s after boot)
- Re-check with `AT+CPIN?`

**QMI service failure (`Failed to connect to service`)**
- Usually caused by aggressive AT commands breaking the QMI service
- Reboot the device to recover
- The netifd QMI proto handler will retry on boot

**WAN interface stays down**
- Check `ifstatus wan` for error messages
- Check system log: `logread | grep netifd`
- Verify SIM is detected: AT `AT+CPIN?` should return `+CPIN: READY`
- Verify network registration: `AT+COPS?` should show operator
- Try manual network registration: `AT+COPS=0` (automatic)
- Increase delay: `uci set network.wan.delay='15'`

## Flash Procedure: sysupgrade (verified 2026-05-19)

The NR7101 arrived running OpenWrt 24.10.5. Upgraded to 25.12.4 via sysupgrade.

1. Verify current firmware: `cat /etc/openwrt_release`
2. SCP image to device: `scp -O openwrt-25.12.4-...-sysupgrade.bin root@192.168.1.1:/tmp/`
   - **Must use `scp -O`** — OpenWrt dropbear lacks `/usr/libexec/sftp-server`
3. Flash: `sysupgrade -n /tmp/openwrt-*.bin`
4. Wait ~60s for boot (SSH comes up at ~60s)
5. Verify: `ssh root@192.168.1.1 'cat /etc/openwrt_release'`

## Partition Layout (verified)
```
mtd0: Bootloader   (512K)   — U-Boot
mtd1: Config       (512K)   — U-Boot environment
mtd2: Factory      (256K)   — IRREPLACEABLE (serial, certs, calibration)
mtd3: Kernel       (~31M)   — Primary firmware
mtd4: ubi          (~27M)   — Rootfs (UBI)
mtd5: Kernel2      (~31M)   — Recovery firmware (also overwritten by zycast)
mtd6: wwan         (1M)     — Modem configuration
mtd7: data         (16M)    — User data
mtd8: rom-d        (1M)     — OEM recovery?
mtd9: reserve      (512K)   — Reserved
```

**Important**: mtd2 (Factory) is irreplaceable — contains device serial, certificates, and calibration data. Backup before any low-level flashing.

## Zycast (multicast flash)
- Zycast writes both Kernel and Kernel2 partitions simultaneously
- Uses initramfs-recovery image with zytrx header
- Multicast group: 225.0.0.0:5631
- Device enters zycast listen mode from Z-Loader (not during normal boot)
- **UNTESTED** on this device — prepared but not executed

## Boot Timing
- OpenWrt boot to SSH: ~60s
- Modem init: additional ~15-30s after SSH available
- First AT commands may fail if sent too early after boot — wait 30s

## SCP Note
OpenWrt dropbear lacks SFTP server. Always use `scp -O` (legacy SCP protocol):
```sh
scp -O file.bin root@192.168.1.1:/tmp/
```

## Modem Firmware (Quectel RG502Q-EA)

### Current firmware
`RG502QEAACR13A03M4G_ZYXEL` — Zyxel-custom build of Quectel RG502Q-EA firmware.

### Firmware naming convention
```
RG502QEAACR13A03M4G_ZYXEL
       │││  │││  │└── 4G/5G capable
       │││  │││  └── Release 13, version A03
       │││  └── Custom variant (see below)
       ││└── Product line identifier
       │└── Product code (RG502Q-EA)
       └── Quectel prefix
```

### Two incompatible firmware tracks
- **AAAR** (`RG502QEAAAR...`) — Generic Quectel firmware, available from Quectel forums
- **AACR** (`RG502QEAACR...`) — **Zyxel-custom firmware**, only available from Zyxel

These tracks are **NOT interchangeable**. Flashing AAAR onto an AACR device results in "illegal image" error. Our NR7101 uses the AACR track.

### Known firmware versions (AACR/Zyxel track)

| Version | Status | Notes |
|---------|--------|-------|
| R13A02M4G_ZYXEL | Older | Available from Zyxel download page |
| **R13A03M4G_ZYXEL** | **Installed** | Works well, CVE-2022-26147 patched |
| R13A04M4G_ZYXEL | Buggy | Region-locking bug — blocks data roaming, some users couldn't connect. Zyxel V1.00(ABUV.10)C0 |
| R13A05M4G_ZYXEL | Latest (Jan 2025) | Mentioned in NR7101 V1.00(ABUV.11)C0 community thread. Not publicly downloadable |

### Known firmware versions (AAAR/Generic track — NOT compatible with our device)

| Version | Notes |
|---------|-------|
| R11A06M4G | Older generic |
| R11A07M4G | Older generic |
| R13A02M4G | Generic R13 |
| R13A03M4G | Latest public generic (available from Quectel forums) |

### Official Zyxel upgrade path
```
R01A04 → R11A03 → R11A06 → R11A07 → ZYXELR13A02 → ZYXELR13A04 → R13A05
```
Each step is a separate download from https://support.zyxel.eu/hc/en-us/articles/4403365084818
Firmware filenames indicate source→target: `RG502QEAAAR11A07M4G-R13A02` means "from R11A07 to R13A02".

### Upgrade assessment (as of 2026-05-19)
- **R13A04**: Not recommended. Had region-locking bugs where the modem ignores "Data Roaming" settings and gets stuck on a specific region. Users reported having to downgrade to R11A07 to recover.
- **R13A05**: Latest but not publicly downloadable. Requires Zyxel support ticket and remote session from Taiwan.
- **Generic AAAR firmware**: Cannot be flashed on AACR devices.
- **Recommendation**: Stay on R13A03. No security urgency (CVE patched). Working well on ice+ Norway LTE.

### CVE history
- **CVE-2022-26147** (CVSS 9.8 Critical): OS command injection in Quectel RG502Q-EA firmware before 2022-02-23. Our R13A03 is post-patch.

### How to flash modem firmware
Modem firmware is flashed via the Zyxel stock firmware WebGUI (Network Setting → Broadband → Cellular Module Firmware Upgrade). The update file is a ZIP containing the firmware delta. On OpenWrt, this would require using Quectel's QFirehose tool directly via AT commands on /dev/ttyUSB2. **This has not been tested.**

## Lessons Learned
1. **AT commands are more reliable than uqmi** — they work regardless of QMI/network config state
2. **Busybox sleep only accepts integers** — no fractional seconds
3. **Use file descriptors for AT communication** — `exec 3<>/dev/ttyUSB2` gives reliable read/write
4. **The QMI WAN interface is pre-configured** on OpenWrt — only the APN needs changing
5. **Modem needs 30s after device boot** — don't query too early
6. **Aggressive AT commands can crash QMI service** — space commands 3+ seconds apart, avoid manual COPS/CEMODE unless necessary
7. **ice.net APN works with no authentication** — simple setup for ice+ Norway
8. **scp -O is required** — dropbear lacks SFTP server
9. **Dual-partition layout** — Kernel + Kernel2, zycast writes both
10. **Factory partition is irreplaceable** — backup before any low-level flash operations
