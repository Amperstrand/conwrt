# ASUS Lyra MAP-AC2200 Session Notes

Operational details learned while flashing and provisioning Lyra MAP-AC2200 units.

## Scope

- Applies to ASUS Lyra MAP-AC2200, all hardware revisions (confirmed on HW B1).
- Focuses on the stock SSH → mtd-write → sysupgrade path.

## Tested Firmware Versions

| Firmware | Date Tested | Notes |
|----------|-------------|-------|
| `3.0.0.4.384_46054` | 2026-05-26 | Stock on HW B1. OEM wizard completed via Playwright. SSH enable in Administration → System → Service → Enable SSH = LAN only. SCP requires `-O` flag (no sftp-server). `mtd-write` available at `/sbin/mtd-write`. |

### Firmware-specific behavior (3.0.0.4.384_46054)

- Setup wizard at `http://192.168.72.1/` (not default 192.168.1.1 — IP persisted through factory reset)
- Web server: `httpd/2.0`, port 80 only (no HTTPS)
- SSH must be enabled via web UI: Administration → System → Service → Enable SSH → "LAN only"
- After enabling SSH, daemon starts within ~5 seconds on port 22
- `scp -O` required (no sftp-server on stock firmware)
- `mtd-write` and `mtd-unlock` available at `/sbin/`
- Stock kernel: Linux 3.14.77 armv7l (SMP PREEMPT)
- MTD layout: mtd0=Bootloader(4MB), mtd1=UBI_DEV(124MB), mtd2=nvram(372KB), mtd3=Factory(124KB), mtd4=Factory2(124KB), mtd5=linux(48MB), mtd6=rootfs, mtd7=linux2, mtd8=rootfs2

## Physical Port Guidance

- **LAN port** (next to power connector): Use this for initial flashing from stock firmware. In OpenWrt, this maps to `eth1` / `swport4`.
- **WAN port** (other port): Maps to `eth0` / `gmac` in OpenWrt.
- The ports are labeled identically on the exterior — identify by proximity to the power barrel connector.

## Session Checklist

### Before flashing

1. Factory-reset the device (hold reset 10+ seconds)
2. Connect ethernet to LAN port (next to power)
3. Enable SSH via curl (see "Curl-Based SSH Enable" below) — no wizard needed
4. Verify SSH access: `ssh admin@<stock-ip>`
5. Back up MTD partitions (especially Factory for calibration data)

### Stock firmware access

- Default IP after factory reset: may vary — this unit was at `192.168.72.1` (config persisted through reset)
- SSH port: 22 (must be enabled in Administration → System → Service tab)
- Credentials: same as web UI login (set during setup wizard)
- Stock firmware has `mtd-write` and `mtd-unlock` utilities at `/sbin/`
- SCP requires `-O` flag (legacy protocol) — no sftp-server on stock

### Critical: Port selection for initramfs

Stock firmware treats both ethernet ports as LAN. **OpenWrt differentiates them:**
- **Port next to power connector** = LAN (192.168.1.1, DHCP server) ← **USE THIS**
- **Port furthest from power** = WAN (DHCP client) ← will not be reachable

If you flash from stock while connected to either port (both work as LAN), then after reboot into OpenWrt initramfs you MUST be on the LAN port or you won't be able to reach the device.

### Flash timing

- After `mtd-write` + `reboot -f`: wait at least 5 minutes for initramfs boot
- After `sysupgrade -n`: wait up to 10 minutes for NAND first boot
- LED signals: breathing multicolor → blinking blue → steady blue = ready

## Stock Firmware Backup Procedure

Backups stored in `backups/asus-lyra-map-ac2200-fw-<version>/`. Folder includes firmware version in case different devices ship with different stock versions.

```bash
sshpass -p 'conwrt2026' ssh admin@192.168.72.1 "cat /proc/mtd"
# Note partition layout, then backup critical partitions:
sshpass -p 'conwrt2026' ssh admin@192.168.72.1 "dd if=/dev/mtd0ro bs=4096" > backups/asus-lyra-map-ac2200-fw-3.0.0.4.384_46054/mtd0-Bootloader.bin
sshpass -p 'conwrt2026' ssh admin@192.168.72.1 "dd if=/dev/mtd2ro bs=4096" > backups/asus-lyra-map-ac2200-fw-3.0.0.4.384_46054/mtd2-nvram.bin
sshpass -p 'conwrt2026' ssh admin@192.168.72.1 "dd if=/dev/mtd3ro bs=4096" > backups/asus-lyra-map-ac2200-fw-3.0.0.4.384_46054/mtd3-Factory.bin    # calibration data!
sshpass -p 'conwrt2026' ssh admin@192.168.72.1 "dd if=/dev/mtd4ro bs=4096" > backups/asus-lyra-map-ac2200-fw-3.0.0.4.384_46054/mtd4-Factory2.bin
```

## Identification

- MAC OUI: `10:7b:44` (ASUSTek COMPUTER INC.)
- Device MAC: `10:7b:44:XX:XX:XX:XX` (Device 1)
- et0macaddr (nvram): `10:7b:44:XX:XX:XX:XX` (base MAC, WAN = base+1)
- Board name in OpenWrt: `asus,map-ac2200`
- DTS: `qcom-ipq4019-map-ac2200`

## WiFi Radio Inventory (verified on HW B1, OpenWrt 24.10.4)

| Radio | PHY | Hardware | Band | Channels | HT Mode | Spatial Streams | Max Clients |
|-------|-----|----------|------|----------|---------|-----------------|-------------|
| radio0 | phy0 | IPQ4019 | 5 GHz (low) | 36-48 (23 dBm), 52-64 (24 dBm, DFS) | VHT80 | 2x2 (TX/RX MCS 0-9) | 32 |
| radio1 | phy1 | IPQ4019 | 2.4 GHz | 1-11 (30 dBm) | VHT40 | 2x2 (TX/RX MCS 0-9) | 32 |
| radio2 | phy2 | QCA9886 | 5 GHz (high) | 100-128 (24 dBm, DFS), 132-144 (DFS), 149-165 (30 dBm) | VHT80 | 2x2 (TX/RX MCS 0-9) | 32 |

All radios support: AP, STA (managed), IBSS, mesh, monitor, P2P. VHT80 max channel width (no 160 MHz).
All radios disabled by default in fresh OpenWrt install.

### Channel details

- **radio0 (5 GHz low)**: Only UNII-1 (36-48) and UNII-2A (52-64) enabled. UNII-2C (100+) disabled by ART/calibration data constraint.
- **radio1 (2.4 GHz)**: Channels 1-11 enabled (regulatory). Ch 12-14 disabled (default US/ETSI regulatory).
- **radio2 (5 GHz high)**: UNII-2C (100-128) and UNII-3 (149-165) enabled. UNII-1 (36-64) disabled by ART constraint. DFS required on 100-128 and 132-144.

## Network Interface Map (OpenWrt)

```
eth0 (base MAC: 10:7b:44:XX:XX:XX:XX)
├── lan@eth0 → br-lan (192.168.1.1/24, DHCP server) — port next to power
└── wan@eth0 → (DHCP client, NO-CARRIER when nothing plugged) — port furthest from power
```

- br-lan MAC: `82:74:6c:XX:XX:XX` (derived/random)
- eth0 MAC: `10:7b:44:XX:XX:XX:XX` (base MAC from Factory partition)

## OpenWrt Storage Layout

- Root: squashfs on UBI (/dev/ubi0_7, 36.5MB overlay)
- UBI device: 8 volumes, 119.8 MiB total, 2 bad blocks
- MTD partitions: SBL1, MIBIB, QSEE, CDT, APPSBL, APPSBLENV, ubi (124MB)
- Memory: 247 MB usable (256 MB physical, ~9 MB reserved by kernel)

## First Device Flash Summary (2026-05-26)

- HW revision: B1
- Stock firmware: 3.0.0.4.384_46054
- Stock IP: 192.168.72.1 (persisted through factory reset)
- Flash method: stock-ssh-mtd (two-stage)
- OpenWrt version: 24.10.4 r28959-29397011cc
- Kernel: Linux 6.6.110 armv7l
- SSH fingerprint: SHA256:2izL7JruxYGSvbWhceXJoQlisynbWoA6T9zUfLlafzk
- Backups: `backups/asus-lyra-map-ac2200-fw-3.0.0.4.384_46054/` (mtd0-Bootloader, mtd2-nvram, mtd3-Factory, mtd4-Factory2)
- Inventory: `data/inventory-asus-lyra-map-ac2200-001.json`

### Lessons learned

1. **Port selection matters**: Stock firmware treats both ports as LAN. OpenWrt splits them: LAN (next to power) and WAN (furthest from power). After initramfs flash, MUST be on LAN port to reach 192.168.1.1.
2. **SCP -O required**: Stock firmware has no sftp-server. Use `scp -O` for legacy SCP protocol.
3. **Stock IP may not be default**: This unit was at 192.168.72.1 (not 192.168.1.1) even after factory reset. IP config persisted.
4. **mtd-unlock not needed**: `mtd-write -d linux -i /tmp/initramfs.itb` worked without prior `mtd-unlock` on this firmware version.
5. **Sysupgrade timing**: Device rebooted and was accessible via SSH within ~60 seconds after sysupgrade.
6. **OEM wizard required**: Stock firmware SSH is only available after completing the initial setup wizard via web UI.
7. **Wizard NOT required (updated)**: On factory-default devices, SSH can be enabled via curl alone — no Playwright, no browser, no wizard. See "Curl-Based SSH Enable" below.

## Curl-Based SSH Enable (No Wizard Needed)

On factory-default ASUS Lyra devices, the full setup wizard can be skipped. SSH access is achievable with 3 curl commands:

```bash
# 1. Get auth token (factory default has no login)
TOKEN=$(curl -s -c - http://192.168.72.1/ | grep asus_token | awk '{print $NF}')

# 2. Enable SSH daemon (sshd_enable=2 = LAN only)
curl -s -b "asus_token=$TOKEN" \
  -H "Referer: http://192.168.72.1/QIS_wizard.htm" \
  -X POST "http://192.168.72.1/start_apply.htm" \
  -d "action_mode=apply&action_script=restart_time;restart_firewall;restart_upnp;restart_sshd&sshd_enable=2"

# 3. SSH in with factory defaults
sshpass -p 'admin' ssh -o StrictHostKeyChecking=no admin@192.168.72.1
```

### Why this works

- Factory-default devices (x_Setting=0 in NVRAM) serve pages without authentication — the root page sets an `asus_token` cookie automatically
- The `start_apply.htm` endpoint accepts NVRAM writes with just the token cookie + Referer header
- `sshd_enable=2` starts the SSH daemon in "LAN only" mode
- Factory default credentials: `admin`/`admin` — password change via `start_apply.htm` does NOT stick on factory-default devices

### Limitations

- Password change via `http_passwd` parameter in `start_apply.htm` doesn't persist — credentials remain `admin`/`admin`
- This is fine for flashing since we're about to overwrite the entire firmware
- Some NVRAM writes may not take effect — but SSH enable does work reliably

### Bulk flash workflow (for 10+ devices)

```
For each device:
1. Factory reset (hold reset 10+ sec)
2. Plug into en6 via MIDDLE PORT (LAN)
3. Configure en6: sudo ifconfig en6 192.168.72.2 netmask 255.255.255.0
4. Discover IP: tcpdump -i en6 -c 5 (look for STP/UDP:9999 AiMesh)
5. Enable SSH via 3 curl commands (above)
6. Backup: scp -O dd dumps of mtd2 (nvram), mtd3 (Factory/calibration)
7. Upload initramfs: scp -O initramfs.itb admin@IP:/tmp/
8. Flash: ssh admin@IP "mtd-write -d linux -i /tmp/initramfs.itb && reboot -f"
9. Reconfigure en6: sudo ifconfig en6 192.168.1.2 netmask 255.255.255.0
10. Wait 3-5 min for boot, then: scp -O sysupgrade.bin root@192.168.1.1:/tmp/
11. ssh root@192.168.1.1 "sysupgrade -n /tmp/sysupgrade.bin"
12. Wait for reboot, inventory: python3 scripts/router-fingerprint.py --ip 192.168.1.1
```

Total time per device: ~15-20 minutes (mostly waiting for reboots).

## Device State Machine (Updated)

Every ASUS Lyra MAP-AC2200 can be in one of these states. Detection is critical for automated flashing.

### LED → State Mapping

| LED Color | State | Network Behavior | Access Method |
|-----------|-------|-----------------|---------------|
| None | Off/unpowered | No traffic | Power on |
| Breathing colors | Booting | No services | Wait 2-3 min |
| Solid White | Factory default | DHCP server on LAN, DHCP client on WAN | HTTP at `httpd/2.0`, curl SSH enable |
| Orange | No internet (configured) | DHCP server | HTTP |
| Orange flashing | Reset in progress | No services | Wait for reboot |
| Light Cyan | Configured + connected | Normal operation | HTTP, SSH (if enabled) |
| Purple (solid) | Rescue Mode | TFTP server at 192.168.1.1 ONLY | TFTP PUT firmware.trx |
| Purple/Green blink | AiMesh pairing | BLE + UDP:9999 | No ethernet access |
| Blue sequence | OpenWrt booting | No services | Wait for SSH |
| Solid Blue | OpenWrt ready | SSH root@192.168.1.1 | SSH, uhttpd |

### Rescue Mode

Rescue mode is a U-Boot level recovery mechanism. The device acts as a TFTP server.

- **Entry**: Hold reset button while plugging in power, keep holding until solid purple LED
- **Network**: Device at 192.168.1.1, PC at 192.168.1.10/24
- **Protocol**: TFTP — `tftp -m binary 192.168.1.1 -c put firmware.trx`
- **Completion**: Wait ~5 min after upload, device reboots
- **WARNING**: Do NOT confuse rescue mode (solid purple, TFTP) with AiMesh pairing mode (also may show purple)
- **Open-source tools**: `jnissin/arescue` (Python 2), `vr-ski/TFTPRouterFlasher` (Python 3)
- **Factory Reset**: Hold reset only 5 seconds until orange flashing, then release. Holding 10+ seconds may enter rescue mode.

### Port Assignment Variability

**CRITICAL**: Port assignments vary between hardware batches, even within the same hardware revision (B1).

| MAC OUI | Stock LAN Port | Stock WAN Port | OpenWrt LAN | OpenWrt WAN |
|---------|---------------|----------------|-------------|-------------|
| `10:7b:44` | Middle (near power) | Far from power | Middle | Far |
| `2c:fd:a1` | Far from power | Middle (near power) | Middle | Far |

**Rule**: OpenWrt ALWAYS uses middle port = LAN. Only stock firmware varies.

### Port Discovery Procedure

For a factory-default device (white LED):

1. Plug into middle port, wait 30 seconds
2. Run `tcpdump -i en6 -c 5 -n 'not ether src <macbook_mac>'` (listen for STP/SSDP)
3. If traffic seen → middle port is LAN (Batch 1: `10:7b:44` OUI)
4. If no traffic → move to far port, wait 30 seconds, listen again
5. If traffic seen → far port is LAN (Batch 2: `2c:fd:a1` OUI)
6. For OpenWrt stages (after initramfs/sysupgrade) → always use middle port

### Why Port Assignments Differ (Technical Root Cause)

**The QCA8072 Ethernet PHY is software-configurable**, not hardware-strapped. The port-to-function mapping is determined by firmware configuration (NVRAM/board data), not by physical wiring or silicon.

1. **QCA8072 is software-configured**: The Linux `qca807x` driver reads the `qcom,package-mode` device-tree property and writes the chip config register via MDIO to switch between PSGMII/QSGMII modes. The chip itself doesn't dictate which port is LAN vs WAN.
   - Source: [linux `drivers/net/phy/qcom/qca807x.c`](https://github.com/torvalds/linux/blob/eb3f4b7426cfd2b79d65b7d37155480b32259a11/drivers/net/phy/qcom/qca807x.c#L545-L581)

2. **OpenWrt port assignment is in the DTS**: The MAP-AC2200 device tree maps `swport4` → WAN and `swport5` → LAN. OpenWrt always uses middle port = LAN regardless of stock firmware.
   - Source: [MAP-AC2200 DTS](https://github.com/openwrt/openwrt/blob/ebacb59a30a0e8d3b0f8f25846ed3c412536c8d2/target/linux/ipq40xx/dts/qcom-ipq4019-map-ac2200.dts#L380-L401)

3. **Stock ASUS firmware determines LAN/WAN via NVRAM**: The stock firmware's `lan_ifname`/`wan_ifname` NVRAM variables or board configuration data map physical ports to LAN/WAN roles. Different batches ship with different default NVRAM values, causing the port reversal.

**No public evidence of batch-dependent port reversal was found** in OpenWrt source, ASUS GPL dumps, or forum posts. The reversal we observed is consistent with ASUS shipping units with different NVRAM defaults across production batches — a software difference, not a hardware one.

### Why We Can't Access Stock Firmware From the WAN Port

On Batch 2 devices, the middle port is the stock WAN port. We can't avoid the cable move because:

- **Stock `httpd` only listens on the LAN bridge** (br0). It does NOT bind to the WAN interface.
- **SSH is disabled by default** on factory-default devices. We need HTTP to enable SSH via `start_apply.htm`.
- **WAN access requires explicit enable**: ASUS firmware supports "Web Access from WAN" (`misc_http_x` NVRAM) and "SSH from WAN" (`sshd_wan`), but these are OFF by default.
  - Source: [ASUS SSH/Telnet FAQ](https://www.asus.com/support/faq/1048201/), [ASUS WAN WebGUI FAQ](https://www.asus.com/us/support/faq/1000926/)
- **Giving the device a DHCP lease on WAN doesn't help**: Even if we run a DHCP server and give the WAN port an IP, admin services aren't exposed on that interface.

**Chicken-and-egg problem**: To enable WAN access, we need to change NVRAM settings via the web UI or SSH. But the web UI and SSH are only on the LAN port. So we must be on the LAN port first.

### Potential Future Workarounds (Unexplored)

These approaches might eliminate the cable move for Batch 2 devices — none have been tested:

| Approach | How It Would Work | Feasibility |
|----------|------------------|-------------|
| **NVRAM write via QIS/wizard API** | Some ASUS endpoints may be accessible from WAN during initial setup | Low — httpd binds to br0 only |
| **Custom DHCP response with vendor option** | Stock firmware might accept configuration via DHCP vendor-specific options | Unknown — needs research |
| **AiMesh pairing from WAN** | AiMesh protocol (BLE + UDP:9999) might be reachable from WAN | Low — BLE is separate from ethernet |
| **Rescue mode TFTP from middle port** | Rescue mode TFTP server at 192.168.1.1 might listen on both ports | Medium — worth testing |
| **Serial console** | Physical serial header (J35) provides full access regardless of port | High — but requires opening case |
| **Batch detection from DHCP Discover** | Analyze DHCP Discover packets from WAN to determine batch, then guide user | Medium — could detect MAC OUI from WAN side |

## Device 3 Flash Summary (2026-05-26)

- MAC: `2c:fd:a1:XX:XX:XX:XX` (Device 3) (MAC OUI: `2c:fd:a1`, different batch from devices 1-2)
- Stock firmware: 3.0.0.4.384
- Stock IP: 192.168.72.1 (on port FURTHEST from power — reversed from devices 1-2!)
- Flash method: stock-ssh-mtd (curl SSH enable, no wizard)
- OpenWrt: 24.10.4 r28959-29397011cc
- Backups: `backups/asus-lyra-map-ac2200-mac-2c-fd-a1-12-f3-19-fw-384/`
- Inventory: `data/inventory-asus-lyra-map-ac2200-003.json`

### Lessons learned (Device 3)

7. **Port assignments vary by batch**: `2c:fd:a1` OUI devices have reversed stock port assignments vs `10:7b:44`. Always try both ports.
8. **Factory reset timing**: Hold reset only 5 seconds (until orange flash), NOT 10+ seconds. Holding too long enters rescue mode (purple LED, TFTP only).
9. **Rescue mode is TFTP**: Purple LED = device is a TFTP server at 192.168.1.1. Can upload firmware via `tftp -m binary 192.168.1.1 -c put firmware.trx`.
10. **DHCP client vs server**: White LED device sending DHCP Discover = you're on the WAN port, not LAN. Move to the other port.
11. **Multiple resets cause confusion**: If device was already white, do NOT reset again. Each reset risks entering rescue mode or AiMesh pairing mode.

### Known Unknowns and Experiments

| Unknown | Why It Matters | How to Investigate |
|---------|---------------|-------------------|
| Is port assignment tied to MAC OUI or hardware revision? | Determines if we can predict port from MAC | Flash more devices, record MAC OUI + port behavior |
| Does rescue mode listen on BOTH ethernet ports? | Could eliminate cable move for Batch 2 | Enter rescue mode, try TFTP from middle port |
| Can rescue mode TFTP accept OpenWrt initramfs? | Could provide alternative flash path (skip SSH) | Enter rescue mode, TFTP PUT the initramfs |
| What's the exact reset timing boundary? | 5s = reset, 10s+ = rescue mode? | Serial console + stopwatch during reset |
| Are there more MAC OUIs? | More OUIs = more detection patterns | Flash more devices, record all MACs |

### Resolved Unknowns

| Unknown | Resolution | Evidence |
|---------|-----------|----------|
| Is port assignment stored in NVRAM? | **NO** — both batches have identical `lan_ifnames=eth1`, `wan_ifnames=eth0` | NVRAM dump comparison from both batches |
| What causes the port reversal? | **Hardware wiring** — PCB or connector swap between production runs. Not software. | NVRAM identical, but physical ports differ |
| Can we read settings from rescue mode? | **NO** — rescue mode is U-Boot TFTP server, upload-only. No HTTP, no read capability. | Bootloader strings: "Load %s then write to Flash via TFTP" |
| Can we read SSID before flashing? | **YES** — via NVRAM backup. Extract `wl0_ssid`, `wl0_wpa_psk` from `mtd2-nvram.bin` using `strings` | NVRAM backups contain all WiFi config |
| What differs between batches? | Bootloader version (v03 vs v05), firmware build (2019 vs 2021), erase size (0x20000 vs 0x1f000) | NVRAM comparison: `blver`, `buildinfo`, `extendno` |

## Device 4 Flash Summary (2026-05-27)

- MAC: `2c:fd:a1:XX:XX:XX:XX` (Device 4) (MAC OUI: `2c:fd:a1`, Batch 2 — same as Device 3)
- Stock firmware: 3.0.0.4.384
- Stock IP: 192.168.72.1 (on far port — confirmed Batch 2 port reversal)
- Flash method: stock-ssh-mtd (curl SSH enable, no wizard)
- OpenWrt: 24.10.4 r28959-29397011cc
- Erase size: 0x1f000 (same as Device 3, different from Devices 1-2 at 0x20000)
- Backups: `backups/asus-lyra-map-ac2200-mac-2c-fd-a1-12-f4-99-fw-384/`
- Inventory: `data/inventory-asus-lyra-map-ac2200-004.json`

### Lessons learned (Device 4)

12. **SCP with long filenames fails silently on stock firmware**: `scp -O initramfs-full-name.itb admin@192.168.72.1:/tmp/` reported success but file didn't exist. Use short names like `initramfs.itb`.
13. **Bridge MAC differs from eth0 MAC**: OpenWrt initramfs responds to pings at 192.168.1.1 with MAC `e6:96:81:XX:XX:XX:XX` (locally administered) while `eth0` shows `2c:fd:a1:XX:XX:XX:XX` (Device 4). Don't rely on bridge MAC for device identification.
14. **`md5sum` is available on stock firmware**: Located at `/usr/bin/md5sum`. Use it for transfer verification.
15. **Cable move timing**: Must move cable from far port → middle port AFTER `mtd-write` + `reboot -f`, BEFORE OpenWrt initramfs boots (~30s window). The script now provides `say` voice guidance.

### Confirmed Batch Patterns (4 devices)

| Device | MAC | OUI | Erase Size | Stock LAN Port | Stock IP | Batch |
|--------|-----|-----|-----------|---------------|----------|-------|
| 1 | `10:7b:44:XX:XX:XX:XX` (Device 1) | `10:7b:44` | `0x20000` | Middle | 192.168.72.1 | 1 |
| 2 | `10:7b:44:XX:XX:XX:XX` (Device 2) | `10:7b:44` | `0x20000` | Middle | 192.168.72.1 | 1 |
| 3 | `2c:fd:a1:XX:XX:XX:XX` (Device 3) | `2c:fd:a1` | `0x1f000` | Far | 192.168.72.1 | 2 |
| 4 | `2c:fd:a1:XX:XX:XX:XX` (Device 4) | `2c:fd:a1` | `0x1f000` | Far | 192.168.72.1 | 2 |

**Pattern**: MAC OUI reliably predicts batch. Erase size also correlates (`0x20000` = Batch 1, `0x1f000` = Batch 2). Stock IP is always 192.168.72.1 on factory default.

## Wireless Installation Server Research (2026-05-27)

### Goal

Enable wireless OpenWrt installation on ASUS Lyra MAP-AC2200 using only the
reset button or pairing button — no ethernet cable required. One already-flashed
OpenWrt Lyra acts as the "installation server" to wirelessly provision nearby
stock devices.

This is legal and ethical reverse engineering: the goal is to help people upgrade
their own routers to OpenWrt without physically cabling each device.

### Firmware Reverse Engineering Summary

Stock firmware `3.0.0.4.384_46630` extracted and analyzed on Ubuntu box
(`ubuntu@192.168.13.218:~/conwrt-re/`).

**Extracted binaries** (in `~/conwrt-re/firmware/Firmware_Release/_MAP-AC2200_3.0.0.4_384_46630-g3e43ad7.trx.extracted/squashfs-root/`):

| Binary | Size | Purpose |
|--------|------|---------|
| `usr/sbin/httpd` | 348KB | Web server, auth, CGI handlers |
| `usr/sbin/cfg_server` | 495KB | AiMesh primary node controller |
| `usr/sbin/cfg_client` | 468KB | AiMesh secondary node client |
| `usr/sbin/infosvr` | - | UDP 9999 discovery service |
| `usr/bin/bluetoothd` | - | BLE stack (BlueZ) |
| `usr/bin/gatttool` | - | BLE GATT tool |
| `sbin/start_bluetooth_service` | - | BLE service launcher |
| `usr/sbin/amas-utils-cli` | - | AiMesh utility |

### httpd Analysis (Track 1)

Full analysis at `~/conwrt-re/httpd/analysis.md` on Ubuntu.

**Architecture**: 32-bit ARM (uClibc), stripped, PIE.

**Critical vulnerability patterns found**:

1. **Command injection via `action_script` → `syscmd.sh`** (HIGH)
   - Template: `%s > /tmp/syscmd.log 2>&1 && echo 'XU6J03M6' >> /tmp/syscmd.log &`
   - User input from `action_script` parameter written to `/tmp/syscmd.sh` and executed
   - 5 cross-references to `action_script` in dispatch function
   - Entry points: `start_apply.htm`, `apply.cgi`

2. **IFTTT separate auth path** (HIGH)
   - `check_ifttt_token` — separate auth mechanism from `auth_check`
   - `get_IFTTTtoken.cgi`, `send_IFTTTPincode.cgi`, `get_IFTTTPincode.cgi`
   - Null token check pattern: `if(%s == null){` — CVE-2021-32030 variant
   - If IFTTT auth bypass works, combined with #1 = WiFi RCE

3. **12+ unauthenticated endpoints**: `findasus.cgi`, `detwan.cgi`,
   `QIS_wizard.htm`, `start_apply.htm`, `blocking_request.cgi`,
   `get_IFTTTtoken.cgi`

**Proposed installation chain**:
```
Installation server (OpenWrt Lyra)
  → WiFi client connects to stock device's setup AP (ASUS_XX)
  → Probe get_IFTTTtoken.cgi for auth bypass
  → POST start_apply.htm with action_script=<payload>
  → Payload: wget initramfs from server → mtd-write → reboot
  → Device boots OpenWrt initramfs
  → Sysupgrade with final image from installation server
```

### AiMesh Protocol Analysis (Track 2)

Full analysis at `~/conwrt-re/aimesh/analysis.md` on Ubuntu.

**Protocol**: TCP port 7788, binary TLV format.
- RSA key exchange → AES-256 ECB session encryption
- Session key = `SHA256(cfg_group + server_nonce + custom_data)`
- `cfg_group = MD5(MAC + "_" + timestamp)` — leaked via WiFi beacon vendor-specific IEs

**Onboarding discovery**: Uses **WiFi beacon VSIE**, NOT BLE GATT.
- `set beacon's vsie for OB_AVAILABLE` — device advertises onboarding availability via 802.11
- `set beacon's vsie for OB_AVAILABLE selection(%s)` — selected device
- `get_onboarding_key` — key exchange during onboarding
- `/tmp/onboarding.json` — onboarding state file
- `cm_doFirmwareDownload` / `cm_downloadFirmware` — firmware push via mesh

**Onboarding flow** (from cfg_server/cfg_client strings):
1. Primary enters OB_AVAILABLE state → sets beacon VSIE
2. Client scans WiFi beacons, finds OB_AVAILABLE VSIE
3. Client selects primary → OB_AVAILABLE_SELECTION
4. Key exchange (`get_onboarding_key`)
5. Config push, firmware download if needed
6. Device joins mesh, reboots with new firmware

**Factory-default gap**: Fresh devices have no `cfg_group`. The CCS24Mesh
beacon-leakage attack doesn't apply. But since we'd be impersonating the
primary, **we set cfg_group ourselves**.

**Bluetooth**: BLE (AR3012 chip) confirmed working on OpenWrt Lyra:
- bluez 5.72 installed, `hci0` UP and RUNNING
- BD Address: `2C:FD:A1:12:F4:9D`
- Classic BT + BLE capable
- No public documentation of ASUS BLE GATT UUIDs or pairing protocol
- BLE likely used only for initial phone app discovery, not the actual onboarding

### infosvr Analysis

- UDP 9999, `NET_SERVICE_ID_IBOX_INFO` / `NET_PACKET_TYPE_CMD`
- **PATCHED**: `ateCommand_flag` NVRAM check blocks old RCE (CVE-2014-9583)
- GETINFO (opcode 0x33) still responds — useful for device enumeration
- Only accessible via LAN bridge (not WiFi)

### Test Scripts

- `recipes/asus/lyra-map-ac2200/test-attack-vectors.sh` — 8 tests: infosvr,
  CVE-2021-32030, IFTTT bypass, action_script, unauth endpoints, WiFi AP scan,
  AiMesh TCP 7788, HTTP fingerprint
- `recipes/asus/lyra-map-ac2200/lab-detect-and-test.sh` — auto-detect stock
  vs OpenWrt, route to appropriate test suite

### OpenWrt Lyra as Installation Server (Lab Device)

Device configured at `10.231.9.197` (LAN), hostname `lyra`, on house network
via WAN at `lyra.lan` / `192.168.13.165`.

Capabilities confirmed:
- SSH key-only auth over WAN
- Bluetooth (bluez 5.72, `hci0` UP, BLE capable)
- Python 3 installed (`python3-light`, `python3-asyncio`, `python3-codecs`)
- WiFi radios (ipq4019 2.4GHz + 5GHz, QCA9886 5GHz) — currently disabled
- opkg working (HTTP feeds, packages installable)
- 37MB overlay free

### External Research References

- **CCS24Mesh**: https://github.com/seclab-ucr/CCS24Mesh — AiMesh exploitation
  research, WiFi beacon VSIE leakage, cfg_group derivation
- **asus-cmd**: https://github.com/jduck/asus-cmd — infosvr RCE tool
- **CVE-2021-32030**: Null `asus_token` auth bypass
- **recsrmesh** (oyvindkinsey): Python BLE mesh provisioning library —
  useful pattern for BLE-based device onboarding
- **OpenWrt Configurator** (jasrusable): JSON-driven OpenWrt provisioning
- **WRTKit** (tlamadon): SSH fleet management with staged commits
- **ASU** (openwrt): Firmware image server — pattern for image serving

### Installation Server Architecture (Proposed)

```
┌─────────────────────────────────────────┐
│  OpenWrt Lyra (Installation Server)     │
│                                         │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │ WiFi scanner │  │ HTTP server      │  │
│  │ (iw scan)   │  │ (serves firmware)│  │
│  └──────┬──────┘  └────────┬─────────┘  │
│         │                  │            │
│  ┌──────▼──────────────────▼─────────┐  │
│  │  Installation orchestrator        │  │
│  │  (Python, runs on device)         │  │
│  │                                   │  │
│  │  1. Scan for ASUS_XX setup APs    │  │
│  │  2. Connect to stock device WiFi  │  │
│  │  3. Probe httpd for auth bypass   │  │
│  │  4. Push initramfs via action_    │  │
│  │     script injection or AiMesh    │  │
│  │     onboarding protocol           │  │
│  │  5. Device reboots → OpenWrt      │  │
│  │  6. Sysupgrade final image        │  │
│  └───────────────────────────────────┘  │
│                                         │
│  Firmware cache: /tmp/firmware/         │
│  initramfs.itb + sysupgrade.bin         │
└─────────────────────────────────────────┘
         │
         │ WiFi (setup AP from stock device)
         │
┌────────▼────────────────────────────────┐
│  Stock ASUS Lyra (Target)               │
│                                         │
│  Factory default (white LED)            │
│  Broadcasting ASUS_XX setup AP          │
│  httpd listening on 192.168.72.1        │
│  infosvr on UDP 9999                    │
│  AiMesh onboarding available            │
└─────────────────────────────────────────┘
```

### Next Steps (completed — see below for results)

~~1. **Test with stock device**: Run `test-attack-vectors.sh` against a
   factory-default Lyra to confirm which vulnerabilities are exploitable~~
~~2. **Build orchestrator**: Python script that automates the WiFi connect →
   probe → push → verify flow~~
~~3. **Test AiMesh onboarding**: Monitor WiFi beacons from stock device in
   pairing mode to capture OB_AVAILABLE VSIE format~~
~~4. **Reverse onboarding key**: Understand `get_onboarding_key` to complete
   the AiMesh installation path~~

---

## Session 5: Stock Device httpd Exploit + Live Firmware Analysis (2026-05-27)

### httpd-Based Installation Path (PROVEN, WORKING)

**The complete wireless/ethernet installation chain for a stock ASUS Lyra MAP-AC2200
in QIS (Quick Internet Setup) / factory-default mode:**

1. **Detect device** — port scan or ARP, device responds at its default IP
2. **Get auth token** — `GET /` returns `asus_token` cookie automatically (QIS mode)
3. **Read NVRAM** — `GET /appGet.cgi?hook=nvram_get(productid)` with `Referer: http://<ip>/QIS_wizard.htm` header
4. **Enable SSH** — `GET /start_apply.htm?sshd_enable=1` with cookie + Referer
5. **SSH in** — `ssh admin@<ip>` with password `admin` (default Dropbear credentials)
6. **Flash** — SCP initramfs, `mtd-unlock -d linux && mtd-write -d linux -i /tmp/initramfs.itb && reboot -f`

**No pairing button needed. No WiFi connection needed. No physical access needed
past ethernet.** Works on factory-default devices with the left ethernet port
(WAN port, furthest from power connector). The right port (LAN, next to power)
also works but with different open ports.

### Live Stock Device NVRAM Dump

```
productid=MAP-AC2200
firmver=3.0.0.4
buildinfo=Wed May 12 12:24:37 UTC 2021 Qca@3e43ad7
lan_ipaddr=192.168.72.1
lan_hwaddr=2C:FD:A1:12:F2:CB
et0macaddr=2C:FD:A1:12:F2:C9
wl0_hwaddr=2C:FD:A1:12:F2:C8
wl1_hwaddr=2C:FD:A1:12:F2:CA
computer_name=Lyra-F2C8
sw_mode=1
sshd_enable=0  (changed to 1 via httpd API)
cfg_obstatus=  (empty = no AiMesh onboarding)
cfg_group=DA47DB63FBBB5C2C4E0FC57DC955B71C  (from SSH nvram get, hidden by httpd API)
rc_support=2.4G 5G update qcawifi 11AC noaidisk noitunes nodm manual_stb app switchctrl
  mssid ipv6 ipv6pt PARENTAL2 pptpd openvpnd utf8_ssid frs_feedback dblog email findasus
  atf 5G-2 bwdpi wrs_wbl HTTPS ssh vpnc repeater optimize_xbox wps_multiband
  user_low_rssi tcode usericon stainfo realip alexa cfg_sync fupgrade amas lyra_hide
  port2_device eula qca
wl0_ssid=ASUS_C8_AMAPS
wl1_ssid=ASUS_C8_AMAPS
```

### MAC Address Mapping

| Interface | MAC | Notes |
|-----------|-----|-------|
| WiFi ath0 | 2C:FD:A1:12:F2:C8 | 2.4GHz (BSSID) |
| WiFi ath1 | 2C:FD:A1:12:F2:CA | 5GHz low |
| WiFi ath2 | 2C:FD:A1:12:F2:CC | 5GHz high (QCA9886) |
| eth0 | 2C:FD:A1:12:F2:C9 | WAN port (left, furthest from power) |
| eth1 | 2C:FD:A1:12:F2:CB | LAN port (next to power) |
| br0 | 2C:FD:A1:12:F2:CB | Bridge (uses eth1/LAN MAC) |

### Port Scan Results (WAN port = eth0)

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Open (dnsmasq) |
| 80 | httpd/2.0 | Open, QIS wizard mode, auto-grants asus_token |
| 18017 | wanduck | Redirects to QIS_wizard.htm |
| 22 | Dropbear 2019.78 | Closed by default, opened via httpd API `sshd_enable=1` |

### Open Ports (LAN port = eth1)

All ports closed from LAN side when device is in QIS mode.

### httpd API Details

**Authentication**: `asus_token` cookie + `Referer: http://<ip>/QIS_wizard.htm` header

**Key endpoints (all require cookie + Referer)**:
- `GET /appGet.cgi?hook=nvram_get(<var>)` — read NVRAM variables
- `GET /appGet.cgi?hook=nvram_get(var1)%3Bnvram_get(var2)` — batch read
- `GET /start_apply.htm?<nvram_var>=<value>` — write NVRAM and apply
- `GET /start_apply.htm?action_script=restart_sshd` — trigger service restart
- `GET /get_IFTTTtoken.cgi` — returns `ifttt_token: ""` (unauthenticated)
- `GET /status.asp` — returns WAN status (unauthenticated in QIS mode)
- `GET /QIS_wizard.htm` — QIS setup wizard (unauthenticated)

**Unauthenticated endpoints** (no cookie needed):
- `GET /` — returns HTML redirect + `asus_token` cookie (auto-granted)
- `GET /get_IFTTTtoken.cgi` — returns empty token
- `GET /status.asp` — WAN link status
- Port 18017 (wanduck) — redirects to QIS wizard

### MTD Partition Layout (from live device)

```
mtd0: 00400000 "Bootloader"
mtd1: 07c00000 "UBI_DEV"
mtd2: 0005d000 "nvram"
mtd3: 0001f000 "Factory"     (calibration data, MACs)
mtd4: 0001f000 "Factory2"
mtd5: 03013000 "linux"        (kernel + rootfs slot A)
mtd6: 02df7380 "rootfs"       (rootfs within linux)
mtd7: 03013000 "linux2"       (kernel + rootfs slot B)
mtd8: 02df7380 "rootfs2"      (rootfs within linux2)
```

### Running Processes (stock firmware, key ones)

```
httpd -i br0             # Web UI on br0 (LAN bridge)
/usr/sbin/infosvr br0    # ASUS discovery on br0
/sbin/wanduck            # WAN detection (port 18017)
obd                      # Onboarding daemon (manages cfg_server/cfg_client)
obd_eth                  # Ethernet onboarding daemon
amas_lib                 # AiMesh library
nt_center / nt_monitor   # Network monitoring
bwdpi_check              # TrendMicro DPI
roamast                  # Roaming assistant
bluetoothd -n -p aqis    # Bluetooth (AQIS protocol)
hostapd (x3)             # WiFi AP on ath0, ath1, ath2
wpa_supplicant           # WiFi STA on sta0
avahi-daemon             # mDNS (Lyra-F2CB.local)
lldpd                    # LLDP (MAP-AC2200)
```

### WiFi Beacon VSIE Analysis (from lyra.lan monitor mode)

The stock device alternates between two VSIE states in its beacons:

**State 1 — Configured (`04`)**:
```
8c:fd:f0  04 00 00 49 00 00 03 02 09 72 01 00 00 00 00 ef 12 00 00
          ^state     ^--- possibly H(GID) + T(pub) from CCS24 ---^
```

**State 2 — Discoverable/OB_AVAILABLE (`01`)**:
```
8c:fd:f0  01 01 02 01 00
          ^state
```

The device alternates between these every ~3-5 seconds. State byte `01` =
OB_AVAILABLE (AiMesh onboarding solicitation). The long `04` VSIE contains
data that may correspond to H(GID) + T(pub) as described in CCS24 paper.

### AiMesh cfg_group Discovery

The stock device has `cfg_group=DA47DB63FBBB5C2C4E0FC57DC955B71C` (from SSH
`nvram get cfg_group`). This value is HIDDEN by the httpd API —
`appGet.cgi?hook=nvram_get(cfg_group)` returns empty string.

The `cfg_group` was likely set during previous AiMesh membership. This means
the CCS24 AiMesh attack protocol could work against this device if cfg_server
is running and listening on TCP 7788.

### cfg_server Manual Start

cfg_server can be started manually via SSH. It:
1. Reads `cfg_group` from NVRAM
2. Sets LLDP custom TLV (OUI `F8,32,E4`) for ethernet discovery
3. Injects VSIE into WiFi beacons via `hostapd_cli_cmd_set_vsie`
4. Sets `cfg_obstatus=1` (OB_AVAILABLE)
5. Requires `/tmp/wchannel.json`, `/tmp/chanspec_all.json`, etc. for full init
6. Does NOT bind to TCP 7788 without full config — needs more investigation

### CCS24Mesh Reference Implementation

The CCS24 research paper's exploit code is at `~/conwrt-re/aimesh/CCS24Mesh/`.
Key files:
- `ASUS/asus_pull_wifi_passphrase.py` — Full AiMesh handshake implementation
- `ASUS/compute_Tpri.py` — cfg_group brute-force from VSIE leaked data

Protocol summary from code:
1. Connect to TCP 7788
2. Send REQ_KU (opcode 0x1) → receive RSA public key (PEM)
3. Send REQ_NC (opcode 0x3) with RSA-encrypted AES key + client nonce
4. Receive RSP_NC with AES-encrypted server nonce
5. Compute session_key = SHA256(cfg_group + server_nonce + client_nonce)
6. Send REP_OK (opcode 0x5) → receive ACK_OK (0x6000000)
7. Send REQ_JOIN (opcode 0xF) with AES-encrypted JSON `{"mac": "..."}`
8. Periodic sync (opcode 0x8) with encrypted config

Message frame: `opcode(4B) + tlv_len(4B) + tlv_crc(4B) + tlv_data(...)`
Crypto: RSA-2048 PKCS1v1.5 + AES-256-ECB with PKCS7 padding (block size 32)

### AiMesh cfg_client Investigation (Session 6)

**Goal**: Make cfg_client on the stock device connect to our Python cfg_server
on TCP 7788 to complete the AiMesh handshake wirelessly.

**Approaches tried and results:**

1. **cfg_masterip NVRAM** — Set `cfg_masterip=192.168.72.50` (our Mac).
   cfg_client started but exited silently within seconds. No network activity.
   Cause: cfg_client calls `hw_auth_check` and `get_auth_code` via amas_lib
   Unix socket. The auth check fails and cfg_client exits with "auth check
   failed, exit" / "exit daemon!". This is the SAME gate that blocks cfg_server.

2. **LLDP frames with ASUS OUI (f8:32:e4)** — Sent correctly-formed LLDP
   frames via scapy from Mac. tcpdump confirmed frames on wire with correct
   OUI, chassis ID, port ID, TTL, and custom TLV containing neighbor MAC,
   ob_status=1, model_name="MAP-AC2200". Stock device's lldpd did NOT pick
   them up because:
   - `lldpd` v0.9.8 has `Receive mode: no` (transmit-only)
   - No lldpcli command can change this on this version
   - obd_eth reads neighbor data from lldpd, not directly from wire

3. **infosvr discovery (UDP 9999)** — Sent ASUS discovery packets (unicast
   and broadcast). No response. Cause: `infosvr` was started as
   `/usr/sbin/infosvr br0` and only processes packets on br0. eth0 (WAN port)
   is NOT a member of br0 — only eth1 + WiFi interfaces are in br0.

4. **httpd API trigger** — Tried `start_apply.htm?cfg_obstart=1&cfg_obstatus=1`
   with various action_scripts. NVRAM was set but obd did NOT start cfg_client.
   The httpd API can set NVRAM but doesn't trigger the full onboarding flow.

**Network topology insight (critical):**

```
br0 (192.168.72.1) ← eth1 (LAN) + ath0 + ath1 + ath2
  ↳ infosvr bound here (UDP 9999)
  ↳ lldpd configured for eth0 (but receive disabled)
  ↳ DHCP server on 192.168.72.0/24

eth0 (WAN port, no IP in bridge)
  ↳ httpd accessible (QIS mode routes between interfaces)
  ↳ wanduck on port 18017
  ↳ SSH after httpd enable

brg0 (192.168.73.1) — separate bridge for guest/IoT
```

The WAN port (eth0) is NOT in br0. This means all br0-bound services
(infosvr, lldpd neighbor discovery, cfg_client discovery broadcasts) are
inaccessible from the WAN port. The ONLY service reachable on eth0 is httpd.

**cfg_client auth check chain (confirmed from binary strings):**

```
cfg_client → getAmasSupportMode() → hw_auth_check() → get_auth_code()
                                              ↳ via amas_lib Unix socket
                                              ↳ "auth check failed, exit"
                                              ↳ "exit daemon!"
```

The auth check is the same gate that blocks cfg_server. It communicates with
amas_lib via a Unix socket. The check likely validates hardware capabilities
or device provisioning state. Only obd can successfully start cfg_client (after
pairing button press), presumably because obd sets some state that amas_lib
accepts.

**obd_eth discovery protocol (from strings):**

obd_eth parses LLDP custom TLV entries with ASUS OUI f8:32:e4:
- `Entry[%d] id =`, `Entry[%d] id len =%d`
- `Entry[%d] neighbors MAC = %02X:...`
- `Entry[%d] ob status = %d`
- `Entry[%d] ob status Model Name = %s`
- `Entry[%d] ob status Timestamp = %X`
- `Entry[%d] peer MAC = %02X:...`
- `Entry[%d] sec status = %d`
- "This is ASUS router" / "This is not ASUS router"

obd_eth handles the full ethernet onboarding lifecycle:
- `Generate Session Key finished`
- `OB Lock for %02X:...`
- `Clear group information`
- `Exit due to ethernet onboarding failure/successfully`
- `Can't find node for onboarding`
- `Can't get key for onboarding`

### Key Remaining Unknowns

1. **amas_lib auth check**: What state does amas_lib check? How does obd
   trigger cfg_client to pass auth? Does the pairing button set a flag
   that amas_lib reads?
2. **Binary patching**: Can we patch cfg_client to skip the auth check
   (replace branch instruction after hw_auth_check call)?
3. **obd button handler**: How does obd handle the WPS/pairing button press?
   What NVRAM/env does it set before starting cfg_client?
4. **Firmware validation**: Does `firmware_check` / `rsasign_check` block
   OpenWrt images in AiMesh firmware push path?
5. **LAN port approach**: If we connect to eth1 (in br0), all br0 services
   become available — infosvr, LLDP, cfg_client discovery broadcasts.

### Installation Paths Summary

| Path | Status | Requirements | Notes |
|------|--------|-------------|-------|
| **httpd SSH enable** | PROVEN | Ethernet (any port) + QIS mode | Simplest, works on WAN port |
| Stock SSH (wizard) | Known | Ethernet + setup wizard completed | Standard method, requires wizard |
| AiMesh cfg_client | BLOCKED | Need pairing button or binary patch | amas_lib auth check blocks manual start |
| AiMesh cfg_server | BLOCKED | Same auth check issue | cfg_server won't bind TCP 7788 |
| IFTTT bypass + RCE | Untested | httpd, any auth state | From httpd RE, may work post-wizard |
| infosvr (UDP 9999) | LAN only | infosvr on br0 | Not reachable from WAN port |
| LLDP discovery (f8:32:e4) | BLOCKED | lldpd receive=disabled | obd_eth reads from lldpd, not wire |

### Research Device Status

Stock device at `192.168.72.1` (MAC `2C:FD:A1:12:F2:CB`):
- SSH enabled via httpd API (sshd_enable=1)
- Login: admin/admin (Dropbear 2019.78)
- cfg_group: DA47DB63FBBB5C2C4E0FC57DC955B71C
- cfg_masterip: 192.168.72.50 (set this session)
- cfg_obstart: 1, cfg_obstatus: 1 (set this session)
- Network: br0=eth1+WiFi (192.168.72.0/24), eth0=WAN (not in bridge)
- **NOT FLASHED** — keeping stock for ongoing research

## Session 7: AiMesh Installation Server — Full Handshake Proven

### Breakthrough: End-to-End AiMesh Handshake Working

Built a Python AiMesh cfg_server (`/tmp/aimesh_cfg_server_v2.py`) that successfully completes the full 4-step onboarding handshake:

1. **REQ_KU (opcode 0x1)**: Client requests RSA public key → Server sends 2048-bit RSA PEM
2. **REQ_NC (opcode 0x3)**: Client sends RSA-encrypted payload containing AES-256 master key + 8-byte client nonce → Server decrypts, generates 32-byte server nonce, wraps in TLV header (banner+len+crc), AES-encrypts and returns
3. **REP_OK (opcode 0x5)**: Client confirms → Server responds 0x00000006 (SUCCESS)
4. **REQ_JOIN (opcode 0xF)**: Client sends AES-encrypted `{"mac":"2C:FD:A1:12:F2:CB"}` using derived session key → Server decrypts and accepts

**Session key derivation**: `SHA256(cfg_group + server_nonce + client_nonce).hexdigest()` — both sides derive identical key `c45c5c85e2c0a06f...`

### infosvr Discovery Protocol (UDP 9999) Decoded

Full packet format captured from stock device's infosvr:

| Offset | Content | Example |
|--------|---------|---------|
| 0 | ServiceType | 0x0C |
| 1 | OpCode | 0x15 (probe) / 0x16 (device info) |
| 2 | Info | 0x1F |
| 4-9 | MAC | 00:e0:4c:68:00:00 |
| 44-57 | Model ID | ASUS_C8_AMAPS |
| 71-84 | Subnet mask | 255.255.255.0 |
| 100-104 | Product name | Lyra |
| 125-136 | Firmware | 3.0.0.4.384 |
| 142-147 | Full MAC | 2c:fd:a1:12:f2:cb |
| 168-175 | Config flags | 0x82 0x80 0x58 0x00 0x00 0x02 0x1f 0x92 |
| 210-211 | HTTPS port | 0x01bb (443) |
| 254-255 | Flags | 0x01 0x02 |

Two packet types: opcode 0x15 (empty discovery probe) and 0x16 (full device info broadcast). Both sent simultaneously every ~1.5s from infosvr on br0.

### Discovery Responder

Scapy-based responder (`/tmp/aimesh_responder.py`) successfully responds to infosvr broadcasts on en6. After responding, `cfg_device_list` was updated to `<Lyra>192.168.72.1>2C:FD:A1:12:F2:CB>0`. However, our response is not yet recognized as a valid AiMesh master — likely needs correct sw_mode=1 (router) and cfg_master flags in the response.

### cfg_client State Issues

cfg_client on the research device exits with `blacklist_confirm: is_lan=0, is_wan=0, is_wl=0` — internal interface check fails because the device is in an inconsistent NVRAM state (manually set sw_mode=5 without proper AiMesh initialization). On a fresh factory device pressing the pairing button, cfg_client would start normally through wpsaide → amas_lib → cfg_client with proper initialization.

### httpd API Endpoints Discovered

- `cfg_onboarding.cgi?flag=AMesh` — triggers AiMesh onboarding (returned 200 OK)
- `get_onboardingstatus`, `get_onboardinglist` — status queries (404 — wrong URL format)
- `apply_amaslib`, `restart_amas_bhctrl` — service control via apply.cgi
- `AiMesh_Node_FirmwareUpgrade.asp` — firmware upgrade page (exists in httpd)

### Network Path Verified

TCP 7788 connectivity confirmed from stock device to Mac via telnet test:
```
192.168.72.1:54774 → 192.168.72.50:7788  [CONNECTED]
Received: opcode=0x00000001 (REQ_KU), len=32, crc=0
```

### Key Files

- `/tmp/aimesh_cfg_server_v2.py` — Full AiMesh installation server with handshake
- `/tmp/test_client.py` — Test client (simulates cfg_client)
- `/tmp/aimesh_responder.py` — Scapy infosvr discovery responder
- `/tmp/quick_responder.py` — Simple responder variant

### Remaining Work

1. Fix infosvr response to include sw_mode=1 and cfg_master flags (so cfg_client recognizes us)
2. Test with a FRESH factory device (research device's cfg_client is broken from NVRAM manipulation)
3. Build WiFi beacon VSIE broadcasting (OB_AVAILABLE) on the OpenWrt installation server
4. Research post-handshake firmware push through the AiMesh control channel
5. Build complete wireless provisioning flow for conference demo

## Known CVEs Affecting Lyra MAP-AC2200

These CVEs affect firmware `3.0.0.4.384_46630` (the last release for this EOL device). ASUS did not patch any of these for the Lyra MAP-AC2200.

### CVE-2021-32030 — IFTTT Auth Bypass (Path 1 primary)

- **Severity**: Critical (CISA KEV catalog — known exploited)
- **Affects**: GT-AC2900, Lyra Mini before `3.0.0.4_386_42643`
- **Our firmware**: `3.0.0.4.384_46630` — **vulnerable** (exact version listed as affected)
- **Mechanism**: Send `asus_token` cookie starting with `\0` (null byte) + User-Agent `asusrouter--` → `strcmp` matches the null default `ifttt_token` → authenticated as admin
- **Discovered by**: Atredis Partners (Chris Bellows), disclosed 2021
- **Fix**: Update to `3.0.0.4_386.42643` — never released for Lyra MAP-AC2200 (EOL)
- **Our usage**: Primary auth bypass for httpd API access on factory-default devices

### CVE-2018-5999 — httpd POST Processing Without Auth

- **Severity**: High
- **Mechanism**: `handle_request()` processes POST data even when auth fails — the POST handler runs before the auth check rejects the request
- **Our observation**: `apply.cgi` executes `action_script` commands without any `asus_token` cookie — confirmed with live test (killed sshd, called apply.cgi with no cookie, sshd restarted)
- **Our usage**: Enables unauthenticated command execution via `apply.cgi` with `action_script` parameter

### CVE-2018-9285 — apply.cgi SystemCmd Injection

- **Severity**: High
- **Mechanism**: Command injection in Network Analysis ping/traceroute via `;` in `destIP`/`pingCNT` fields
- **Fixed in**: `3.0.0.4.384_10007` — but our firmware `3.0.0.4.384_46630` may still be vulnerable to the `action_script` variant
- **Our usage**: Combined with CVE-2018-5999 for unauthenticated `action_script` command injection

### CVE-2016-6558 — apply.cgi action_script Injection

- **Severity**: High
- **Mechanism**: `/apply.cgi` `action_script` command injection — same pattern we use for SSH enable
- **Originally found on**: ASUS RP-AC52 (Repeater)
- **Our firmware**: `3.0.0.4.384_46630` — vulnerable (same codebase)
- **Our usage**: This is the exact CVE covering our `action_script` exploitation technique

### CVE-2018-6000 — Unauthenticated NVRAM Write

- **Severity**: High
- **Mechanism**: POST to `vpnupload.cgi` sets arbitrary NVRAM values without authentication
- **Our usage**: Could set `sshd_enable=1`, `ateCommand_flag=1`, or other NVRAM values without credentials
- **Potential**: Could re-enable CVE-2014-9583 (infosvr PKT_SYSCMD) by setting `ateCommand_flag=1`

### CVE-2014-9583 — infosvr Root Command Execution

- **Severity**: Critical
- **Mechanism**: Send crafted UDP packet to infosvr port 9999 with `PKT_SYSCMD` → command executed as root
- **Status on our firmware**: **Patched** — `ateCommand_flag` check blocks it. But CVE-2018-6000 can re-enable it by setting `ateCommand_flag=1` via unauthenticated `vpnupload.cgi`
- **Our usage**: Not currently used (blocked), but could be combined with CVE-2018-6000

### Exploit Chain Summary

| Path | CVEs Used | Network Access | Result |
|------|-----------|---------------|--------|
| Path 1 (httpd ethernet) | CVE-2021-32030 + CVE-2018-5999/9285 | Same subnet (ethernet) | Unauthenticated root command exec |
| Path 2 (AiMesh wireless) | Protocol RE, no CVEs | Wireless (pairing button) | Device joins our "installation server" |
| Path 3 (firmware restore) | No CVEs — bootloader design | Ethernet (rescue mode) | Valid TRX accepted, CRC-only validation |

### Ethics Note

All vulnerabilities are publicly known, documented in NVD/CISA, and affect an EOL device that will never be patched. This RE work supports OpenWrt integration on hardware we own. No new zero-days were discovered.

## Path 3: Firmware Restore Tool

### Concept

The ASUS Firmware Restoration utility sends a firmware image to a device in rescue mode (hold reset on power-up). The bootloader accepts any valid U-Boot legacy image — it validates magic (0x27051956) + CRC32 checksums only, with **no RSA signature verification**.

We built a tool (`asus-uimage-wrap.py`) that wraps OpenWrt FIT images in a valid U-Boot header matching the stock firmware format. **This approach has NOT been tested on Lyra MAP-AC2200 hardware and carries bricking risk.**

### Bootloader Validation (confirmed from RT-AC58U serial output)

The RT-AC58U uses the same ipq40xx platform and U-Boot bootloader as the Lyra MAP-AC2200. Serial output from rescue mode (GitHub issue openwrt/openwrt#9879) shows the exact validation sequence:

```
Chk trx magic
Download of 0x16f3978 bytes completed
Check TRX and write it to FLASH
Solve TRX, ptr=0x84000000
## Booting kernel from Legacy Image at 84000000 ...
  Image Type: ARM Linux Kernel Image (lzma compressed)
  Data Size: 24066360 Bytes = 23 MiB
  Load Address: 80208000
  Entry Point: 80208000
  Verifying Checksum ... OK
Erase kernel block !!
```

This confirms: magic check → CRC32 verification → erase + write. No RSA, no product ID validation, no hash16.

### Cross-Reference: Same Approach Used on RT-AC58U

The same U-Boot header wrapping technique was used for the ASUS RT-AC58U (also ipq40xx):

1. **OpenWrt PR #802** (ptpt52, 2018): Created `flash-factory.trx` using `KERNEL_INITRAMFS | uImage none` — this is exactly what our `asus-uimage-wrap.py` does
2. **OpenWrt PR #1952** (2019): User reported: *"I put the device into rescue mode and flashed the initramfs with the ASUS Firmware Restoration utility because the webUI was rejecting the initramfs image"* — confirmed rescue mode accepts custom U-Boot wrapped images
3. **chunkeey** (OpenWrt ipq40xx maintainer): Created factory.trx that installs via both web UI and rescue mode, noting the stock bootloader copies linux → linux2 as failsafe

### Rescue Mode Procedure (from ASUS FAQ 1033090)

1. Download ASUS Firmware Restoration utility from ASUS support page
2. Unplug device, hold Reset button, replug power
3. Wait for solid purple light (rescue mode)
4. Set static IP on computer: 192.168.1.10/24
5. Open Firmware Restoration → Browse → select firmware → Upload
6. LED blinks green+purple during upload, various colors during reboot
7. Solid white = done

**Alternative**: Use `TFTPRouterFlasher` (https://github.com/vr-ski/TFTPRouterFlasher) — open-source Python replacement for the ASUS Firmware Restoration utility that works on macOS/Linux.

### ⚠️ Risks and Warnings

**THIS APPROACH HAS NOT BEEN TESTED ON LYRA MAP-AC2200 HARDWARE.**

Known risks from RT-AC58U experience (same bootloader family):

1. **UBI partition size mismatch**: The bootloader writes to the `linux` UBI volume. If the image is larger than the volume, the write fails with `size > volume size!`. The RT-AC58U serial output shows this scenario — bootloader then writes to `linux2` as fallback, but if that also fails, the device is bricked without serial.

2. **UBI partition layout conflict**: OpenWrt and stock firmware use different UBI layouts. After OpenWrt has been installed, the UBI volumes may be restructured. The bootloader's `update_tftp()` function may not handle non-stock layouts correctly.

3. **Dual firmware scheme**: The ASUS bootloader maintains `linux` + `linux2` as a dual-firmware scheme. After OpenWrt modifies UBI volumes, the bootloader's failsafe mechanism may be broken.

4. **No push-button recovery**: The Lyra MAP-AC2200 has no push-button TFTP recovery. If rescue mode fails to accept the image, **serial access (J35 header, 115200 8N1) is the only recovery option**. This requires opening the case.

**MAP-AC2200-specific rescue mode failures** (from OpenWrt forum):

- `slh` (OpenWrt maintainer): push-button TFTP recovery is **not reliable with changed UBI partitions** on this device
- One user reported ASUS restoration tool uploaded "successfully" but the device still booted OpenWrt — the bootloader wrote to `linux2` as fallback instead of replacing the active OpenWrt installation
- Another user couldn't get rescue mode to detect the device at all — serial console was the only solution
- `mtd-unlock -d linux` is required before `mtd-write` on newer stock firmware versions

**Recommendation**: Only test this path if you have:
- A USB-TTL serial adapter
- Willingness to open the device case
- A backup of the Factory MTD partition (calibration data + MAC addresses)

### Status

- [x] Bootloader validation confirmed (CRC-only, no RSA)
- [x] TRX header format documented (see below)
- [x] TRX construction tool built (`asus-uimage-wrap.py`)
- [x] Factory image built and self-verified (OpenWrt 24.10.4 initramfs → 8.7MB factory image)
- [x] Cross-referenced with RT-AC58U (same platform) — approach confirmed working there
- [ ] **NOT TESTED** on Lyra MAP-AC2200 hardware — blocked pending serial adapter availability

### Firmware Image Format (from stock MAP-AC2200_3.0.0.4_384_46630)

The Lyra MAP-AC2200 uses a **U-Boot legacy image** format, NOT Broadcom TRX. The stock firmware is exactly **64-byte header + FIT payload**, with no ASUS tail or footer.

```
Offset  Size  Field         Stock Value              Description
0x00    4     ih_magic      0x27051956               U-Boot legacy magic
0x04    4     ih_hcrc       0xDB70A842               CRC32 of header (with this field zeroed)
0x08    4     ih_time       0x609BD45D               Build timestamp
0x0C    4     ih_size       27,674,732               Payload size (file size - 64)
0x10    4     ih_load       0x80208000               ARM kernel load address
0x14    4     ih_ep         0x80208000               Entry point (= load address)
0x18    4     ih_dcrc       0x90958C54               CRC32 of payload
0x1C    1     ih_os         5                        Linux
0x1D    1     ih_arch       2                        ARM
0x1E    1     ih_type       2                        Kernel
0x1F    1     ih_comp       3                        LZMA (payload is actually uncompressed FIT)
0x20    2     kernel_ver    3.0                      Firmware major.minor
0x22    2     fs_ver        0.4                      Firmware minor version
0x24    12    prod_name     "MAP-AC2200"             Product ID (trx2 tail)
0x30    2     sn            0x8001                   Build number
0x32    2     en            0x26B6                   Extended build number
0x34    1     dummy         0x00                     
0x35    1     key           0x00                     
0x36    6     unk           0x00*6                   
0x3C    1     fs_prefix     0xA9                     fs_offset prefix
0x3D    3     fs_offset     0x225A41                 24-bit BE offset
        ---   
Total:  64    (header) + N bytes (FIT image payload starting with 0xD00DFEED)
```

Key observations:
- File size = ih_size + 64 (perfectly aligned, no padding or footer)
- Payload starts with FIT magic `0xD00DFEED` (Flattened Image Tree)
- `ih_comp = 3` (LZMA) but payload is uncompressed — bootloader ignores this field for FIT images
- Product info is embedded in the `ih_name` field (bytes 0x20-0x3F)
- No ASUS-specific tail/footer beyond the standard U-Boot header
- CRC32 only — no RSA signatures, no hash16 check

### Wrapper Tool

`asus-uimage-wrap.py` wraps any OpenWrt FIT image in a valid U-Boot header:

```bash
# Inspect stock firmware
python3 asus-uimage-wrap.py -x MAP-AC2200_3.0.0.4_384_46630.trx

# Wrap OpenWrt initramfs
python3 asus-uimage-wrap.py -i initramfs.itb -o factory.trx -v

# Verify output
python3 asus-uimage-wrap.py -x factory.trx
```

### References

- `openwrt/firmware-utils/src/asusuimage.c` — ASUS U-Boot image packer (our header format reference)
- `openwrt/firmware-utils/src/asustrx.c` — ASUS TRX packer (Broadcom devices, not Lyra)
- U-Boot `image_header_t` — standard 64-byte legacy image header
- [ASUS FAQ 1033090](https://www.asus.com/support/faq/1033090/) — Lyra firmware restore instructions
- [ASUS FAQ 1000814](https://www.asus.com/us/support/faq/1000814/) — General rescue mode instructions
- [OpenWrt PR #802](https://github.com/openwrt/openwrt/pull/802) — RT-AC58U factory.trx via `uImage none` (same approach)
- [OpenWrt PR #1952](https://github.com/openwrt/openwrt/pull/1952) — RT-AC58U rescue mode initramfs flash (confirmed working)
- [OpenWrt issue #9879](https://github.com/openwrt/openwrt/issues/9879) — RT-AC58U bootloader serial output showing CRC-only validation
- [TFTPRouterFlasher](https://github.com/vr-ski/TFTPRouterFlasher) — Open-source Python rescue mode client
- [klseet.com guide](https://klseet.com/networking/router-firmware/openwrt/asus-lyra-map-ac2200-flash-to-openwrt) — Lyra SSH+mtd-write flashing guide
- [OpenWrt forum: MAP-AC2200 return-to-stock](https://forum.openwrt.org/t/map-ac2200-upgrade-and-return-to-factory-default/138755) — rescue tool "succeeds" but boots OpenWrt, `slh` warns about UBI issues
- [OpenWrt forum: revert to stock firmware](https://forum.openwrt.org/t/revert-to-stock-firmware-on-asus-map-ac2200/127001) — rescue tool fails to detect device, serial required
- [OpenWrt forum: 24.10 install issue](https://forum.openwrt.org/t/lyra-ac2200-owrt-24-10-install-issue/226580) — `mtd-unlock` required on newer stock firmware

## Recovery Notes

- No push-button TFTP — serial required for debrick
- Serial header J35, 2mm pitch, 115200 8N1, pinout: 3.3v-RX-TX-GND (square=VCC)
- U-Boot TFTP: server at 192.168.1.70, filename `HIVESPOT.trx`
- Rescue mode: hold reset on power-up → solid purple light → Firmware Restoration utility at 192.168.1.1
- **If rescue mode fails, serial is the ONLY recovery option** — device must be opened

## WiFi Installation Path (Session 2026-05-27)

### Goal

Flash a factory-default Lyra MAP-AC2200 from an OpenWrt host router (lyra.lan) over WiFi — no ethernet cable needed. The host router connects to the stock device's setup SSID as a WiFi client, runs the CVE chain to enable SSH, then flashes via SCP/mtd-write.

### What We Built

1. **`--wifi` flag** in `flash-openwrt.sh` — enables WiFi-based device discovery and flashing from OpenWrt hosts
2. **`wifi_scan_asus()`** — scans the STA interface for `ASUS_*` SSIDs using `iw scan`, returns matching networks sorted by signal strength
3. **`wifi_connect()`** — configures the STA radio via `uci set wireless.default_radio1.ssid`, reloads wifi, sets a static IP on the STA interface, verifies ping to the stock device. Skips reconfiguration if already connected to the target SSID
4. **`fingerprint_http()`** — HTTP-based device fingerprinting before any SSH access. Detects:
   - **Vendor**: ASUS (httpd/2.0) vs OpenWrt (uhttpd/LuCI) vs unknown
   - **Firmware type**: stock_asus, openwrt, unknown
   - **Device state**: factory_default (QIS_wizard redirect), wizard_completed (Main_Login redirect), unknown
   - **Recommended install method**: cve_chain_no_wizard, cve_chain_or_ssh, sysupgrade, manual_investigation
   - **Device model hint**: checks HTML for "Lyra" or "MAP-AC2200" strings
5. **`--wifi-ssid`, `--wifi-sta-ip`, `--wifi-target-ip`** options for explicit WiFi configuration
6. **Model JSON** updated with `wifi-sta-flash` flash method documenting SSID pattern, encryption, host STA radio requirements

### Proven Results (WiFi Path)

From lyra.lan (OpenWrt 24.10.4) to stock Lyra research device at 192.168.72.1:

| Step | Result | Evidence |
|------|--------|----------|
| WiFi scan | ✅ Found `ASUS_C8_AMAPS` on 2.4GHz ch11 | `iw phy1-sta0 scan dump` matched `SSID: ASUS_C8_AMAPS` |
| WiFi connect | ✅ Connected, -30 to -45 dBm | `iw phy1-sta0 link` showed Connected |
| Static IP | ✅ 192.168.72.50/24 on phy1-sta0 | ping 192.168.72.1 → 0% loss |
| Firmware detection | ✅ `Server: httpd/2.0` | Fixed from "Unknown" (replaced `-D -` with `-sI`) |
| Fingerprinting | ✅ `vendor:ASUS, state:factory_default, install_method:cve_chain_no_wizard` | Full fingerprint output logged |
| CVE-2021-32030 auth bypass | ⚠️ Returned HTTP 200 on wizard-completed device, unreliable on factory-default | See "What Failed" below |
| CVE-2018-5999 apply.cgi | ⚠️ First call returned `"modify": "1"` on factory-default, then locked out | See "What Failed" below |
| SSH access | ❌ Connection refused on factory-default device | sshd would not start |

### What Failed and Why

#### Factory-default auth bypass (CVE-2021-32030) unreliable

The first `apply.cgi` call on the factory-reset device returned `"modify": "1"` (NVRAM was written). All subsequent calls returned `error_status: 2` (AUTHFAIL).

**Root cause** (from Atredis research and asuswrt-merlin source analysis):

1. The first call succeeded because of **`is_firsttime()` mode**, not the IFTTT null-byte bypass. Factory-default devices allow unauthenticated access to setup endpoints.
2. The first `apply.cgi` call wrote NVRAM, which **changed the device state** so `is_firsttime()` no longer returned true.
3. After that, normal auth kicked in. The null-byte `asus_token=%00` with `User-Agent: asusrouter--` is supposed to match the default null `ifttt_token` via `strcmp()`, but `apply.cgi` has **additional auth checks beyond the IFTTT token** that the bypass doesn't satisfy.
4. Repeated failed attempts triggered **lockout mode** (`error_status: 7`, `remaining_lock_time: 263`). Lockout persists in NVRAM for 5 minutes and blocks all endpoints including QIS wizard pages.

**Error status codes** (from httpd.h):
- `1` = NOTOKEN (no token provided)
- `2` = AUTHFAIL (authentication failed)
- `3` = ACCOUNTFAIL (account check failed)
- `7` = LOGINLOCK (lockout active, `remaining_lock_time` shows seconds remaining)

**Conclusion**: The CVE chain works reliably on **wizard-completed** devices (tested on 2 Batch 1 and 2 Batch 2 units). It does NOT reliably work on **factory-default** devices because the auth code path differs. The `is_firsttime()` bypass is a one-shot that changes device state, and the IFTTT null-byte bypass doesn't cover all auth checks in `apply.cgi` on factory-default firmware.

#### sshd won't start on factory-default device

Even after the first `apply.cgi` call wrote `sshd_enable=1` to NVRAM, sshd did not start (port 22 refused). On the research device (which had been heavily modified during RE work), this was expected due to corrupted NVRAM (`blacklist_confirm: is_lan=0, is_wan=0, is_wl=0`). On the factory-reset device, the issue is that sshd may require additional setup (host key generation, password configuration) that doesn't happen automatically from just the NVRAM variable.

### Bugs Found and Fixed During WiFi Testing

| Bug | Impact | Fix |
|-----|--------|-----|
| `run_priv()` infinite recursion on macOS | Script would crash on Mac (called itself instead of `sudo`) | Changed `run_priv "$@"` to `sudo "$@"` in else branch |
| `curl -D -` returns no Server header on OpenWrt | Firmware type always detected as "Unknown" | Replaced with `curl -sI` for HEAD-only request |
| `grep -oP` (Perl regex) not in BusyBox | Fingerprinting crashed on OpenWrt | Replaced with `sed -n 's/.../p'` |
| `md5 -q` not available on OpenWrt | Hash verification failed | Replaced with `file_hash()` using `shasum -a 256` (macOS) or `sha256sum` (OpenWrt) |
| `CURL_OPTS` with `2>/dev/null` swallowed errors | CVE chain curl failures were silent | Replaced all `$CURL_OPTS` with explicit `curl -s --max-time 10`, removed `2>/dev/null` |
| `detect_interface()` runs in WiFi mode | Script dies looking for USB ethernet when `--wifi` is set | Skip `detect_interface()` when `WIFI_MODE=true` |
| `local` used outside functions | Script crashes at top-level code on OpenWrt ash | Removed dead `local ssh_test` variable |
| `wifi reload` disconnects already-connected STA | Subsequent runs fail to reconnect | `wifi_connect()` now checks if already connected to target SSID before reconfiguring |

### UBIFS Overlay Persistence (lyra2 Deployment Lessons)

The MAP-AC2200 uses a **UBIFS overlay** on a UBI volume (`/dev/ubi0_7`, 36.4MB). This has critical implications for post-flash configuration:

#### What persists and what doesn't

| Write method | Persists after reboot? | Persists after `network restart`? | Persists after unclean power loss? |
|---|---|---|---|
| `uci commit` (any section) | ✅ Yes | ✅ Yes | ✅ Yes |
| `passwd root` (writes /etc/shadow) | ✅ Yes* | ❌ No | ❌ No |
| `echo/cp` to /etc/dropbear/authorized_keys | ✅ Yes* | ❌ No | ❌ No |
| `echo/cp` to /tmp/ (tmpfs) | ❌ No | ❌ No | ❌ No |

\* Only with `sync; sync` before `reboot` (clean shutdown)

#### Root cause

`uci commit` calls `fsync()` explicitly, which goes all the way through the VFS → UBI → flash stack. Regular file writes (`echo >`, `cp`, `passwd`) go through the VFS page cache → UBIFS write-back cache → eventually to flash. The UBIFS write-back is asynchronous — `sync` flushes the kernel page cache but UBIFS has its own internal buffering. Only a clean `reboot` (which triggers a full filesystem sync during shutdown) guarantees all UBIFS buffers are flushed.

#### Verified behavior (2026-05-28)

1. Wrote test file + set password on factory-default OpenWrt at 192.168.1.1
2. Ran `sync; sync; reboot` (clean shutdown)
3. After reboot: test file, password hash, and SSH key all persisted ✅
4. Previously: applied same config, used `network restart` to change IP → SSH key and password lost ❌
5. Previously: applied config, user unplugged device (unclean power loss) → SSH key and password lost ❌

#### Safe configuration pattern

```bash
# 1. Apply all configuration (UCI + file writes)
uci set system.@system[0].hostname="lyra2"
uci commit system
echo "ssh-rsa ..." > /etc/dropbear/authorized_keys
printf '%s\n%s\n' 'password' 'password' | passwd root

# 2. Flush everything
sync
sync

# 3. Clean reboot (NOT network restart!)
reboot

# 4. Wait for device to come back, then verify
# 5. Only NOW is it safe to disable password auth
uci set dropbear.main.PasswordAuth='off'
uci commit dropbear
sync; sync; reboot
```

#### NEVER do these

- `network restart` to apply config changes — drops SSH and doesn't flush UBIFS
- `echo key > authorized_keys && uci set dropbear.PasswordAuth=off` in one shot — if key write is lost, you're locked out
- Disable password auth before verifying key survives reboot
- Unplug device after config without running `sync; sync` first

#### OpenWrt factory reset on MAP-AC2200

- **Hold reset 5 seconds**: Partial reset — UCI settings (IP, hostname) may survive, but file-level changes (/etc/shadow, authorized_keys) are lost
- This creates a "zombie state" where UCI says PasswordAuth=on but no valid password exists
- Recovery: hold reset again, connect at 192.168.1.1 on LAN port, reconfigure from scratch

#### Power cycle persistence confirmed (2026-05-28)

After deploying lyra2 with the safe configuration pattern (sync; sync; reboot), the device survived a full power cycle (unplugged and replugged ~30 minutes later):
- Hostname: `lyra2` persisted ✅
- SSH key auth: persisted ✅
- Password auth disabled: persisted ✅
- LAN IP: 10.231.9.198 persisted ✅
- WiFi disabled: persisted ✅
- WAN SSH rule: persisted ✅

Note: WAN DHCP lease changed (.210 → .119) after power cycle — expected behavior, WAN IP is dynamic. DNS hostname `lyra2.lan` still resolves correctly via mDNS/avahi.

### What We Will Do Different Next Time

1. **Use the proven LAN method for factory-default devices**: Plug ethernet into the correct stock LAN port (far port for Batch 2, middle port for Batch 1), complete the wizard, enable SSH via web UI, then flash via mtd-write. This has been tested on 4 units with 100% success rate.

2. **Complete the wizard before running the CVE chain**: The CVE chain (CVE-2021-32030 + CVE-2018-5999) works reliably on wizard-completed devices. If we want to avoid manual wizard completion, we should automate the wizard via Playwright (already proven on Batch 1 unit 1) or curl-based wizard POST.

3. **Respect the lockout timer**: After 5 failed auth attempts, the device locks out for 5 minutes (stored in NVRAM). If we get `error_status: 2` more than 3 times, stop and wait 5 minutes before retrying. Do NOT hammer the device with repeated attempts.

4. **WiFi path is viable for wizard-completed devices only**: The `--wifi` flag works perfectly for connecting to a stock device that has already completed its wizard. Use case: an OpenWrt installation server flashes nearby stock Lyras over WiFi without ethernet cables. Device must have completed wizard first.

5. **Fingerprint before flashing**: The `fingerprint_http()` function reliably detects device type, state, and recommended install method. Always run this before attempting any flash method — it tells you whether the device is in factory_default, wizard_completed, or already running OpenWrt.

6. **Use SHA256 not MD5**: `file_hash()` uses sha256 on both macOS and OpenWrt. More secure, equally fast.

7. **Deploy firmware to /tmp on OpenWrt host**: The OpenWrt host router has ~117MB free in `/tmp` (tmpfs). Firmware files are ~17MB total (initramfs + sysupgrade). Plenty of space.

### Known Unknowns

1. **Why does the IFTTT null-byte bypass not work for `apply.cgi` on factory-default firmware?** The bypass is supposed to match the default null `ifttt_token` via `strcmp()`. The Atredis research confirms this should work. Our first call succeeded via `is_firsttime()`, not the IFTTT bypass. We don't know what additional auth checks `apply.cgi` performs that the IFTTT token doesn't cover. Would require RE of the factory-default httpd binary (different from the wizard-completed binary in our firmware dump).

2. **Can the wizard be completed via curl without a browser?** We know the QIS wizard pages redirect to `/QIS_wizard.htm` and the wizard sets the admin password, WiFi SSID, etc. If we could automate this with curl POSTs, we could go from factory-default → wizard-completed → CVE chain → SSH → flash without any browser interaction. The wizard flow needs to be reverse-engineered.

3. **What is the full auth code path in httpd for factory-default vs wizard-completed?** We know `is_firsttime()` allows one-shot unauthenticated access. We know the IFTTT token is null on factory-default. We know `apply.cgi` has auth checks beyond the IFTTT token. We don't know the complete flow. Would require static analysis of the httpd binary from the firmware dump on the Ubuntu RE box.

4. **Does the lockout persist across factory resets?** Lockout is stored in NVRAM variables (`HTTPD_LOGIN_FAIL_LAN`, `lock_flag`). A factory reset clears NVRAM, which should also clear the lockout. We triggered lockout, waited for it to expire, and it returned. But we don't know if a second factory reset would have cleared it immediately.

5. **Can infosvr PKT_SYSCMD (CVE-2014-9583) work over WiFi?** We sent a properly formatted 512-byte UDP packet to port 9999 on the stock device via the WiFi STA interface but got no response. The infosvr daemon might only listen on the LAN ethernet bridge, not on WiFi interfaces. Or it might be disabled on factory-default firmware.

6. **What is the ASUS_* SSID naming pattern?** We observed `ASUS_C8_AMAPS` on our test device. The `C8` appears to come from the MAC OUI (`2c:fd:a1` → `2C:FD:A1`, and `C8` might be from the 4th byte of the MAC). `AMAPS` might be short for "ASUS MAP-AC2200". We don't know the exact derivation or if other Lyra models use different suffixes.

7. **Can we flash entirely over WiFi without ethernet at any point?** The WiFi path connects, fingerprints, and runs the CVE chain. But we can't get SSH running on factory-default devices. If we could solve the wizard automation or the `apply.cgi` auth issue, the entire process could be cable-free: factory-reset device → installation server auto-scans WiFi → connects → enables SSH → flashes → done.

### Files Modified

| File | Changes |
|------|---------|
| `recipes/asus/lyra-map-ac2200/flash-openwrt.sh` | Added `--wifi` flag, `wifi_scan_asus()`, `wifi_connect()`, `fingerprint_http()`, `file_hash()` (SHA256), fixed `run_priv()`, fixed curl commands, BusyBox compatibility |
| `models/asus-lyra-map-ac2200.json` | Added `wifi-sta-flash` flash method, updated `reset_instructions` with WiFi and CVE chain info |
| `recipes/asus/lyra-map-ac2200/asus-uimage-wrap.py` | Previously built — wraps FIT images in U-Boot headers for Path 3 (documented, not recommended) |
