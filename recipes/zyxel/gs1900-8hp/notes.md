# ZyXEL GS1900-8HP — OpenWrt Installation Notes

## Device Identification

Two hardware revisions exist, both supported in OpenWrt 25.12.1:

| Revision | Old name | RAM | PoE Controller | DTS compatible |
|----------|----------|-----|----------------|----------------|
| A1 | v2 | 128 MiB DDR3 (Samsung) | Broadcom BCM59121B0KMLG | `zyxel,gs1900-8hp-a1` |
| B1 | v1 | 128 MiB DDR2 (Nanya) | Broadcom BCM59111KMLG x2 | `zyxel,gs1900-8hp-b1` |

OpenWrt renamed v1/v2 to B1/A1 in September 2025 (commit d205878) to match ZyXEL's actual labeling. The first revision is NOT labeled "A1" on the sticker — check the web UI or U-Boot banner (`Model: ZyXEL_GS1900_8HP`).

### Identifying your revision

- **U-Boot banner** (serial): Shows `Model: ZyXEL_GS1900_8HP` — revision not displayed, must identify by PCB
- **OEM web UI**: Dashboard shows Model Name, Serial Number, MAC, Firmware Version but NOT hardware revision
- **Physical**: A1 shares casing with GS1900-10HP; B1 shares casing with non-PoE GS1900-8
- **MAC OUI**: BC:CF:4F and E8:37:7A (both revisions, both OUIs observed)
- **Firmware file naming**: The .bix filename inside the zip is `runtime-GS1900-8HPv2.1-V2.90(AAHI.0).bix` — the "v2.1" may indicate the firmware targets v2/A1 hardware. However, ZyXEL's release notes list both A1 and B1 using the same download, so the firmware is universal.

### Hardware fingerprint (live device S/N XXXXX-XXXXXXXXX)

**Verified on hardware, 2026-05-21:**

| Field | Value |
|-------|-------|
| Model Name | GS1900-8HP |
| **Hardware Revision** | **A1** (confirmed by v2.90 firmware dashboard) |
| Serial Number | XXXXX-XXXXXXXXX (S15 → NOT S21+, firmware update not mandatory) |
| MAC Address Range | E8:37:7A:XX:XX:XX ~ E8:37:7A:XX:XX:XX |
| MAC OUI | E8:37:7A (ZyXEL) |
| Boot Module | 1.000 |
| Original Firmware | V2.00(AAHI.2) \| 2015-02-09 |
| **Current Firmware** | **V2.90(AAHI.0) \| 10/24/2024** |

**LLDP discovery data:**
```
LLDP System Desc:  GS1900-8HP
LLDP ZyXEL Model:  GS1900-8HP
LLDP ZyXEL FW:     V2.00(AAHI.2) (pre-update; will report V2.90 after next LLDP cycle)
LLDP ZyXEL Serial: E8-37-7A-9E-F6-86 (= MAC address, NOT the real serial)
```

The LLDP-reported "serial" is actually the MAC address, not the real serial number (XXXXX-XXXXXXXXX from dashboard). The real serial is only available from the dashboard page or device label.

### Second device (S/N S150H13001490, Rev A1)

**Verified on hardware, 2026-05-21:**

| Field | Value |
|-------|-------|
| Model Name | GS1900-8HP |
| **Hardware Revision** | **A1** (confirmed by v2.90 firmware dashboard) |
| Serial Number | S150H13001490 (S15 → NOT S21+, firmware update not mandatory) |
| MAC Address | 4C:9E:FF:XX:XX:XX |
| MAC OUI | **4C:9E:FF** (ZyXEL — NEW OUI, not previously in model JSONs) |
| Boot Module | 1.000 |
| Original Firmware | V2.00(AAHI.0) \| 2014-06-25 |
| **Current Firmware** | **V2.90(AAHI.0)** (updated 2026-05-21) |
| Update Method | curl HTTP upload to httpupload.cgi (V2.00 plaintext login → flash → V2.90 encode() login → password change) |
| New Credentials | admin/Zyxel2026! |

**Key observations from this device:**
1. **MAC OUI 4C:9E:FF** observed on a Rev A1 unit (previous device used E8:37:7A)
2. **V2.00 firmware from 2014** (AAHI.0, not AAHI.2 like the first device) — older factory firmware
3. **V2.90 encode() login verified** — the obfuscated POST login works with curl (no browser needed)
4. **Password change via curl verified** — POST to dispatcher.cgi with encoded passwords works
5. **Same .bix firmware file** works for both devices regardless of MAC OUI or initial firmware minor version

## Safety Warnings

### CRITICAL: Serial Number Check

**Devices with serial numbers starting "S21" or higher MUST run stock firmware v2.70 or newer before any firmware changes.** Older stock firmware can **irreversibly brick PoE capabilities** regardless of what firmware is flashed afterwards (including newer stock or OpenWrt).

Source: https://community.zyxel.com/en/discussion/15891/

Check serial number on the device label or dashboard (cmd=7) before proceeding.

### Serial Number Assessment (this device)

- Serial: XXXXX-XXXXXXXXX → starts with **S15**, NOT S21+
- **Firmware update NOT mandatory** for this specific device
- Recommended anyway for security fixes (CVE-2024-8881, CVE-2024-8882 in v2.90)

### PoE Power Loss During Reboot

The PoE MCU (STM32F100C8) is initialized by the bootloader at power-on, enabling PoE+ on all ports. MCU state is **not preserved across reboots** — all connected PoE devices will briefly lose power when the switch restarts. Plan accordingly for sensitive equipment (IP cameras, APs, etc.).

## Hardware

- **SoC**: Realtek RTL8380M MIPS 4KEc @ 500MHz
- **Flash**: 16 MiB SPI NOR (Macronix MX25L12835F)
- **RAM**: 128 MiB (DDR2 for B1, DDR3 for A1)
- **Ethernet**: 8x 10/100/1000 Mbps via RTL8218B internal PHYs
- **PoE**: 70W budget, 802.3af/at (PoE+), all 8 ports
- **PoE MCU**: STM32F100C8 ARM Cortex-M3 (manages Broadcom PoE controllers)
- **Serial**: UART header, 115200 8N1, 3.3V (left side PCB, labeled VCC/TX/RX/GND)
- **GPIO**: RTL8231 for LED/GPIO expansion, poe_enable on gpio1 pin 13

## Flash Layout

Dual-partition layout (identical to GS1900-24E):

```
0x000000 - 0x040000  u-boot         256K   (read-only)
0x040000 - 0x050000  u-boot-env     64K    (read-only)
0x050000 - 0x060000  u-boot-env2    64K    (read-only)
0x060000 - 0x160000  jffs           1024K
0x160000 - 0x260000  jffs2          1024K
0x260000 - 0x930000  firmware       6976K  (active, partition 0)
0x930000 - 0x1000000 runtime2       6976K  (backup, partition 1)
```

OpenWrt 25.12.1 may merge to a single 13952K firmware partition after sysupgrade (same as GS1900-24E behavior).

## OEM Web UI Reference

### Frameset Architecture

The OEM web UI uses a 3-frame frameset loaded from `dispatcher.cgi?cmd=1`:

```
cmd=1 (frameset container)
├── topFrame    → cmd=6  (header: logo, model name, Help/About/Save/Logout)
├── contentFrame → cmd=7 (main content area: dashboard, config pages, etc.)
└── floorFrame  → /admin/floor.html (footer, static)
```

When navigating to Monitoring/Configuration/Maintenance, the contentFrame replaces the whole frameset with a new 2-frame layout:

```
cmd=18/19/20 (section frameset)
├── pannel    → cmd=21/22/23 (left tree navigation + section icons)
└── mainFrame → cmd=515/516/5903 (actual page content)
```

### Login Flow

#### V2.00 (plaintext GET login)

1. Navigate to `http://192.168.1.1/` → redirects to `dispatcher.cgi?cmd=0`
2. JavaScript constructs login URL: `dispatcher.cgi?login=1&username=admin&password=1234&dummy=<timestamp>`
3. Response: `AUTHING` (async auth)
4. Session is established server-side (no cookie visible via curl)
5. Session check: `dispatcher.cgi?session_chk=1` → returns `NOTIMEOUT` or triggers redirect to cmd=2 (login)
6. Session timeout: 15-second polling via `session_check()` JavaScript

#### V2.80+ (encode() obfuscated POST login)

V2.80+ uses a custom JavaScript `encode()` function that obfuscates the password by embedding it at fixed positions in a random alphanumeric string. This is NOT RSA encryption — it's reversible obfuscation.

1. POST to `dispatcher.cgi` with body: `username=<user>&password=<urlencoded(encode(password))>&login=true;`
2. Response is a hex authId hash (e.g. `E8EAC5161A7C3D6D40DBE4B316611C60`)
3. POST to `dispatcher.cgi` with body: `authId=<hash>&login_chk=true`
4. Response: `OK` on success, `FAIL` on failure
5. Cookie `HTTP_XSSID` is set in session

**encode() algorithm** (Python implementation):
```python
def encode_password(password):
    import random, string
    text = ''
    possible = string.ascii_letters + string.digits
    length = len(password)
    remaining = length
    for i in range(1, 322 - length + 1):
        if i % 5 == 0 and remaining > 0:
            remaining -= 1
            text += password[remaining]  # chars inserted backwards
        elif i == 123:
            text += '0' if length < 10 else str(length // 10)
        elif i == 289:
            text += str(length % 10)
        else:
            text += random.choice(possible)
    return text
```

Verified on hardware (S/N S150H13001490, V2.90 firmware), 2026-05-21.

#### V2.80+ Mandatory Password Change

After V2.90 boots with default password `1234`, all pages redirect to `cmd=30` (password change form).

Password change form fields:
- `XSSID`: Hidden token from cmd=30 page HTML
- `usrName`: admin
- `usrOldPass`: encode(old_password)
- `usrPass`: encode(new_password)
- `usrPass2`: encode(new_password)
- `usrPassEncode`: encode(new_password) (same as usrPass)
- `cmd`: 31
- `sysSubmit`: Apply

POST to `dispatcher.cgi`. Success redirects to `cmd=4`. New password cannot be `1234` (default).

Verified on hardware (S/N S150H13001490), 2026-05-21.

### Complete cmd Map (V2.00 firmware)

Verified by Playwright evaluation on live device, 2026-05-21:

#### Top-level navigation

| cmd | Section | Description |
|-----|---------|-------------|
| 0 | Login | Login page |
| 1 | Main frameset | 3-frame layout (topFrame/contentFrame/floorFrame) |
| 2 | Session timeout | Redirect target when session expires |
| 4 | Save | Save current configuration |
| 5 | About | Popup: Boot Module, Firmware Version, Release Date |
| 6 | Header frame | topFrame content |
| 7 | Dashboard | Getting Start page with Device Information, Wizard, Virtual Device |

#### Section framesets

| cmd | Section | Left panel | Default content |
|-----|---------|-----------|-----------------|
| 18 | Monitoring | cmd=21 | cmd=515 (IP Information) |
| 19 | Configuration | cmd=22 | cmd=516 (IP Configuration) |
| 20 | Maintenance | cmd=23 | cmd=5903 (Firmware) |

#### Monitoring menu tree (cmd=21)

| Menu path | cmd |
|-----------|-----|
| System → IP | 515 |
| System → Information | 514 |
| Port → Port | 798 |
| Port → PoE | 775 |
| Port → Bandwidth Management | 4618 |
| Port → Storm Control | 4613 |
| VLAN → VLAN | 1320 |
| VLAN → Guest VLAN | 5132 |
| VLAN → Voice VLAN | 1327 |
| MAC Table | 3089 |
| Link Aggregation | 1043 |
| Loop Guard | 7941 |
| Multicast → IGMP | 1812 |
| Spanning Tree | 5393 |
| LLDP | 6154 |
| Security → Port Security | 781 |
| Security → 802.1X | 5126 |
| Management → Syslog | 4876 |
| Management → Error Disable | 792 |

#### Configuration menu tree (cmd=22)

| Menu path | cmd |
|-----------|-----|
| System → IP | 516 |
| System → Time | 554 |
| System → Information | 512 |
| Port → Port | 768 |
| Port → EEE | 4352 |
| Port → PoE | 771 |
| Port → Bandwidth Management | 4614 |
| Port → Storm Control | 4608 |
| VLAN → VLAN | 1282 |
| VLAN → Guest VLAN | 5127 |
| VLAN → Voice VLAN | 1307 |
| MAC Table | 3079 |
| Link Aggregation | 1024 |
| Loop Guard | 7936 |
| Mirror | 2816 |
| Multicast → IGMP | 1805 |
| Spanning Tree | 5376 |
| LLDP | 6144 |
| QoS → General | 3330 |
| QoS → Trust Mode | 3341 |
| Security → Port Security | 779 |
| Security → Protected Port | 785 |
| Security → 802.1X | 5120 |
| Security → DoS | 6400 |
| AAA → Auth Method | 6656 |
| AAA → RADIUS | 7681 |
| AAA → TACACS+ | 6679 |
| Management → Syslog | 4864 |
| Management → SNMP | 3840 |
| Management → Error Disable | 790 |
| Management → HTTP/HTTPS | 544 |
| Management → Users | 525 |
| Management → Remote Access Control | 8704 |

#### Maintenance menu tree (cmd=23)

| Menu path | cmd |
|-----------|-----|
| Firmware | 5903 |
| Configuration | 5901 |
| Diagnostics → Port Test | 8448 |
| Diagnostics → PING | 530 |
| Diagnostics → Trace | 534 |
| Reboot | 5888 |

### Firmware Upload Page (cmd=5903)

Verified by Playwright on live device, 2026-05-21:

#### Form structure

```html
<form id="upform" method="post" action="/cgi-bin/httpupload.cgi" enctype="multipart/form-data">
  <!-- Upload method: 0=TFTP, 1=HTTP -->
  <input type="radio" name="upmethod" value="0" id="upmethod_0">  <!-- TFTP -->
  <input type="radio" name="upmethod" value="1" id="upmethod_1">  <!-- HTTP -->

  <!-- TFTP fields (active when upmethod=0) -->
  <input type="text" name="tftp_srvip" id="tftp_srvip">    <!-- Server IP -->
  <input type="text" name="tftp_file" id="tftp_file">      <!-- File name -->

  <!-- Partition selection -->
  <input type="radio" name="partition" value="0" id="partition_0">  <!-- Active -->
  <input type="radio" name="partition" value="1" id="partition_1">  <!-- Backup -->

  <!-- HTTP file upload (active when upmethod=1) -->
  <input type="file" name="http_file" id="http_file">

  <!-- Submit -->
  <input type="hidden" name="cmd" value="5904">
  <input type="submit" name="sysSubmit" value="Apply">
  <input type="reset" name="Cancel" value="Cancel">
</form>
```

#### JavaScript behavior

When `upmethod=1` (HTTP) is selected:
- Form action changes to `/cgi-bin/httpupload.cgi`
- Encoding changes to `multipart/form-data`
- TFTP fields are disabled
- File input is enabled

When `upmethod=0` (TFTP) is selected:
- Form action stays at `/cgi-bin/dispatcher.cgi`
- Encoding changes to `text/plain`
- TFTP fields are enabled
- File input is disabled

#### Upload flow (HTTP)

1. Select HTTP method (upmethod=1)
2. Select partition (0=Active for firmware upgrade, 1=Backup)
3. Choose .bix file via Browse button
4. Click Apply → form POSTs to `/cgi-bin/httpupload.cgi` with `cmd=5904`
5. JavaScript `showLoader()` shows loading animation
6. `submitValidate()` checks file is selected and filename ≤ 128 chars
7. Device reboots with new firmware

#### Upload flow (TFTP)

1. Select TFTP method (upmethod=0)
2. Enter TFTP server IP (your machine, e.g. 192.168.1.2)
3. Enter filename (e.g. `runtime-GS1900-8HPv2.1-V2.90(AAHI.0).bix`)
4. Select partition
5. Click Apply → device fetches file from TFTP server
6. Device reboots with new firmware

**Note**: TFTP is a good long-term option for conwrt automation since it doesn't require browser automation. conwrt already includes `scripts/tftp-server.py`.

#### Partition strategy

- **Active (partition 0)**: The running firmware lives here. Use for stock firmware upgrades.
- **Backup (partition 1)**: Contains backup OEM firmware. Useful for recovery.
- For stock firmware update: flash to Active partition (0)
- For OpenWrt initramfs: flash to Active partition (0), keeping Backup with OEM for recovery
- To return to stock: boot from Backup partition (serial: `setsys bootpartition 1`)

### Dashboard Device Information (cmd=7)

The dashboard iframe at cmd=7 shows:

```
System Name:      Switch
Model Name:       GS1900-8HP
Serial Number:    XXXXX-XXXXXXXXX
MAC Address:      E8:37:7A:XX:XX:XX ~ E8:37:7A:XX:XX:XX
Firmware Version: V2.00(AAHI.2)
System Up Time:   0 days, 0 hours, 51 mins
Current Date:     00:51:48 UTC+0 Jan 01 2000
CPU Usage:        3.0%
Memory Usage:     71.0%
```

The dashboard also embeds iframes:
- cmd=8: Dashboard info overlay (hidden by default)
- cmd=256: Virtual Device display

### About page (cmd=5)

```
Boot Module:     1.000
Current Version: V2.00(AAHI.2)
Released Date:   2015-02-09 16:28:16
```

## Stock Firmware Update

### Firmware Version History

| Version | Date | Download | Key Changes |
|---------|------|----------|-------------|
| V2.00(AAHI.2) | 2015-02-09 | (factory) | Original firmware |
| V2.80(AAHI.0) | 2023-10 | [download](https://download.zyxel.com/GS1900-8HP/firmware/GS1900-8HP_2.80\(AAHI.0\)C0.zip) | OpenSSL fixes, PoE fix, mandatory password change, HTTPS cert import |
| V2.90(AAHI.0) | 2024-11 | [download](https://download.zyxel.com/GS1900-8HP/firmware/GS1900-8HP_2.90\(AAHI.0\)C0.zip) | CVE-2024-8881 (cmd injection), CVE-2024-8882 (buffer overflow), port counter display |

Both A1 and B1 revisions use the same firmware file.

### Firmware file

- **Latest**: `runtime-GS1900-8HPv2.1-V2.90(AAHI.0).bix`
- **Size**: 5.8 MB (6,084,808 bytes)
- **SHA-256**: `38e5cb9eca497c57d47c325d70f2d008b54cefe37a2057e599e44ca40c871fae`
- **Source**: `data/GS1900-8HP_2.90(AAHI.0)C0.zip`
- **Inside zip**: `runtime-GS1900-8HPv2.1-V2.90(AAHI.0).bix` + release notes PDF + FOSS PDF

### Recommended update path

1. V2.00(AAHI.2) → V2.90(AAHI.0) — direct upgrade, no intermediate steps needed
2. Flash to Active partition (0) via HTTP upload
3. After reboot, login will require password change (v2.80+ feature)

### Update procedure (Playwright HTTP upload)

Prerequisites: Device reachable at 192.168.1.1, firmware .bix extracted to data/

1. Start pcap capture on interface (`tcpdump -i en5 -w captures/gs1900-8hp-firmware-upgrade.pcap`)
2. Navigate to `http://192.168.1.1/` → auto-redirect to `cmd=0` login
3. Fill username=admin, password=1234, click Login
4. Navigate to Maintenance section (cmd=20)
5. In the mainFrame, evaluate the firmware upload form:
   - Select HTTP method (upmethod=1)
   - Select Active partition (partition=0)
   - Upload .bix file
   - Click Apply
6. Wait for device to reboot (~90 seconds based on GS1900-24E timing)
7. After reboot, device will be at 192.168.1.1 with new firmware
8. Login with admin/1234 → mandatory password change prompt
9. Stop pcap capture

### Update procedure (TFTP)

Prerequisites: Device reachable at 192.168.1.1, firmware .bix in TFTP server root

1. Start TFTP server: `python3 scripts/tftp-server.py --directory data/`
2. Navigate to Maintenance → Firmware (cmd=5903)
3. Select TFTP method (upmethod=0)
4. Enter server IP: 192.168.1.2
5. Enter filename: `runtime-GS1900-8HPv2.1-V2.90(AAHI.0).bix`
6. Select partition: Active (0)
7. Click Apply
8. Wait for device to reboot (~90 seconds)

### Post-update expectations

- Firmware: V2.90(AAHI.0)
- Mandatory password change on first login
- Enhanced port status page with Tx/Rx and error counters
- ECDSA certificate support
- Fixed CVE-2024-8881, CVE-2024-8882

## Flashing Methods

### Method 1: OEM Web UI (Recommended, No Serial Required)

This is the easiest method and works on stock firmware without any special equipment.

1. Connect ethernet to any port (port 1 recommended)
2. Set your PC to 192.168.1.x (e.g. 192.168.1.2/24)
3. Browse to http://192.168.1.1, login with admin/1234
4. **Check active partition**: Maintenance → Firmware → Management
   - If first option is active → flash to "Active" partition
   - If second option is active → flash to "Backup" partition
5. **Upload initramfs**: Maintenance → Firmware → Upload → upload `*-initramfs-kernel.bin`
6. Reboot when prompted → device boots OpenWrt initramfs
7. **Permanent install**: SCP the sysupgrade image to /tmp, run `sysupgrade -n /tmp/<image>`

The conwrt `oem-playwright` method automates this entire flow (RSA login, frameset navigation, firmware upload).

**If you flashed initramfs to the wrong partition**: Device will appear to reset on every boot (no overlay). Fix via serial:
```
fw_setenv bootpartition 0
```

### Method 2: Serial + TFTP (Recovery)

Requires FTDI adapter (3.3V) connected to UART header.

1. Connect serial, power on, press SPACE within 1 second
2. Set boot partition: `setsys bootpartition 0` then `savesys`
3. Enable network: `rtk network on`
4. Load initramfs: `tftpboot 0x84f00000 192.168.1.2:openwrt-initramfs.bin`
5. Boot: `bootm`
6. Permanent install: `sysupgrade -n /tmp/<sysupgrade-image>`

### Return to Stock Firmware

From U-Boot serial console:
```
setsys bootpartition 1
savesys
boot
```
This boots the backup partition which still has OEM firmware. From there, flash primary partition with stock firmware via OEM web UI.

## PoE Configuration (OpenWrt)

The `realtek-poe` package is included in OpenWrt images for this device.

### Default Behavior

- Bootloader enables PoE+ on ALL ports at power-on
- OpenWrt PoE daemon takes over after boot
- **Default config manages all 8 ports** — all enabled by default in OpenWrt 25.12.1 (verified on hardware)

### Configure All 8 Ports

Edit `/etc/config/poe`:

```
config global
    option budget        '70'
    option force_baudrate '115200'
    option force_dialect  'realtek'

config port
    option id '1'
    option name 'lan1'
    option enable '1'
    option priority '2'
    option poe_plus '1'

config port
    option id '2'
    option name 'lan2'
    option enable '1'
    option priority '2'
    option poe_plus '1'

# ... repeat for ports 3-8
```

### PoE Management Commands

```
ubus call poe info                          # Current status (all ports)
ubus call poe reload                        # Reload config
ubus call poe manage '{"port":"lan1","enable":true}'   # Enable port
ubus call poe manage '{"port":"lan1","enable":false}'  # Disable port
/etc/init.d/poe restart                     # Restart daemon
```

### PoE Port Mapping

PoE port IDs match network interface numbers: lan1 = PoE port 1, lan2 = PoE port 2, etc.

## Firmware Images (OpenWrt 25.12.1)

### A1 (old v2)
- Initramfs: `openwrt-25.12.1-realtek-rtl838x-zyxel_gs1900-8hp-a1-initramfs-kernel.bin`
- Sysupgrade: `openwrt-25.12.1-realtek-rtl838x-zyxel_gs1900-8hp-a1-squashfs-sysupgrade.bin`

### B1 (old v1)
- Initramfs: `openwrt-25.12.1-realtek-rtl838x-zyxel_gs1900-8hp-b1-initramfs-kernel.bin`
- Sysupgrade: `openwrt-25.12.1-realtek-rtl838x-zyxel_gs1900-8hp-b1-squashfs-sysupgrade.bin`

## PoE: Stock vs OpenWrt Comparison

| Aspect | Stock Firmware | OpenWrt |
|--------|---------------|---------|
| PoE Controller | Broadcom BCM59111/BCM59121 | Same hardware |
| MCU | STM32F100C8 | Same, managed by realtek-poe daemon |
| Management | Web UI per-port (cmd=771/775) | `/etc/config/poe` + ubus |
| Auto-enable | Bootloader → all ports PoE+ | Same bootloader behavior |
| Budget | 70W | 70W (configurable) |
| Default | All ports enabled | All ports enabled (verified on hardware) |
| Power loss on reboot | Yes (MCU reinit) | Yes (same behavior) |

## conwrt Model Files

- `models/zyxel-gs1900-8hp-a1.json` — A1 (old v2) revision
- `models/zyxel-gs1900-8hp-b1.json` — B1 (old v1) revision

Both validated against schema. Flash method signatures verified on live hardware (GS1900-8HP, S/N XXXXX-XXXXXXXXX, 2026-05-21). OEM web UI cmd map fully verified.

### Verified vs Inherited

| Field | Status | Source |
|-------|--------|--------|
| cmd=5903 firmware page | ✅ Verified | Live Playwright, 2026-05-21 |
| cmd=5904 upload trigger | ✅ Verified | Form hidden field, 2026-05-21 |
| /cgi-bin/httpupload.cgi | ✅ Verified | Form action, 2026-05-21 |
| partition=0 Active, =1 Backup | ✅ Verified | Form radio buttons, 2026-05-21 |
| upmethod=0 TFTP, =1 HTTP | ✅ Verified | Form radio buttons, 2026-05-21 |
| Frameset UI structure | ✅ Verified | Live Playwright, 2026-05-21 |
| RSA-encrypted login | ❌ Not verified | V2.00 uses plaintext GET; V2.90 login flow uses JS |
| Progress poll cmd=5911 | ❌ Not verified | Inherited from GS1900-24E |
| Boot time ~90s | ✅ Verified | ~90s from "Rebooting now" to login page, 2026-05-21 |
| Firmware upload works | ✅ Verified | Playwright HTTP upload V2.00→V2.90, 2026-05-21 |
| Hardware revision display | ✅ Verified | V2.90 dashboard shows "Revision: A1" |
| Mandatory password change | ✅ Verified | V2.90 forces password change from default 1234 |
| cmd=5903 same across versions | ✅ Verified | Both V2.00 and V2.90 use cmd=5903 for firmware page |

## Firmware Update Log (2026-05-21)

### Update: V2.00(AAHI.2) → V2.90(AAHI.0)

**Device**: GS1900-8HP, S/N XXXXX-XXXXXXXXX, Rev A1, MAC E8:37:7A:XX:XX:XX
**Method**: Playwright HTTP upload via OEM web UI cmd=5903
**Firmware file**: `runtime-GS1900-8HPv2.1-V2.90(AAHI.0).bix` (5.8 MB)
**SHA-256**: `38e5cb9eca497c57d47c325d70f2d008b54cefe37a2057e599e44ca40c871fae`
**Partition**: Active (0)

### Timeline

| Time (CEST) | Event |
|-------------|-------|
| 08:55:39 | Form submitted: HTTP upload, partition=0, cmd=5904 |
| 08:56:29 | "Writing image to FLASH... Do not power down..." |
| 08:57:05 | "Do you really want to reboot?" dialog appeared |
| 08:57:43 | "Rebooting now......" |
| 08:58:21 | Device back online, login page at cmd=0 |
| 08:58:49 | Logged in → redirected to cmd=30 (mandatory password change) |
| 08:59:53 | Password changed from 1234 to Zyxel2026! |
| 09:00:48 | Logged in with new password, dashboard shows V2.90(AAHI.0) |

### Key observations

1. **Flash write + reboot took ~2 minutes** from submit to device back online
2. **Confirmation dialog appeared** after flash write — needed to accept "Do you really want to reboot?"
3. **Mandatory password change**: v2.90 requires changing from default password (1234). New password cannot be the default.
4. **New credentials**: admin/Zyxel2026! (note: update conwrt model JSON for future automation)
5. **System name changed**: "Switch" → "GS1900" (v2.90 default)
6. **Revision now displayed**: v2.90 dashboard shows "Revision: A1"
7. **UI redesigned**: v2.90 has completely different frameset with LeftTop/Title/menuTree/contentFrame/Down

### v2.90 OEM Web UI cmd Map

The v2.90 firmware has different top-level cmd numbers but the same firmware page cmd:

| v2.00 cmd | v2.90 cmd | Section |
|-----------|-----------|---------|
| 7 (dashboard) | 12 (Getting Started) | Dashboard |
| 18 (Monitoring) | 26 (Monitor) | Monitor section |
| 19 (Configuration) | 27 (Configuration) | Configuration section |
| 20 (Maintenance) | 28 (Maintenance) | Maintenance section |

**Firmware upload cmd is the SAME**: cmd=5903 in both versions.

#### v2.90 Maintenance tree (cmd=28)

| Menu path | cmd |
|-----------|-----|
| Firmware | 5903 (SAME as v2.00) |
| Configuration | 5901 (SAME as v2.00) |
| Certificates | 5914 (NEW in v2.80+) |
| Diagnostics → Port Test | 5632 (changed from 8448) |
| Diagnostics → PING | 530 (SAME) |
| Diagnostics → Trace | 534 (SAME) |
| Reboot | 5888 (SAME) |

### Firmware upload automation notes

The firmware upload process is fully automatable via Playwright:

1. Login (admin + password) → session established
2. Navigate to Maintenance section (cmd=20 in v2.00, cmd=28 in v2.90)
3. In the mainFrame/contentFrame, navigate to cmd=5903 (firmware page)
4. Select HTTP method (upmethod=1)
5. Select partition (0=Active, 1=Backup)
6. Set file input to .bix file path
7. Click Apply button (sysSubmit)
8. Wait for "Writing image to FLASH..." message
9. Accept "Do you really want to reboot?" dialog
10. Wait for device to come back online (~90s)

**For conwrt automation**: The cmd=5903 endpoint is stable across firmware versions. The only difference is the section cmd (20 vs 28). The firmware page can be accessed directly via the contentFrame URL without navigating through the menu.

**TFTP alternative**: The firmware upload form also supports TFTP (upmethod=0). This avoids browser automation but requires a TFTP server. The filename field must contain the exact .bix filename.

**v2.90 filename length limit**: Firmware upload rejects filenames longer than 64 characters. OpenWrt initramfs filenames are typically 75+ chars. Must rename to ≤64 chars before upload (e.g. `openwrt-initramfs.bin`).

## OpenWrt Flash Log (2026-05-21)

### Stage 1: Initramfs upload via OEM web UI

**Device**: GS1900-8HP Rev A1, S/N XXXXX-XXXXXXXXX, running V2.90(AAHI.0) stock firmware
**Method**: Playwright HTTP upload via OEM web UI cmd=5903
**Image**: `openwrt-25.12.1-realtek-rtl838x-zyxel_gs1900-8hp-a1-initramfs-kernel.bin` (renamed to `openwrt-initramfs.bin` to avoid 64-char filename limit)
**SHA-256**: `4c08eafcb515b8b35644c2197c07b0dccf675dd330a0477879a10fde2d2dfabd`
**Partition**: Active (0)

### Stage 1 Timeline

| Time (CEST) | Event |
|-------------|-------|
| 09:12:23 | Form submitted: HTTP upload, partition=0, cmd=5904 |
| 09:13:59 | "Prepare for firmware upgrade ... Do not power down your device." |
| 09:14:56 | "Do you really want to reboot?" dialog |
| 09:15:38 | "Rebooting now..." |
| 09:16:02 | SSH available (~24s boot time for initramfs) |

### Stage 1 Observations

1. **Initramfs boot time: ~24 seconds** (much faster than permanent install because no flash write)
2. **Same upload endpoint as stock firmware**: cmd=5903 → httpupload.cgi works for both .bix and .bin files
3. **Filename must be ≤64 chars**: OpenWrt default filename (75 chars) rejected by v2.90 firmware. Rename required.
4. **Password from stock V2.90**: admin/Zyxel2026! — session cookie based auth
5. **OpenWrt initramfs has no root password**: SSH allows root login without password by default

### Stage 2: Permanent install via sysupgrade

**Method**: SCP + sysupgrade -n from initramfs
**Image**: `openwrt-25.12.1-realtek-rtl838x-zyxel_gs1900-8hp-a1-squashfs-sysupgrade.bin` (6.5 MB)
**SHA-256**: `4eb47c72b09efddb9f846ebd44efcbc16c8ec63a6e4edfe5cb25cfa4bd30b8ad`
**SCP**: Must use `scp -O` (legacy protocol) — OpenWrt initramfs lacks sftp-server

### Stage 2 Timeline

| Time (CEST) | Event |
|-------------|-------|
| 09:16:55 | SCP started (legacy protocol -O) |
| 09:17:06 | SCP completed, SHA-256 verified |
| 09:17:24 | `sysupgrade -n /tmp/sysupgrade.bin` executed |
| 09:17:40 | SSH session closed ("Closing all shell sessions") |
| ~09:19:25 | SSH available (~105s boot time for permanent install) |

### Stage 2 Observations

1. **Permanent install boot time: ~105 seconds** (sysupgrade writes squashfs to flash + JFFS2 overlay init)
2. **SCP requires `-O` flag**: OpenWrt initramfs has no sftp-server, must use legacy SCP protocol
3. **sysupgrade output**: "Commencing upgrade. Closing all shell sessions." then ubus call fails (expected — session terminated)
4. **MTD layout changed**: Dual-partition OEM → single merged 13.5MB firmware partition
5. **JFFS2 overlay init**: ~30 seconds of JFFS2 erasing blocks during first boot

### Post-Install Verification

```
OpenWrt 25.12.1 r32768-b21cfa8f8c
Target: realtek/rtl838x
Arch: mips_24kc
Board: zyxel,gs1900-8hp-a1
Model: Zyxel GS1900-8HP A1 Switch

MTD Layout (merged single-partition):
mtd0: 00040000 (256K)   u-boot
mtd1: 00010000 (64K)    u-boot-env
mtd2: 00010000 (64K)    u-boot-env2
mtd3: 00100000 (1024K)  jffs
mtd4: 00100000 (1024K)  jffs2
mtd5: 00da0000 (13824K) firmware (MERGED from dual 6976K+6976K)
mtd6: 003b0000 (3712K)  kernel
mtd7: 009f0000 (10176K) rootfs (squashfs)
mtd8: 00750000 (7504K)  rootfs_data (JFFS2 overlay)

PoE Status:
  MCU: ST Micro ST32F100 Microcontroller
  Firmware: v17.1
  Budget: 70W
  All 8 ports: Searching (enabled, no PoE devices connected)

U-Boot env:
  boardmodel=ZyXEL_GS1900_8HP
  boardversion=V1.00(AAHI.0)
  bootdelay=1 (set by OEM)
  serverip=192.168.1.X (should update to 192.168.1.2 for TFTP recovery)
  ethaddr=E8:37:7A:XX:XX:XX

PoE config: All 8 ports enabled by default in /etc/config/poe
Network: Bridge switch with all 8 ports in VLAN 1, IP 192.168.1.1/24
```

### Complete flash timeline (end to end)

| Time | Event | Duration |
|------|-------|----------|
| 08:55:39 | Stock firmware update: V2.00 → V2.90 | ~3 min |
| 09:10:00 | Download OpenWrt images | ~30s |
| 09:12:23 | Initramfs upload via OEM web UI | ~3 min |
| 09:16:02 | Initramfs booted | 24s |
| 09:16:55 | SCP sysupgrade image | ~12s |
| 09:17:24 | sysupgrade -n executed | - |
| 09:19:25 | Permanent OpenWrt booted | 105s |
| **Total** | **From stock V2.00 to permanent OpenWrt** | **~24 min** |

### Return to stock firmware

The backup partition (runtime2, partition 1) still has the V2.90 stock firmware. To return:

1. Connect serial console (UART, 115200 8N1, 3.3V)
2. Interrupt U-Boot within 1 second
3. Run: `setsys bootpartition 1` → `savesys` → `boot`
4. Device boots into V2.90 stock firmware from backup partition
5. From stock UI, flash primary partition with stock firmware via cmd=5903

**Note**: After OpenWrt sysupgrade, the MTD layout merged the dual partitions. The backup partition data may still exist on flash but is no longer mapped as a separate MTD partition. The U-Boot `bootpartition` command should still work to switch boot source.

### PoE Test Results (2026-05-21)

Tested on OpenWrt 25.12.1 with a PoE device connected to port 8.

**Disable test** (`uci set poe.@port[7].enable=0` + restart):
- PoE status immediately changes to "Disabled"
- Power consumption drops to 0.0W (confirmed zero)
- Ethernet link drops in ~1-2 seconds as device loses power

**Enable test** (`uci set poe.@port[7].enable=1` + restart):
- PoE status changes to "Delivering power"
- Device boots, consumption rises to ~4.9W during boot, settles at ~1.7W
- Ethernet link comes back after device finishes booting

**PoE control methods**:
- `uci set poe.@port[N].enable=0/1; uci commit poe; /etc/init.d/poe restart` — persistent config change
- `ubus call poe manage '{"port":"lan8","enable":false}'` — runtime only (not persistent across reboot)
- `ubus call poe info` — read status of all ports

**Note**: The `ubus call poe manage` command had JSON parsing issues when invoked via SSH due to quoting. The `uci` method works reliably over SSH.

### conwrt automation notes for oem-playwright method

**Required steps for automation:**

1. Auto-detect device via LLDP → match model → check firmware version
2. If stock firmware < v2.70 and serial starts S21+: abort with warning
3. If stock firmware < v2.90: optional stock firmware update first
4. Login to OEM web UI (handle V2.00 plaintext vs V2.90 password-change flow)
5. Navigate to cmd=5903 in contentFrame
6. Select HTTP method, Active partition
7. **Rename initramfs to ≤64 chars** before upload
8. Submit form, wait for "Prepare for firmware upgrade...", accept reboot dialog
9. Wait ~90s for initramfs boot
10. SCP sysupgrade image (use `-O` flag for legacy protocol)
11. Run `sysupgrade -n /tmp/sysupgrade.bin`
12. Wait ~105s for permanent install boot
13. Verify SSH, board_name matches model

**Key gotchas for automation:**
- Filename length limit: 64 chars in V2.90 (V2.00 had 128)
- Mandatory password change in V2.80+ stock
- SCP requires `-O` flag on OpenWrt initramfs
- serverip in U-Boot defaults to 192.168.1.X (should be updated for TFTP recovery)
- Stock firmware uses JavaScript-based login — session management is server-side, no visible cookies via curl

## PoE Research: Stock Firmware RE & Improvement Opportunities

We reverse-engineered the stock ZyXEL V2.90 firmware (`board_poe.ko` + `libsal.so`) by MIPS objdump on the unstripped kernel module. Full analysis in `firmware/stock_v290/RE_ANALYSIS.md` and parity comparison in `docs/POE_PARITY.md`.

### Architecture Comparison

| Aspect | Stock V2.90 | OpenWrt (realtek-poe) |
|--------|-------------|----------------------|
| Layers | 3-tier: CLI → SAL (libsal.so) → Kernel (board_poe.ko) | 2-tier: ubus → userspace daemon |
| Chip support | BCM59111, BCM59121, RTL8238B/BCM59011 | BCM59111 (realtek dialect exists but unused) |
| Transport | UART + SMI | UART only |
| Threading | 2 kernel threads (port status + threshold monitoring) | Single-threaded uloop, 2s poll |

### Parity Score

53% wire command parity (35/66 items). Excluding intentionally skipped items (global enable, deprecated commands, safety-critical resets): **21 actionable gaps**.

### Potential Contributions to realtek-poe

These are improvements we identified that could be PR'd upstream:

**P0 — Under-decoding fixes (quick wins, no new commands needed):**
1. **Decode 0x21 fault_type** — The detailed port status reply has 9 fields (fault_type, power_mode, chan_pwr, pd_alt), we only parse 3. Stock extracts structured fault reasons: OVLO, MPS absent, Short, Overload, Denied, Thermal, Startup, UVLO.
2. **Decode 0x28 upper nibble** — The 4-port status reply's upper nibble contains class info + fault_type + PD flag. We discard it.
3. **Set 0x22 reset=1 on counter reads** — Stock clears counters every read cycle to prevent single-byte MCU counter overflow. We send reset=0, causing silent wraps.

**P1 — Missing SET commands:**
1. Port reset (0x03) — Clear fault states without full port disable/enable cycle
2. Device power management (0x0b) — Pre-allocated vs actual power accounting
3. Global high power limit (0x07) — Max per-port power envelope for class-based limits

**P2 — Extended features:**
- LED control (0x41-0x49) — MCU-driven PoE status LEDs
- Port power pair (0x19) — A-pair/B-pair for 4-pair PoE
- Per-port PSE output mapping (0x1d)

### Stock Firmware Extraction Tooling

- `firmware/extract.sh` — Extracts board_poe.ko and libsal.so from V2.90 firmware image
- `firmware/gs1900fw.py` — Python firmware image parser (602 lines)

### Files

- `docs/POE_PARITY.md` — Full parity comparison with scorecard
- `firmware/stock_v290/RE_ANALYSIS.md` — Raw RE data: command tables, SAL API, chip support matrix
- `firmware/extract.sh` — Firmware extraction script
- `firmware/gs1900fw.py` — Firmware image parser
