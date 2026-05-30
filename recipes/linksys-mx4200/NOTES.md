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

## Bluetooth (Silicon Labs EFR32MG21)

The stock firmware advertises a JNAP Bluetooth service, and the device tree has `blsp1_uart3` enabled. However, **the Bluetooth chip is a Silicon Labs EFR32MG21 IoT MCU** (Bluetooth 5 + Zigbee + Thread multiprotocol), NOT a Qualcomm WCNSS integrated chip.

**Status: NOT WORKING under OpenWrt. This is not an opkg-install situation.**

What works:
- Bluetooth kernel stack is loaded (bluetooth.ko, hci_uart, rfcomm, L2CAP, btusb all present)
- UART device exists (`/dev/ttyMSM0`, `/dev/ttyMSM1`)

What's missing:
- No `bluetooth {}` child node in the device tree — Linux doesn't bind HCI to the UART
- No Linux driver for EFR32MG21 (uses proprietary Silicon Labs QAPI protocol, not standard HCI H4)
- No firmware files — proprietary, not in `linux-firmware` or any OpenWrt package
- No GPIO configuration for power/enable/reset pins

The `wcnss@4b000000` reserved memory (97MB) is for the WiFi DSP (ath11k), NOT for Bluetooth.

**Practical workaround**: Use a USB Bluetooth dongle. The xHCI controller and btusb driver are already loaded:
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

## References

- OpenWrt Wiki: https://openwrt.org/toh/linksys/mx4200_v1
- CVE-2019-16340: https://nvd.nist.gov/vuln/detail/CVE-2019-16340
- 5GHz BDF issue: https://github.com/openwrt/openwrt/issues/14523
- EFR32MG21 datasheet: https://www.silabs.com/wireless/zigbee/efr32mg21-series-2-soCs
- MX4200 OpenWrt support PR: https://github.com/openwrt/openwrt/pull/13432
