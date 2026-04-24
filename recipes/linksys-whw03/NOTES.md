# Linksys Velop WHW03 Session Notes

This file captures the operational details learned while flashing and provisioning WHW03 units in April 2026. Use it as the first reference before another session with this router family.

## Scope

- Applies to Linksys Velop WHW03 V1 and V2.
- Focuses on the factory-reset to OpenWrt path, especially stock readiness timing, flash timing, post-flash provisioning order, and recovery behavior.

## Physical Port Guidance

- The direct ethernet link used successfully in this session was on a port that presented the device as `192.168.1.1` and served DHCP to the operator workstation.
- The capture confirms that once OpenWrt was up, the router answered as `OpenWrt.lan` and ARP resolved the router MAC `14:91:82:XX:XX:XX`.
- When in doubt, prefer the port that gives the workstation a `192.168.1.x` lease and shows ARP for `192.168.1.1`. If the link is up but there is no DHCP, no ARP, and no JNAP after several minutes, try the other ethernet port.

## What Happened Today

### 1. Pre-reset behavior

- The router identified as `Linksys WHW03 V1`, serial `20J10C61776049`, firmware `1.1.19.215389`.
- Before a fresh factory reset, `admin:admin` was rejected on both `/fwupdate.html` and `/jcgi/`.
- That strongly suggests the unit still had a non-default admin password before reset.

### 2. After factory reset

- The device did not become fully ready immediately.
- Network stack and ICMP came up before HTTP/JNAP became usable.
- During this window, the automation kept probing `192.168.1.1`, but JNAP timed out because stock services were not ready yet.
- Later, the exact same device accepted `admin:admin` over HTTP on `/fwupdate.html` and the firmware upload succeeded.

### 3. Flash result

- Firmware upload returned `{"result": "OK"}` on `https://192.168.1.1/jcgi/`.
- The device then disappeared from the network for longer than the script's original 120-second boot window.
- OpenWrt eventually came up successfully, but the first boot was slow enough that the automation treated it as a failure.

### 4. Post-flash verification

- Packet capture later showed the router as `OpenWrt.lan`.
- The router served DHCP on `192.168.1.1`, answered ARP, sent IPv6 router advertisements, and rejected upstream DNS/HTTP as expected for a fresh LAN-only OpenWrt install.
- SSH to `root@192.168.1.1` worked and confirmed `OpenWrt 24.10.6`.
- WiFi STA provisioning on `radio1` succeeded and the router obtained WAN IP `192.168.13.XXX`.
- SSH key auth worked over WAN and password auth was rejected.

## Timing Rules That Matter

### Stock readiness after reset

- Do not assume JNAP or `/fwupdate.html` are ready just because the link is up.
- Wait for one of these before starting the flash step:
  - `GetDeviceInfo` returns valid JSON, or
  - `curl -u admin:admin http://192.168.1.1/fwupdate.html` returns HTTP 200.
- Expect this to take a few minutes after a reset.

### OpenWrt first boot after flash

- WHW03 V1 eMMC first boot can exceed 120 seconds.
- A 5-minute window is safer for the first boot after stock-to-OpenWrt migration.
- If pings stop after the flash upload is accepted, that is expected during reboot.
- Do not power-cycle too early unless the device has been silent well past the expected boot window.

## Identification and MAC Handling

- `GetDeviceInfo` is enough to identify `modelNumber` and `hardwareVersion`, but on this V1 unit it did not include a `macAddresses` field.
- ARP fallback was required to recover the router MAC.
- Captured/router-confirmed values from this session:
  - MAC: `14:91:82:XX:XX:XX`
  - Hostname: `fa3adc4d29f4`
  - WAN IP after provisioning: `192.168.13.XXX`

## Configuration Order That Must Be Preserved

The reliable post-flash order remains:

1. Set hostname and authorized key.
2. Configure WiFi STA on `radio1`.
3. Set `network.wan.device='phy1-sta0'`.
4. Allow WAN SSH via firewall zone input `ACCEPT`.
5. Disable dropbear password auth.
6. Run `wifi reload`.
7. Wait for STA association and DHCP.
8. Restart dropbear in a separate SSH session.

Do not restart dropbear in the same SSH session that runs `wifi reload`.

## Signals That OpenWrt Is Alive Even If The Script Thinks It Failed

These were the decisive indicators in the packet capture:

- `OpenWrt.lan.bootps` replying with DHCP offers.
- ARP replies: `OpenWrt.lan is-at 14:91:82:XX:XX:XX`.
- IPv6 router advertisements from `fe80::1691:82ff:fe94:c71d`.
- DNS replies from `OpenWrt.lan.domain` returning `Refused` for upstream queries.

If you see those, the flash succeeded and the router is already in OpenWrt, even if earlier polling windows expired.

## Recovery Notes

- If stock `admin:admin` is rejected, do a full factory reset before assuming the documented default is wrong.
- If the router disappears after flash and the script times out, capture traffic before declaring failure. The device may simply be booting slowly.
- If OpenWrt truly fails to boot, use the known three power-cycle rollback behavior to return to stock.

## Practical Next-Session Checklist

1. Cable to the port that gives `192.168.1.x` DHCP and ARP for `192.168.1.1`.
2. Start packet capture early.
3. Reset the router and wait for stock readiness, not just link readiness.
4. Confirm `admin:admin` on `/fwupdate.html` before upload.
5. After upload returns `OK`, wait up to 5 minutes for V1 boot.
6. If the script times out, inspect traffic for `OpenWrt.lan`, DHCP, ARP, and router advertisements before retrying or power-cycling.
7. If OpenWrt is already up, continue with provisioning instead of reflashing.
