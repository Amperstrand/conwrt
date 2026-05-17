# GL.iNet GL-MT3000 (Beryl AX) — Validated Notes

## Hardware
- SoC: MediaTek MT7981B (Filogic 820) dual-core Cortex-A53 @ 1.3GHz
- RAM: 512MB DDR4
- Flash: 256MB NAND (Macronix SPI NAND per OpenWrt commit)
- WiFi: 2.4GHz + 5GHz WiFi 6 (MT7981B + MT7976C)
- Ethernet: 1x WAN (2.5G MaxLinear GPY211) + 1x LAN (1G built-in PHY) + USB 3.0
- Power: USB-C 5V/3A
- LEDs: 1x light-blue (boot/failsafe/upgrade), 1x warm-white (running)
- Reset button: side, under antenna (NOT recessed — no paperclip needed). GPIO 1, KEY_RESTART.
- Mode toggle: side switch (forward/backward). GPIO 0, EV_SW/BTN_0.
  GL.iNet firmware: configurable (VPN/Tor/WiFi/AdGuard). OpenWrt: /etc/rc.button/BTN_0 (no-op).
  NOT used for U-Boot entry.
- Serial: internal 4-pin header, 115200 8n1
- PWM fan with tachometer

## OpenWrt
- Target: mediatek/filogic
- Device: glinet_gl-mt3000
- Arch: aarch64_cortex-a53
- Default OpenWrt IP: 192.168.1.1
- Default GL.iNet IP: 192.168.8.1

## U-Boot Recovery (Validated on hardware 2026-05-07)
- Procedure:
  1. Power off router, connect ethernet to LAN port only
  2. Hold RESET button (side, under antenna — no paperclip needed)
  3. Plug in power WHILE holding reset
  4. Blue LED flashes 6 times, then turns SOLID WHITE
  5. Release reset when LED turns solid white
  6. U-Boot HTTP at http://192.168.1.1

- U-Boot HTTP API (tested):
  - GET  /             → 200 OK, HTML firmware upload page (no Server header!)
  - HEAD /             → 405 Method Not Allowed (U-Boot only supports GET/POST)
  - POST /upload       → multipart form, field "firmware" → returns "size md5hash"
  - GET  /flashing.html → triggers flash, returns "Update in progress" page
  - GET  /version      → returns U-Boot version string

- Headless upload (validated):
  ```bash
  curl -sk --max-time 300 -F "firmware=@image.bin;type=application/octet-stream" http://192.168.1.1/upload
  # Returns: "8653674 63e1be5586be17f1e2127b43d1437bac" (size + md5)
  curl -s http://192.168.1.1/flashing.html  # triggers flash
  ```

- Timing: flash takes ~4 minutes, then router reboots. Total ~6-7 minutes.
- Browser: Chrome/Edge only (NOT Firefox — may brick)
- Use Chrome/Edge, NOT Firefox (may brick)
- GL.iNet default LAN: 192.168.8.1; stock OpenWrt default: 192.168.1.1

- Network signatures (from pcap analysis — captures/mt3000-uboot-recovery-*.pcap):
  - OpenWrt running: ICMPv6 Router Advertisements every ~10s from router MAC (94:83:c4:xx:xx:xx)
  - U-Boot mode: no ICMPv6 RA, HTTP GET port 80 returns HTML, HEAD returns 405
  - Router off: no traffic from router MAC
  - U-Boot responds ~22s after link up (LED sequence takes time)
  - U-Boot flash time: ~6 minutes (not 3 as GL.iNet docs claim)
  - U-Boot → OpenWrt gap: ~11s (clear gap between last U-Boot TCP and first OpenWrt ICMPv6)
  - First OpenWrt sign: ICMPv6 multicast listener report from router MAC
  - No OpenWrt failsafe UDP broadcast (port 4919) observed on MT3000 with OpenWrt 24.10.1

- DTS source (openwrt/openwrt target/linux/mediatek/dts/mt7981b-glinet-gl-mt3000.dts):
  - LED aliases: led-boot=blue, led-failsafe=blue, led-running=white, led-upgrade=blue
  - gpio-keys: reset (GPIO 1, KEY_RESTART), mode (GPIO 0, EV_SW/BTN_0)

## Default OpenWrt Packages
- dropbear, firewall4, dnsmasq, odhcpd-ipv6only, netifd, ubus, uci
- libopenssl3, libustream-mbedtls (TLS libraries, NOT openssl-util CLI)
- wpad-basic-mbedtls (WPA supplicant)
- fitblk (MT7981 boot helper)
- NO openssl-util by default
- NO LuCI by default

## Gotchas (Validated)

### chpasswd does not exist on BusyBox
OpenWrt's BusyBox does not include chpasswd. Use:
```bash
printf '%s\n%s\n' 'password' 'password' | passwd root
```

### Never use set -eu in uci-defaults
If any command fails, the script aborts and later commands (firewall rules) never run. This can leave the router unreachable from WAN.

### SCP requires -O flag
Modern OpenSSH uses SFTP by default, but OpenWrt lacks sftp-server. Always use `scp -O`.

### ASU API blocks Python default User-Agent
Set a custom User-Agent header when calling the ASU API at sysupgrade.openwrt.org.

### sysupgrade -n kills SSH mid-command
Exit code 246 is expected (connection dropped by router rebooting).

### MAC OUI 94:83:C4 is shared
All GL.iNet devices share this OUI. Cannot distinguish models by MAC alone.
