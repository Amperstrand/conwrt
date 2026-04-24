# D-Link COVR-X1860 A1 — Validated Notes

## Hardware
- SoC: MediaTek MT7621AT (MIPS) @ 880MHz
- RAM: 256MB
- Flash: 128MB NAND
- Ethernet: 4x 1G (1 WAN + 3 LAN)
- WiFi: 2.4GHz (MT7603EN) + 5GHz (MT7612N)
- Reset button: recessed, UNDER the device (needs a pin)
- LEDs: status LED on top

## OpenWrt
- Target: ramips/mt7621
- Device: dlink,covr-x1860-a1
- Arch: mipsel_24kc
- Default OpenWrt IP: 192.168.1.1

## Recovery Mode (Validated on hardware 2026-05-07)
- Procedure:
  1. Power off router, connect ethernet to LAN port
  2. Use a pin to press and hold the reset button UNDER the device
  3. Plug in power WHILE holding reset
  4. Status LED blinks red
  5. Release reset after LED starts blinking red
  6. Recovery HTTP at http://192.168.0.1/

- Recovery HTTP API (tested):
  - GET  /          → 200 OK, "D-Link Router Recovery Mode" HTML page
  - POST /upload    → multipart form, field "firmware" → returns HTML status page
  - No separate flash trigger needed (auto-flashes after upload)

- Headless upload (validated):
  ```bash
  curl -s --max-time 300 -F "firmware=@image.bin;type=application/octet-stream" http://192.168.0.1/upload
  ```

- Timing: upload ~4 seconds for 13MB, then ~30 seconds flash, then reboot
- Recovery IP: 192.168.0.1 (different from OpenWrt default 192.168.1.1!)

## Network Signatures (from pcap analysis 2026-05-07)
- Recovery mode MAC prefix: 3e:85:be (temporary/derived, not hardware MAC)
- OpenWrt br-lan MAC: bc:22:28:99:1d:xx
- Recovery mode: HTTP at 192.168.0.1:80, responds to ARP
- Upload: POST /upload, 4 seconds for 13MB over 1Gbps
- Flash: ~30 seconds silence from recovery MAC after upload ACK
- Response page: "Upgrade successfully!" (means upload accepted, NOT flash complete)
- Reboot: ~115 seconds silence (recovery MAC gone → OpenWrt MAC appears)
- First OpenWrt packet: ICMPv6 MLDv2 report
- First IPv4: DHCP reply from 192.168.1.1:67
- First ARP: who-has 192.168.1.XXX tell 192.168.1.1
- No DHCP client requests (device is DHCP server)
- No mDNS from device
- No SSH SYN from device (SSH is server, not client)

## Gotchas
- Recovery mode is at 192.168.0.1, OpenWrt boots at 192.168.1.1 — different subnets!
- Client needs IPs on both subnets (192.168.0.10 + 192.168.1.254)
- Reset button is recessed under the device — needs a pin or paperclip
- "Upgrade successfully!" response comes BEFORE flash is done — device flashes in background
- No browser restriction (unlike GL.iNet which warns about Firefox)
