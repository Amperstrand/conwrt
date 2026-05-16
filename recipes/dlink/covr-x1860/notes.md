# D-Link COVR-X1860 A1 — Validated Notes

## Hardware
- SoC: MediaTek MT7621AT (MIPS) @ 880MHz
- RAM: 256MB
- Flash: 128MB NAND
- Ethernet: 2x 1G (1 WAN + 1 LAN)
- WiFi: 2.4GHz + 5GHz (MT7915DAN + MT7975DN, WiFi 6/ax, DBDC)
- Reset button: recessed, UNDER the device (needs a pin)
- LEDs: 3 LEDs (red, orange, white) routed to one indicator on top
- Serial: labeled on board (VCC, TX, RX, GND), 3.3V, 115200 8n1

## OpenWrt
- Target: ramips/mt7621
- Device: dlink,covr-x1860-a1
- Arch: mipsel_24kc
- Default OpenWrt IP: 192.168.1.1

## Known Good State (validated 2026-05-16)

### Image format is critical
- **U-Boot recovery mode** → MUST use `squashfs-recovery.bin` (NOT factory.bin)
- **OEM web UI flash** → use `squashfs-factory.bin`
- **sysupgrade** → use `squashfs-sysupgrade.bin`
- Using factory.bin via U-Boot recovery causes a red LED / boot failure on some devices
- Source: official OpenWrt git commit `0a18259e` and tested on hardware 2026-05-16
- conwrt.py correctly prefers `recovery.bin` for U-Boot mode (`preferred_types = ["recovery", "factory", "initramfs"]`)

### Working flash procedure (validated 2026-05-16, 3 successful devices)
1. Power off router, connect ethernet to **any port** (WAN or LAN both work for recovery)
2. Hold reset pin under device, plug in power, hold ~10-12s until LED blinks red
3. Recovery HTTP at http://192.168.0.1/
4. Upload `recovery.bin`: `curl -F "firmware=@recovery.bin;type=application/octet-stream" http://192.168.0.1/upload`
5. Wait ~90 seconds for flash + reboot
6. Move cable to a **LAN port** for SSH access at 192.168.1.1
7. SSH key auth works (key baked in via ASU defaults)

### Gotchas
- Do NOT use factory.bin for U-Boot recovery — it uploads successfully ("Upgrade successfully!") but causes boot failure (solid red LED)
- Do NOT abort conwrt.py during the 150s flash wait — let it run to completion
- After flash, cable MUST be on a LAN port (not WAN) for SSH — OpenWrt WAN is DHCP client, not server
- Multiple rapid re-flashes in succession can leave the device in a bad state — re-enter recovery and use recovery.bin to fix

## Recovery Mode (Validated 2026-05-07, 2026-05-12, 2026-05-16)
- Procedure:
  1. Power off router, connect ethernet to **any port** (WAN and LAN both validated)
  2. Use a pin to press and hold the reset button UNDER the device
  3. Plug in power WHILE holding reset
  4. Hold for ~10-12 seconds until status LED blinks red
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

## Network Signatures (from pcap analysis 2026-05-07, retested 2026-05-12)
- Recovery mode MAC prefix: 3e:85:be (temporary/derived, not hardware MAC)
- OpenWrt WAN MAC: a8:63:7d:91:f8:94 (observed post-flash on WAN port; different from recovery MAC)
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

## HNAP API (stock firmware, reverse-engineered 2026-05-16)

### Auth Flow (verified working)
1. **Login challenge**: POST to `/HNAP1/` with `SOAPAction: "http://purenetworks.com/HNAP1/Login"`, `HNAP_AUTH` using key `"withoutloginkey"`. No `HNAP_CONTENT` on Login or GetDeviceSettings.
2. **Derive keys**:
   - `PrivateKey = HMAC-MD5(PublicKey + password, Challenge).upper()`
   - `LoginPassword = HMAC-MD5(PrivateKey, Challenge).upper()`
3. **Login final**: POST with derived `LoginPassword`, returns `success`
4. **HNAP_AUTH for subsequent calls**: `HMAC-MD5(PrivateKey, timestamp_ms + SOAPAction).upper() + " " + timestamp_ms`
5. **HNAP_CONTENT**: `AES_Encrypt128(MD5(body).upper()).upper()` — D-Link's custom simplified AES (no MixColumns, 1 round). Required for all calls except Login and GetDeviceSettings.
6. **Cookie**: Session cookie from challenge XML `<Cookie>` element, sent as `uid=<value>`

### Custom AES
- NOT standard AES-128 — simplified implementation with SubBytes + ShiftRows + AddRoundKey only (no MixColumns)
- Key: PrivateKey (truncated to 32 hex chars / 16 bytes). If not valid hex (e.g. "withoutloginkey"), convert via str2hex.
- Input: 4 blocks of 16 bytes (64 bytes total), padded with zeros
- Source: `/js/AES.js` in stock firmware

### Firmware Upload (tested, API works)
- `FirmwareUpload` action accessible via HNAP, returns `OK` when auth is correct
- Upload via multipart POST with field `FWFile` or `file`
- `GetFirmwareValidation` checks staged firmware → returns `IsValid: true/false`

### CRITICAL: HNAP Does NOT Flash OpenWrt (Verified Failed)
- `GetFirmwareValidation` returns `IsValid: false` for OpenWrt factory images
- The stock firmware's validation checks RSA signatures against **production keys** not included in the GPL source
- The GPL RSA key (password: `12345678`) is a **test key** — production devices use different keys burned into the bootloader
- Both signed (GPL key) and unsigned OpenWrt images are rejected
- **No router has ever been successfully flashed via HNAP** — both x1860 flashes used recovery-http (U-Boot)
- **Result**: HNAP upload mechanism works perfectly, but the firmware validation blocks non-D-Link firmware on stock v1.02
- **Solution**: Use recovery-http (U-Boot) method to bypass firmware validation entirely

### Files
- `/tmp/hnap_upload.py`: Working standalone HNAP login + upload script (Python, uses `requests`)
- `/Users/macbook/src/conwrt/scripts/dlink_sge_sign.py`: Firmware RSA signing tool (GPL key — NOT production)
- `/Users/macbook/src/conwrt/scripts/conwrt.py`: Main flasher, HNAP auth integrated at lines 580-886

## WireGuard Key Architecture (decided 2026-05-16)

**`private_key='generate'`** — selected for production use.

- OpenWrt wireguard-tools natively supports `private_key='generate'` (commit `54066840`)
- On first interface bringup, the proto handler auto-generates a Curve25519 key pair, saves the private key to UCI, replaces `'generate'` with the actual key
- Same firmware image works for all devices — each generates a unique key on first boot
- Keys survive sysupgrade automatically (stored in UCI overlay)
- Post-flash workflow: SSH in → `uci get network.wg0.private_key | wg pubkey` → register pubkey with VPN server → save to inventory
- WireGuard pubkey should be saved in device inventory (`data/inventory.jsonl`) for tracking
- Future: U-Boot env or unused MTD partition (e.g. `private` mtd8, 20MB) for persistence across full recovery reflash

## Gotchas
- **Use recovery.bin (NOT factory.bin) for U-Boot recovery mode** — factory.bin uploads OK but causes red LED boot failure. recovery.bin is the correct format per official OpenWrt commit.
- **Recovery mode works on both WAN and LAN ports** — validated on both 2026-05-12. Recovery IP is 192.168.0.1 regardless of which port is used.
- Recovery mode is at 192.168.0.1, OpenWrt boots at 192.168.1.1 — different subnets!
- Client needs IPs on both subnets (192.168.0.10 + 192.168.1.254) if flashing from the same interface
- If device is already in recovery mode (recovery HTTP live), conwrt skips the power cycle and uploads directly
- Reset button is recessed under the device — needs a pin or paperclip
- Must hold reset for ~10-12 seconds during power-on — releasing too early boots stock firmware normally (DHCP client mode, not recovery)
- "Upgrade successfully!" response comes BEFORE flash is done — device flashes in background
- No browser restriction (unlike GL.iNet which warns about Firefox)
- Post-flash WAN port: OpenWrt configures WAN as DHCP client. If still on WAN port after flash, device sends DHCP requests — need to move cable to LAN for SSH access.
- **HNAP firmware upload returns OK but stock v1.02 rejects OpenWrt during validation — NO successful flash ever recorded. Use recovery-http instead**
- **Stock firmware wizard is aggressive**: session times out after ~170s of inactivity, redirects to Login.html
- **GetFirmwareSettings confirms `UpdateMethods: HNAP_UPLOAD`** — the device claims to support it, but validation blocks non-OEM firmware
