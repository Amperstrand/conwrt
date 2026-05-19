# Zyxel GS1900-24E — Validated Notes

## Hardware
- SoC: Realtek RTL8382M MIPS 4KEc @ 500MHz
- RAM: 128MB DDR2 SDRAM
- Flash: 16MB SPI NOR (Macronix MX25L12835F)
- Ethernet: 24x 10/100/1000 Mbps (switch, no WAN/LAN distinction)
- WiFi: none (managed switch)
- Serial: UART JP2 header, 115200 8N1, 3.3V (Pin1=VCC, Pin2=RX, Pin3=TX, Pin4=GND)
- Board revision: A1 (board_name: `zyxel,gs1900-24e-a1`)
- MAC OUI observed: `5C:F4:AB`

## OpenWrt
- Target: `realtek/rtl838x`
- Device: `zyxel,gs1900-24e`
- Supported since: 22.03.0
- Default IP: 192.168.1.1
- No LuCI in default build — SSH only management
- Issue #18620 (switch driver regression in 24.10.1+): CLOSED/FIXED as of 2026-02-25

## Known Good State (validated 2026-05-18)

### Flash procedure: OEM to OpenWrt (two-stage)

This is a dual-partition device with OEM firmware. The OEM web UI is frameset-based with RSA-encrypted passwords — too complex for curl, requires Playwright.

**Stage 1: Flash initramfs via OEM web UI**
1. Connect Mac to switch via ethernet (any port, it's a switch)
2. Set IP alias: `sudo ifconfig en6 192.168.1.2 netmask 255.255.255.0`
3. Open OEM web UI at http://192.168.1.1 (login: admin/1234)
4. Navigate: Maintenance → Firmware → Upload (cmd=5903)
5. Upload initramfs image (NOT sysupgrade) via /cgi-bin/httpupload.cgi
6. Wait ~90s for reboot into OpenWrt initramfs

**Stage 2: Sysupgrade to permanent install**
1. SSH to 192.168.1.1 (OpenWrt initramfs, no password)
2. SCP sysupgrade image to /tmp/
3. Run: `sysupgrade -n /tmp/<sysupgrade-image>.bin`
4. Wait ~120s for permanent install boot

### Image format is critical
- **OEM web UI** → MUST use `initramfs.bin` (NOT sysupgrade, NOT squashfs-factory)
- **sysupgrade** → use `sysupgrade.bin`
- **mtd write** → use `initramfs.bin` (when sysupgrade rejects cross-version upgrades)
- initramfs boots to RAM — changes don't persist across reboot
- sysupgrade writes permanently to flash with overlay

### Cross-version upgrade gotcha
sysupgrade from 22.03.x to 25.12.1 is REJECTED with:
```
Dual firmware partition merged into a single bigger one.
Upgrade requires a new factory install.
Image version mismatch.
```
Workaround: use `mtd -r write` to flash 25.12.1 initramfs directly to the firmware partition, then sysupgrade from there. This is safe because:
- mtd write only touches the firmware partition (mtd5)
- U-Boot (mtd0) and env (mtd1/mtd2) are untouched
- initramfs boots from RAM, so writing to flash while running is fine

## OEM Web UI Details

### Authentication
- Login URL: `/cgi-bin/dispatcher.cgi?cmd=0`
- Username: `admin`, Password: `1234`
- Password is RSA-encrypted via JavaScript before submission
- Session cookie: `XSSID` (set after login)
- Session check: `/cgi-bin/dispatcher.cgi?session_chk=1`

### Navigation (frameset-based)
- Main frameset loads `dispatcher.cgi` with cmd numbers
- Menu cmd: 28 (Maintenance)
- Firmware page cmd: 5903
- Progress poll cmd: 5911
- Upload endpoint: `/cgi-bin/httpupload.cgi` (POST, multipart form)
- Form fields: `upmethod=1` (HTTP), `partition=0` (active partition)
- Confirm dialog: "Do you really want to reboot?"

### Playwright tips
- The UI uses frames — target `mainFrame` for firmware page interactions
- After upload, poll cmd=5911 for progress
- RSA encryption happens in browser JS — Playwright handles this natively
- Wait for page ready state between navigation steps

## Partition Layout

### OEM / OpenWrt 22.03.x (dual-partition)
```
mtd0: u-boot       (256K)    — bootloader
mtd1: u-boot-env   (64K)     — U-Boot environment
mtd2: u-boot-env2  (64K)     — backup environment
mtd3: jffs         (1024K)   — OEM config
mtd4: jffs2        (1024K)   — OEM config
mtd5: firmware     (6976K)   — active partition 0
mtd6: runtime2     (6976K)   — backup partition 1 (OEM firmware)
```

### OpenWrt 25.12.1 permanent (merged single-partition)
```
mtd0: u-boot       (256K)    — bootloader (unchanged)
mtd1: u-boot-env   (64K)     — U-Boot environment
mtd2: u-boot-env2  (64K)     — backup environment
mtd3: jffs         (1024K)   — unused
mtd4: jffs2        (1024K)   — unused
mtd5: firmware     (13952K)  — merged from dual 6976K+6976K
mtd6: kernel       (3712K)   — Linux kernel
mtd7: rootfs       (10176K)  — squashfs root
mtd8: rootfs_data  (7504K)   — JFFS2 overlay
```

**Important**: After permanent OpenWrt 25.12.1 install, the OEM backup partition (runtime2) is GONE. The merged layout has no dual-boot failover. OEM web UI recovery is no longer available.

## U-Boot Recovery

### Current environment (verified 2026-05-18)
```
bootdelay=1
bootcmd=cst fcTest; boota
serverip=192.168.1.2      (changed from 192.168.1.X via fw_setenv)
ipaddr=192.168.1.1
baudrate=115200
ethaddr=5C:F4:AB:XX:XX:XX
```

### Safety assessment
- `bootdelay=1` — gives 1 second to interrupt boot and enter U-Boot console. Was already set by OEM.
- `fw_setenv` works from OpenWrt — can modify U-Boot environment without serial
- `serverip=192.168.1.2` — set to our Mac's IP for TFTP recovery
- Serial required for TFTP recovery (no network-based U-Boot access)
- **UNTESTED**: Serial TFTP recovery not actually performed on this device

### Recovery paths (in order of preference)
1. **sysupgrade from OpenWrt** — if OpenWrt boots, just sysupgrade a new image
2. **mtd write from OpenWrt** — if sysupgrade rejects, write initramfs to mtd5 directly
3. **U-Boot TFTP via serial** — if OpenWrt won't boot, interrupt U-Boot, TFTP initramfs, bootm
4. **U-Boot mtd write** — extreme case: boot initramfs via TFTP, then mtd write OEM backup

### OEM firmware restoration
Full MTD backups exist at `data/backups/gs1900-24e/`. To restore OEM:
1. Boot OpenWrt (or initramfs via TFTP)
2. `mtd write /tmp/mtd5.bin firmware` (OEM firmware partition)
3. `mtd write /tmp/mtd6.bin runtime2` (OEM backup partition) — only if restoring dual-layout
4. Reboot — OEM firmware will boot

## Boot Timing
- OEM firmware: ~60s to web UI
- OpenWrt initramfs: ~70s to SSH
- OpenWrt permanent (25.12.1): ~120s to SSH (first boot longer due to overlay init)
- sysupgrade flash: ~30s write + ~120s reboot

## Forum / Community Notes
- slh (OpenWrt maintainer) confirmed 16MB dual-boot design on this device family
- mtdconcat was suggested for combining dual partitions (~13.5MB usable)
- Alternative: U-Boot reconfigure to single-boot (not attempted)
- Forum thread: https://forum.openwrt.org/t/zyxel-gs1900-24e-move-overlay-to-recovery-partition/208125/20

## Lessons Learned
1. **OEM web UIs with RSA encryption need Playwright** — curl cannot handle JS-based password encryption
2. **Dual-partition devices may reject cross-version sysupgrade** — have mtd-write as fallback
3. **MTD backup before any flashing** — critical for recovery, saved all 7 partitions
4. **fw_setenv works from OpenWrt on this device** — can set bootdelay, serverip without serial
5. **bootdelay=1 is enough** for serial recovery, but you MUST have serial adapter connected before boot
6. **Managed switches have no WiFi** — conwrt's WiFi detection should be gracefully skipped
7. **Switch ports are all equivalent** — no WAN/LAN distinction, any port works for management
