# Extreme Networks WS-AP3915i — No-Serial OpenWrt Flash

## Supported Models

| Model | SoC | Flash | Status |
|-------|-----|-------|--------|
| WS-AP3915i | IPQ4029 | SPI-NOR | Primary target |
| WS-AP3912 | IPQ4029 | SPI-NOR | Same family, likely compatible |
| WS-AP3916 | IPQ4029 | SPI-NOR | Same family, likely compatible |
| WS-AP3917 | IPQ4029 | SPI-NOR | Same family, likely compatible |
| WS-AP7662 | IPQ4029 | SPI-NOR | Same family, untested |

**Note**: This recipe has NOT been tested on real hardware. All procedures are based on
documented U-Boot behavior and OpenWrt DTS analysis. Use at your own risk.

## Hardware

- SoC: Qualcomm IPQ4029 (4x Cortex-A7 @ 717 MHz)
- Flash: SPI-NOR (partition layout from OpenWrt DTS)
- RAM: 512MB DDR3 (confirm from live device)
- Ethernet: 2x GbE (GE1 = PoE+ data, GE2 = passive)
- WiFi: 2.4GHz 2x2 + 5GHz 2x2 (IPQ4029 integrated)
- Console: Internal serial header (3.3V UART, 115200 8N1) — NOT required for this method

## OpenWrt

- Target: `ipq40xx/generic`
- Device: `extreme-networks,ws-ap3915i`
- Profile: `extreme-networks_ws-ap3915i`
- Default IP: 192.168.1.1
- Tested version: untested

## Hardware Setup

1. Power the AP via PoE on GE1/LAN1 port
2. Connect Ethernet from your computer to GE1 (same cable carries PoE + data)
3. Configure your computer's Ethernet interface:
   - Stock firmware default: DHCP or 192.168.1.x/24
   - OpenWrt after flash: 192.168.1.x/24

## Required Files

1. **OpenWrt initramfs**: `openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-initramfs-uImage`
2. **OpenWrt sysupgrade**: `openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-squashfs-sysupgrade.bin`
3. **Optional**: Official Extreme AP391x firmware image (for bootcmd fallback restore)

## Flash Method: extreme-rdwr-tftp-initramfs

Two-stage no-serial flash using the stock firmware's `rdwr_boot_cfg` utility to
reconfigure U-Boot for temporary TFTP boot.

### Stage 1: Stock Firmware → TFTP Boot OpenWrt Initramfs

The stock Extreme firmware includes `rdwr_boot_cfg`, a utility that can read and write
U-Boot environment variables from Linux. By setting `bootcmd=run boot_net`, we instruct
U-Boot to TFTP boot instead of flashing from SPI-NOR.

```bash
# Request ASU images and flash
python3 scripts/conwrt.py flash \
  --model-id extreme-networks-ws-ap3915i \
  --flash-method extreme-rdwr-tftp-initramfs \
  --request-image \
  --ssh-key ~/.ssh/id_ed25519.pub

# Or with local images
python3 scripts/conwrt.py flash \
  --model-id extreme-networks-ws-ap3915i \
  --flash-method extreme-rdwr-tftp-initramfs \
  --initramfs openwrt-*-initramfs-uImage \
  --image openwrt-*-sysupgrade.bin
```

**What happens automatically:**
1. SSH to stock firmware (admin/new2day)
2. Save `rdwr_boot_cfg read_all` output (mandatory backup)
3. Disable SSH timeout: `cset sshtimeout 0 && capply && csave`
4. Start conwrt TFTP server serving initramfs as `vmlinux.gz.uImage.3912`
5. Write U-Boot vars: `bootcmd=run boot_net`, `serverip=<your-ip>`, etc.
6. Reboot AP → U-Boot TFTP boots OpenWrt initramfs

### Stage 2: Backup + Permanent Install

After OpenWrt initramfs boots (IP: 192.168.1.1):

1. Full MTD backup to `data/backups/extreme-networks-ws-ap3915i/`
2. Restore `bootcmd=run boot_flash` via `fw_setenv` (if safe)
3. Upload sysupgrade.bin
4. `sysupgrade -n /tmp/sysupgrade.bin`
5. Reboot into permanent OpenWrt

### bootcmd Restoration

The `bootcmd` variable MUST be restored to `run boot_flash` before or during sysupgrade.
Otherwise the AP will keep trying to TFTP boot on every power cycle.

**Preferred path**: `fw_setenv` from OpenWrt initramfs
- Only if `fw_printenv` works, `/etc/fw_env.config` exists, and validation passes

**Fallback path**: Extreme TFTP detour
- If `fw_setenv` is unavailable or unsafe
- Serve the original Extreme vmlinux.gz.uImage via TFTP
- After OpenWrt sysupgrade writes flash and reboots, U-Boot still has `bootcmd=run boot_net`
- U-Boot TFTP boots the original Extreme image temporarily
- SSH into Extreme environment, run `rdwr_boot_cfg write_var bootcmd "run boot_flash"`
- Reboot again → permanent OpenWrt boots from flash

## Dry Run / Analysis

```bash
# Dry run — no changes to device
python3 scripts/conwrt.py flash \
  --model-id extreme-networks-ws-ap3915i \
  --flash-method extreme-rdwr-tftp-initramfs \
  --initramfs openwrt-*-initramfs-uImage \
  --image openwrt-*-sysupgrade.bin \
  --no-upload

# Analyze firmware image
python3 scripts/extreme_ap391x_analyze.py --ap-image path/to/AP3915-*.img
python3 scripts/extreme_ap391x_analyze.py --controller-image path/to/IdentiFi-*.img
python3 scripts/extreme_ap391x_analyze.py --url https://example.com/firmware.img
```

## Rollback / Debrick

If the flash fails or OpenWrt doesn't boot:

1. **Serial recovery**: Connect UART (3.3V, 115200 8N1), interrupt U-Boot, manually boot
2. **Extreme TFTP detour**: Serve original Extreme image via TFTP to get a working shell
3. **Restore from backup**: Use saved MTD backup to restore original firmware
4. **Worst case**: JTAG or SPI-NOR programmer (requires disassembly)

## Warnings

- **Misconfigured U-Boot may require serial recovery.** The `rdwr_boot_cfg` writes are
  permanent until changed. If `bootcmd` points to a non-existent TFTP server, the AP
  will hang at U-Boot.
- **Stock Extreme shell may reboot periodically** if no controller is present. Disable
  SSH timeout immediately on connection.
- **Full MTD backup is mandatory** before permanent install. Without a backup, there is
  no way to restore stock firmware.
- **Direct image_upgrade is experimental.** The stock `image_upgrade` command's signature
  verification status is unknown. Do not use it unless the firmware analyzer proves it
  uses only checksums (not cryptographic signatures).

## Known Risks

1. **AP may reboot during stock SSH session** if no controller is present — work quickly
   or use SSH timeout disable commands
2. **TFTP boot failure** leaves AP in U-Boot loop — requires serial or TFTP server to recover
3. **fw_setenv may not work in OpenWrt initramfs** — fallback path requires Extreme firmware image
4. **SPI-NOR partition layout** may differ between hardware revisions — verify with `cat /proc/mtd`
5. **OpenWrt ipq40xx support for this device is relatively new** — verify DTS matches your hardware
