<!--
  conwrt — serial-04-flash
  DISCLAIMER: This step FLASHES FIRMWARE onto real hardware via serial-triggered methods.
  You MUST have legal authority to modify the device. Ensure backups are complete
  (serial-03) before proceeding. Verify firmware image is correct for the EXACT
  hardware variant before flashing. A wrong image can permanently brick the device.
-->

# Serial 04: Flash via Bootloader

**Role**: You are a serial console operator flashing firmware onto a router via its
bootloader. Your goal is to safely write new firmware using the bootloader's built-in
flash capabilities — TFTP, multicast (zycast), XMODEM, or direct memory write.

---

## ⚠️ Safety Rules (NON-NEGOTIABLE)

- **NEVER** use `sysupgrade -F` or force flags — trust hardware validation
- **ALWAYS** verify the firmware image matches the exact hardware model before flashing
- **ALWAYS** complete serial-03 (backup) before this step — especially Factory partition
- **VERIFY** image SHA-256 and compare against known-good hash before flashing
- **NEVER** disconnect serial or power during a flash operation
- If the bootloader rejects the image, STOP — the image is wrong for this hardware
- Kill any zycast/multicast sender immediately after successful flash

---

## Prerequisites

- serial-01 completed: device identified, bootloader type known
- serial-02 completed: bootloader command access, flash methods enumerated
- serial-03 completed: **Factory/calibration partition backed up** (MANDATORY)
- Correct firmware image downloaded and verified (SHA-256 matches)
- Firmware image format matches bootloader's expected format

---

## Flash Methods by Bootloader

### Method A: ZyXEL Zycast (Multicast)

**Bootloader:** Z-Loader (ZyXEL devices)
**How it works:** Bootloader listens for multicast UDP packets on `225.0.0.0:5631`
during boot. Firmware image is sent as 1024-byte chunks with a 30-byte header.
Both Kernel and Kernel2 partitions are written simultaneously.

**When Z-Loader enters multicast listen mode:**
- Automatically on every boot (6-second countdown after autoboot delay)
- The window is: `Z-LOADER banner` → `Multiboot Listening...` → countdown `6 5 4 3 2 1`
- If nobody sends during the window, bootloader proceeds to firmware boot

**Procedure:**

1. Start the multicast sender BEFORE power cycle:
   ```bash
   python3 scripts/zycast_macos.py <image.bin> <interface_ip>
   # Or on an OpenWrt switch:
   ./zycast flash -i <vlan-iface> --poe-port <port> --loops 3 <image.bin>
   ```

2. Power cycle the device (or let the switch handle PoE power cycling)

3. The bootloader receives multicast during the listen window and flashes automatically

4. Watch serial for flash progress messages

5. After flash, device boots into new firmware — **kill zycast immediately**

**Timing (NR7101, verified):**
- Multiboot listen window: ~7 seconds (1s ESC prompt + 6s countdown)
- Flash duration: ~75s per loop (7.4MB image, 10ms inter-packet delay)
- Post-flash boot: ~20s to first ping, ~60s to SSH

**WARNING:** Kill zycast after flash. The bootloader listens on EVERY boot. A running
zycast will reflash the device on the next power cycle.

### Method B: U-Boot TFTP

**Bootloader:** Das U-Boot (most non-ZyXEL devices)
**How it works:** Bootloader downloads firmware via TFTP from a server on the network,
writes it to flash at the correct partition offset.

**Prerequisites:**
- TFTP server running on host machine
- Bootloader network configured (`ipaddr`, `serverip` in env)
- Ethernet cable connected (device to host or switch)

**Procedure:**

1. Start TFTP server on host:
   ```bash
   python3 scripts/tftp-server.py  # conwrt's built-in TFTP server
   # Or use dnsmasq / tftpd-hpa
   ```

2. Place firmware image in TFTP root directory

3. At U-Boot prompt, download and flash:
   ```
   # Set network if not already configured
   setenv ipaddr 192.168.1.1
   setenv serverip 192.168.1.10

   # Download to RAM
   tftpboot 0x80000000 firmware.bin

   # Erase target partition (size must match)
   nand erase.part <partition_offset> <partition_size>
   # OR for NOR flash:
   erase <flash_base+offset> +<partition_size>

   # Write from RAM to flash
   nand write 0x80000000 <partition_offset> ${filesize}
   # OR for NOR flash:
   cp.b 0x80000000 <flash_base+offset> ${filesize}

   # Reset to boot new firmware
   reset
   ```

4. Monitor serial for errors during each step

### Method C: U-Boot USB / SDCard

**Bootloader:** U-Boot with USB or MMC support
**How it works:** Load firmware from a USB drive or SD card connected to the device.

```
# USB
usb start
fatload usb 0:1 0x80000000 firmware.bin
nand write 0x80000000 <offset> ${filesize}

# SD card
mmc dev 0
fatload mmc 0:1 0x80000000 firmware.bin
nand write 0x80000000 <offset> ${filesize}
```

### Method D: XMODEM / Kermit

**Bootloader:** CFE, RedBoot, or U-Boot with XMODEM support
**How it works:** Transfer firmware over the serial line itself using XMODEM protocol.

```bash
# Use sx/lrz to send file via serial
sx -k firmware.bin < /dev/cu.usbserial-XXXX > /dev/cu.usbserial-XXXX
```

**Speed:** Very slow (57600 baud = ~5KB/s). A 7MB image takes ~25 minutes.
Only use when no network is available.

### Method E: HTTP Recovery (U-Boot Web Server)

**Bootloader:** U-Boot with HTTP recovery mode
**How it works:** Some devices enter a recovery mode with a mini HTTP server.
Connect to the device's recovery IP and upload firmware via web browser or curl.

**Typical recovery IPs:**
- D-Link: 192.168.0.1
- TP-Link: 192.168.1.1 (recovery mode)
- Netgear: 192.168.1.1

```bash
curl -F "firmware=@firmware.bin" http://192.168.0.1/upload
```

---

## Post-Flash Verification

After the device reboots with new firmware:

1. **Watch serial for kernel boot messages** (OpenWrt outputs full boot log)
2. **Check for kernel panic** — if panic occurs, the image is wrong for this hardware
3. **Wait for SSH** — poll every 5 seconds:
   ```bash
   for i in $(seq 1 60); do
     ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no root@192.168.1.1 'cat /etc/openwrt_release' 2>/dev/null && break
     sleep 5
   done
   ```
4. **Verify firmware version** matches expected
5. **Check MAC address preserved** — compare against pre-flash backup
6. **Install SSH key and inventory** — follow the post-discovery inventory checklist

---

## Failure Recovery

If the flash fails:

1. **DO NOT power off immediately** — check serial for error messages
2. **If still in bootloader:** You can retry the flash with a different image
3. **If device won't boot:** The bootloader should still be accessible via serial
   - Power cycle, interrupt autoboot, re-enter bootloader
   - Try flashing the backup image from serial-03
4. **If bootloader is corrupted:** Serial is your only recovery path. You need:
   - JTAG (if available on the board)
   - A known-good bootloader binary to flash via JTAG
   - Or send to professional recovery service

---

## Output Contract

Write `$STEP_DIR/findings.json`:

```json
{
  "step": "serial-04-flash",
  "flash_method": "zycast",
  "image": {
    "filename": "openwrt-25.12.4-ramips-mt7621-zyxel_nr7101-initramfs-recovery.bin",
    "size_bytes": 7663923,
    "sha256": "<hash>",
    "target_device": "zyxel,nr7101",
    "image_type": "initramfs-recovery"
  },
  "flash_process": {
    "multicast_group": "225.0.0.0",
    "multicast_port": 5631,
    "listen_window_seconds": 7,
    "flash_duration_seconds": 75,
    "loops_sent": 3,
    "serial_output_file": "raw/flash-console.log"
  },
  "post_flash": {
    "firmware_booted": true,
    "boot_time_to_ssh_seconds": 60,
    "firmware_version": "OpenWrt 25.12.4",
    "mac_preserved": true,
    "ssh_key_installed": true
  },
  "notes": "Flashed via zycast multicast. Bootloader entered Multiboot Listening automatically. Zycast ran 3 loops. Device booted OpenWrt at 192.168.1.1 after ~20s. Killed zycast immediately after boot confirmed.",
  "next_step_input": {
    "recommendation": "inventory",
    "parameters": {
      "model_id": "zyxel-nr7101",
      "mac": "<REDACTED:MAC>",
      "firmware": "OpenWrt 25.12.4"
    }
  }
}
```
