<!--
  conwrt — serial-06-flash
  DISCLAIMER: This step transfers firmware over the serial line itself. No network
  required. Slow (~22 min for 7.3MB at 57600 baud) but 100% reliable. You MUST
  have legal authority to modify the target device.
-->

# Serial 06: Flash via Serial Line

**Role**: You are a serial console operator transferring firmware to a router over
the serial line itself — no network, no zycast, no TFTP. Just the serial cable.

**Use case**: The device has serial access but NO reliable network path. This is
the MOST RELIABLE flash method because it depends only on the serial cable, which
is the most stable connection you have.

---

## ⚠️ Safety Rules (NON-NEGOTIABLE)

- **VERIFY** the firmware image matches the exact hardware model before transferring
- **ALWAYS** backup Factory/calibration partition first (serial-03)
- **NEVER** disconnect serial or power during a transfer
- Transfer takes 15-30 minutes — ensure stable power and don't bump the cable
- If transfer corrupts, the device can be re-flashed — bootloader is not touched

---

## Prerequisites

- Serial console active (`root@OpenWrt:~#` or bootloader prompt)
- Firmware image on host machine
- Serial cable stable (not loose)
- Time: ~22 min for 7.3MB at 57600 baud, ~25 min for 8.2MB

---

## Method Selection

| Method | Speed | Requirements | When to Use |
|--------|-------|-------------|-------------|
| **Base64** | ~25 min for 8MB | OpenWrt shell + `base64` on device | Always works, no special protocol |
| **XMODEM** | ~22 min for 7MB | Bootloader XMODEM support + `sx` on host | If bootloader supports it |
| **Kermit** | ~22 min for 7MB | U-Boot `loadb` + `kermit` on host | If U-Boot supports it |
| **wget** | ~1 min | Device has internet (modem/ethernet WAN) | If device has internet access |

**Default to base64** — it works everywhere, needs no special protocol support.

---

## Procedure: Base64 Method (RECOMMENDED)

Works with any OpenWrt serial console. No special protocol needed.

### Step 1: Encode image on host

```bash
python3 scripts/serial-flash.py /dev/cu.usbserial-XXXX 57600 \
    --base64 images/firmware-sysupgrade.bin
```

The script will:
1. Split the image into ~1KB base64 chunks
2. Send each chunk as: `echo '<base64>' >> /tmp/firmware.b64`
3. After all chunks: `base64 -d /tmp/firmware.b64 > /tmp/firmware.bin`
4. Verify: `wc -c /tmp/firmware.bin` matches expected size
5. Show progress and estimated time

### Step 2: Manual base64 (if script unavailable)

On the host, split the image into chunks:
```bash
base64 firmware.bin | split -b 512 - chunks/
```

Send each chunk over serial:
```python
import serial, time, base64, os

PORT = '/dev/cu.usbserial-XXXX'
BAUD = 57600
IMAGE = 'firmware.bin'
CHUNK_SIZE = 512  # bytes of raw data per serial line

s = serial.Serial(PORT, BAUD, timeout=2)

with open(IMAGE, 'rb') as f:
    data = f.read()

total = len(data)
offset = 0
chunk_num = 0

# Clear any existing file on device
s.write(b'rm -f /tmp/fw.b64\r\n')
time.sleep(1)
s.read(4096)

while offset < total:
    chunk = data[offset:offset + CHUNK_SIZE]
    b64 = base64.b64encode(chunk).decode()
    s.write(f"echo '{b64}' >> /tmp/fw.b64\r\n".encode())
    time.sleep(0.15)  # pacing at 57600 baud
    s.read(4096)  # drain echo

    offset += CHUNK_SIZE
    chunk_num += 1
    if chunk_num % 100 == 0:
        pct = offset / total * 100
        print(f"  {offset}/{total} bytes ({pct:.1f}%)")

# Decode on device
s.write(b'base64 -d /tmp/fw.b64 > /tmp/fw.bin\r\n')
time.sleep(5)
s.write(b'wc -c /tmp/fw.bin\r\n')
time.sleep(2)
r = s.read(4096)
print(r.decode('ascii', errors='replace'))
s.close()
```

### Step 3: Verify size matches

```
wc -c /tmp/fw.bin
```
Must match the original file size on the host.

### Step 4: Flash

For sysupgrade image:
```
sysupgrade -n /tmp/fw.bin
```

For initramfs (if at bootloader), write to flash via bootloader commands.

---

## Procedure: XMODEM Method (if bootloader supports)

### Step 1: Enter bootloader

Power cycle, send ESC during boot delay, get Z-Loader/U-Boot prompt.

### Step 2: Check XMODEM support

```
help
```
Look for `xmodem`, `loadx`, `loadb`, or similar commands.

### Step 3: Start XMODEM receive on device

```
# Z-Loader (example — actual command may differ):
xmodem receive 0x80000000

# U-Boot:
loadx 0x80000000
```

### Step 4: Send file from host

```bash
sx -k firmware.bin < /dev/cu.usbserial-XXXX > /dev/cu.usbserial-XXXX
```

Or using kermit:
```bash
kermit -i -l /dev/cu.usbserial-XXXX -b 57600 -s firmware.bin
```

### Step 5: Write to flash from RAM

After transfer completes, write from RAM to flash:
```
# U-Boot example:
nand erase.part <offset> <size>
nand write 0x80000000 <offset> ${filesize}
```

---

## Procedure: wget Method (if device has internet)

If the device has a working WAN (modem or ethernet uplink), download directly:

```bash
# Via serial:
wget -O /tmp/fw.bin http://server/firmware.bin
sysupgrade -n /tmp/fw.bin
```

This is the FASTEST method (~1 min) but requires internet access.

---

## Post-Transfer Verification

After the image is on the device:

1. **Verify size**: `wc -c /tmp/fw.bin` matches original
2. **Verify SHA-256** (if `sha256sum` available): compare hash
3. **Watch the flash on serial**: `sysupgrade -n /tmp/fw.bin` — kernel boot messages appear on serial
4. **Verify post-flash boot**: device should boot into new firmware with full serial output

---

## Output Contract

Write `$STEP_DIR/findings.json`:

```json
{
  "step": "serial-06-flash",
  "method": "base64",
  "image": {
    "filename": "openwrt-25.12.4-sysupgrade.bin",
    "size_bytes": 8172061,
    "sha256": "<hash>"
  },
  "transfer": {
    "duration_seconds": 1500,
    "chunks_sent": 15962,
    "verify_size_match": true,
    "serial_baud": 57600
  },
  "flash_result": "sysupgrade -n successful",
  "post_flash": {
    "booted": true,
    "firmware": "OpenWrt 25.12.4",
    "serial_output": "full kernel boot log"
  }
}
```
