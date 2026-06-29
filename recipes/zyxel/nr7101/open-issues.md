# NR7101 Open Issues & Known Unknowns

**Last updated**: 2026-06-28  
**Device**: ZyXEL NR7101 (Telenor-branded), MT7621A, serial at J5/57600  
**Current state**: Booting partial OpenWrt initramfs via zycast flash. Serial works. Ethernet broken. No SSH. No SIM. No backup.

---

## Session Resume Checklist

When reconnecting the NR7101 to serial, do these FIRST:

```bash
# 1. Verify serial connection
python3 scripts/serial-boot-capture.py /dev/cu.usbserial-BG02QAPG 57600 --session resume-check --timeout 10

# 2. Press Enter to activate console
python3 -c "
import serial, time
s = serial.Serial('/dev/cu.usbserial-BG02QAPG', 57600, timeout=2)
s.write(b'\x03\r\n')
time.sleep(1)
r = s.read(4096)
print(r.decode('ascii', errors='replace'))
s.close()
"

# 3. Check firmware + network state
python3 scripts/serial-configure.py /dev/cu.usbserial-BG02QAPG 57600 --show-firmware --show-config

# 4. Check if eth0 is up
python3 scripts/serial-configure.py /dev/cu.usbserial-BG02QAPG 57600 --command "ip link show eth0"
```

If device is off, power cycle and use `serial-boot-capture.py` with `--recovery-wait 3`.

---

## Open Issues

### I-001: Serial flash via XMODEM/Kermit — NEVER TESTED 🔴 CRITICAL

**Problem**: We spent the entire session on zycast (network multicast) and never tried the simplest path: transferring firmware over the serial wire itself.

**Why it matters**: Serial was the ONLY reliable connection the entire session. A serial flash method would bypass ALL macOS networking issues.

**How to test**:
1. Power cycle the device
2. Send ESC during the 1-second boot delay to enter Z-Loader
3. Run `help` or `?` to enumerate commands
4. Look for: `xmodem`, `loadb`, `loads`, `tftpd`, `flwrite`, `upload`
5. If XMODEM exists: `xmodem receive <addr>` then send file from host with `sx`
6. Transfer time: ~22 min for 7.3MB at 57600 baud

**Needed**: Serial connection, power cycle, the initramfs image
**Image**: `images/openwrt-25.12.4-ramips-mt7621-zyxel_nr7101-initramfs-recovery.bin`

### I-002: Ethernet data path broken (0 packets) 🔴 CRITICAL

**Problem**: Mac en9 and NR7101 eth0 both show "active 1000baseT" but zero packets pass between them. NR7101 `rx_packets=0`.

**Possible causes** (in order of likelihood):
1. PoE injector not passing data (power-only, or wrong port)
2. Cable damaged (PoE power pairs work, data pairs don't)
3. Switch in path with VLAN/port isolation
4. NR7101 PHY in bad state

**How to test**:
1. Bypass the PoE injector — connect Mac USB ethernet directly to NR7101 (use separate PoE for power)
2. Test cable continuity with a cable tester
3. Try a different PoE injector
4. Check NR7101 eth0 link status via serial: `cat /sys/class/net/eth0/statistics/rx_packets`
5. `tcpdump` on Mac en9 while sending pings

**Needed**: Cable tester, known-good PoE injector, possibly a direct ethernet cable

### I-003: Factory partition not backed up 🔴 CRITICAL

**Problem**: mtd2 (Factory, 256KB) contains irreplaceable device data (MAC address, serial number, WiFi calibration, certificates). We flashed via zycast WITHOUT backing up first. Factory data survived (zycast doesn't touch mtd2), but it must be backed up before any further flashing.

**How to backup**:
```bash
# Via SSH (once ethernet works):
ssh root@192.168.5.1 'dd if=/dev/mtd2 of=/tmp/factory.bin'
scp -O root@192.168.5.1:/tmp/factory.bin ./nr7101-factory-backup.bin

# Via serial (if SSH unavailable):
# Read partition with: cat /dev/mtd2 | base64
# Capture serial output, decode base64 on host
```

**Needed**: SSH access or serial file transfer

### I-004: ASU sysupgrade image built but not delivered 🟡 READY

**Problem**: Custom ASU image built successfully with 192.168.5.1 LAN IP, SSH key, WAN SSH — but can't deliver to device (no SSH, no reliable file transfer).

**Image location**:
```
images/zyxel_nr7101/59433f1193b6add5f2f79d6530c47c00191d7dde17e792fe29badb4e23a15c26/
  openwrt-25.12.4-535cf27917f1-ramips-mt7621-zyxel_nr7101-squashfs-sysupgrade.bin
```
Size: 8.2MB, SHA-256 verified.

**How to deliver**:
1. **Via SSH** (once I-002 resolved): `scp -O sysupgrade.bin root@192.168.5.1:/tmp/ && ssh root@192.168.5.1 'sysupgrade -n /tmp/sysupgrade.bin'`
2. **Via serial** (if XMODEM works — see I-001): Transfer to RAM, then sysupgrade from RAM
3. **Via modem** (needs SIM — not available)
4. **Via wget** (needs internet — no SIM, no working WAN)

### I-005: Z-Loader command set unknown 🟡 MEDIUM

**Problem**: We never entered Z-Loader command mode. We don't know what commands are available for flashing, environment inspection, or serial transfer.

**How to test**:
1. Power cycle
2. Send ESC repeatedly during boot delay (1-second window after "Hit ESC key to stop autoboot")
3. Run `help` or `?` at the Z-Loader prompt
4. Document every command and its usage

**Key questions to answer**:
- Does Z-Loader support XMODEM file transfer?
- Does `printenv` show BootingFlag, Image1Stable, Image2Stable?
- Does it have a TFTP command?
- Can we read/write flash from the Z-Loader prompt?

### I-006: Partial initramfs in flash — PCIe timing-dependent 🟢 LOW

**Problem**: The zycast flash delivered only ~60% of the image. The partial kernel boots OpenWrt but PCIe init (Quectel modem) is timing-sensitive — it hung on first boot, succeeded on second and third boots.

**Impact**: Device is usable but unreliable. PCIe hang may return on future boots.

**Fix**: sysupgrade to complete ASU image (I-004) will replace the partial kernel with a complete one.

### I-007: DSA switch ports not created in initramfs 🟡 MEDIUM

**Problem**: OpenWrt initramfs expects DSA ports `lan` and `wan` (from device tree) but only `eth0` exists. The `br-lan` bridge never came up, `lan` and `wan` network interfaces had no physical device.

**Workaround applied**: Manually assigned IPs to `eth0` via serial.

**Fix**: The permanent OpenWrt image (sysupgrade) should create the DSA ports correctly. The initramfs may have a different DSA configuration path.

---

## Known Unknowns

### KU-001: Does Z-Loader V1.30 support XMODEM?

**Why it matters**: If yes, we can flash the device entirely via serial — no network needed. ~22 min transfer at 57600 baud.
**How to answer**: Enter Z-Loader via ESC, check `help` output.

### KU-002: What bootloader environment variables are set?

**Why it matters**: BootingFlag determines which partition boots. Image1Stable/Image2Stable indicate if the boot was successful. Understanding these helps diagnose boot issues.
**How to answer**: `printenv` from Z-Loader, or `fw_printenv` from OpenWrt.

### KU-003: What is the real factory MAC address?

**Why it matters**: eth0 shows `d4:1a:d1:ec:41:d8` — NOT a ZyXEL OUI (`4C:C5:3E`). This might be a random MAC assigned by the initramfs, or the device's real MAC might be from a different OUI block. The Factory partition (mtd2) has the real MAC.
**How to answer**: `hexdump -C /dev/mtd2 | head -20` or `cat /sys/class/net/eth0/address` vs factory data.

### KU-004: Is PCIe hang reproducible?

**Why it matters**: If PCIe init is flaky, the device may hang on future boots. We need to know the pattern.
**How to answer**: Boot the device 5+ times and note PCIe init success/failure each time.

### KU-005: Does 10kΩ pull-up fix the UART break?

**Why it matters**: The FT232R gets stuck after UART break during power cycles. A pull-up resistor on RX→3.3V should prevent this. Would make serial boot capture more reliable.
**How to answer**: Solder a 10kΩ resistor between FT232R RX and 3.3V, then power cycle with serial monitor running.

### KU-006: Can base64 serial transfer handle 8.2MB?

**Why it matters**: If no XMODEM in Z-Loader, base64 is the fallback serial transfer method. But we don't know if the serial console can handle ~11MB of base64 text without buffer issues.
**How to answer**: Test with a small file first (e.g., `/etc/config/network`), then scale up.

### KU-007: Does the GS1900-8HP switch fix the zycast reliability?

**Why it matters**: The previous successful flash (2026-05-26) used a GS1900-8HP with Go zycast binary. The switch keeps link stable during PoE cycling and handles power cycling in software.
**How to answer**: Connect NR7101 to GS1900-8HP, cross-compile Go zycast for MIPS, run from switch.

### KU-008: What firmware was originally on the device?

**Why it matters**: The device had broken stock firmware. Knowing the original version helps understand what went wrong and whether it can be restored.
**How to answer**: Check Kernel2 partition (mtd5) — if the stock firmware is there, we can identify the version.

### KU-009: Does the Z-Loader have a TFTP command?

**Why it matters**: TFTP from Z-Loader would be faster than XMODEM (~2 min vs ~22 min) and more reliable than zycast.
**How to answer**: Enter Z-Loader, check `help` for `tftp`, `tftpboot`, `tftpd`.

### KU-010: Can we read flash contents from Z-Loader?

**Why it matters**: `md.b` (memory dump) in U-Boot/Z-Loader would let us read the Factory partition via serial, even without OpenWrt running.
**How to answer**: Enter Z-Loader, try `md.b 0x1e000000 0x100` to read first 256 bytes of flash.

---

## Resolved Issues (for reference)

### R-001: UART break recovery ✅ FIXED

**Problem**: FT232R gets stuck after UART break during power cycle.  
**Fix**: `serial-boot-capture.py` detects break byte (0x00), closes port, waits 3s, reopens fresh. Works reliably.  
**Commit**: `d228fbd`

### R-002: Serial-based device configuration ✅ FIXED

**Problem**: Device at wrong IP, no SSH, no network access.  
**Fix**: `scripts/serial-configure.py` — change IP, install SSH key, enable/disable password auth via serial console.  
**Commit**: `d228fbd`

### R-003: ASU custom LAN IP ✅ FIXED

**Problem**: ASU images boot at 192.168.1.1, conflicting with EdgeRouter.  
**Fix**: `scripts/profile/builder.py` — `include_in_asu=True` + `firstboot_script` for static LAN IP. ASU image bakes 192.168.5.1 into firmware defaults.  
**Commit**: `d228fbd`

### R-004: Z-Loader Multiboot Listening timing ✅ DOCUMENTED

**Finding**: Z-Loader enters Multiboot Listening on EVERY boot automatically (~7 second window: 1s ESC prompt + 6s countdown). Serial trigger NOT required for zycast.  
**Commit**: `b6798fc`
