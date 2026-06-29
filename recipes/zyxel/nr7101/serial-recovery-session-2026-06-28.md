# NR7101 Serial Recovery Session — 2026-06-27/28

## Device

- **Model**: ZyXEL NR7101 (Telenor-branded)
- **SoC**: MT7621A dual-core MIPS 1004Kc @ 880MHz
- **Flash**: 128MB NAND
- **Serial**: J5 header, 57600 8N1
- **Condition**: Broken/corrupt stock firmware — boots through bootloader but firmware produces no serial output and no network activity

## What Worked

1. **Serial console access** — FT232R adapter on J5 header at 57600 baud. Full boot sequence captured: DDR3 calibration → U-Boot 1.1.3 → Ralink UBoot 5.0.0.0 → Z-Loader V1.30 → Multiboot Listening (6s countdown) → firmware handoff
2. **Zycast flash (partial)** — Delivered ~60% of initramfs image (4487/7438 packets) before zycast crashed. The partial image was enough to boot OpenWrt — kernel booted, PCIe init succeeded, modem detected, userspace started
3. **Serial-based configuration** — Changed LAN IP from 192.168.1.1 to 192.168.5.1, enabled password auth, via serial console. This is a new conwrt capability
4. **ASU image build** — Custom sysupgrade image built with 192.168.5.1 LAN IP, SSH key, WAN SSH — all baked into firmware defaults
5. **Boot timing capture** — Each boot stage documented with timestamps

## What Failed

### 1. Zycast from macOS — UNRELIABLE

**Root cause**: macOS removes USB ethernet adapter (en9) IP addresses during device power cycles. When PoE power drops, the NR7101's ethernet PHY goes down, causing a link state change on en9. macOS detects this and immediately removes the configured IP, even if it was set as "manual." This crashes zycast (OSError: Can't assign requested address) mid-transmission.

**What we tried**:
- `ifconfig en9 inet 192.168.10.1/24` — IP removed within seconds of power cycle
- `ipconfig set en9 MANUAL` — same result
- `networksetup -setmanual` — same result
- IP-keeper daemon (re-adds IP every 0.1s) — zycast still crashed during the gap
- Multicast routing (`route add -net 224.0.0.0/4 -interface en9`) — multicast went out but bootloader couldn't receive complete image before zycast crashed
- Tmux-based restart loop — zycast restarted but only delivered ~144 packets per cycle

**The fix that wasn't**: Adding a switch between Mac and NR7101 should keep en9's link stable during power cycle. We tried this but en9's IP was still removed (possibly because the switch itself briefly dropped the link during PoE cycling).

**What WOULD work**: Running zycast from an OpenWrt switch (GS1900-8HP) with software-controlled PoE power cycling. This is the proven method from the previous NR7101 flash (2026-05-26).

### 2. UART Break During Power Cycle

**Root cause**: When PoE power drops, the NR7101's UART TX pin goes from 3.3V (idle-high) to 0V. The FT232R serial adapter sees this as a break condition and enters an error state. After power returns, the FT232R does NOT cleanly recover — the serial port stays "open" but delivers zero data.

**Symptom**: Serial reader gets a single 0x00 byte (the break), then nothing — even though the device is booting and producing serial output.

**Fix implemented**: `serial-boot-capture.py` now detects the break byte, closes the serial port, waits 2-3 seconds, then REOPENS the port fresh. This resets the FT232R's internal state. The fix worked — we captured full boot sequences after power cycles.

**Hardware fix (not tested)**: 10kΩ pull-up resistor between adapter RX and 3.3V keeps the line at idle-high during power-off, preventing the break condition.

### 3. Ethernet Data Path — 0 PACKETS

**Root cause**: Despite both Mac en9 and NR7101 eth0 showing "active 1000baseT full-duplex," zero packets were received on either side. The physical data path between them is broken.

**Likely cause**: The PoE injector or cable between the Mac's USB ethernet and the NR7101 is not passing data correctly. Possible explanations:
- PoE injector is "power only" (doesn't bridge data pairs)
- Cable between PoE injector and NR7101 is damaged (PoE power uses different pairs than data — power can work while data doesn't)
- Switch in the path has port isolation or VLAN filtering

**Not resolved**: We ran out of session time before diagnosing the physical layer.

### 4. DSA Switch Ports Not Created

**Root cause**: The OpenWrt initramfs-recovery image expects DSA switch ports (`lan`, `wan`) to be created by the device tree. On the NR7101, only `eth0` exists — the DSA ports were never created, so `br-lan` bridge couldn't be configured, and the `lan` and `wan` network interfaces had no physical device.

**Impact**: 
- LAN interface (`br-lan`) never came up — device was unreachable on its configured IP
- WAN interface (`wan` port) didn't exist — modem WAN couldn't be configured
- We manually assigned IPs to `eth0` via serial to work around this

**Fix applied via serial**: `ip addr add 192.168.5.1/24 dev eth0` + `ip link set eth0 up`

## What We Never Tried

### Serial Flashing (XMODEM/Kermit) — MISSED OPPORTUNITY

We spent the entire session trying zycast (network-based multicast) and fighting macOS networking issues. We never tried the simplest approach: **transfer the firmware image over the serial wire itself.**

**Options that might work**:
1. **Z-Loader XMODEM**: Enter Z-Loader via ESC during boot, check if `xmodem` command exists. If so, transfer initramfs image via XMODEM at 57600 baud (~22 minutes for 7.3MB)
2. **U-Boot `loadb`**: U-Boot Kermit protocol for serial file transfer
3. **Base64 over serial**: Encode image as base64 text, `cat` over serial, decode on device. Very slow but needs no protocol support

**Why this matters**: Serial is the ONE connection that worked reliably this entire session. A serial-based flash method would have avoided ALL the macOS networking issues. This should be the FIRST method to try for future serial recovery sessions, not the last.

## Partition Layout (verified via serial, `cat /proc/mtd`)

```
mtd0: 00080000 "Bootloader"     (512KB)
mtd1: 00080000 "Config"         (512KB)
mtd2: 00040000 "Factory"        (256KB, IRREPLACEABLE)
mtd3: 01ec0000 "Kernel"         (~31MB)
mtd4: 01ac0000 "ubi"            (~27MB)
mtd5: 01ec0000 "Kernel2"        (~31MB)
mtd6: 00100000 "wwan"           (1MB)
mtd7: 01000000 "data"           (16MB)
mtd8: 00100000 "rom-d"          (1MB)
mtd9: 00080000 "reserve"        (512KB)
```

## MAC Address

- **eth0 MAC**: `d4:1a:d1:ec:41:d8` (observed in initramfs — may differ from factory MAC)
- **Expected OUI**: `4C:C5:3E` (ZyXEL) — not observed on this unit
- **Factory partition** (mtd2, irreplaceable): NOT backed up. Contains real MAC, serial number, calibration data

## Recommendations for Next Session

1. **Try serial flashing FIRST** — enter Z-Loader via ESC, check for XMODEM support
2. **Use the GS1900-8HP switch** for zycast — proven reliable method
3. **Diagnose the ethernet path** — test cable continuity, PoE injector data passthrough
4. **Backup Factory partition** before any further flashing
5. **Install the ASU sysupgrade image** once a reliable transfer path is established
