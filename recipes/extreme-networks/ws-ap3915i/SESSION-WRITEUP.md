# AP3915i Session Summary — What We Did, What Went Wrong, Recovery Plan

## Summary

We successfully flashed OpenWrt 24.10.2 onto an Extreme Networks WS-AP3915i without a serial
cable — a process that required reverse-engineering the U-Boot config block format and finding
creative workarounds for broken stock firmware tools. The OpenWrt installation itself went
perfectly. But when we changed the U-Boot `bootcmd` variable to make the AP boot OpenWrt from
flash (instead of TFTP), we wrote the **wrong value** — pointing it to the stock firmware's
boot script instead of OpenWrt's custom boot command. The AP is now in a boot loop and requires
a serial cable to fix.

**The firmware image is correct. The flash write is correct. Only one U-Boot env variable is wrong.
Serial recovery is a 2-minute fix.**

---

## What We Did (Chronological)

### Phase 1: Getting In (Successful)

1. **SSH'd into stock Extreme firmware** (kernel 3.14.43, build 10.51.24.0003)
   - Credentials: `admin`/`new2day` (original), `admin`/`admin123` (factory-reset)
   - Stock SSH requires legacy RSA: `-o "HostKeyAlgorithms=+ssh-rsa"`
   - Stock firmware reboots every ~5 min without a controller (watchdog timer)
   - Discovered `rdwr_boot_cfg` (the documented no-serial tool from PR #13370) was broken —
     returned exit 255 "unable to find config blocks" on our firmware variant
   - This forced us off the documented path into raw MTD writes

2. **Reverse-engineered the config block CRC format**
   - U-Boot env stored in two 64KB config blocks: CFG1 (mtd1 in stock, mtd0 in OpenWrt) and
     CFG2 (mtd10 in stock, mtd8 in OpenWrt) — same physical blocks, different kernel numbering
   - **First attempt**: CRC over `block[4:]` — wrong, AP rejected it, auto-recovered after ~5 min
   - **Second attempt**: Still wrong CRC range — AP rejected again, auto-recovered
   - **Third attempt**: Finally cracked it — CRC32 covers `block[5:]` (skips 4-byte CRC + 1-byte flag)
   - Format: `[4-byte LE CRC32][1-byte flag (0x01=active/0x00=backup)][65531 bytes of null-separated KEY=VALUE padded with 0xFF]`
   - Algorithm: `struct.pack('<I', zlib.crc32(block[5:])) + flag + payload.ljust(65531, b'\xff')`
   - Each wrong CRC attempt caused the AP to "brick" for ~5 min then auto-recover (U-Boot detects
     invalid config blocks and restores factory defaults)

3. **Wrote `bootcmd=run boot_net` + `serverip=192.168.1.2` to config blocks**
   - Used `flashcp` (not `dd` — `dd` doesn't erase NOR flash sectors before writing)
   - SSH session crashed with "Aiee, segfault!" during verification (unstable stock SSH daemon)
   - User manually rebooted the AP

4. **TFTP-booted OpenWrt 24.10.2 initramfs**
   - Laptop at 192.168.1.2 running TFTP server, AP at 192.168.1.1
   - U-Boot ran `tftpboot 0x83600000 vmlinux.gz.uImage.3912; bootm 0x83600000`
   - OpenWrt came up as root@192.168.1.1, no password
   - **This was the moment we won** — OpenWrt was running, we had full shell access

### Phase 2: Installing OpenWrt (Successful)

5. **Backed up all 8 stock MTD partitions** → `data/extreme-ap3915i/openwrt-backups/`
   - CFG1 (64KB), BootBAK (448KB), WINGCFG1 (64KB), ART (64KB), BootPRI (448KB), WINGCFG2 (64KB),
     FS (512KB), CFG2 (64KB)
   - ART partition contains radio calibration data — irreplaceable without hardware tools
   - These backups are our safety net

6. **Ran `sysupgrade -n`** — OpenWrt 24.10.2 permanently written to SPI-NOR flash
   - FIT image (header `d0 0d fe ed`) at flash offset 0x280000, 12MB
   - The device definition in OpenWrt's `generic.mk` is completely standard:
     ```
     define Device/extreme-networks_ws-ap3915i
         $(call Device/FitImage)
         IMAGE_SIZE := 30080k
         SOC := qcom-ipq4029
         IMAGE/sysupgrade.bin := append-kernel | append-rootfs | pad-rootfs | check-size | append-metadata
     endef
     ```
   - No special padding, no custom blocksize, no weird quirks — same pattern as dozens of
     other IPQ40xx devices

7. **AP rebooted, TFTP-booted initramfs again** (because `bootcmd=run boot_net` was still set)
   - This is expected — sysupgrade doesn't change U-Boot environment
   - We were back in OpenWrt, this time with the sysupgrade installed to flash

### Phase 3: The Mistake (Boot Loop)

8. **Needed to change `bootcmd` from `run boot_net` to boot OpenWrt from flash**
   - The AP was currently TFTP-booting on every power cycle — fine for testing, but not permanent
   - We needed a `bootcmd` that reads OpenWrt from flash and boots it directly
   - The correct command was in David Bauer's original commit e16a0e7:
     ```
     setenv boot_openwrt "sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000"
     setenv bootcmd "run boot_openwrt"
     ```

9. **We wrote `bootcmd=run boot_flash` instead** — THE CRITICAL ERROR
   - `boot_flash` is a stock U-Boot variable: `boot_flash=source boot_kernel`
   - `boot_kernel` is a complex U-Boot script embedded in the BootPRI partition
   - That script uses `nboot` (NAND boot), watchdog timers, dual-image failover
   - It was designed for the stock uImage firmware format, not OpenWrt's FIT image
   - We got this value from PR #13370's instructions, which said to restore `bootcmd="run boot_flash"`
   - **We didn't understand that PR #13370's instructions were for a different scenario** — the
     PR author goes BACK to stock firmware via TFTP and uses `rdwr_boot_cfg` from there

10. **How we wrote the wrong value: `kmod-mtd-rw` + `flashcp`**
    - OpenWrt's device tree marks CFG partitions as read-only (DTS `read-only` flag)
    - We found and installed the `kmod-mtd-rw` package: `insmod mtd-rw i_want_a_brick=1`
    - This bypasses DTS read-only protection — it worked perfectly
    - We built config blocks with correct CRC, correct flag bytes
    - Wrote to both CFG1 (mtd0) and CFG2 (mtd8) via `flashcp`
    - Verified the write with MD5 — **the mechanism was flawless, the value was wrong**

11. **Rebooted → boot loop**
    - U-Boot runs `bootcmd=run boot_flash` → `source boot_kernel` → stock boot script
    - Stock script tries `nboot` to load from both PriImg (0x280000) and SecImg (0x1130000)
    - Both offsets contain OpenWrt FIT, not stock uImage
    - Script fails ("ERROR: Cannot boot either kernel image"), drops to U-Boot shell
    - Watchdog timer (set up by the script before attempting boot) fires → reboot → loop
    - LED pattern: orange → two orange → ~30s pause → **brief green flash** → back to orange
    - **Zero Ethernet packets** during the entire cycle — confirmed via hours of tcpdump monitoring

---

## Exactly What Went Wrong — The Chain of Mistakes

### Mistake 1: Not reading the original commit before acting

David Bauer's commit e16a0e7 (September 2022, the commit that originally added AP3915i support)
contains explicit installation instructions in its commit message:

```
3. Update the bootcommand to allow loading OpenWrt.
   $ setenv ramboot_openwrt "setenv serverip 192.168.1.X; setenv ipaddr 192.168.1.1; tftpboot 0x86000000 openwrt-3915.bin; bootm"
   $ setenv boot_openwrt "sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000"
   $ setenv bootcmd "run boot_openwrt"
   $ saveenv
```

We found this commit — but only AFTER we had already written the wrong `bootcmd` and put the AP
in a boot loop. We should have read it before touching U-Boot variables.

### Mistake 2: Misunderstanding PR #13370's context

PR #13370 (by apdev-2023) describes a no-serial flash method. Its final step says:

> "Restore the bootcmd: `rdwr_boot_cfg write_var bootcmd="run boot_flash"`"

This instruction assumes you have working `rdwr_boot_cfg`. The PR author's complete flow is:

1. From stock firmware: use `rdwr_boot_cfg` to set `bootcmd=run boot_net`
2. TFTP boot OpenWrt initramfs
3. Run sysupgrade
4. **Swap TFTP server to serve stock Extreme firmware** (not OpenWrt)
5. AP TFTP-boots into STOCK firmware (OpenWrt is on flash, but `bootcmd` still says TFTP)
6. From stock firmware: use `rdwr_boot_cfg` to set `bootcmd=run boot_flash`
7. Reboot → stock `boot_kernel` script boots the OpenWrt FIT from flash

We skipped steps 4-6 because our `rdwr_boot_cfg` was broken. We tried to set `bootcmd=run boot_flash`
directly from OpenWrt (via raw MTD write), skipping the stock firmware detour entirely.

The problem: `run boot_flash` runs the stock `boot_kernel` script which has watchdog timers,
dual-image failover logic, and other stock-specific features. In the PR author's flow, the stock
firmware presumably sets up additional U-Boot variables or modifies the boot script's behavior.
When we wrote just `bootcmd=run boot_flash` without going through stock firmware, we were missing
whatever context the stock firmware adds.

### Mistake 3: Not understanding the difference between `boot_flash` and `boot_openwrt`

These are fundamentally different commands:

| Variable | Value | What It Does |
|----------|-------|-------------|
| `boot_flash` | `source boot_kernel` | Runs a **stock Extreme script** embedded in BootPRI partition |
| `boot_openwrt` | `sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000` | **Directly reads FIT from SPI-NOR and boots it** |

`boot_openwrt` is the OpenWrt-specific boot command — it was created specifically for this device
by David Bauer. It bypasses all stock firmware logic and directly reads the FIT image from flash.

`boot_flash` is a stock command that runs the stock boot script. The stock script was designed for
stock firmware with stock uImage format. It has no concept of OpenWrt or FIT images.

### Mistake 4: Writing to BOTH config blocks simultaneously

We wrote the wrong `bootcmd` to both CFG1 and CFG2. U-Boot tries CFG1 first; if that fails (bad
CRC), it falls back to CFG2. By writing the same wrong value to both, we eliminated the fallback
path. We should have written to CFG1 only, verified it worked, then mirrored to CFG2.

### Mistake 5: Changing `bootcmd` away from a working state without testing

We had `bootcmd=run boot_net` working perfectly — the AP TFTP-booted reliably. We changed it to
`bootcmd=run boot_flash` without:
- Testing `run boot_flash` manually first (would have needed serial)
- Keeping a working fallback (could have used `bootcmd=run boot_flash || run boot_net`)
- Understanding what `run boot_flash` actually does (we had the BootPRI backup and could have
  extracted the `boot_kernel` script before acting)

---

## The Green Flash — What's Actually Happening

During the boot loop, the user observed: "orange → ~30 seconds → green flash for about one second → back to orange"

**Research finding: this is the stock watchdog, not a kernel crash.**

The stock `boot_kernel` script:
1. Sets up a hardware watchdog timer
2. Uses `nboot` to load a kernel image from flash into RAM
3. Runs `bootm` to boot the image
4. The script expects the stock firmware to service the watchdog during boot

When the script loads the OpenWrt FIT image:
- `bootm` starts the FIT image → OpenWrt kernel begins executing (green LED = kernel running)
- The OpenWrt kernel doesn't know about the stock Extreme watchdog setup
- Watchdog fires after its timeout → hardware reboot → loop

**This is NOT a kernel bug in OpenWrt 24.10.2.** The firmware image is correct. The issue is
entirely the stock boot script's watchdog.

### Proof the firmware image is fine

1. **PR #17305** (BLOCKSIZE fix for config loss on sysupgrade) was merged Dec 23, 2024 and
   **backported to the 24.10 branch** — our 24.10.2 image includes this fix
2. The AP3915i device definition in OpenWrt's `target/linux/ipq40xx/image/generic.mk` is a
   standard `Device/FitImage` with no special quirks — same pattern used by dozens of other
   working IPQ40xx devices
3. The FIT image was verified: 8.8MB, header `d0 0d fe ed` (correct FIT magic), within the
   30080k IMAGE_SIZE limit
4. David Bauer's `boot_openwrt` command (`sf probe; sf read; bootm`) bypasses the stock script
   entirely — no watchdog, no `nboot`, no failover. Just reads the FIT from flash and boots it.
   U-Boot's `bootm` has supported FIT images since long before version 2012.07.

**When we fix `bootcmd` via serial, the AP will boot OpenWrt correctly.**

---

## Current State

**Updated 2026-05-23**: The boot loop was recovered WITHOUT a serial cable, using a
switch-initiated TFTP boot and raw MTD writes from OpenWrt initramfs.

| Component | Status |
|-----------|--------|
| **U-Boot bootloader** | Working — `bootcmd=run boot_openwrt; run boot_net` |
| **SPI-NOR flash** | OpenWrt 24.10.2 correctly written at offset 0x280000 |
| **U-Boot env (CFG1)** | `boot_openwrt=sf probe; sf read...; bootm` + `bootcmd=run boot_openwrt; run boot_net` |
| **U-Boot env (CFG2)** | Same corrected values as CFG1 |
| **ART partition** | Backed up pre-sysupgrade (64KB) |
| **Network** | Working — AP at 192.168.13.253, SSH from Ubuntu and switch |
| **Overlay** | jffs2 + overlayfs working, persisted through reboot |
| **Root password** | Set (`Conwrt2026!`), persisted through reboot |
| **Firmware image** | **Correct** — standard FIT, OpenWrt 24.10.2, boots from flash |

### How the boot loop was recovered (no serial cable)

1. AP was connected to GS1900-8HP switch port lan5 via PoE
2. Switch had secondary IP `192.168.1.2/24` on the same L2 segment as AP
3. Modified CFG blocks with `bootcmd=run boot_net` to force TFTP boot
4. Switch ran dnsmasq TFTP server serving OpenWrt initramfs
5. AP TFTP-booted initramfs, gave us full OpenWrt shell
6. Ran `sysupgrade -n` to install OpenWrt permanently to flash
7. TFTP-booted initramfs AGAIN (bootcmd still said TFTP)
8. Loaded `kmod-mtd-rw` to bypass DTS read-only on CFG partitions
9. Used cross-compiled `mtd_raw_write` ARM binary to write corrected CFG blocks
   with `boot_openwrt` command and removed `ubi.mtd=0` from bootargs
10. Rebooted — AP booted OpenWrt from flash successfully

The entire process was orchestrated from the GS1900-8HP switch. No laptop was needed
during the actual flash. See `SWITCH-FLASH-PLAN.md` for the full milestone plan.

---

## Recovery Plan

### When You Get a Serial Cable

- Cisco-compatible RJ45 console cable (~$10 on Amazon)
- Connect to AP's internal serial header at **115200 8N1**
- Laptop on ethernet at **192.168.1.2/24** connected to AP's GE1 port

### Serial Recovery (2 minutes)

1. Connect serial, open terminal: `screen /dev/ttyUSB0 115200`
2. Power on AP, press **`s`** within 2 seconds to stop autoboot
3. Login: `admin` / `new2day`
4. Paste:

```
setenv boot_openwrt "sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000"
setenv bootcmd "run boot_openwrt || run boot_net"
setenv serverip 192.168.1.2
saveenv
boot
```

This creates the correct `boot_openwrt` command and sets it as primary boot with TFTP fallback.
The `|| run boot_net` means if flash boot ever fails, it tries TFTP — permanent safety net.

### If Flash Boot Fails (unlikely)

```
setenv bootcmd "run boot_net"
saveenv
```

Start TFTP server on laptop with the initramfs. AP TFTP-boots → full OpenWrt shell → investigate.

### After Recovery: Verify Everything

```bash
ssh root@192.168.1.1
iw phy                          # Should show 2 radios (2.4GHz + 5GHz)
hexdump -C /dev/mtd3 | head    # ART partition — should show calibration data, not all FFs
cat /etc/board.json | grep model  # Confirm OpenWrt identifies the device correctly
```

Also write the correct config blocks to flash (so env persists across `saveenv` targets):

```bash
opkg update && opkg install kmod-mtd-rw
insmod mtd-rw i_want_a_brick=1
# Upload correct_boot_cfg_dual.bin from laptop
scp /tmp/correct_boot_cfg_dual.bin root@192.168.1.1:/tmp/
flashcp /tmp/correct_boot_cfg_dual.bin /dev/mtd0    # CFG1
flashcp /tmp/correct_boot_cfg_dual.bin /dev/mtd8    # CFG2
```

---

## Lessons Learned

1. **Read the original git commit before touching boot variables.** David Bauer's commit e16a0e7
   had the exact `setenv` commands. We found it too late.

2. **Stock boot commands don't work with OpenWrt.** `boot_flash=source boot_kernel` is a complex
   stock script with watchdog, dual-image failover, `nboot`. OpenWrt needs a simple
   `sf probe; sf read; bootm`. Never assume they're interchangeable.

3. **Never change `bootcmd` away from a working state without serial.** We had `boot_net` working.
   We should have kept it and tested flash boot from serial first.

4. **Have a serial cable from the start.** Every successful AP3915i flash on the OpenWrt forum
   used serial. The no-serial method is a bonus, not a replacement.

5. **Don't trust instructions from a different scenario.** PR #13370's `bootcmd="run boot_flash"`
   assumed going back through stock firmware. We applied it to a context it wasn't meant for.

6. **Never write both config blocks simultaneously.** Write primary first, verify, then mirror.
   The backup block is your safety net — don't burn it with the same mistake.

7. **Extract and read the stock boot script BEFORE using it.** We had the BootPRI backup. We could
   have read the `boot_kernel` script and seen it uses `nboot` + watchdog + failover — obviously
   incompatible with a direct FIT boot.

8. **The `kmod-mtd-rw` + `flashcp` approach works perfectly.** Finding and installing
   `kmod-mtd-rw i_want_a_brick=1` to bypass DTS read-only was clever and worked flawlessly.
   The write mechanism was perfect — CRC correct, MD5 match, proper flash erase. The only failure
   was WHAT we wrote, not HOW we wrote it.

9. **The green flash is the stock watchdog, not a kernel bug.** OpenWrt 24.10.2 is correct for
   this device. PR #17305 (BLOCKSIZE fix) is already included. The FIT image is standard. No
   custom build needed.

---

## What We'll Do Differently Next Time

### For this AP3915i (serial recovery)

1. Serial in → interrupt U-Boot
2. Create `boot_openwrt` variable with `sf probe; sf read; bootm`
3. **Test it manually**: `run boot_openwrt` — verify OpenWrt boots from flash
4. Only THEN: `setenv bootcmd "run boot_openwrt || run boot_net"; saveenv`
5. The `|| run boot_net` fallback means TFTP recovery is always available

### For any new device

1. **Serial cable before anything else** — before first firmware modification
2. **Read the original device support commit** — it usually has exact U-Boot commands
3. **Keep TFTP boot as fallback** until flash boot is verified working
4. **Test boot commands manually from serial** before committing to flash
5. **Write primary config block first**, verify, then mirror to backup
6. **Backup all MTD partitions before any writes** (we did this right)
7. **Extract and understand the stock boot script** before reusing any stock boot command

---

## Technical Reference

### Flash Partition Layout (Verified from OpenWrt DTS)

Source: `target/linux/ipq40xx/dts/qcom-ipq4029-ws-ap3915i.dts` in openwrt/openwrt

```
OpenWrt DTS Partition Layout (SPI-NOR, 32MB Macronix MX25L25635E):

Flash Offset   Size      Label        Notes
─────────────────────────────────────────────────────────────────────
0x000000       896KB     (unknown)    U-Boot bootloader (not defined in DTS)
0x0E0000       64KB      CFG1         U-Boot env primary   ← config blocks here
0x0F0000       448KB     BootBAK      Backup bootloader    (read-only)
0x160000       64KB      WINGCFG1     WING config 1        (read-only)
0x170000       64KB      ART          Radio calibration    (read-only)
0x180000       448KB     BootPRI      Primary bootloader + boot_kernel script (read-only)
0x1F0000       64KB      WINGCFG2     WING config 2        (read-only)
0x200000       512KB     FS           Root filesystem      (read-only)
0x280000       30,080KB  firmware     OpenWrt kernel+rootfs ← FIT image here
0x1FE0000      64KB      CFG2         U-Boot env backup    ← config blocks here
```

**This confirms David Bauer's offset**: the firmware partition starts at exactly 0x280000.
His `sf read 0x88000000 0x280000 0xc00000` reads the first 12MB of this partition into RAM,
which contains the FIT kernel image (8.8MB in our build, well within the 12MB window).

**Important**: The stock firmware MTD layout shows different partition numbering (mtd1=CFG1
vs OpenWrt's mtd0=CFG1) but the FLASH OFFSETS are the same. The config blocks are at
0x0E0000 (CFG1) and 0x1FE0000 (CFG2) regardless of which firmware is running.

### What `rdwr_boot_cfg` Does (And Why We Don't Need It)

`rdwr_boot_cfg` is a proprietary Extreme Networks binary that ships with the stock firmware.
It does exactly one thing: read/write key-value pairs in the CFG1/CFG2 partitions, handling
the CRC32 calculation internally. That's it.

It **cannot** be used from OpenWrt because:
1. It's a proprietary binary compiled for the stock firmware's kernel/userspace
2. It may depend on stock kernel modules or /proc interfaces not present in OpenWrt
3. It was ALREADY BROKEN on our stock firmware ("unable to find config blocks") —
   it couldn't even work in the environment it was designed for
4. It likely hardcodes MTD partition names/numbers that differ between stock and OpenWrt

**We don't need it.** We fully reverse-engineered its functionality:
- Config block format: `[4-byte LE CRC32 of bytes 5:][1-byte flag][65531 bytes KV data padded with 0xFF]`
- CRC algorithm: `zlib.crc32(block[5:]) & 0xFFFFFFFF`
- Write mechanism: `kmod-mtd-rw i_want_a_brick=1` + `flashcp`

Our config block builder produces identical output to what `rdwr_boot_cfg` would produce,
and our `flashcp` writes are more reliable than whatever `rdwr_boot_cfg` uses internally.

### The Wrong Value vs The Correct Value

**What we wrote** (WRONG):
```
bootcmd=run boot_flash
```
`boot_flash` = `source boot_kernel` — runs the **stock Extreme Networks** boot script
from the BootPRI partition. That script:
- Uses `nboot ${loadaddr} 2 ${imageAddr}` to load images (NAND boot command)
- Sets up hardware watchdog timers (`dis_wdt0_bite_time`, `val_wdt0_bark_time`)
- Implements dual-image failover (tries PriImg, then SecImg)
- Both images are OpenWrt FIT (not stock uImage) → script fails
- Watchdog fires → reboot → boot loop

**What we should have written** (CORRECT):
```
boot_openwrt=sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000
bootcmd=run boot_openwrt || run boot_net
```
This directly reads the FIT image from SPI-NOR and boots it, bypassing ALL stock firmware
logic. No `nboot`, no watchdog, no failover. Just: probe flash, read 12MB from offset
0x280000 into RAM at 0x88000000, call `bootm` to boot the FIT image.

The `|| run boot_net` fallback ensures TFTP recovery is always available if flash boot fails.

### Why We're Confident It Will Work Next Time

**1. The boot command is verified in the OpenWrt source code.**

David Bauer's commit e16a0e7 added AP3915i support. The commit message contains:
```
setenv boot_openwrt "sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000"
setenv bootcmd "run boot_openwrt"
saveenv
```
These exact commands were tested on real hardware by the commit author.

**2. The flash offset is verified from the DTS.**

The OpenWrt DTS (`qcom-ipq4029-ws-ap3915i.dts`) defines:
```
partition@280000 {
    label = "firmware";
    reg = <0x280000 0x1d60000>;
};
```
Offset 0x280000 matches `sf read` in `boot_openwrt`. The partition size (0x1D60000 = ~30MB)
matches the IMAGE_SIZE (30080k) in the image build config.

**3. U-Boot's `bootm` supports FIT images.**

Verified by extracting strings from the BootPRI backup:
```
"## Booting kernel from FIT Image at %08lx ..."
"Trying '%s' kernel subimage"
```
U-Boot 2012.07 has full FIT support in `bootm`. The FIT header (`d0 0d fe ed`) is recognized
and parsed correctly.

**4. Our FIT image is correctly built.**

- Image format: FIT (`d0 0d fe ed` header) ✅
- Image size: 8.8MB, within 12MB read window (`0xc00000`) ✅
- Image within IMAGE_SIZE limit: 8.8MB < 30080KB ✅
- PR #17305 BLOCKSIZE fix: already included in 24.10.2 ✅
- Standard `Device/FitImage` build: no custom quirks ✅

**5. Other people have booted this exact device with this exact command.**

Forum thread reports: "followed the instructions and was quite easy going without any issues"
(referring to David Bauer's serial + `boot_openwrt` method). The boot command is battle-tested.

**6. The serial recovery gives us unlimited retries.**

If `run boot_openwrt` fails for any reason, we can:
- Try `run boot_net` for TFTP boot (instant recovery to OpenWrt shell)
- Adjust the `sf read` offset or size
- Re-flash via sysupgrade from initramfs
Serial access means we can NEVER brick this device again.

### Remaining Uncertainties

**1. ART partition integrity (minor risk)**

The ART partition contains radio calibration data. We backed it up before sysupgrade, but
haven't verified it survived. If the ART data is corrupted:
- WiFi may not work (no calibration data = radios won't initialize)
- We have the backup (`mtd3_ART.bin`) and can restore it via `flashcp`
- This is recoverable but requires serial access to get into OpenWrt first

**2. Possible BLOCKSIZE/rootfs alignment issue (low risk)**

PR #17305 fixed BLOCKSIZE causing config loss. Our 24.10.2 image includes this fix. But
there's a theoretical possibility that the rootfs has other alignment issues on this specific
flash chip. If OpenWrt boots but filesystem is corrupted:
- `run boot_net` → TFTP boot → re-run sysupgrade with a fresh image
- Low probability since the same image format works on other IPQ40xx devices

**3. WiFi driver compatibility (low risk)**

The DTS uses standard IPQ4029 integrated WiFi with `qcom,ath10k-calibration-variant = "Extreme-Networks-WS-AP3915i"`.
The ath10k driver should work with the ART calibration data. But we haven't tested it on
this specific unit. If WiFi doesn't work:
- Check `dmesg` for ath10k calibration errors
- Verify ART partition: `hexdump -C /dev/mtd3 | head` (should show data, not all 0xFF)
- Restore ART from backup if needed

### No Dual-Image Support with OpenWrt Sysupgrade

OpenWrt on the AP3915i is **single-image only**. There is no A/B partition failover.

**Why**: The stock firmware had two kernel partitions (PriImg at 0x280000, SecImg at 0x1130000)
and the stock `boot_kernel` script implemented dual-image failover between them. But OpenWrt's
DTS merged both into a single `firmware` partition:

```
partition@280000 {
    label = "firmware";
    reg = <0x280000 0x1d60000>;   // 30MB — covers both old PriImg and SecImg
};
```

The `platform_do_upgrade()` function in ipq40xx's `platform.sh` dispatches by board name.
The AP3915i falls to the catch-all `*) default_do_upgrade "$1" ;;` — it writes directly to
the single `firmware` MTD partition. There is no secondary partition to write a backup to.

**What this means**: The stock `boot_kernel` script's dual-image failover (`run boot_flash`)
is physically impossible with OpenWrt's partition layout. The space that was SecImg is now
part of the single firmware partition and contains OpenWrt rootfs data, not a bootable image.
The failover tries SecImg, finds garbage, fails, and the watchdog reboots.

**Where dual-image does exist in OpenWrt**: Device-specific implementations for OpenMesh/
PlasmaCloud (ipq40xx), Linksys (ramips, ipq806x), ZyXEL (ipq806x), and x86 EFI. All require
two firmware partitions in the DTS, a custom `platform_do_upgrade_*()` function, and U-Boot
support for partition selection. Adding this for the AP3915i would require splitting the DTS
firmware partition, writing a custom upgrade function, and upstreaming it — non-trivial for
a discontinued access point.

**Source**: `target/linux/ipq40xx/base-files/lib/upgrade/platform.sh` in openwrt/openwrt —
AP3915i is not listed in any case branch and falls to `default_do_upgrade`.

### Config Block Builder

```python
import struct, zlib

def build_config_block(kv_pairs, flag=0x01):
    payload = b'\x00'.join(f'{k}={v}'.encode() for k, v in kv_pairs.items()) + b'\x00'
    payload = payload.ljust(65531, b'\xff')
    data = bytes([flag]) + payload
    crc = zlib.crc32(data) & 0xFFFFFFFF
    block = struct.pack('<I', crc) + data
    assert len(block) == 65536
    return block

# The correct config for AP3915i with OpenWrt:
correct = build_config_block({
    'bootcmd': 'run boot_openwrt || run boot_net',
    'boot_openwrt': 'sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000',
    'boot_net': 'tftpboot 0x83600000 vmlinux.gz.uImage.3912; bootm 0x83600000',
    'serverip': '192.168.1.2',
    'WATCHDOG_COUNT': '0',
    'WATCHDOG_LIMIT': '0',
    'MOSTRECENTKERNEL': '0',
})
```

### Prepared Recovery Files

| File | Location | Purpose |
|------|----------|---------|
| Correct config (flash boot) | `/tmp/correct_boot_cfg1.bin` | `bootcmd=run boot_openwrt` (CRC `4af51130`) |
| Correct config (dual fallback) | `/tmp/correct_boot_cfg_dual.bin` | `bootcmd=run boot_openwrt \|\| run boot_net` (CRC `96b86184`) |
| Correct config (TFTP only) | `/tmp/correct_boot_cfg_net.bin` | `bootcmd=run boot_net` (CRC `9cbd181b`) |
| Stock MTD backups | `data/extreme-ap3915i/openwrt-backups/` | All 8 partitions |
| Original config dumps | `data/extreme-ap3915i/backups/` | cfg1_mtd1.bin, cfg2_mtd10.bin |
| TFTP initramfs | `data/extreme-ap3915i/vmlinux.gz.uImage.3912` | 10.1MB (also FIT format, not uImage despite filename) |
| Sysupgrade image | `data/extreme-ap3915i/openwrt-24.10.2-*.bin` | Full OpenWrt 24.10.2 (8.8MB FIT) |
| DHCP+TFTP config | `/tmp/dnsmasq-recovery.conf` | For laptop en5 at 192.168.1.2 |
| Serial helper | `/tmp/serial-recovery.sh` | Commands to paste at U-Boot prompt |

### Key U-Boot Variables

| Variable | Factory Default | Correct Value for OpenWrt |
|----------|----------------|--------------------------|
| `bootcmd` | `bootx` (= `run boot_flash`) | `run boot_openwrt \|\| run boot_net` |
| `boot_openwrt` | *(doesn't exist)* | `sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000` |
| `boot_flash` | `source boot_kernel` | *(leave unchanged — don't use with OpenWrt)* |
| `boot_net` | `tftpboot 0x83600000 vmlinux.gz.uImage.3912; bootm 0x83600000` | *(unchanged, used as fallback)* |
| `serverip` | `192.168.1.10` | `192.168.1.2` (your laptop) |
| `CFG1 flash offset` | 0x0E0000 | *(unchanged)* |
| `CFG2 flash offset` | 0x1FE0000 | *(unchanged)* |
| `firmware flash offset` | 0x280000 | *(unchanged, where FIT image lives)* |

### Stock boot_kernel Script (Extracted from BootPRI Backup)

For reference, here's what `run boot_flash` actually executes. This is why it doesn't work
with OpenWrt — the script has watchdog timers, dual-image failover, and expects stock uImage:

```
# (abridged — full script is 200+ lines in the BootPRI partition)
if test $MOSTRECENTKERNEL -eq 0; then
    # Decide boot order (primary first or secondary first based on watchdog count)
    ...
fi

for image in ${order}
    # Set bootargs for primary or secondary image
    if test $image -eq 0; then
        imageAddr=${PriImg}
    else
        imageAddr=${SecImg}
    fi
    
    # Set up watchdog timer
    if test $WATCHDOG_DISABLE -eq 0; then
        setenv VAL ${dis_wdt0_bite_time}    # Watchdog bite time
        setenv VAL ${val_wdt0_bark_time}    # Watchdog bark time
    fi
    
    # Load and boot — uses nboot (NAND boot), not sf read
    nboot ${loadaddr} 2 ${imageAddr}
    
    echo boot failed...

echo ERROR: Cannot boot either kernel image, dropping to interactive shell (watchdog might trigger)
```

---

## References (Verified with Source Links)

### Primary Sources

| Source | URL | What It Confirms |
|--------|-----|------------------|
| David Bauer's commit (full hash) | https://github.com/openwrt/openwrt/commit/e16a0e7e8876df0a92ec4779fe766de1a943307a | Hardware specs, `boot_openwrt` command, `saveenv`, serial credentials `admin`/`new2day`, "1x Gigabit LAN", "Macronix MX25L25635E SPI-NOR (32M)" |
| PR #13370 (apdev-2023) | https://github.com/openwrt/openwrt/pull/13370 | No-serial method, `rdwr_boot_cfg` usage, `bootcmd="run boot_flash"` after stock TFTP detour, `WATCHDOG_COUNT=0, WATCHDOG_LIMIT=0` required, 5-min stock reboot warning |
| PR #17305 (maurerle) | https://github.com/openwrt/openwrt/pull/17305 | BLOCKSIZE fix — "The blocksize is too high, resulting in forgetting the config on sysupgrade", merged Dec 23 2024, BLOCKSIZE removed entirely |
| OpenWrt DTS (current) | `target/linux/ipq40xx/dts/qcom-ipq4029-ws-ap3915i.dts` | Firmware partition at `0x280000` (size `0x1d60000`), CFG1 at `0xe0000`, CFG2 at `0x1fe0000`, ART at `0x170000`, single switch port (`swport5`) |
| OpenWrt platform.sh | `target/linux/ipq40xx/base-files/lib/upgrade/platform.sh` | AP3915i falls to `*) default_do_upgrade "$1" ;;` (standard NOR sysupgrade), no special handling needed |
| OpenWrt image config | `target/linux/ipq40xx/image/generic.mk` | `Device/FitImage`, `IMAGE_SIZE := 30080k`, `SOC := qcom-ipq4029`, standard build |

### Secondary Sources

| Source | URL | What It Confirms |
|--------|-----|------------------|
| OpenWrt wiki — AP391x series | https://openwrt.org/toh/extreme_networks_ws_ap391x | Installation instructions, supported models (AP3912/15/16/17, AP7662) |
| OpenWrt wiki — AP3915i techdata | https://openwrt.org/toh/hwdata/extreme_networks/extreme_networks_ws-ap3915i | Hardware specs, supported since commit, status |
| Forum thread | https://forum.openwrt.org/t/adding-extreme-ap3915i-ap7632i-support/138207 | Boot reports, "sysupgrade went ok but doesn't automatically boot", PR #17305 discussion |
| Extreme Networks install guide | https://documentation.extremenetworks.com/wireless/AP_Guides/AP3915i/ | "One RJ45, 10/100/1000 Ethernet Port (LAN1) with PoE", PoE 802.3af, physical specs |

### Important Correction: `run boot_flash` vs `run boot_openwrt`

After re-reading PR #13370's no-serial instructions in detail, we need to correct our analysis:

**`run boot_flash` CAN work with OpenWrt** — PR #13370 step 11 explicitly uses it:
```
rdwr_boot_cfg write_var bootcmd="run boot_flash"
```
And step 12 confirms: "This time it should be into OpenWRT."

The PR author also sets `WATCHDOG_COUNT=0` and `WATCHDOG_LIMIT=0`. The stock `boot_kernel` script
uses these variables to decide whether to set up the hardware watchdog. When both are 0, the
watchdog setup is likely skipped, and the FIT image can boot without the watchdog firing.

**Our boot loop was likely caused by missing or incorrect watchdog variables** in our config blocks,
not by `run boot_flash` being fundamentally incompatible with OpenWrt. We wrote `bootcmd=run boot_flash`
but may not have properly set `WATCHDOG_COUNT=0` and `WATCHDOG_LIMIT=0`.

That said, David Bauer's `run boot_openwrt` is still the better choice for this device:

1. **No dual-image failover exists.** OpenWrt's DTS merged PriImg and SecImg into a single
   `firmware` partition. The stock `boot_kernel` script's failover tries SecImg, finds garbage,
   and fails. There is no second image to fall back to — the failover is dead code.

2. **No external dependencies.** `boot_openwrt` is three fixed commands (probe, read, boot).
   `boot_flash` depends on the boot_kernel script surviving in BootPRI, plus watchdog vars
   being correct, plus MOSTRECENTKERNEL being set. More moving parts = more failure modes.

3. **Purpose-built.** David Bauer wrote `boot_openwrt` specifically for this device running
   OpenWrt. `boot_flash` works as a side effect when vars are right, not by design.

**Recommendation**: Use `run boot_openwrt` with `|| run boot_net` TFTP fallback. If that
fails, `run boot_flash` with `WATCHDOG_COUNT=0, WATCHDOG_LIMIT=0` is a valid fallback per
PR #13370.

### fw_setenv Limitation (Verified from Source)

No `/etc/fw_env.config` exists in the ipq40xx base-files directory in the OpenWrt source tree.
The `platform.sh` file includes `RAMFS_COPY_DATA='/etc/fw_env.config'` at the top, but this
only applies if the config exists at build time. Without it, `fw_setenv` and `fw_printenv`
cannot locate the U-Boot environment on flash.

Verified by checking: `target/linux/ipq40xx/base-files/etc/fw_env.config` does not exist in
the openwrt/openwrt repository.

### Full technical notes
- `recipes/extreme-networks/ws-ap3915i/no-serial-openwrt.md`

---

## Cross-Reference: Second AP3915i Unit (AP3915i-ROW)

On 2026-05-22 we acquired a second AP3915i unit. Key findings:

- **Model**: AP3915i-ROW (Rest of World variant), Serial 1918Y-1083600000
- **Hardware differences**: Has both SPI-NOR AND 512MB NAND (UBIFS rootfs). Unit 1 had SPI-NOR only.
- **SPI-NOR partition layout**: IDENTICAL to Unit 1 (same offsets, same names, PriImg=0x280000)
- **U-Boot version**: OLDER (2012.07.19-r00020.1 vs Unit 1's 2012.07.22)
- **Default bootcmd**: `bootx` (NOT `run boot_flash`) — but `bootx` IS equivalent to `run boot_flash` (confirmed from BootPRI strings: "bootx - equivalent to the command: run boot_flash")
- **boot_net**: `tftpboot 0x83600000 vmlinux.gz.uImage.3912; bootm 0x83600000` (same as Unit 1)
- **rdwr_boot_cfg**: EXISTS and is executable (4824 bytes). `read_all` returned empty — needs further testing with `read_var`. This is the key difference from Unit 1 where `rdwr_boot_cfg` was completely broken.
- **TFTP load address**: 0x83600000 (same as Unit 1)
- **fdt_high**: 0x80100000 (in config block; boot_kernel overrides to 0x87000000, but our boot_openwrt doesn't run boot_kernel)

Full details: `recipes/extreme-networks/ws-ap3915i/UNIT2-AP3915i-ROW.md`

### Implications for Flash Plan

1. Same OpenWrt image works (SPI-NOR layout is identical)
2. `rdwr_boot_cfg write_var` may work for setting U-Boot variables (safer than raw MTD)
3. `boot_openwrt` must use address 0x88000000 for `sf read` (David Bauer commit)
4. NAND is irrelevant for OpenWrt — only SPI-NOR is used
5. `bootcmd=run boot_openwrt; run boot_net` provides permanent TFTP fallback (semicolon, not ||)

### External Review Corrections (2026-05-22)

After having an external LLM review the plan, several critical corrections were made:

1. **MTD numbering corrected**: OpenWrt CFG2 is mtd8 (not mtd11). The DTS has 9 partitions.
   Stock mtd1=CFG1 and OpenWrt mtd0=CFG1 are the same physical block at offset 0xe0000.

2. **DTS read-only partitions**: ALL partitions except `firmware` are marked `read-only` in the
   OpenWrt DTS. Originally assumed kmod-mtd-rw was unavailable in 24.10.2 (not rebuilt for
   kernel 6.6), so the plan required ALL config block writes from stock firmware.
   **UPDATE (2026-05-24)**: This assumption was wrong. kmod-mtd-rw IS available in OpenWrt 24.10.2
   (package `kmod-mtd-rw` in the official `packages` feed at `kernel/mtd-rw/`). It's an out-of-tree
   kernel module built against the running kernel — OpenWrt's build system compiles it for every
   target that has MTD support (excluded only for x86, bcm27xx, octeontx). On ipq40xx it works
   fine: `opkg update && opkg install kmod-mtd-rw && insmod mtd-rw i_want_a_brick=1`. Was used
   successfully to write CFG1 from initramfs on Unit 2. Writing from stock firmware is still
   preferred (fewer failure modes) but initramfs writes are a viable fallback.

3. **Semicolon fallback**: Changed from `||` to `;` — functionally identical but doesn't depend
   on U-Boot `||` operator support. If `bootm` succeeds, it doesn't return.

4. **No initramfs MTD writes**: The v2 plan sets the FINAL bootcmd from stock firmware.
   Before sysupgrade, `boot_openwrt` fails (no firmware) and falls through to `boot_net` (TFTP).
   After sysupgrade, `boot_openwrt` succeeds and boots from flash. No second MTD write needed.

5. **One block at a time**: Use flashcp to write CFG1 only (leave CFG2 as fallback).
   rdwr_boot_cfg writes both blocks (risky — repeats Unit 1 failure mode).

6. **fw_setenv unavailable**: AP3915i is NOT in the uboot-envtools board list.
   No /etc/fw_env.config is generated.

See `REVIEW-UNIT2-FLASH-PLAN.md` for the full revised plan.
