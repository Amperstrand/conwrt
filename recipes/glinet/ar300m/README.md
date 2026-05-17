# GL.iNet AR-300M Family — conwrt Recipe

> Updated with hands-on testing results (2026-05-17).

## NAND vs NOR Recommendation

Dual-flash AR-300M units have two flash chips. Pick the right one.

| | NAND | NOR |
|---|---|---|
| Size | 128MB | 16MB |
| Overlay | ~113MB (UBIFS) | ~8.9MB (JFFS2) |
| Speed | Faster | Slower |
| Use case | Primary OS | Automatic failsafe recovery only |
| Switch position | LEFT (toward USB) | RIGHT (away from USB) — designed for NOR but may not work (see below) |
| Recommended? | **Yes** | No. Recovery fallback only. |

**Bottom line**: Stick with NAND (switch LEFT). NOR is an automatic failsafe. After 3 failed NAND boots, U-Boot falls back to NOR. You do not need to do anything special for this to happen.

If you want to manually boot NOR for recovery, use the bootcount method. The physical switch is designed to select NAND vs NOR boot but may not work on all U-Boot versions (see below).

## Hardware

| Spec | Value |
|---|---|
| SoC | QCA9531 @ 650MHz |
| RAM | 128MB DDR2 |
| Flash | 16MB NOR + optional 128MB NAND (variant-dependent) |
| WiFi | 2.4GHz 802.11b/g/n, 300Mbps (+ 5GHz on AR300MD) |
| USB | 1x USB 2.0 |
| Power | Micro USB 5V/2A |

## U-Boot Version

| Property | Value |
|---|---|
| Version | `uboot-gl-ar300m-20220216` (2022-02-16) |
| Base | pepe2k/u-boot_mod fork |
| Source | https://github.com/gl-inet/uboot-for-qca95xx |
| SHA256 | `1c092a1bed08954861cf4d3cfa0ca168cab1f766acdaf412673ec9dc4548cc39` |
| HTTP server | uIP/0.9 |

Upgrading U-Boot is the only dangerous operation on this device. Power loss during mtd0 write causes a brick, recoverable only via UART serial. Do not upgrade U-Boot unless you have a specific reason and a serial cable ready.

## Variant Matrix

| Variant | NAND | Ethernet Ports | Antenna | 5GHz | OpenWrt Device |
|---|---|---|---|---|---|
| AR300M | 128MB | WAN + LAN | Internal PCB | No | glinet,gl-ar300m-nand |
| AR300M-Ext | 128MB | WAN + LAN | External RP-SMA | No | glinet,gl-ar300m-nand |
| AR300M16 | None | WAN + LAN | Internal | No | glinet,gl-ar300m-lite |
| AR300M16-Ext | None | WAN + LAN | External RP-SMA | No | glinet,gl-ar300m-lite |
| AR300M-Lite | None | WAN only | Internal | No | glinet,gl-ar300m-lite |
| AR300MD | 128MB | WAN + LAN | Internal | Yes (QCA9887) | glinet,gl-ar300m-nand |

## Physical Identification

All AR-300M variants share FCC ID **2AFIW-AR300M**. You cannot tell them apart by looking at the FCC label.

### What to check

| Check | What to look for | Tells you |
|---|---|---|
| Bottom label | Printed model name: GL-AR300M, GL-AR300M16, or GL-AR300M-Lite | Rough variant group |
| Ethernet jack count | 1 port = Lite, 2 ports = others | Lite vs non-Lite |
| External antenna connectors | RP-SMA jacks on sides | -Ext variant |
| 5GHz module | QCA9887 chip visible inside | AR300MD |

### What you cannot determine physically

- Whether NAND is present (AR300M vs AR300M16)
- Exact OpenWrt target without booting or SSH

## Network Identification

| Property | Value |
|---|---|
| MAC OUI | `94:83:C4` (common GL.iNet) or `E4:95:6E` (observed on tested hardware) |
| Default IP (stock) | 192.168.8.1 |
| Default IP (OpenWrt) | 192.168.1.1 |
| Default SSID | GL-AR300M-XXXX |
| Default WiFi password | `goodlife` |
| Open ports (stock) | 22 (SSH), 80 (HTTP), 83 (GL.iNet remote admin) |

MAC OUI and SSID are identical across all six variants. Network-only identification cannot distinguish AR300M from AR300M16 from AR300M-Lite. SSH access is required for exact identification.

## SSH Variant Identification

SSH into the device on 192.168.8.1 (stock) or 192.168.1.1 (OpenWrt), then run these checks in order.

### 1. Flash layout (most definitive)

```bash
cat /proc/mtd
```

| Output | Meaning |
|---|---|
| 6 partitions (mtd0 through mtd5, includes "kernel" and "ubi") | Dual-flash: AR300M, AR300M-Ext, or AR300MD |
| 4 partitions (mtd0 through mtd3, only "firmware") | NOR-only: AR300M16, AR300M16-Ext, or AR300M-Lite |

### 2. Port count

```bash
ls /sys/class/net/ | grep eth
```

| Output | Meaning |
|---|---|
| `eth0` only | AR300M-Lite (single WAN port) |
| `eth0` and `eth1` | All other variants |

### 3. 5GHz module check

```bash
dmesg | grep -i "ath10k\|9887\|5g"
```

| Output | Meaning |
|---|---|
| Matches found | AR300MD (has QCA9887 5GHz radio) |
| No matches | All other variants |

### 4. OpenWrt board name (final confirmation)

```bash
cat /tmp/sysinfo/board_name
```

| Board Name | Variant |
|---|---|
| `glinet,gl-ar300m-lite` | AR300M-Lite or AR300M16 (same image) |
| `glinet,gl-ar300m-nor` | AR300M booted from NOR partition |
| `glinet,gl-ar300m-nand` | AR300M or AR300MD booted from NAND |

### Decision flow

```
cat /proc/mtd
+-- 4 partitions -> NOR-only
|   +-- ls eth ports
|       +-- eth0 only -> AR300M-Lite
|       +-- eth0+eth1 -> AR300M16 or AR300M16-Ext (check for external antenna)
+-- 6 partitions -> Dual-flash
    +-- dmesg | grep ath10k
        +-- Found -> AR300MD
        +-- Not found -> AR300M or AR300M-Ext (check for external antenna)
```

## OpenWrt Targets

| Variant | Target | Device Name | Firmware Filename |
|---|---|---|---|
| AR300M-Lite | ath79/generic | glinet,gl-ar300m-lite | `openwrt-{ver}-ath79-generic-glinet_gl-ar300m-lite-squashfs-sysupgrade.bin` |
| AR300M16 | ath79/generic | glinet,gl-ar300m-lite | Same as AR300M-Lite |
| AR300M16-Ext | ath79/generic | glinet,gl-ar300m-lite | Same as AR300M-Lite |
| AR300M (NAND) | ath79/nand | glinet,gl-ar300m-nand | `openwrt-{ver}-ath79-nand-glinet_gl-ar300m-nand-squashfs-sysupgrade.bin` |
| AR300M (NOR) | ath79/nand | glinet,gl-ar300m-nor | `openwrt-{ver}-ath79-nand-glinet_gl-ar300m-nor-squashfs-sysupgrade.bin` |
| AR300MD (NAND) | ath79/nand | glinet,gl-ar300m-nand | Same as AR300M NAND |

NOR-only models (AR300M16, AR300M16-Ext, AR300M-Lite) all use the same firmware image. Dual-flash models have separate NAND and NOR images.

## Boot States

| State | IP | Detection Method | What You See |
|---|---|---|---|
| U-Boot safe mode | 192.168.1.1 (static, no DHCP) | `curl -sI` returns `Server: uIP/0.9` | Left green LED only, upload page at http://192.168.1.1 |
| GL.iNet stock | 192.168.8.1 (DHCP) | GL.iNet web UI responds, port 83 open | Normal boot LEDs |
| OpenWrt | 192.168.1.1 (DHCP) | LuCI page or `openwrt` in response body | Normal OpenWrt boot sequence |
| OpenWrt failsafe | 192.192.192.1 | Serial console required | Power LED blinks rapidly |

Quick detection:

```bash
# Check for U-Boot
HEADER=$(curl -sI --max-time 3 http://192.168.1.1/ 2>/dev/null)
echo "$HEADER" | grep -q "uIP/0.9" && echo "U-BOOT SAFE MODE"

# Check for stock firmware
curl -s --max-time 3 http://192.168.8.1/ | grep -q "GL.iNet" && echo "STOCK FIRMWARE"
```

## Button Operations

| Operation | Button | Timing | LED Pattern | Result |
|---|---|---|---|---|
| U-Boot safe mode | Reset | Hold reset, apply power, release on **6th blink** (after 5 red blinks) | Red blinks then left green LED only | HTTP upload server at 192.168.1.1 |
| OpenWrt failsafe | `f` key | Press during boot on serial console | Power LED blinks rapidly | Failsafe shell at 192.192.192.1 |
| Factory reset | Reset | Hold 10+ seconds while powered on | LEDs flash | Returns to GL.iNet stock defaults |
| NAND/NOR toggle | Side switch | Flip while powered off | N/A | Left = NAND (nboot), Right = NOR (bootm). Requires boot_dev=on. See below for status |

### Side Toggle Switch (Dual-Flash Models Only)

The physical toggle switch on the side of dual-flash units is designed to select the boot device. It requires `fw_setenv boot_dev on` to activate.

| Switch Position | GPIO Value | U-Boot Action |
|---|---|---|
| Left (toward USB) | 1 or 2 | `nboot 0x81000000 0` (NAND boot) |
| Right (away from USB) | 0 | `bootm 0x9f050000` (NOR boot) |

**Source code analysis** from `gl-inet/uboot-for-qca95xx`:

`GL_BOOT_ADDR = 0x9f050000` (set in `configs/ar300m-ar71xx_generic.mk` line 24). This is the **NOR firmware partition address** (NOR flash starts at `0x9f000000`, firmware at offset `0x050000`).

- `switch_boot_load()` in `board953x.c` reads GPIO 0 and GPIO 1 (debounced, 20ms gap)
- Returns 0 (both low), 1 (bit 0 high), 2 (bit 1 high), or 3 (both high)
- `select_boot_dev()` in `device_check.c` uses the return value:
  - `val=0` (switch RIGHT, both LOW) → `bootm 0x9f050000` → **NOR boot**
  - `val=1` or `val=2` (switch LEFT, one HIGH) → `nboot 0x81000000 0` → **NAND boot**
  - `val=3` → fall through (no action)

**NOTE: Switch-based NOR boot was reported broken on many devices.** GL.iNet forum threads from 2017-2018 document users unable to boot NOR via switch. GL.iNet staff (alzhao, Oct 2017) acknowledged: "the function may be broken by a recent update." OpenWrt contributor jeffsf (2019) noted: "it does not appear that the switch can be used to select NOR vs. NAND boot."

Possible root cause: The initial test of switch-based NOR boot may have been done with NAND-specific bootargs (`root=/dev/mtdblock8`), causing the NOR kernel to panic immediately and reboot back to NAND. With correct generic bootargs (`console=ttyS0,115200 rootfstype=squashfs,jffs2 noinitrd`), switch-based NOR boot should work. **Retest pending with corrected bootargs.**

For guaranteed NOR boot, use the bootcount method. See "Dual-Flash Boot Behavior (Tested Findings)" below.

### Reset Hold Timing

| Hold Duration | Result |
|---|---|
| ~5 seconds | Web failsafe mode (HTTP server on port 80) |
| ~8 seconds | U-Boot serial console |
| ~10+ seconds | Netconsole (UDP port 6666) |

## Dual-Flash Boot Behavior (Tested Findings)

On AR300M, AR300M-Ext, and AR300MD, U-Boot manages two flash chips. All findings below were confirmed on real hardware running U-Boot 2022-02-16 on 2026-05-17.

### What works: Bootcount method (Method 1)

This is the **only reliably working method** to force NOR boot, though the mechanism is indirect.

```bash
# Force NOR boot on next reboot
fw_setenv bootcount 3 && reboot
```

How it works: U-Boot increments `bootcount` to 4 on startup, sees it exceeds `bootlimit=3`, sets `nand_boot_failed=1`, and changes `bootcmd` to `bootm 0x9f050000`. Then `select_boot_dev()` runs — with switch LEFT, this calls `nboot 0x81000000 0` which loads NAND kernel via `do_bootm()` inline. **If NAND kernel is valid, `nboot` never returns** (the NAND kernel boots), and the NOR `bootm` in bootcmd is never reached.

The bootcount method appears to have worked previously when the NAND kernel was in a transiently broken state — `nboot`'s `do_bootm()` would fail/return, execution would continue to the NOR `bootm` at main.c line 726-727, and NOR would boot (with clean caches thanks to the NAND read having perturbed cache state per the root cause analysis above).

**Reliability**: Depends on NAND kernel being broken or `nboot` failing. With a working NAND kernel, the bootcount path boots NAND (not NOR). To make bootcount reliably boot NOR, you may need to corrupt the NAND kernel first.

To return to NAND from NOR:

```bash
# Return to NAND boot
fw_setenv bootcount 0 && reboot
```

### Switch-based NOR boot (Method 2) — Designed to work, CAUSES KERNEL PANIC

GL.iNet documentation and U-Boot source code confirm the switch IS designed to select NAND vs NOR boot. With `boot_dev=on`:

- Switch RIGHT (GPIO both LOW, val=0) → `bootm 0x9f050000` (NOR address)
- Switch LEFT (GPIO one HIGH, val=1/2) → `nboot 0x81000000 0` (NAND)

**Tested 2026-05-17 (two tests, both failed):**

**Test 1:** Switch RIGHT, bootcount=0, correct bootargs. Device ended up in NAND. `select_boot_dev()` calls `bootm 0x9f050000` → NOR kernel starts → panics → device reboots → NAND boots on second attempt (bootcount still under bootlimit).

**Test 2:** Switch RIGHT, bootcount=3 (bootlimit exceeded), correct bootargs. **Device entered infinite boot loop.** Every boot cycle: `select_boot_dev()` → `bootm 0x9f050000` → NOR kernel panics → reboot → repeat. Device stuck with green LED on, unreachable. Recovery requires flipping switch LEFT and power cycling.

The NOR OpenWrt kernel has `kernel.panic = 3` (auto-reboot 3 seconds after panic), which turns a single panic into an infinite reboot loop when `select_boot_dev()` always tries NOR first.

**The NOR kernel DOES start** — `bootm` succeeds and jumps to the kernel. The kernel then panics for an unknown reason. The same NOR image boots fine via the bootcount path (main.c line 726-727, after `nboot` has run). The difference is the calling context: `select_boot_dev()` runs `bootm` directly without `nboot` preceding it, while the bootcount path has `nbood 0x81000000 0` (NAND load) run first in `select_boot_dev()` before `bootm` runs from main.c.

### Root cause analysis: MIPS D-cache not flushed after LZMA decompression (CONFIRMED)

**Source code traced from `gl-inet/uboot-for-qca95xx`. Bug is in `cmd_bootm.c`.**

#### The bug

In `src/common/cmd_bootm.c`, the cache flush runs **BEFORE** LZMA decompression, not after:

```c
// Line 321-329 (Atheros/QCA path):
mips_cache_flush();       // Line 325 — flushes D-cache for phys 0x0-0x7FFF only
mips_icache_flush_ix();   // Line 326 — properly invalidates ALL I-cache
/* dcache_disable(); */   // Line 329 — COMMENTED OUT

// Lines 388-396 — LZMA decompression (runs AFTER cache flush):
case IH_COMP_LZMA:
    lzma_inflate(data, len, ntohl(hdr->ih_load), &unc_len);
```

Then in `src/lib_mips/mips_linux.c`, the kernel is jumped to with **NO D-cache flush**:

```c
// Line 247-251 — direct jump, no cache flush:
wasp_set_cca();
theKernel(linux_argc, linux_argv, linux_env, flash_size_mbytes);
```

#### Why this causes a kernel panic

1. `mips_cache_flush()` (cache.S:340-371) iterates from KSEG0 (0x80000000) to KSEG0 + 32KB, using `Hit_Writeback_Inv_D` (tag-matched). It only flushes D-cache lines for physical addresses 0x00000000-0x00007FFF — the first 32KB of RAM.
2. LZMA decompresses ~2.9MB kernel to `0x80060000` (KSEG0, write-back cached). Physical range: 0x00060000-0x00300000. **This data is dirty in D-cache and NOT in physical RAM.**
3. `mips_icache_flush_ix()` properly invalidates ALL I-cache entries.
4. `do_bootm_linux()` jumps to `0x80060000`. I-cache misses fetch from physical RAM. But the kernel data is still dirty in D-cache (Harvard architecture — I-cache and D-cache are independent, no snooping).
5. I-cache fills get stale/wrong data from RAM → corrupt instructions → **kernel panic**.

#### MIPS address space context

| Address | Region | Properties |
|---|---|---|
| `0x80060000` | KSEG0 | Cached, write-back — where kernel is decompressed |
| `0x9f050000` | KSEG0 | Cached — NOR firmware source reads |
| `0xbf050000` | KSEG1 | Uncached — NOR alias (tested, does NOT fix the bug) |

#### Test results (2026-05-17)

| Test | Result | Notes |
|---|---|---|
| `bootm 0x9f050000` (switch RIGHT) | ❌ Kernel panic | Cached source + dirty dest in D-cache |
| `bootm 0xbf050000` (boot_dev=off) | ❌ Boot loop | Uncached source fixes reads, but **dest still dirty in D-cache** |

Testing `bootm 0xbf050000` via U-Boot env vars (`boot_dev=off`, `boot_local=""`, `bootcmd=bootm 0xbf050000`) confirmed that uncached source reads are NOT sufficient — the decompressed data at 0x80060000 stays dirty in D-cache regardless of source address.

#### Why NAND boot works despite the same bug (RESOLVED)

Both NAND and NOR kernels use the same `do_bootm()` code path with the same missing D-cache flush. **Both paths have the same fundamental bug.** NAND survives by probabilistic luck.

**MIPS 24Kc has zero hardware I/D cache coherency** (confirmed from 24Kc Software User's Manual, Section 8.8). The 1004K multi-core added MESI snooping; the 24Kc single-core has nothing.

**Linux kernel `head.S` does NO cache flush** — it only sets CP0_STATUS, clears BSS, and jumps to `start_kernel()`. ath79's `kernel_entry_setup` only sets Config.K0=3 (write-back). Cache initialization happens much later in `setup_arch()`, long after entry.

The ~2.9MB decompressed kernel overflows the 32KB D-cache ~90 times. Only the last ~32KB of writes stays dirty. Most of the kernel IS correctly in RAM (earlier writes were evicted and written back). Whether the remaining dirty lines cause a crash depends on **which specific instructions they corrupt**.

**NAND path**: Before `do_bootm()`, NAND reads ~2MB via DMA+memcpy through `ath_nand_rw_buff`, filling D-cache with compressed kernel data at `0x81000000+`. The D-cache pre-state causes the remaining dirty lines after decompression to map to **non-critical kernel code**.

**NOR path**: Before `do_bootm()`, no heavy memory operations. D-cache contains U-Boot execution artifacts from `0x9F000000+`. The D-cache pre-state causes dirty lines to hit **critical early kernel instructions near the entry point**.

This is probabilistic, not deterministic. Both paths have corruption. NAND survives because the corruption lands in different (non-critical) code paths than NOR.

#### The fix (U-Boot source patch)

**Option A (APPLIED)** — Add D-cache flush after decompression:
```c
// In cmd_bootm.c, after LZMA decompression (line 397):
flush_cache(ntohl(hdr->ih_load), unc_len);
```

This matches the mainline U-Boot fix from commit `99ffccbd3e5b` (Aug 2011, Diana Craciun, Freescale, patchwork #112550). GL.iNet's fork predates this fix.

**Fork**: https://github.com/Amperstrand/uboot-for-qca95xx (branch `conwrt-fix`)
**CI**: GitHub Actions builds `u-boot.bin` artifact automatically on push. CI run `25995448558` produced a green build.
**Issue tracking**: https://github.com/Amperstrand/uboot-for-qca95xx/issues/1

Additional fixes on the branch:
- `init-953x.c:411`: Bare `#elif` without expression → `#else` (pre-existing bug)
- `tools/spi_prog/Makefile`: Hardcoded `mips-openwrt-linux-` → overridable `?=`
- `config.mk`: Added `--allow-multiple-definition` for duplicate uip symbols (pre-existing bug)

**Option B** (alternative) — Uncomment `dcache_disable()` at line 329. Makes KSEG0 uncached during decompression. Slower but works.

**Building**: `gcc-mips-linux-gnu` on Ubuntu (GitHub Actions). Board config: `board953x_config`, env vars from `configs/ar300m-ar71xx_generic.mk`. Flash from OpenWrt: `mtd write /tmp/u-boot.bin u-boot`.

**NOT YET TESTED ON DEVICE.** NAND is working and is the primary boot path. NOR fix testing is deferred — see GitHub issue #1 for the test plan.

**WARNING: Do NOT set bootcount >= bootlimit with switch RIGHT — causes infinite boot loop.**
**WARNING: The `bootm 0xbf050000` test via env vars requires U-Boot safe mode recovery (hold reset during power-on).**

The `boot_local=nor` env var also triggers `bootm 0x9f050000` in `select_boot_dev()`, subject to the same panic.

Source: `gl-inet/uboot-for-qca95xx` — `src/common/cmd_bootm.c:321-406` (cache flush + decompression order bug), `src/lib_mips/mips_linux.c:73-251` (kernel jump, no flush), `src/cpu/mips/cache.S:340-371` (mips_cache_flush — only flushes phys 0x0-0x7FFF), `src/cpu/mips/cpu.c:98-108` (flush_cache — range-based dcache_flush_range via Hit_Writeback_Inv_D).

### Bootargs fix is REQUIRED for dual-boot

Default U-Boot `bootargs` contains `root=/dev/mtdblock8 ubi.mtd=5,2048`, which is NAND-specific. The NOR kernel uses a different MTD layout with fewer partitions, so `mtdblock8` does not exist. Booting NOR with default bootargs causes an immediate kernel panic.

You must set bootargs to a generic value that works for both NAND and NOR:

```bash
fw_setenv bootargs 'console=ttyS0,115200 rootfstype=squashfs,jffs2 noinitrd'
```

Source: `gl-inet/uboot-for-qca95xx` file `src/include/configs/board953x.h` has bootargs hardcoded for NAND layout.

### Automatic NAND fallback

U-Boot always tries NAND first during normal boot. After 3 consecutive NAND boot failures (bootcount exceeds bootlimit=3), it falls back to NOR automatically. This is a built-in safety net: if NAND gets corrupted, the device still boots from NOR.

This fallback has not been explicitly tested (would require intentionally corrupting NAND), but the mechanism is the same bootcount/bootlimit system that the manual NOR boot method relies on.

### NAND boot details

When booted from NAND:
- Kernel from NAND mtd4 (4MB)
- Rootfs from NAND UBI mtd5, volumes: rootfs (squashfs) + rootfs_data (UBIFS overlay, ~113MB)
- Board name: `glinet,gl-ar300m-nand`

### NOR boot details

When booted from NOR:
- Kernel from NOR mtd3 (2.9MB, uImage at 0x050000)
- Rootfs from NOR mtd4 (squashfs)
- Overlay on NOR mtd5 (JFFS2, ~8.9MB available)
- ART on NOR mtd6 (64KB at 0xFF0000)
- Board name: `glinet,gl-ar300m-nor`

For NOR-only models (AR300M16, AR300M16-Ext, AR300M-Lite), none of this applies. They have a single flash chip and boot normally.

## Sysupgrade Behavior

Sysupgrade is **image-type-aware, not boot-source-aware**. The upgrade function auto-detects what kind of firmware you are flashing by checking magic numbers, regardless of whether the device is currently booted from NAND or NOR.

### Image detection

The function `glinet_nand_nor_do_upgrade()` in OpenWrt's `target/linux/ath79/nand/base-files/lib/upgrade/platform.sh` checks the magic number of the uploaded file:

| Magic Number | Image Type | Action |
|---|---|---|
| `27051956` (U-Boot Image Magic) | NOR sysupgrade | Writes to NOR firmware partition |
| tar archive | NAND sysupgrade | Writes to NAND kernel + UBI partitions |

Source: openwrt/openwrt commit `55e6c903ae`.

### Cross-flashing is supported

You can flash NAND firmware from a NOR boot, and NOR firmware from a NAND boot. The `SUPPORTED_DEVICES` lists in the images are deliberately cross-referenced:

- NAND image `SUPPORTED_DEVICES` includes `glinet,gl-ar300m-nor` (can flash from NOR)
- NOR image `SUPPORTED_DEVICES` includes `glinet,gl-ar300m-nand` (can flash from NAND)

### Image formats

| Image | File format | What sysupgrade.bin actually is |
|---|---|---|
| NAND firmware | POSIX tar archive | tar containing uImage kernel + UBI rootfs |
| NOR firmware | Raw uImage | uImage (U-Boot Image Magic `27051956`) |

### Post-sysupgrade boot device

After sysupgrade, the system automatically sets the boot environment so the next boot uses the correct flash chip:

- After NOR sysupgrade: `fw_setenv bootcount 3` (next boot will be NOR)
- After NAND sysupgrade: `fw_setenv bootcount 0` (next boot will be NAND)

## Recovery

### U-Boot HTTP Recovery

1. Enter U-Boot safe mode (hold reset, apply power, release on 6th blink)
2. Set PC to 192.168.1.2/24
3. Browse to http://192.168.1.1
4. Upload firmware using the form. Field names:
   - `firmware` or `nand_firmware` for NAND images (.img, .ubi)
   - `nor__firmware` for NOR images (.bin)
5. Wait 10-30 seconds (NOR) or up to 3 minutes (NAND)
6. Device reboots automatically

The U-Boot page also exposes `uboot` and `art` upload fields. Do not touch these. Flashing the wrong U-Boot or ART partition will brick the device permanently. Only use the `firmware` field.

Headless alternative:

```bash
curl -sk --max-time 300 -F firmware=@image.bin http://192.168.1.1/
```

### Dual-Flash Recovery

If NAND is bricked, the device is still recoverable:

1. Force NOR boot: `fw_setenv bootcount 3 && reboot` (if you still have SSH)
2. If SSH is gone, enter U-Boot safe mode and flash the NOR image via the HTTP form
3. Once booted from NOR, flash NAND from within OpenWrt using sysupgrade with a NAND image

### TFTP Recovery

```bash
# Set PC to 192.168.1.2/24
# Filename MUST contain "tftp" or U-Boot ignores it
tftp -i 192.168.1.1 put firmware-tftp.bin
```

| Parameter | Value |
|---|---|
| TFTP server IP (router) | 192.168.1.1 |
| Client IP (your PC) | 192.168.1.2 |
| Filename requirement | Must contain "tftp" |
| Port | UDP/69 |

### Serial Recovery

For devices where U-Boot is unresponsive:

- Pinout: standard QCA9531 UART header (3.3V, TX, RX, GND)
- Baud: 115200
- Format: 8N1
- Flash via U-Boot command line with TFTP

If the ART partition (WiFi calibration data) is corrupted, the device becomes wired-only. ART data is unique per unit and cannot be regenerated.

## Tested Hardware

| Test | Date | Result | Notes |
|---|---|---|---|
| U-Boot HTTP recovery (NAND) | 2026-05-16 | Pass | Flashed NAND factory.img (8.6MB) via HTTP POST. ~4s upload, ~60s write+reboot. Switch LEFT. |
| NAND boot | 2026-05-17 | Pass | OpenWrt 24.10.2 (hostname: switchleft, `glinet,gl-ar300m-nand` DTB). UBI rootfs with ~113MB overlay. |
| NOR setup | 2026-05-17 | Pass | U-Boot upgraded to 2022-02-16, NOR firmware flashed (7MB to mtd2), boot_dev=on, bootargs fixed. NAND boot survived the setup. |
| NOR boot via switch (RIGHT) | 2026-05-17 | **FAIL** | Switch RIGHT + boot_dev=on. `select_boot_dev()` tries `bootm 0x9f050000` but returns failure. Falls through to NAND. |
| NOR boot via bootcount | 2026-05-17 | **Pass** | `fw_setenv bootcount 3`, power cycle. NOR booted: `glinet,gl-ar300m-nor` DTB, squashfs rootfs, JFFS2 overlay 8.9MB. Hostname: ar300-nor-recovery. |

Test device: GL.iNet AR300M, U-Boot: pepe2k/u-boot_mod fork (uboot-gl-ar300m-20220216).

## Post-Flash Configuration

After flashing vanilla OpenWrt, the conwrt pipeline applies:

| Setting | Value |
|---|---|
| WiFi STA radio | `radio0` (2.4GHz) |
| WiFi STA interface | `phy0-sta0` (used as WAN) |
| Hostname | First 12 chars of `sha256(MAC_UPPERCASE_WITH_COLONS)` |
| SSH | Key auth only, password auth disabled |
| Dropbear | `PasswordAuth=off`, `RootPasswordAuth=off` |

```bash
# After sysupgrade, device is at 192.168.1.1
ssh root@192.168.1.1  # no password on fresh OpenWrt
```
