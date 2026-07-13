# Device Recovery Status — 2026-07-13

Quick-reference for all physical devices and their current state.
Detailed notes are in `recipes/<vendor>/<model>/`.

---

## Status Overview

| Device | Model | State | Accessible? | Urgency |
|--------|-------|-------|-------------|---------|
| GS1920-24 | Zyxel GS1920-24 (non-PoE) | Stock ZyNOS V4.50, all mgmt services disabled | No (L2 only) | **Recover now** |
| MX4200 #1 | Linksys MX4200 V1 | OpenWrt, working | Yes (SSH) | None |
| MX4200 #2 | Linksys MX4200 V1 | Stuck on broken alt_kernel partition | No | **Recover soon** |
| COVR #1-6 | D-Link COVR-X1860 A1 | OpenWrt, working | Yes (SSH) | None |
| GS1900-8HP #1 | Zyxel GS1900-8HP A1 | OpenWrt | Yes (SSH) | None |
| GS1900-8HP #2 | Zyxel GS1900-8HP A1 | ZyXEL stock V2.90 | Yes (HTTP) | None |

---

## GS1920-24 — Services Disabled (Recover Now)

**What happened:** Attempted to flash OpenWrt via FTP/web without serial cable. ZyNOS firmware handler rejected all non-stock images (6 attempts). During Playwright automation, all management services (HTTP, FTP, Telnet) were left disabled. Switch is running stock ZyNOS V4.50 from slot 2 with L2 fabric alive but zero management access.

**How we know:** 90-second packet capture showed only LLDP frames every 30s from MAC `4c:9e:ff:77:5c:93`. Zero DHCP, zero TCP, zero ARP requests. Our OpenWrt build doesn't include LLDP — stock ZyNOS does.

**Switch identity:**
- MAC: `4c:9e:ff:77:5c:91` (chassis), port 2: `4c:9e:ff:77:5c:93`
- Default IP: 192.168.1.1
- Default login: admin/1234
- OUI: `4C:9E:FF` (Zyxel)
- BootBase unlock string: `ATEN1,887852B1`

### Recovery Step 1: Factory Reset (try first)

1. Power on the switch, wait for LEDs to finish boot sequence (~60s)
2. Hold the reset button for **15+ seconds** (our earlier 10s hold was too short)
3. Wait for reboot (~60s)
4. Verify: browse to `http://192.168.1.1` — should show ZyXEL login page
5. Login with admin/1234
6. Re-enable all services via Access Service page (`/rpaccessservice.html`)

### Recovery Step 2: Serial + XMODEM (if factory reset fails)

This is the **only proven method** for GS1920 OpenWrt installation:

1. Obtain a USB-RS232 adapter (3.3V or 5V TTL, NOT RS-232 voltage levels)
2. Connect to the switch's console port (9600 baud, 8N1)
3. Power on, press any key during BootBase countdown to enter debug mode
4. Enter BootBase debug mode, upload initramfs via XMODEM
5. Boot OpenWrt initramfs, then sysupgrade to permanent image

**Detailed notes:** `recipes/zyxel/gs1920-24/notes.md` (1095 lines)
**OpenWrt build workspace:** `/home/ubuntu/src/conwrt/` (toolchain preserved, `make clean` run)

### What NOT to do

- Do NOT attempt FTP or web upload of OpenWrt firmware — the ZyNOS handler does model-ID + version validation beyond SIG+checksum and will reject it
- Do NOT toggle services via Playwright without a cleanup step that re-enables them afterward
- Do NOT interpret ARP response as evidence of a working OS — L2 fabric responds regardless

---

## MX4200 #2 — Stuck on Broken alt_kernel (Recover Soon)

**What happened:** Attempted to enable PMIC LDO11 (Bluetooth EFR32 power rail) by patching the DTB inside the kernel FIT image. Three attempts:
1. Raw binary injection — **booted** but DTB was truncated (24 bytes), `regulator-always-on` lost
2. mkimage rebuild — **failed to boot**, wrote to alt_kernel (mtd23) with `boot_part=2`
3. Proper FDT patch — validated but **not deployed** (device already stuck)

The broken mkimage-rebuilt FIT on alt_kernel doesn't boot, and U-Boot's fallback to partition 1 (working OpenWrt on mtd21) isn't triggering automatically.

**Device identity:**
- MAC OUI: `E8:9F:80` (Linksys)
- Firmware: 1.0.11.208553 (stock, both devices identical)
- SoC: Qualcomm IPQ8174 (qualcommax/ipq807x)

**Partition layout:**
- mtd21 (`kernel`): Working OpenWrt — **this is the fallback we need**
- mtd23 (`alt_kernel`): Broken mkimage-rebuilt FIT — **currently selected by boot_part=2**

### Recovery Step 1: 30/30/30 Reset (try first)

1. Hold reset button for 30 seconds
2. Unplug power while holding reset
3. Wait 30 seconds (still holding)
4. Plug power back in (still holding)
5. Hold for 30 more seconds, then release
6. This may reset U-Boot env to defaults, restoring `boot_part=1`

### Recovery Step 2: Repeated Power Cycling

Some U-Boot builds fall back after N failed boots:
1. Power cycle 5-10 times with 30-second intervals
2. Watch for the device to appear at 192.168.1.1 via ARP
3. If SSH comes up, immediately run `fw_setenv boot_part 1`

### Recovery Step 3: Serial Console (most reliable)

1. Open the MX4200 case
2. Locate unpopulated serial header pads on the PCB
3. Solder a 3.3V USB-serial adapter (TX→RX, RX→TX, GND→GND, NO VCC)
4. Connect at 115200 baud (verify from OpenWrt DTS `stdout-path`)
5. Interrupt U-Boot during boot countdown
6. Run: `setenv boot_part 1; saveenv; boot`
7. Device boots from working partition 1

### Recovery Step 4: TFTP Recovery Mode

If MX4200 U-Boot has network TFTP recovery (common on IPQ807x):
1. Set up a TFTP server with a recovery image
2. Power cycle repeatedly
3. Watch if device requests a TFTP download after failed boots

**Detailed notes:** `recipes/linksys-mx4200/NOTES.md` (519 lines)

### What NOT to do

- Do NOT write to both partitions without serial access — always keep one as known-good fallback
- Do NOT use mkimage to rebuild FIT images for this device — the U-Boot expects a specific FIT layout
- Do NOT attempt FIT DTB injection without updating ALL FDT header fields (totalsize, off_dt_strings, size_dt_struct)

---

## MX4200 Bluetooth (EFR32MG21) — Not Working (Research)

**Status:** EFR32MG21 SoC is likely unpowered under OpenWrt. Root cause identified (PMIC LDO11, 2.94V, zero consumers, not always-on). Requires DTB patch to enable the regulator.

**Attempt 3 (proper FDT patch) is validated but not deployed** — `/tmp/fit-properly-patched.img` exists on the machine where the patching was done. The patch correctly updates all FDT header fields and `mkimage -l` validates the image.

**After recovering MX4200 #2** (see above), the safe path to deploy the L11 fix is:
1. Build a complete OpenWrt image using Image Builder with a DTS patch (not FIT injection)
2. Flash via `sysupgrade` (updates current partition, preserves alt)
3. Or use `mtd write` to the INACTIVE partition + `fw_setenv boot_part` with verified fallback

**Full investigation:** `recipes/linksys-mx4200/NOTES.md` — "Bluetooth" and "DTB Patching Attempt" sections

---

## conwrt Workspace — Build Lab Status

**Location:** `/home/ubuntu/src/conwrt/`
**Size:** 7.3 GB (after `make clean` on 2026-07-13, was 11 GB)

### What's there

| Path | Size | Purpose |
|------|------|---------|
| `openwrt-minimal/` | 7.0 GB | OpenWrt source tree + toolchain (preserved) |
| `openwrt-minimal/build_dir/toolchain-*/` | 3.8 GB | Compiled cross-toolchain (preserved for fast rebuild) |
| `openwrt-minimal/dl/` | 498 MB | Source tarballs (preserved, no re-download needed) |
| `openwrt-minimal/staging_dir/` | 608 MB | Staged headers/libs |
| `openwrt-minimal/feeds/` | 265 MB | Package feed checkouts |
| `openwrt-imagebuilder-realtek-rtl839x.*/` | 212 MB | Pre-built ImageBuilder |
| `images/` | 136 MB | 25+ experimental firmware builds (all preserved) |
| `450AAOB3C0.bin` | 3.6 MB | Stock ZyXEL firmware backup |

### Kernel config (backed up)

The aggressive size-reduction kernel config for fitting OpenWrt into the 3.7MB ZyNOS slot is backed up to:
```
conwrter/recipes/zyxel/gs1920-24/
├── config-6.18-aggressive-size-reduction       (445-line full config)
└── config-6.18-aggressive-size-reduction.diff  (179-line diff vs upstream)
```

### To rebuild firmware after make clean

```bash
cd /home/ubuntu/src/conwrt/openwrt-minimal
make V=s -j$(nproc)  # Toolchain preserved, should take ~30 min
# Output appears in bin/targets/realtek/rtl839x/
```

---

## Consolidated Lessons Learned

1. **Serial cable is the #1 recovery tool.** Both stuck devices (GS1920-24, MX4200 #2) could be recovered immediately with serial. Every device should get a serial cable as part of onboarding.

2. **Always capture boot traffic first.** A 60-second pcap during boot reveals more than hours of hypothesis exploration. LLDP = stock firmware, DHCP = OpenWrt, silence = dead.

3. **Never toggle device services via automation without a cleanup step.** Every Playwright/HTTP session must end by restoring all services to enabled state.

4. **Trust empirical evidence over logical reasoning.** The ZyNOS FTP upload chain was logically sound but had an untested assumption. When forums say "serial only," believe them.

5. **Never write to both partitions without serial access.** Always keep one partition as a known-good fallback with a verified recovery mechanism.

6. **Test upload handlers with modified stock images first.** Before attempting a full custom firmware upload, probe with a stock image with one byte changed.

7. **ARP response != working OS.** L2 fabric responds to ARP regardless of whether any management services are running.

8. **Record inventory immediately after first access.** The GS1920-24 was never inventoried or SSH-keyed, making it harder to find after the services were disabled.
