# EdgeRouter 6P PoE Diagnosis: Wave 0 Findings

**Date**: 2026-05-20
**Router**: 192.168.X.X (EdgeRouter 6P, UBNT_E300, CN7030p1.2-1000-AAP)
**Kernel**: Linux 6.12.87 (OpenWrt 25.12.4, mips64)
**Purpose**: Diagnose why 24V passive PoE GPIO writes fail under OpenWrt. Document all Wave 0 read-only diagnostic findings, rank remaining hypotheses, and prescribe next steps.

---

## Table of Contents

1. [Baseline State](#1-baseline-state)
2. [ISL28022 Zero-Load Reading](#2-isl28022-zero-load-reading)
3. [GPIO_BIT_CFG Audit](#3-gpio_bit_cfg-audit)
4. [Pin-Mux Audit](#4-pin-mux-audit)
5. [I2C Sweep Results](#5-i2c-sweep-results)
6. [GPIO17 Regression](#6-gpio17-regression)
7. [Wave 0 Conclusions](#7-wave-0-conclusions)
8. [ISL28022 ALERT# Reference](#8-isl28022-alert-reference)

---

## 1. Baseline State

**Evidence**: `test-evidence/wave-0/w0-1-baseline/`

### System Identity

| Property | Value |
|----------|-------|
| Kernel | Linux OpenWrt 6.12.87 SMP mips64 |
| Machine | UBNT_E300 (CN7030p1.2-1000-AAP), Cavium Octeon III |
| Boot | `root=/dev/mmcblk0p2 rootdelay=10 rw rootsqimg=squashfs.img` |
| Rootfs | Squashfs overlay on F2FS (`/dev/loop0 on /overlay`) |
| Debugfs | mounted at `/sys/kernel/debug` |

**Source**: `w0-1-baseline/uname.txt`, `w0-1-baseline/proc-cmdline.txt`, `w0-1-baseline/mount.txt`

### Loaded Modules

The `gpio_reg` module is loaded (the custom diagnostic module), alongside `leds_gpio`, `gpio_button_hotplug`, `i2c_dev`, `dwc3`, and standard netfilter modules. No `ubnt_platform` or vendor-specific PoE module is present.

**Source**: `w0-1-baseline/lsmod.txt`

### GPIO Controller State

The Cavium Octeon GPIO controller base is at physical address `0x1070000000800`.

| Register | Value | Notes |
|----------|-------|-------|
| RX_DAT | `0x0000000000067910` | Input readback. Bits 4, 8, 11, 12, 14, 17 set |
| TX_SET | `0x0000000000020010` | Output latch. Bits 4, 17 set |
| TX_CLEAR | `0x0000000000020010` | Mirror of TX_SET (hardware behavior) |

RX_DAT bit analysis:
- Bit 4 (GPIO 4, eth1 power-en) = 1 (high)
- Bit 8 (GPIO 8) = 1 (high, unknown role)
- Bit 11 (GPIO 11, reset button) = 1 (high, active-low)
- Bit 12 (GPIO 12, SFP mod-def0) = 1 (high, active-low)
- Bit 14 (GPIO 14) = 1 (high, unknown)
- Bit 17 (GPIO 17, blue LED) = 1 (high, LED on)

Only GPIO 4 (eth1 power-en) and GPIO 17 (blue LED) show as actively driven outputs in TX_SET.

**Source**: `w0-1-baseline/gpio-reg-summary.txt`

### I2C Bus State

Bus 1 scan shows two responding devices at addresses `0x38` and `0x39` (SMBus read range), plus the full 0x50-0x5F EEPROM range. The two ISL28022 power monitors are at `0x3F` and `0x40`, confirmed by register dumps showing repeated `0x1f79` (configuration register pattern).

**Source**: `w0-1-baseline/i2c-bus1-scan.txt`, `w0-1-baseline/i2c-0x40-dump.txt`, `w0-1-baseline/i2c-0x3F-dump.txt`

---

## 2. ISL28022 Zero-Load Reading

**Evidence**: `test-evidence/wave-0/w0-2-isl28022-zero-load/`

Both ISL28022 devices (at I2C addresses 0x3F and 0x40) were read with no PoE load attached. The `i2cget` dumps show identical register maps across all 256-byte pages, which is expected for the ISL28022's 8-register banked architecture.

### Register Values (from `isl-0x3F-all-regs.txt` and `isl-0x40-all-regs.txt`)

| Register | 0x3F Value | 0x40 Value | Description |
|----------|-----------|-----------|-------------|
| 0x00 (CFG) | `0x1f79` | `0x1f79` | Configuration register |
| 0x01 (SHUNT) | `0x4601` | `0x4401` | Shunt voltage reading |
| 0x02 (BUS) | `0x765f` | `0x765f` | Bus voltage reading |
| 0x03 (PWR) | `0x0000` | `0x0000` | Power (zero, no load) |
| 0x04 (CUR) | `0x0100` | `0x0100` | Current |
| 0x05 (CAL) | `0x1000` | `0x1000` | Calibration register |
| 0x07 (MASK) | `0x00ff` | `0x00ff` | Mask/enable register |

### Analysis

**Bus voltage**: `0x765f` converts to approximately 29.6V. Both devices agree, confirming the PSU is delivering expected voltage. The PSU is GOOD.

**Shunt voltage**: `0x4601` and `0x4401`. These are big-endian register reads from a 16-bit signed shunt voltage register. The values need byte-swap analysis: `0x4601` raw may represent a small residual offset or noise floor, consistent with zero-load conditions. No unexpected current paths are active.

**Configuration**: `0x1F79` decodes to the ISL28022's default-ish configuration. Both devices match, suggesting they were initialized by the same code path (likely EdgeOS firmware or board setup).

**Mask register**: `0x00FF` means all alert functions are enabled. This is notable for H1 (ALERT# gating theory). If the ALERT# pin physically gates a MOSFET enable line, the current alert state might block power output. This needs hardware tracing to confirm.

**Calibration**: `0x1000` (4096 decimal). Standard calibration for the expected current range.

**Key conclusion**: The PSU is healthy at ~29.6V. The ISL28022 monitors are correctly configured and reporting sensible zero-load values. Power delivery hardware upstream of the GPIO control points is functional.

**Source**: `w0-2-isl28022-zero-load/isl-0x3F-all-regs.txt`, `w0-2-isl28022-zero-load/isl-0x40-all-regs.txt`

---

## 3. GPIO_BIT_CFG Audit

**Evidence**: `test-evidence/wave-0/w0-3-gpio-bit-cfg/`

This is the **critical finding** of Wave 0. A custom kernel module (`gpio-reg-v2.ko`) was deployed to expose per-pin BIT_CFG registers via `/proc/gpio-reg/bit_cfg/N` for N=0 through 19.

### Tool: gpio-reg-v2

The module maps the GPIO controller physical base (`0x1070000000800`) and provides:
- `/proc/gpio-reg/summary` — full register dump (backward compatible with v1)
- `/proc/gpio-reg/bit_cfg/N` — per-pin BIT_CFG hex value with decoded fields

BIT_CFG register formula: `GPIO_BIT_CFGn = GPIO_BASE + 0x100 + (n * 8)`

BIT_CFG fields (Cavium Octeon):
- Bit 0: `tx_oe` (output enable, 1=output)
- Bit 1: `pin_xor` (XOR with pin value)
- Bits 2-5: interrupt configuration
- Bits 8-9: `output_sel` (0=GPIO, 1-3=alternate function)
- Bits 10-11: `fil_sel` (glitch filter)

**Source**: `w0-3-gpio-bit-cfg/gpio-reg-v2.c`

### Complete BIT_CFG Table

| GPIO | Offset | Raw | tx_oe | output_sel | PIN val | Role |
|------|--------|-----|-------|------------|---------|------|
| 0 | 0x100 | 0x1 | **1** | 0 | 0 | Unknown (output) |
| 1 | 0x108 | 0x1 | **1** | 0 | 0 | eth0 pair-mode |
| 2 | 0x110 | 0x0 | **0** | 0 | 0 | eth0 power-en |
| 3 | 0x118 | 0x0 | **0** | 0 | 0 | eth1 pair-mode |
| 4 | 0x120 | 0x0 | **0** | 0 | 1 | eth1 power-en |
| 5 | 0x128 | 0x0 | **0** | 0 | 0 | eth2 pair-mode |
| 6 | 0x130 | 0x0 | **0** | 0 | 0 | eth2 power-en |
| 7 | 0x138 | 0x0 | **0** | 0 | 0 | eth3 pair-mode |
| 8 | 0x140 | 0x0 | **0** | 0 | 1 | Unknown |
| 9 | 0x148 | 0x0 | **0** | 0 | 0 | eth3 power-en |
| 10 | 0x150 | 0x0 | **0** | 0 | 0 | eth4 power-en |
| 16 | 0x180 | 0x0 | **0** | 0 | 0 | misc-unknown |
| 17 | 0x188 | 0x0 | **0** | 0 | 1 | Blue LED (working) |

### Critical Finding: All PoE GPIOs Have tx_oe=0

Of the 11 PoE-relevant GPIOs (1, 2, 3, 4, 5, 6, 7, 9, 10, 16, 18), only GPIO 1 (eth0 pair-mode) has `tx_oe=1`. The remaining 10 PoE GPIOs all have `BIT_CFG=0x0`, meaning:

- `tx_oe = 0` (output driver disabled)
- `output_sel = 0` (GPIO function, not alternate)
- All interrupt and filter fields = 0

**Writes to TX_SET and TX_CLEAR for pins with tx_oe=0 are no-ops.** The Cavium Octeon GPIO controller requires `tx_oe=1` in BIT_CFG before the pin will actually drive a signal. This is the root cause: the PoE GPIO writes that `poe-reverse-engineering.md` documents are targeting unconfigured pins.

### GPIO 17 Paradox Explained

GPIO 17 (blue LED) also shows `BIT_CFG=0x0` with `tx_oe=0`, yet the LED toggles correctly via `/sys/class/leds/blue:power/brightness`. This works because the `leds_gpio` kernel driver dynamically manages `tx_oe`: it sets `tx_oe=1` when driving the pin and the register reflects 0 when we read it back because the driver restores state around its operations (or the sysfs path goes through the gpio-octeon driver which handles BIT_CFG internally).

This confirms that `tx_oe` management is expected to happen at the driver level. OpenWrt's generic GPIO framework handles it for claimed pins, but raw register writes (as used in the PoE control path) bypass this mechanism entirely.

**Source**: `w0-3-gpio-bit-cfg/bit_cfg_raw.txt`, `w0-3-gpio-bit-cfg/summary_raw.txt`, `w0-3-gpio-bit-cfg/analysis.md`

---

## 4. Pin-Mux Audit

**Evidence**: `test-evidence/wave-0/w0-4-pin-mux/`

### Methodology

Direct register access via `devmem2` was **not possible**: the kernel was compiled without `CONFIG_DEVMEM`, `/dev/mem` does not exist, and `/proc/kcore` is unavailable. Pin-mux state was inferred from:

1. `gpioinfo` (libgpiod v2.1.3) — direction and claim status for all 20 lines
2. `/sys/kernel/debug/gpio` — direction and value
3. `/sys/class/gpio/gpioN/{value,direction}` — per-pin readback after export
4. `strace` of `gpioinfo` confirming `GPIO_V2_GET_LINEINFO_IOCTL` returns valid data for all 20 pins
5. Kernel source analysis of `drivers/gpio/gpio-octeon.c` and `cvmx-gpio-defs.h`

**Source**: `w0-4-pin-mux/hardware-info.txt`, `w0-4-pin-mux/strace-gpioinfo-ioctl.txt`

### Register Address Correction

The initial BIT_CFG address formula had an error. From `drivers/gpio/gpio-octeon.c`:

```
Pins 0-15:  CVMX_GPIO_BIT_CFGX(n)  = base + n*8       (offset 0x00 to 0x78)
Pins 16-19: CVMX_GPIO_XBIT_CFGX(n) = base + 0x100 + (n-16)*8  (offset 0x100 to 0x118)
```

The DT-declared register window is only 0x100 bytes (base to base+0xFF), but the driver accesses XBIT_CFG registers beyond this window. Octeon's MMIO allows the access regardless.

### All Pair-Mode Pins Confirmed as GPIO

| Pin | Role | gpioinfo Direction | Value | output_sel |
|-----|------|--------------------|-------|------------|
| 1 | eth0 pair-mode | input | 0 | 0 (GPIO) |
| 3 | eth1 pair-mode | input | 0 | 0 (GPIO) |
| 5 | eth2 pair-mode | input | 0 | 0 (GPIO) |
| 7 | eth3 pair-mode | input | 0 | 0 (GPIO) |
| 9 | eth3 power-en (pair-mode?) | input | 0 | 0 (GPIO) |

All five pair-mode pins respond to GPIO operations. `gpioinfo` lists them with `consumer=sysfs` (exported by our test). The `strace` output confirms `GPIO_V2_GET_LINEINFO_IOCTL` returns valid metadata for every pin.

The `output_sel` field is 0 for all pins. In Cavium Octeon III, `output_sel=0` means GPIO function, not alternate. Pin-mux is **not** preventing GPIO writes from reaching the pins.

### Even Pins (Power-Enable)

| Pin | Role | Direction | Value |
|-----|------|-----------|-------|
| 2 | eth0 power-en | output | 0 |
| 4 | eth1 power-en | output | 1 |
| 6 | eth2 power-en | output | 0 |
| 10 | eth4 power-en | output | 0 |

These show as "output" in gpioinfo because the `octeon_gpio_dir_out()` function sets `tx_oe=1` when a pin is exported as output via sysfs. This is the Linux GPIO framework managing BIT_CFG, not the hardware's default state.

### H6 Assessment

**H6 REJECTED**: Pin-mux is NOT the problem. All pair-mode pins are confirmed muxed to GPIO (output_sel=0).

**Source**: `w0-4-pin-mux/findings.md`, `w0-4-pin-mux/gpioinfo-output.txt`, `w0-4-pin-mux/debugfs-gpio.txt`, `w0-4-pin-mux/sysfs-gpio-values.txt`

---

## 5. I2C Sweep Results

**Evidence**: `test-evidence/wave-0/w0-5-i2c-aggressive/`

Both I2C buses were scanned exhaustively to search for hidden PoE controller chips.

### Bus 0 (System Bus)

```
     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
00:                                                 
10:                                                 
20:                                                 
30: -- -- -- -- -- -- --                         
40:                                                 
50: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 
60:                                                 
70:                                                 
```

Responding: 0x38, 0x39, 0x50-0x5F (EEPROM range). Only 0x38 and 0x39 are actual devices. The 0x50-0x5F range is typical for SPD EEPROMs and shows all addresses responding, likely due to bus topology rather than 16 actual chips.

### Bus 1 (PoE Monitor Bus)

Identical response pattern to Bus 0. Devices at 0x3F and 0x40 are the two ISL28022 power monitors (confirmed by register dumps in W0-2).

### No Hidden Controllers Found

No unknown I2C devices were discovered. No PoE management IC, no microcontroller, no additional power controllers. The only chips on the bus are the two ISL28022 monitors.

This eliminates the possibility of a separate I2C-controlled PoE switch or a management MCU that needs explicit enabling.

### H7 Assessment

**H7 REJECTED**: No hidden I2C device found on either bus.

**Source**: `w0-5-i2c-aggressive/i2c-bus0-full.txt`, `w0-5-i2c-aggressive/i2c-bus1-full.txt`

---

## 6. GPIO17 Regression

**Evidence**: `test-evidence/wave-0/w0-3-gpio-bit-cfg/`, `test-evidence/wave-0/w0-6-regression/`

After deploying `gpio-reg-v2.ko` and running all diagnostic tests, the router's baseline functionality was verified to confirm no regression.

### Blue LED Toggle Test

| Action | Result |
|--------|--------|
| Read `/sys/class/leds/blue:power/brightness` (off) | Returns `0` |
| Write `1` to brightness | LED turns on physically |
| Read brightness (on) | Returns `1` |
| Write `0` to brightness | LED turns off physically |

The LED control path through the `leds_gpio` driver and `gpio-octeon` driver remains fully functional. The `gpio-reg-v2` module does not interfere with existing GPIO consumers.

### Module Load Status

The regression check (`w0-6-regression/lsmod.txt`) shows three modules loaded:
- `gpio_button_hotplug` (16384 bytes)
- `gpio_reg` (12288 bytes)
- `leds_gpio` (12284 bytes)

All loaded cleanly, no kernel taint, no error messages. The `gpio-reg-v2` module coexists with `leds_gpio` without conflict because it only reads registers (plus the write path for manual register poking via the summary file, which was not used during these tests).

### Register State Stability

The W0-6 regression check confirmed that GPIO register values are stable:
- RX_DAT = `0x0000000000067910` (unchanged from W0-1 baseline)
- TX_SET = `0x0000000000020010` (unchanged)
- TX_CLEAR = `0x0000000000020010` (unchanged)

No spurious register changes occurred during the diagnostic sequence.

**Source**: `w0-6-regression/initial-state.txt`, `w0-6-regression/lsmod.txt`, `w0-3-gpio-bit-cfg/analysis.md`

---

## 7. Wave 0 Conclusions: Hypothesis Ranking

Wave 0 was a set of read-only diagnostic tests designed to eliminate hypotheses about why PoE GPIO writes fail under OpenWrt. Seven hypotheses were evaluated against the collected evidence.

### Hypothesis Rankings

#### 1. H4 (CONFIRMED - PRIMARY): GPIO_BIT_CFG OUTPUT_SEL/TX_OE not set

**Status**: CONFIRMED by direct register evidence.

All PoE GPIOs (2, 3, 4, 5, 6, 7, 9, 10, 16) have `BIT_CFG=0x0` with `tx_oe=0`. GPIO 1 is the only PoE pin with `tx_oe=1`. Writing to TX_SET/TX_CLEAR for pins with `tx_oe=0` has no effect on the physical pin state.

**Evidence**: `w0-3-gpio-bit-cfg/bit_cfg_raw.txt` shows every PoE GPIO except pin 1 has raw value `0x0000000000000000`.

**Implication**: Any PoE enable sequence MUST set `tx_oe=1` in BIT_CFG for each target GPIO before writing to TX_SET. This is a mandatory prerequisite that EdgeOS's `poe_st` function presumably handles but `er_gen2_set_poe_24v` (the smaller function we analyzed) does not.

#### 2. H5 (LIKELY - HIGH): poe_st does more than er_gen2_set_poe_24v

**Status**: Strongly supported by H4 evidence.

The binary analysis in `poe-reverse-engineering.md` found that `er_gen2_set_poe_24v` only touches even-numbered (power-enable) GPIOs via TX_SET/TX_CLEAR. It does not touch odd-numbered (pair-mode) GPIOs and does not configure BIT_CFG. The larger `poe_st` function likely handles:

1. Setting `tx_oe=1` in BIT_CFG for all relevant GPIOs
2. Configuring pair-mode (odd) GPIOs for the desired PoE mode (2-pair vs 4-pair)
3. Setting power-enable (even) GPIOs high
4. Possibly configuring the ISL28022 alert thresholds

**Evidence**: `poe-reverse-engineering.md` section 5-6 documents `er_gen2_set_poe_24v` touching only TX_SET/TX_CLEAR for even GPIOs. H4 finding that `tx_oe=0` for those pins confirms this function cannot work alone.

**Implication**: We need to either reverse-engineer `poe_st` more thoroughly or determine the correct BIT_CFG initialization sequence independently.

#### 3. H1 (POSSIBLE - MEDIUM): ISL28022 ALERT# gates MOSFET

**Status**: Unconfirmed but plausible.

Both ISL28022 devices have `MASK=0x00FF` (all alerts enabled). If the ALERT# output pin on either ISL28022 is physically connected to a MOSFET gate or enable line in the PoE output circuit, the current alert state could prevent power delivery even after GPIO configuration.

**Evidence**: `w0-2-isl28022-zero-load/isl-0x3F-all-regs.txt` and `isl-0x40-all-regs.txt` show `mask=0x00FF`.

**Implication**: After fixing H4 (tx_oe), if PoE still doesn't work, check whether ISL28022 ALERT# is physically connected to the power output circuit. This requires board-level tracing or schematic access.

#### 4. H3 (POSSIBLE - MEDIUM): PHY power-on prerequisite

**Status**: Unknown, no evidence for or against.

The VSC8504 PHY state was not examined in Wave 0. If the Ethernet PHY must be powered and initialized for the PoE circuit to complete (e.g., PHY provides a ground reference or bias voltage), then PoE control might fail even with correct GPIO configuration.

**Evidence**: No PHY-specific evidence collected in Wave 0.

**Implication**: If H4 and H5 fixes don't resolve PoE output, investigate PHY power state via `ethtool` or MDIO bus access.

#### 5. H2 (UNLIKELY - LOW): Untested GPIO is master enable

**Status**: Not ruled out but H4 already explains the core issue.

GPIOs 8, 13, 14, 16, 18, 19 were identified as potentially relevant but their exact roles are unknown. GPIO 16 is listed in the `POE_GPIO_E301` table as "misc-unknown". It's possible that one of these is a global PoE master enable.

**Evidence**: `w0-3-gpio-bit-cfg/analysis.md` lists GPIO 16 and 18 among PoE-relevant pins. GPIO 16 has `tx_oe=0`, same as all other PoE pins.

**Implication**: Low priority. Fix H4 first. If individual port control works after setting tx_oe, investigate whether a master enable exists.

#### 6. H6 (REJECTED): Pin-mux prevents GPIO function

**Status**: REJECTED by multiple evidence sources.

All pair-mode pins (1, 3, 5, 7, 9) are confirmed as GPIO function with `output_sel=0`. The `gpioinfo`, `debugfs`, and `sysfs` paths all show these pins responding correctly to GPIO operations. Pin-mux is not the problem.

**Evidence**: `w0-4-pin-mux/findings.md` section "Critical Finding: Pair-Mode Pins ARE Muxed to GPIO".

#### 7. H7 (REJECTED): Hidden I2C device

**Status**: REJECTED by exhaustive bus scan.

Both I2C buses (0 and 1) were scanned across all 128 addresses. Only the expected devices were found: two ISL28022 monitors at 0x3F and 0x40 on Bus 1. No hidden PoE controller, microcontroller, or management IC exists.

**Evidence**: `w0-5-i2c-aggressive/i2c-bus0-full.txt`, `w0-5-i2c-aggressive/i2c-bus1-full.txt`.

### Summary Table

| Rank | Hypothesis | Status | Rationale |
|------|-----------|--------|-----------|
| 1 | H4: BIT_CFG tx_oe not set | CONFIRMED | Direct register evidence: all PoE GPIOs have tx_oe=0 |
| 2 | H5: poe_st does more setup | LIKELY | H4 confirms er_gen2_set_poe_24v is incomplete |
| 3 | H1: ISL28022 ALERT# gates MOSFET | POSSIBLE | MASK=0xFF enables all alerts; ALERT# pin routing unknown |
| 4 | H3: PHY power-on prerequisite | POSSIBLE | PHY state not examined; no evidence either way |
| 5 | H2: Untested GPIO master enable | UNLIKELY | H4 already explains the core issue; low priority |
| 6 | H6: Pin-mux prevents GPIO | REJECTED | output_sel=0 confirmed for all pins |
| 7 | H7: Hidden I2C device | REJECTED | Exhaustive scan found nothing unexpected |

### Prescribed Next Steps (Wave 1)

1. **Set tx_oe=1 for all PoE GPIOs** via BIT_CFG writes (using gpio-reg's write path or a dedicated tool). Then attempt TX_SET writes and measure output with a multimeter or PoE device.
2. **Reverse-engineer `poe_st` more thoroughly** to understand the full initialization sequence, especially BIT_CFG configuration and pair-mode GPIO handling.
3. **Test one port first** (e.g., GPIO 4 for eth1, which already reads as output=1 in gpioinfo). Set BIT_CFG tx_oe=1, drive TX_SET, and verify with a multimeter on the RJ45 pins.
4. **If H4 fix alone is insufficient**, investigate ISL28022 ALERT# pin routing (H1) and PHY state (H3).

---

## 8. GPIO_BIT_CFG Reference

**Source**: Linux kernel `arch/mips/include/asm/octeon/cvmx-gpio-defs.h` (Cavium Networks SDK, GPL-2.0)
**Secondary**: `drivers/gpio/gpio-octeon.c` (driver usage patterns)
**SoC**: CN7030 (OCTEON III, big-endian MIPS64)
**Date**: 2026-05-20

### Register Address Map

The GPIO controller base physical address is `0x1070000000800` (from device tree / `CVMX_ADD_IO_SEG`).

**Register stride**: 8 bytes per pin.

| Register | Address Formula | Pins | Notes |
|----------|----------------|------|-------|
| `CVMX_GPIO_BIT_CFGX(n)` | `base + n*8` | 0–15 | Offset 0x00 to 0x78 |
| `CVMX_GPIO_XBIT_CFGX(n)` | `base + 0x100 + (n-16)*8` | 16–19 | Offset 0x100 to 0x118 |
| `CVMX_GPIO_RX_DAT` | `base + 0x80` | — | Read all pin inputs |
| `CVMX_GPIO_TX_SET` | `base + 0x88` | — | Set output bits (write-1-set) |
| `CVMX_GPIO_TX_CLR` | `base + 0x90` | — | Clear output bits (write-1-clear) |

**Source**: `cvmx-gpio-defs.h` lines 28–40, `gpio-octeon.c` `bit_cfg_reg()` function.

### GPIO_BIT_CFGX Bit Field Layout (Pins 0–15)

The `cvmx_gpio_bit_cfgx` union uses the generic `s` struct for OCTEON III (CN70XX). The struct is defined with `__BIG_ENDIAN_BITFIELD` ordering — fields are listed from MSB to LSB, but the bit positions below reflect the actual register bit indices.

| Bits | Width | Field | Description | Reset |
|------|-------|-------|-------------|-------|
| 63–22 | 42 | `reserved` | Must be zero | 0 |
| 21–17 | 5 | `output_sel` | Pin mux / alternate function select. 0 = GPIO function, 1–31 = alternate functions (varies by pin; e.g., USB, SYNCE, clock gen). | 0 |
| 16–15 | 2 | `synce_sel` | Synchronous Ethernet select. Selects which SYNCE clock to use when `clk_gen=1`. | 0 |
| 14 | 1 | `clk_gen` | Clock generator enable. When set, pin outputs a clock signal instead of GPIO. | 0 |
| 13–12 | 2 | `clk_sel` | Clock select. Selects which internal clock to output when `clk_gen=1`. | 0 |
| 11–8 | 4 | `fil_sel` | Glitch filter selection. 0 = no filter. Higher values = longer filter window. Typical IRQ setup uses `fil_sel=3` (140ns). | 0 |
| 7–4 | 4 | `fil_cnt` | Glitch filter count. Number of consecutive samples required before accepting a transition. Typical IRQ setup uses `fil_cnt=7`. | 0 |
| 3 | 1 | `int_type` | Interrupt type. 0 = level-triggered, 1 = edge-triggered. | 0 |
| 2 | 1 | `int_en` | Interrupt enable. 1 = generate CIU interrupt on this GPIO pin transition. | 0 |
| 1 | 1 | `rx_xor` | Receive XOR. When set, the input value is XOR'd with the pin value before being read via RX_DAT. Effectively inverts the input. | 0 |
| 0 | 1 | `tx_oe` | **Transmit output enable.** 1 = GPIO output driver is active; pin drives the value from TX_SET/TX_CLR. 0 = output driver disabled; writes to TX_SET/TX_CLR for this pin are no-ops. **THIS IS THE CRITICAL BIT.** | 0 |

**Source**: `cvmx-gpio-defs.h` union `cvmx_gpio_bit_cfgx`, struct `cvmx_gpio_bit_cfgx_s` (big-endian bitfield).

### GPIO_XBIT_CFGX Bit Field Layout (Pins 16–19)

The `cvmx_gpio_xbit_cfgx` union for extended GPIO pins (16–19) is similar but **lacks `output_sel`** — these pins have no alternate function multiplexing.

| Bits | Width | Field | Description | Reset |
|------|-------|-------|-------------|-------|
| 63–17 | 47 | `reserved` | Must be zero | 0 |
| 16–15 | 2 | `synce_sel` | Synchronous Ethernet select | 0 |
| 14 | 1 | `clk_gen` | Clock generator enable | 0 |
| 13–12 | 2 | `clk_sel` | Clock select | 0 |
| 11–8 | 4 | `fil_sel` | Glitch filter selection | 0 |
| 7–4 | 4 | `fil_cnt` | Glitch filter count | 0 |
| 3 | 1 | `int_type` | Interrupt type | 0 |
| 2 | 1 | `int_en` | Interrupt enable | 0 |
| 1 | 1 | `rx_xor` | Receive XOR / input invert | 0 |
| 0 | 1 | `tx_oe` | **Transmit output enable** | 0 |

**Source**: `cvmx-gpio-defs.h` union `cvmx_gpio_xbit_cfgx`, struct `cvmx_gpio_xbit_cfgx_s`.

### Register Summary Diagram (Pins 0–15)

```
 63                  22 21    17 16 15 14 13 12 11   8 7    4 3  2  1  0
┌──────────────────────┬────────┬──────┬──┬──────┬──────┬──────┬──┬──┬──┬──┐
│     reserved (42b)   │out_sel │syncE │cg│clksel│fil_sel│fil_cnt│ity│ie│rx│tx│
│                      │ (5b)   │(2b)  │   │(2b)  │(4b)  │(4b)  │   │  │xo│oe│
└──────────────────────┴────────┴──────┴──┴──────┴──────┴──────┴──┴──┴──┴──┘
```

### W0-3 Captured Values Decoded

| GPIO | Role | Raw Value | tx_oe | rx_xor | int_en | int_type | fil_cnt | fil_sel | clk_sel | clk_gen | synce_sel | output_sel | Notes |
|------|------|-----------|-------|--------|--------|----------|---------|---------|---------|---------|-----------|------------|-------|
| 0 | Unknown (output) | 0x0000000000000001 | **1** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | Output enabled, GPIO function |
| 1 | eth0 pair-mode | 0x0000000000000001 | **1** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | Output enabled, GPIO function |
| 2 | eth0 power-en | 0x0000000000000000 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **Output DISABLED** |
| 3 | eth1 pair-mode | 0x0000000000000000 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **Output DISABLED** |
| 4 | eth1 power-en | 0x0000000000000000 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **Output DISABLED** |
| 5 | eth2 pair-mode | 0x0000000000000000 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **Output DISABLED** |
| 6 | eth2 power-en | 0x0000000000000000 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **Output DISABLED** |
| 7 | eth3 pair-mode | 0x0000000000000000 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **Output DISABLED** |
| 8 | Unknown | 0x0000000000000000 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **Output DISABLED** |
| 9 | eth3 pair-mode | 0x0000000000000000 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **Output DISABLED** |
| 10 | eth4 power-en | 0x0000000000000000 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **Output DISABLED** |
| 16 | misc-unknown | 0x0000000000000000 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | N/A | **Output DISABLED** (XBIT) |
| 17 | Blue LED | 0x0000000000000000 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | N/A | Managed by leds_gpio driver |

**Key observation**: Only GPIO 0 and GPIO 1 have `tx_oe=1`. All 11 PoE-relevant GPIOs have `tx_oe=0`, confirming the root cause identified in W0-3: output drivers are disabled, making TX_SET/TX_CLEAR writes no-ops.

### Safe Value for A6: Output Enable Without Side Effects

**Goal**: Enable GPIO output for PoE control without enabling interrupts, glitch filters, clock generation, or alternate functions.

**Recommended write value**: `0x0000000000000001`

| Bit | Field | Value | Rationale |
|-----|-------|-------|-----------|
| 0 | `tx_oe` | **1** | Enable output driver — this is the essential change |
| 1 | `rx_xor` | 0 | Don't invert input reads |
| 2 | `int_en` | 0 | Don't enable GPIO interrupts |
| 3 | `int_type` | 0 | Don't care (int_en=0 makes this irrelevant) |
| 7–4 | `fil_cnt` | 0 | No glitch filter count |
| 11–8 | `fil_sel` | 0 | No glitch filter selection |
| 13–12 | `clk_sel` | 0 | No clock output |
| 14 | `clk_gen` | 0 | Don't generate clock on pin |
| 16–15 | `synce_sel` | 0 | No SYNCE function |
| 21–17 | `output_sel` | 0 | GPIO function (not alternate) |
| 63–22 | reserved | 0 | Must be zero |

**Rationale**: This matches exactly what GPIO 0 and GPIO 1 already have (`BIT_CFG=0x1`), and matches the pattern used by `gpio-octeon.c` in `octeon_gpio_dir_out()`:

```c
cfgx.u64 = 0;
cfgx.s.tx_oe = 1;
// writes 0x1 — only tx_oe set, all other fields zero
cvmx_write_csr(gpio->register_base + bit_cfg_reg(offset), cfgx.u64);
```

**Source**: `drivers/gpio/gpio-octeon.c` lines 60–68.

**For XBIT_CFGX (pins 16–19)**: The same value `0x1` is safe. The XBIT register has the same bit 0 = `tx_oe`, and lacks `output_sel` (which is irrelevant — no alternate functions for these pins).

### Driver Usage Patterns (gpio-octeon.c)

The kernel GPIO driver provides reference patterns for BIT_CFG configuration:

**Set pin as output** (`octeon_gpio_dir_out`):
1. Write desired value to TX_SET or TX_CLR
2. Write `0x1` to BIT_CFGX (tx_oe=1, all else 0)

**Set pin as input** (`octeon_gpio_dir_in`):
1. Write `0x0` to BIT_CFGX (all fields zero, including tx_oe)

**Configure pin for GPIO interrupt** (`octeon_irq_gpio_setup` in `octeon-irq.c`):
1. Set `fil_cnt=7`, `fil_sel=3` (140ns glitch filter)
2. Set `int_en=1` and `int_type` as needed

**Configure pin for USB (alternate function)** (`dwc3_octeon_config_gpio`):
1. Set `tx_oe=1`
2. Set `output_sel=0x14` (USB0) or `0x15`/`0x19` (USB1)

For PoE control, we need only the "set as output" pattern: write `0x1` to BIT_CFGX.

### References

1. **Linux kernel source** (torvalds/linux):
   - `arch/mips/include/asm/octeon/cvmx-gpio-defs.h` — register union/struct definitions (authoritative bit field layout)
   - `drivers/gpio/gpio-octeon.c` — GPIO driver, `bit_cfg_reg()`, `octeon_gpio_dir_out()`
   - `arch/mips/cavium-octeon/octeon-irq.c` — interrupt configuration with glitch filter settings
   - `drivers/usb/dwc3/dwc3-octeon.c` — alternate function configuration (output_sel usage)

2. **Cavium OCTEON III HRM** (Hardware Reference Manual):
   - CN70XX/CN71XX Family HRM, Chapter "GPIO" — register descriptions for GPIO_BIT_CFGX and GPIO_XBIT_CFGX
   - The kernel header `cvmx-gpio-defs.h` is derived from the HRM and is the software-equivalent authoritative source

3. **W0-3 evidence**: `test-evidence/wave-0/w0-3-gpio-bit-cfg/bit_cfg_raw.txt`

---

## 9. ISL28022 ALERT# Reference

**Datasheet**: [Renesas ISL28022](https://www.renesas.com/en/document/dst/isl28022-datasheet) (Published 2023-03-02)
**Register Map**: Table 2, Pages 14-15 (Intersil version)
**Pin Description**: EXT_CLK/INT, Page 5 (Renesas version)

This section documents the ISL28022 ALERT# pin behavior and the registers that control it. This is reference material for testing H1 (ALERT# gates MOSFET).

### 9.1 ALERT# Pin Electrical Characteristics

The ALERT# pin (labeled EXT_CLK/INT in the Renesas datasheet) doubles as an external ADC clock input or a CPU interrupt output. Pin functionality is set through a control register bit.

| Parameter | Value |
|-----------|-------|
| Pin function | External ADC clock input **or** CPU interrupt output |
| Output type | Open-drain (when configured as interrupt output) |
| Open-drain voltage | 24V |
| Open-drain output current | 10mA |
| Active state | Pulls LOW when asserted (open-drain characteristic) |
| Pull-up requirement | External pull-up resistor to power supply, up to 20V |

From the Renesas datasheet:

> When the EXT_CLK/INT pin is configured as an output, the pin functionality becomes an interrupt flag to connecting devices. EXT_CLK/INT pin as an output requires a pull-up resistor to a power supply, up to 20V, for proper operation. The internal threshold detectors (OVsh/UVsh/OVb/UVb) signal level relative to the measured value determines the state of the INT pin.

**Implication for H1**: If ALERT# is wired to a MOSFET gate in the PoE output circuit, the pin pulling LOW would assert the interrupt and could disable power delivery. The open-drain topology means the pin can only pull LOW; it floats HIGH when inactive, relying on the external pull-up.

### 9.2 Relevant Register Map

| Address | Register Name | Function | POR Value | Access |
|---------|--------------|----------|-----------|--------|
| 0x07 | Bus Voltage Threshold | Min/Max VBUS thresholds | 0xFF00 | R/W |
| 0x08 | DCS Interrupt Status | Threshold interrupt flags | 0x0000 | R/W |
| 0x09 | Aux Control Register | Interrupt and clock control | 0x0000 | R/W |

### 9.3 Register 0x07 — Bus Voltage Threshold

Sets minimum and maximum VBUS voltage thresholds. When the measured bus voltage crosses these thresholds, an interrupt is generated and ALERT# asserts.

- **Range**: 0V to 60V (does not scale with BRNG setting)
- **LSB Resolution**: 256mV per LSB
- **POR Default**: 0xFF00

**Bit layout** (16-bit register):

| Bits | Field | Description |
|------|-------|-------------|
| 15-8 | Max threshold | Upper VBUS threshold (high byte) |
| 7-0 | Min threshold | Lower VBUS threshold (low byte) |

**Threshold calculation**: `voltage = register_value × 0.256V`

Example: Upper threshold 40V → `40.0 / 0.256 = 156.25` → 0x9C (high byte).

### 9.4 Register 0x08 — DCS Interrupt Status

Reports which threshold detectors have triggered (fault flags). The four internal comparators are:

| Detector | Meaning |
|----------|---------|
| OVsh | Shunt voltage over-voltage |
| UVsh | Shunt voltage under-voltage |
| OVb | Bus voltage over-voltage |
| UVb | Bus voltage under-voltage |

- **Read**: Check which flags are set
- **Write**: Writing clears the flags (write-to-clear behavior)
- **POR Default**: 0x0000

### 9.5 Register 0x09 — Aux Control Register

Controls interrupt generation and external clock functionality.

**Bit layout** (16-bit register):

| Bit(s) | Name | Description |
|--------|------|-------------|
| 0-5 | ExtCLKDiv | External clock divider (6 bits) |
| 6 | ExtClkEn | External clock enable |
| 7 | **INTREN** | **Interrupt enable** — set to enable ALERT# assertion on threshold violation; clear to disable |
| 8 | **FORCEINTR** | **Force interrupt** — set to 1 to force ALERT# LOW regardless of threshold status |
| 9-15 | resv | Reserved — must write 0 |

**Key bits for PoE testing**:

- **INTREN (bit 7)**: Master interrupt enable. When cleared, ALERT# will never assert regardless of threshold crossings. When set, any matching threshold condition triggers ALERT#.
- **FORCEINTR (bit 8)**: Software-forced interrupt. Setting this bit pulls ALERT# LOW immediately. Useful for verifying pin connectivity and MOSFET response without altering thresholds.

### 9.6 W0-2 Baseline Analysis

From W0-2 readings, both ISL28022 devices (0x3F and 0x40) show:

| Register | Read Value | POR Default | Interpretation |
|----------|-----------|-------------|----------------|
| 0x07 (Mask/Threshold) | **0x00FF** | 0xFF00 | Vendor-configured; byte-swapped from POR |
| 0x09 (Aux Control) | not explicitly read | 0x0000 | Assumed unchanged (no vendor override known) |

**Decoding 0x00FF for register 0x07**:

| Bits | Value | Meaning |
|------|-------|---------|
| 15-8 (max threshold) | 0x00 | Upper threshold = 0 × 0.256V = **0V** |
| 7-0 (min threshold) | 0xFF | Lower threshold = 255 × 0.256V = **65.28V** |

This inverts the expected threshold window: the upper threshold is below the lower threshold. In the ISL28022's comparator logic, this means the threshold window is effectively "always outside range" — the bus voltage (~29.6V) will always exceed the 0V upper threshold, keeping ALERT# in a steady state. The vendor may have deliberately set this to prevent spurious interrupts, or the register may be used differently than the datasheet implies (some ISL28022 variants repurpose this register as a mask/enable register).

**Practical implication**: With 0x00FF, ALERT# behavior is vendor-determined and stable. Changing this register carries risk.

### 9.7 Safe Test Value for H1

**Goal**: Modify registers to test whether ALERT# physically gates a PoE MOSFET, without disrupting power delivery.

**Test strategy**: Use register 0x09 FORCEINTR (bit 8) to manually assert ALERT# LOW and observe whether PoE output changes. This avoids changing thresholds entirely.

#### Step 1: Read current state

```bash
# Record baseline before any changes
i2cget -y 1 0x40 0x07 w    # Bus Voltage Threshold (expect 0x00FF)
i2cget -y 1 0x40 0x08 w    # DCS Interrupt Status (expect 0x0000)
i2cget -y 1 0x40 0x09 w    # Aux Control (expect 0x0000)
```

#### Step 2: Force ALERT# LOW via FORCEINTR

```bash
# Set bit 8 (FORCEINTR) in register 0x09
# Value: 0x0100 (bit 8 = 1, all others = 0)
i2cset -y 1 0x40 0x09 0x01 0x00

# ALERT# should now be LOW (asserted)
# Observe: does PoE output change? Does a connected device lose power?
```

#### Step 3: Release FORCEINTR (restore ALERT# HIGH)

```bash
# Clear FORCEINTR by writing 0x0000
i2cset -y 1 0x40 0x09 0x00 0x00

# ALERT# should return HIGH (released)
# Observe: does PoE output return?
```

#### Step 4: Restore baseline

```bash
# Ensure register 0x09 is 0x0000 (POR default)
i2cset -y 1 0x40 0x09 0x00 0x00

# Clear any latched interrupt flags in 0x08
i2cset -y 1 0x40 0x08 0x00 0x00

# Verify threshold register unchanged
i2cget -y 1 0x40 0x07 w    # Should still be 0x00FF
```

**Why FORCEINTR is the safest test**:

1. Does not change threshold register (0x07) — no risk of unexpected interrupt conditions
2. Does not enable INTREN — no risk of threshold-triggered interrupts after the test
3. Directly tests the ALERT# → MOSFET hypothesis with a single bit toggle
4. Fully reversible — clearing FORCEINTR releases ALERT# immediately

### 9.8 Restore Procedure

**Baseline values** (from W0-2):

| Register | Value | Notes |
|----------|-------|-------|
| 0x07 | 0x00FF | Vendor baseline (byte-swapped from POR 0xFF00) |
| 0x08 | 0x0000 | Clear all interrupt flags |
| 0x09 | 0x0000 | POR default, no interrupts enabled |

**Full restore**:

```bash
# Restore vendor threshold baseline
i2cset -y 1 0x40 0x07 0x00 0xFF

# Clear interrupt status
i2cset -y 1 0x40 0x08 0x00 0x00

# Clear aux control
i2cset -y 1 0x40 0x09 0x00 0x00

# Repeat for second ISL28022 at 0x3F
i2cset -y 1 0x3F 0x07 0x00 0xFF
i2cset -y 1 0x3F 0x08 0x00 0x00
i2cset -y 1 0x3F 0x09 0x00 0x00

# Verify
i2cget -y 1 0x40 0x07 w    # Expect 0x00FF
i2cget -y 1 0x3F 0x07 w    # Expect 0x00FF
```

### 9.9 Safety Rules

1. **ALWAYS read current register values before any modification**
2. **ALWAYS restore to baseline after testing** — the vendor set these values for a reason
3. **NEVER write non-zero to reserved bits (bits 9-15 of register 0x09)** — undefined behavior
4. **NEVER enable INTREN (bit 7) unless you intend to test threshold-triggered interrupts** — this can cause persistent ALERT# assertions
5. **Prefer FORCEINTR over threshold changes for initial testing** — it's a controlled, reversible single-bit test
6. **Verify device still powers on after restore** — check bus voltage reads ~29.6V
7. **Test one ISL28022 at a time** — if ALERT# gates a shared MOSFET, both chips may be involved
8. **Have a serial console or out-of-band access** — if PoE is how the test device is powered, an unexpected ALERT# assertion could lose your SSH session

### 9.10 Key Reference Summary

| Item | Value |
|------|-------|
| ALERT# pin type | Open-drain, active-low |
| Open-drain voltage | 24V |
| Open-drain current | 10mA |
| Pull-up required | External, up to 20V |
| Register 0x07 (vendor) | 0x00FF |
| Register 0x07 (POR) | 0xFF00 |
| Register 0x09 INTREN | Bit 7 |
| Register 0x09 FORCEINTR | Bit 8 |
| Vbus threshold range | 0V–60V |
| Vbus LSB | 256mV |
| Safe H1 test method | FORCEINTR (bit 8) toggle |
| Restore value (0x07) | 0x00FF (vendor baseline) |
| Restore value (0x08, 0x09) | 0x0000 (POR default) |
| ISL28022 addresses | 0x3F and 0x40 on I2C bus 1 |

---

## 10. Hypothesis Verdicts & Milestone A Summary

**Date**: 2026-05-20
**Scope**: Consolidation of all evidence from tasks A6 through A10.
**Outcome**: 24V passive PoE confirmed working on eth1. All 7 hypotheses resolved. PROCEED TO MILESTONE B.

### Verdict Summary

| Hypothesis | Description | Verdict | Key Evidence |
|-----------|-------------|---------|-------------|
| H1 | ISL28022 ALERT# gates MOSFET | **DISPROVEN** | A8 |
| H2 | Unknown GPIOs needed (master enable) | **DISPROVEN** | A10 |
| H3 | PHY must be powered on | **DISPROVEN** | A9 |
| H4 | GPIO_BIT_CFG tx_oe=0 prevents output | **DISPROVEN** (revised) | A6 |
| H5 | Full poe_st sequence has hidden steps | **CONFIRMED** (partial) | A7 |
| H6 | Pin-mux prevents GPIO function | **DISPROVEN** | W0-4, A10 |
| H7 | Hidden I2C PoE controller | **DISPROVEN** | W0-5 |

### H1: ISL28022 ALERT# Gates MOSFET — DISPROVEN

**Evidence**: A8 tested FORCEINTR (bit 8 of Aux Ctrl register 0x09) to force ALERT# LOW, and aggressive threshold settings (0x0028) that triggered DCS interrupt flags (0x0300). Neither condition produced a measurable change in PoE power delivery beyond thermal drift.

- FORCEINTR shifted shunt readings but the shift persisted after clearing FORCEINTR, indicating thermal drift, not ALERT# response.
- Threshold-triggered ALERT# (DCS=0x0300, bus voltage exceeding 10V threshold) caused zero shunt change.
- GPIO 4 remains the sole power-enable control.

**Implication**: The ISL28022 is purely a monitoring device. It measures current and voltage on the PoE rails but has no role in controlling power delivery. ISL28022 registers can be left at vendor defaults for normal operation.

### H2: Unknown GPIOs Needed (Master Enable) — DISPROVEN

**Evidence**: A10 tested all 20 GPIOs (0-19). Only GPIOs 3, 4 (eth1), 7, 10 (eth3), 9, 16 (eth4) are in the PoE GPIO table from disassembly. GPIOs 8, 13, 14, 18, 19 showed no ISL28022 response when toggled. GPIOs 11, 12, 15, 17 are claimed by kernel drivers (reset button, SFP detect, LEDs) and are confirmed non-PoE.

- GPIO 0 has tx_oe=1 at boot but is not in any PoE function list. It is not required for PoE operation on eth1 (confirmed by A7 positive result with GPIO 0 untouched).
- No GPIO outside the known mapping affects PoE power delivery.

**Implication**: No hidden master-enable GPIO exists. The 10 PoE GPIOs (5 ports x 2 functions) are the complete set. Per-port control is the only mechanism.

### H3: PHY Must Be Powered On — DISPROVEN

**Evidence**: A9 tested the VSC8504 PHY (MDIO address 6) in four states while GPIO 4 was HIGH: normal (aneg on), BMCR power-down (bit 11), admin down (`ip link set down`), and BMCR isolate (bit 10). ISL28022 shunt readings were identical across all states (~0x0A01-0x3401), confirming PoE current delivery was unaffected.

- PoE works with the PHY in power-down mode.
- PoE works with the interface administratively down.
- PoE works with the PHY in electrical isolation mode.

**Implication**: The PoE power path is electrically independent of the Ethernet PHY/MII circuit. The PoE driver does not need to initialize or check PHY state. PoE can be enabled at any time, even before PHY initialization completes.

### H4: GPIO_BIT_CFG tx_oe=0 Prevents Output — DISPROVEN (Revised)

**Evidence**: A6 discovered that the Wave 0 W0-3 finding was based on reading a **read-only mirror** region at offset `0x100 + n*8`. The actual BIT_CFG registers are at offset `0x00 + n*8`. When the kernel's `octeon_gpio` driver sets `direction=out` via sysfs, it writes `tx_oe=1` to the correct register. The gpio-reg-v2 module was reading the mirror, which always shows 0.

- BIT_CFG(4) at offset 0x020 reads 0x1 (tx_oe=1), not the 0x0 reported by the mirror at 0x120.
- The existing poe init script (`echo out > direction`) causes the kernel to set tx_oe=1 correctly.
- The original W0-3 finding was a false alarm caused by incorrect register offset in the diagnostic module.

**Implication**: tx_oe was never the problem. The Linux GPIO framework handles BIT_CFG correctly when pins are exported as outputs via sysfs. No manual BIT_CFG writes are needed.

### H5: Full poe_st Sequence Has Hidden Steps — CONFIRMED (Partial)

**Evidence**: A7 replayed the full `poe_st` sequence from A1 disassembly for `poe_st(port=2, value=2)` (eth1, 24V mode). The sequence calls both `er_gen2_set_poe_48v` and `er_gen2_set_poe_24v` with specific pre-disable and re-enable ordering.

However, the "hidden steps" are not I2C writes, MMIO writes, or register configuration. The full sequence is simply:
1. Pre-disable pair-mode (GPIO 3 CLEAR)
2. Pre-disable 24V (GPIO 4 CLEAR)
3. Ensure pair-mode off (GPIO 3 CLEAR, redundant)
4. Enable 24V (GPIO 4 SET)

The smoking gun is that step 4 alone (`echo 1 > /sys/class/gpio/gpio4/value`) is sufficient to enable 24V PoE. The pre-disable steps are defensive but not required when transitioning from a known-off state.

**Implication**: The production driver only needs per-port GPIO control: set HIGH to enable, set LOW to disable. No multi-step sequence is required.

### H6: Pin-Mux Prevents GPIO Function — DISPROVEN

**Evidence**: W0-4 confirmed all pair-mode pins (1, 3, 5, 7, 9) have `output_sel=0` (GPIO function). A10 verified all 20 GPIOs have `output_sel=0`. None are muxed to alternate functions.

**Implication**: Pin-mux is not and was never an issue. All PoE GPIOs are correctly configured for GPIO function by default.

### H7: Hidden I2C PoE Controller — DISPROVEN

**Evidence**: W0-5 performed exhaustive scans of both I2C buses (0 and 1) across all 128 addresses. Only the expected devices were found: two ISL28022 monitors at 0x3F and 0x40 on bus 1. No mystery device, no microcontroller, no additional power controller.

**Implication**: There is no I2C-controlled PoE switch on the ER-6P. The E301 board uses direct GPIO control exclusively.

---

### Smoking Gun: 24V Passive PoE on eth1

The MINIMUM steps to get 24V PoE working on eth1:

```bash
# 1. Export GPIO 4
echo 4 > /sys/class/gpio/export

# 2. Set direction (kernel sets tx_oe=1 automatically)
echo out > /sys/class/gpio/gpio4/direction

# 3. Enable 24V
echo 1 > /sys/class/gpio/gpio4/value

# 4. Disable 24V
echo 0 > /sys/class/gpio/gpio4/value
```

Three sysfs writes. No I2C. No PHY dependency. No register poking. No hidden initialization.

### GPIO-to-Port Mapping (Verified)

| GPIO | Port | Function | Verified By |
|------|------|----------|------------|
| 1 | eth0 (lan0) | 48V pair-mode | Disassembly (FORBIDDEN to test) |
| 2 | eth0 (lan0) | 24V power-enable | Disassembly (FORBIDDEN to test) |
| 3 | eth1 (lan1) | 48V pair-mode | A7 (kept LOW for 24V) |
| 4 | eth1 (lan1) | 24V power-enable | A6, A7 (MikroTik powered up) |
| 5 | eth2 (lan2) | 48V pair-mode | Disassembly (FORBIDDEN to test) |
| 6 | eth2 (lan2) | 24V power-enable | Disassembly (FORBIDDEN to test) |
| 7 | eth3 (lan3) | 48V pair-mode | A10 (no ISL28022 response, expected) |
| 9 | eth4 (lan4) | 48V pair-mode | A10 (no ISL28022 response, expected) |
| 10 | eth3 (lan3) | 24V power-enable | A10 (no ISL28022 response, no load) |
| 16 | eth4 (lan4) | 24V power-enable | A10 (no ISL28022 response, no load) |

### Non-PoE GPIOs (Confirmed)

| GPIO | Function | Verified By |
|------|----------|------------|
| 0 | Unknown (tx_oe=1 at boot, not PoE) | A10 |
| 8 | Unknown (not PoE, has pull-up) | A10 |
| 11 | Reset button (kernel claimed) | A10 |
| 12 | SFP mod-def0 (kernel claimed) | A10 |
| 13 | Unknown (not PoE, has pull-up) | A10 |
| 14 | Unknown (not PoE, has pull-up) | A10 |
| 15 | White power LED (kernel claimed) | A10 |
| 17 | Blue power LED (kernel claimed) | A10 |
| 18 | Unknown (not PoE, has pull-up) | A10 |
| 19 | Unknown (not PoE) | A10 |

### Evidence Completeness Check

| Check | Status |
|-------|--------|
| All 7 hypotheses evaluated | Pass (H1-H7 all classified) |
| H1 (ALERT#) tested with FORCEINTR + threshold triggers | Pass (A8, 5 phases) |
| H2 (unknown GPIOs) tested exhaustively | Pass (A10, all 20 GPIOs) |
| H3 (PHY) tested in 4 states | Pass (A9, normal/power-down/admin-down/isolate) |
| H4 (tx_oe) corrected with register offset fix | Pass (A6, mirror vs actual) |
| H5 (poe_st) replayed from disassembly | Pass (A7, MikroTik powered up) |
| H6 (pin-mux) verified output_sel=0 for all pins | Pass (W0-4, A10) |
| H7 (hidden I2C) excluded by bus scan | Pass (W0-5) |
| 24V PoE confirmed working with real hardware | Pass (A7, MikroTik SXTsq 5 ac) |
| GPIO control reversible | Pass (A6, A7, multiple toggle cycles) |
| No regression in router functionality | Pass (LED, reset, SFP all working) |

---

### Decision: PROCEED TO MILESTONE B

**Rationale**: 24V PoE confirmed working on eth1 via simple GPIO control. All hypotheses resolved. The mechanism is fully understood and documented: three sysfs writes to enable 24V PoE. No I2C dependency, no PHY dependency, no hidden initialization. The production driver path is clear.

**Evidence Files**:
- `.sisyphus/evidence/openwrt-er6p-poe/a6-h4-test-result.md`
- `.sisyphus/evidence/openwrt-er6p-poe/a7-summary.md`
- `.sisyphus/evidence/openwrt-er6p-poe/a8-h1-alert-test-results.md`
- `.sisyphus/evidence/openwrt-er6p-poe/a9-h3-phy-state-result.md`
- `.sisyphus/evidence/openwrt-er6p-poe/a10-gpio-test-results.md`
- `.sisyphus/evidence/openwrt-er6p-poe/a10-gpio-inventory.md`

---

## 11. Hypothesis Verdicts: Final Summary

**Date**: 2026-05-20
**Scope**: All hypotheses H1-H7 with final verdicts after complete evidence collection.

### Final Verdict Table

| Hypothesis | Description | Wave 0 Rank | Final Verdict | Key Evidence |
|-----------|-------------|-------------|---------------|-------------|
| H1 | ISL28022 ALERT# gates MOSFET | POSSIBLE | **REJECTED** | A8: FORCEINTR and threshold triggers had no effect on power delivery |
| H2 | Unknown GPIOs needed (master enable) | UNLIKELY | **REJECTED** | A10: all 20 GPIOs tested, only mapped PoE GPIOs have effect |
| H3 | PHY must be powered on | POSSIBLE | **REJECTED** | A9: PoE works with PHY in power-down, admin-down, and isolate modes |
| H4 | GPIO_BIT_CFG tx_oe=0 prevents output | CONFIRMED | **CORRECTED** | A6: mirror region confusion. Real on cold boot (E1), not on warm boot |
| H5 | Full poe_st sequence needed | LIKELY | **CONFIRMED** | A7: smoking gun found. Pre-disable + re-enable sequence works |
| H6 | Pin-mux prevents GPIO function | REJECTED | **REJECTED** | W0-4, A10: all pins have output_sel=0 (GPIO function) |
| H7 | Hidden I2C PoE controller | REJECTED | **REJECTED** | W0-5: exhaustive scan found only ISL28022 monitors |

### H4 Evolution

H4 went through three phases:

1. **Wave 0 (CONFIRMED)**: W0-3 found all PoE GPIOs with tx_oe=0. Seemed like the root cause.
2. **Milestone A (DISPROVEN/CORRECTED)**: A6 found the diagnostic module was reading a read-only mirror. The actual registers had tx_oe=1 when pins were exported via sysfs. The warm-boot PoE script worked because the kernel's `octeon_gpio` driver sets tx_oe=1 on `direction=out`.
3. **Milestone E (REAL BUG)**: On cold boot with the kernel module (no prior sysfs exports), all BIT_CFG registers are at hardware reset (tx_oe=0). EdgeOS handles this in `ubnt_platform.ko` module init. The production driver must also handle it. Fix: `er6p_poe_gpio_init()` explicitly sets tx_oe=1 for all PoE GPIOs.

The takeaway: H4 was a real issue, but it only manifested on cold boot. The Wave 0 evidence was technically correct (tx_oe=0 at hardware reset) but was masked during warm testing by the kernel's sysfs GPIO framework.

---

## 12. Smoking-Gun Sequence

The minimum sequence to get 24V passive PoE working on eth1, verified with a MikroTik SXTsq 5 ac as PoE load:

```
1. Clear 48V pair-mode GPIO: TX_CLEAR (1 << GPIO 3)
2. Clear 24V power-enable GPIO: TX_CLEAR (1 << GPIO 4)
3. Set 24V power-enable GPIO HIGH: TX_SET (1 << GPIO 4)
```

Step 3 is the critical action. Steps 1 and 2 are defensive, ensuring a clean transition from any prior state. When starting from a known-off state (cold boot, all GPIOs LOW), step 3 alone is sufficient.

In sysfs terms (legacy approach, not used by production driver):

```bash
echo 4 > /sys/class/gpio/export
echo out > /sys/class/gpio/gpio4/direction
echo 1 > /sys/class/gpio/gpio4/value
```

In production driver terms (via the er6p-poe module):

```bash
echo 1 > /sys/kernel/er6p_poe/eth1/enable
```

The production driver's enable path (`er6p_poe_enable` in `er6p-poe-engine.c`) executes the full three-step sequence: clear 48V, clear 24V, set 24V. This matches the EdgeOS `poe_st` mode 2 path from the disassembly.

---

## 13. GPIO_BIT_CFG Cold-Boot Bug

### Problem

On a cold boot, the Cavium Octeon III GPIO controller resets all BIT_CFG registers to 0x0. This means `tx_oe = 0` for every GPIO pin. The output driver is disabled, and writes to TX_SET/TX_CLEAR are no-ops.

Under EdgeOS, the `ubnt_platform.ko` module configures tx_oe during module init. Under OpenWrt, if no driver sets tx_oe, the GPIOs remain in reset state and PoE control has no effect.

### Discovery Timeline

- **W0-3**: Initial discovery that all PoE GPIOs had tx_oe=0. Led to H4 hypothesis.
- **A6**: Correction that W0-3 was reading a mirror region. Actual registers had tx_oe=1 on warm boot (set by sysfs `direction=out`).
- **E1**: Cold-boot test confirmed the real bug. Without sysfs GPIO exports, tx_oe stays 0.

### Fix

The production driver's `er6p_poe_gpio_init()` function:

1. `ioremap` the GPIO controller base at `0x1070000000800`
2. For each allowlisted port's 24V and 48V GPIOs:
   - Read current BIT_CFG value and save it
   - Set bit 0 (tx_oe=1) and clear bits 8-9 (output_sel=0, GPIO function)
   - Write back
3. On module unload, restore the saved values

This ensures PoE works on cold boot without depending on sysfs GPIO exports.

---

## 14. ISL28022 Byte-Swap Discovery

### The Problem

Reading ISL28022 registers via `i2cget -y 1 0x3F 0x01 w` returns values that need byte-swapping before they can be interpreted as current or voltage readings.

### Root Cause

The ISL28022 stores data in big-endian format (MSB first). The SMBus word protocol transmits data little-endian (LSB first). The `i2cget` command with the `w` flag performs an SMBus word read, which involves a byte swap on the wire. On a big-endian MIPS64 host, the kernel i2c driver does the SMBus protocol swap, resulting in the raw `i2cget` output having swapped bytes compared to the register's native value.

### Example

Raw shunt reading: `i2cget -y 1 0x3F 0x01 w` returns `0xf500`

1. Byte-swap: `0xf500` becomes `0x00f5` (245 decimal)
2. Shunt voltage = 245 * 10uV = 2450uV = 2.45mV
3. With R_shunt = 0.05 ohm: current = 2.45mV / 0.05ohm = 49mA

The `poe-watchdog` and `poe-monitor` scripts handle this swap explicitly in shell:

```sh
lo=$((val & 255))
hi=$(((val >> 8) & 255))
val=$(((lo << 8) | hi))
```

The `poe` CLI tool's `read_current_ma` function uses the same swap logic.

---

## 15. Mode Encoding Verification

The PoE mode encoding was verified by cross-referencing three independent sources:

1. **Binary disassembly** (`poe_st`): The value dispatch table at addresses 0x1810-0x1830 maps value 0 to all-off, value 1 to 48V-on, value 2 to 24V-on, value 5 to both-on.
2. **EdgeOS HAL** (`ubnt-hal-e`): The `pportSetPoe` function validates `mode < 6` and writes the integer to sysfs.
3. **Live testing** (A7): Writing value 2 (24V mode) to the sysfs `poe` attribute produced 24V output on eth1, confirmed with a MikroTik PoE device.

All three sources agree on the encoding.

---

## 16. Why We Never Submitted Upstream

The operator's constraints prevent submitting this work to the OpenWrt project:

1. **Port allowlist**: eth0 and eth2 are permanently blocked. An upstream submission would need to support all 5 PoE-capable ports, but the operator refuses to allow PoE on eth0 (WAN) and eth2 (management). Submitting a driver that artificially restricts ports would not be accepted.

2. **Testing scope**: Only eth1 was tested with a live PoE load. eth3 and eth4 were toggled but not verified with load. Upstream requires testing on all supported ports.

3. **ISL28022 driver**: The I2C power monitoring layer is a stub. A complete upstream submission would need a kernel-mode ISL28022 driver with interrupt-driven overcurrent protection.

4. **No 48V support**: The ER-6P's PSU only delivers ~29.6V. 48V mode is untested. An upstream driver would be expected to support all modes the hardware claims to support.

5. **User constraint on testing**: The operator forbids testing PoE on eth0 and eth2. This means we cannot verify the GPIO mapping for those ports with live hardware, which upstream would require.

This work remains a local, operator-specific deployment. The reverse engineering findings and driver architecture are documented here for reference and potential reuse by others.

---

## 17. Next Steps If Regression

If PoE stops working after a firmware update or configuration change, follow this diagnostic sequence:

### Step 1: Check module loaded

```bash
lsmod | grep er6p_poe
```

If not loaded, try `insmod /tmp/er6p-poe.ko` and check `dmesg` for errors.

### Step 2: Check BIT_CFG

```bash
cat /sys/kernel/debug/er6p_poe/registers
```

If debugfs is not mounted:

```bash
mount -t debugfs none /sys/kernel/debug
```

The TX_SET register should show the bit for the enabled port. If all registers show 0, the GPIO controller mapping failed.

### Step 3: Check kernel version

```bash
uname -r
```

If the kernel version changed (firmware update), the module must be rebuilt against the new kernel headers. The vermagic must match exactly.

### Step 4: Check I2C

```bash
i2cget -y 1 0x3F 0x02 w
```

If this fails, the I2C bus is not available. Voltage and current monitoring won't work, but PoE control should still function (it's pure GPIO).

### Step 5: Manual GPIO test

As a last resort, test raw GPIO control:

```bash
echo 4 > /sys/class/gpio/export 2>/dev/null
echo out > /sys/class/gpio/gpio4/direction
echo 1 > /sys/class/gpio/gpio4/value
cat /sys/class/gpio/gpio4/value
```

If this works, the GPIO hardware is fine. The issue is in the driver or sysfs interface. If it doesn't work, the GPIO controller may be in an unexpected state. Try a reboot.

### Step 6: Dmesg audit

```bash
dmesg | grep -i "er6p-poe\|gpio\|octeon"
```

Look for error messages about ioremap failures, unknown symbols, or register access problems.

---

## 18. Driver Architecture Summary

The production `er6p-poe` driver (v0.4.0) consists of these components:

| Component | File | Purpose |
|-----------|------|---------|
| Main | `er6p-poe.c` | Module init/exit, orchestrator |
| GPIO | `er6p-poe-gpio.c/h` | ioremap, BIT_CFG setup, TX_SET/TX_CLEAR writes |
| Engine | `er6p-poe-engine.c/h` | State machine, power budget, enable/disable logic |
| Sysfs | `er6p-poe-sysfs.c/h` | `/sys/kernel/er6p_poe/` interface |
| Debugfs | `er6p-poe-debugfs.c/h` | Register dump and state summary |
| I2C | `er6p-poe-i2c.c/h` | ISL28022 placeholder (stub) |
| Types | `er6p-poe-types.h` | Enums and data structures |
| Allowlist | `er6p-poe-allowlist.h` | Hard port allowlist + GPIO mapping table |

The enable path: sysfs write -> engine (budget check) -> GPIO layer (allowlist check + register write).

### Userspace Components

| Component | Purpose |
|-----------|---------|
| `poe` | CLI tool for enable/disable/status/list/debug |
| `poe.init` | Procd init script for boot persistence |
| `poe.config` | UCI configuration file |
| `poe-watchdog` | Overcurrent polling daemon (ISL28022) |
| `poe-monitor` | Voltage/current export to /run/poe/ |

---

## 19. Lessons Learned

1. **Read-only mirror regions exist.** The Cavium Octeon GPIO controller has mirror copies of BIT_CFG registers at offset 0x100. These are read-only and always show reset values. Reading from the wrong region produces misleading diagnostic data. Always verify register offsets against the kernel source (`gpio-octeon.c`), not just the HRM.

2. **Cold boot vs warm boot matters.** The Wave 0 finding that "all PoE GPIOs have tx_oe=0" was correct at hardware reset but masked during warm testing by the kernel's sysfs GPIO framework. The real bug only showed on cold boot. Always test both paths.

3. **The simplest hypothesis was correct.** H5 (the full sequence is just GPIO writes) turned out to be right. No I2C, no PHY, no hidden initialization. Just three GPIO register writes. The complexity was in discovering the correct sequence, not in the mechanism itself.

4. **EdgeOS uses direct sysfs writes.** No socket protocol, no shared memory, no ioctl. The HAL writes an integer to a sysfs file and reads it back to verify. This made the OpenWrt implementation straightforward once the GPIO mapping was understood.

5. **ISL28022 is a monitor, not a controller.** The ALERT# pin has no effect on PoE power delivery. The chip measures current and voltage but does not gate the MOSFET. This eliminated a significant class of potential failure modes.

6. **The allowlist is a feature, not a limitation.** Forcing eth0 and eth2 to be permanently blocked prevents a whole category of operational mistakes. The dual-layer enforcement (kernel + userspace + compile-time assert) makes it impossible to accidentally cut power to the WAN or management port.

7. **Power budget is a software concern.** The ER-6P PSU can deliver enough power for all 3 allowed ports simultaneously, but the driver enforces a budget to prevent overheating. The budget is configurable and the accounting is straightforward (increment on enable, decrement on disable).
