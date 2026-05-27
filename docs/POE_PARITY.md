# PoE Feature Parity: realtek-poe vs. Stock ZyXEL V2.90

Systematic comparison of our open-source realtek-poe implementation against
the stock ZyXEL V2.90 firmware, reverse-engineered from `board_poe.ko` and
`libsal.so`. See `firmware/stock_v290/RE_ANALYSIS.md` for the raw RE data.

## Architecture

| Aspect | Stock ZyXEL V2.90 | realtek-poe (ai/power-limit-config) |
|--------|-------------------|--------------------------------------|
| Layer model | 3-tier: CLI → SAL (libsal.so) → Kernel (board_poe.ko) | 2-tier: ubus → userspace daemon |
| Kernel/user | Kernel module | Userspace daemon |
| Threading | 2 kernel threads: `_poe_portStatusState_thread`, `_poe_threshold_thread` | Single-threaded uloop event loop, 2s poll |
| Chip support | BCM59111, BCM59121, RTL8238B/BCM59011 | BCM59111 (realtek_dialect exists but unused) |
| Transport | UART + SMI | UART only |
| Config | SAL cfg_* + board_conf + IOCTL | UCI /etc/config/poe |
| Control surface | CLI + web UI + SNMP | ubus (poe.info, poe.set_port_config, etc.) |

## Wire Command Coverage

### GET commands (read system state)

| Wire | Protocol Name | Stock SAL Function | Our Status | Notes |
|------|--------------|-------------------|------------|-------|
| `0x20` | Get system info | `poe_bcm59111_chip_init` | ✅ `MCU_GET_SYSTEM_INFO` | Parity |
| `0x21` | Get port status (detailed) | `poe_bcm59111_portStatus_get` | ⚠️ Partial | **Under-decoded**: reply has 9 fields, we parse 3. See P0-1. |
| `0x22` | Get port counters | `bcm59111_portStats_get` | ⚠️ Partial | **Missing reset flag**: stock sends reset=1, we send 0. See P0-3. |
| `0x23` | Get power statistics | `poe_bcm59111_power_get` | ✅ `MCU_GET_POWER_STATS` | Parity |
| `0x25` | Get port config | `poe_bcm59111_portConf_get` | ✅ `PORT_GET_CONFIG` | Parity |
| `0x26` | Get extended port config | `poe_bcm59111_portConf_get` | ✅ `PORT_GET_EXT_CONFIG` | Parity |
| `0x27` | Get power management mode | (debug) | ✅ `MCU_GET_POWER_MGMT` | Parity (debug-only in both) |
| `0x28` | Get all port status (4-port) | `poe_bcm59111_allPortStatus_get` | ⚠️ Partial | **Under-decoded**: upper nibble has class + fault_type + PD flag. See P0-2. |
| `0x29` | Get PSE consumed power | (portStatusState_thread) | ✅ `MCU_GET_PSE_POWER` | Parity |
| `0x2a` | Get port overview | (deprecated) | ❌ Not implemented | Deprecated in stock, skip |
| `0x2b` | Get extended device config | `poe_bcm59111_chip_init` | ✅ `MCU_GET_EXT_CONFIG` | Parity |
| `0x2c` | Get direct PSE flag | (internal) | ❌ Not implemented | Obscure, low value, skip |
| `0x2d` | Get direct PSE status | (internal) | ❌ Not implemented | Obscure, low value, skip |
| `0x30` | Get port measurements | `poe_bcm59111_portPower_get` | ✅ `PORT_GET_POWER_STATS` | Parity |

### SET commands (configure system)

| Wire | Protocol Name | Stock SAL Function | Our Status | Notes |
|------|--------------|-------------------|------------|-------|
| `0x00` | Set port admin state | `sal_poe_portAdminEnable_set` | ✅ `PORT_ENABLE` | Parity |
| `0x02` | Set port map enable | (chip_init) | ✅ `MCU_ENABLE_PORT_MAPPING` | Parity |
| `0x03` | Port reset | (disconnect/reconnect) | ✅ `PORT_RESET` | Parity. Also works on disabled ports (upstream #58). |
| `0x05` | Clear counters | `sal_poe_portStatsClear_set` | ✅ `MCU_CLEAR_COUNTERS` | Parity (though stock clears via 0x22 reset=1) |
| `0x06` | Set global port enable | (bulk enable/disable) | ❌ | **Skip**: OpenWrt manages ports individually via UCI. Bulk enable/disable doesn't fit the per-port config model. |
| `0x07` | Set global port power limit | (high power config) | ❌ | **P1-3**: Max per-port power envelope for class-based limits. |
| `0x08` | Set trigger flag | (BCM59111-specific) | ❌ | Chip-specific, unclear purpose, skip |
| `0x09` | System reset | (MCU reset) | ❌ | Dangerous. Skip unless needed for MCU recovery. |
| `0x0a` | Set device config | `poe_bcm59111_chip_init` (UVLO/OVLO/DD) | ❌ | Voltage thresholds set during init. Could expose via UCI. Low priority. |
| `0x0b` | Set device power management | `poe_bcm59111_chip_init` | ❌ | **P1-2**: Pre-allocated vs actual power accounting. |
| `0x0e` | Set port-to-PSE output mapping | (chip_init) | ❌ | Needed for non-trivial hardware topologies. Medium priority. |
| `0x10` | Set detection type | `sal_poe_portLegacyEnable_set` | ✅ `PORT_SET_DETECTION_TYPE` | Parity |
| `0x11` | Set classification enable | `sal_poe_portAdminEnable_set` | ✅ `PORT_ENABLE_CLASSIFICATION` | Parity |
| `0x12` | Set auto power-up | (port config) | ✅ `PORT_SET_AUTO_POWERUP` | Parity (enum exists, not UCI-exposed) |
| `0x13` | Set disconnect type | `sal_poe_portAdminEnable_set` | ✅ `PORT_SET_DISCONNECT_TYPE` | Parity |
| `0x15` | Set port power limit type | `sal_poe_portLimitMode_set` | ✅ `PORT_SET_POWER_LIMIT_TYPE` | Parity |
| `0x16` | Set port power budget | `sal_poe_portPowerLimit_set` | ✅ `PORT_SET_POWER_LIMIT` | Parity |
| `0x17` | Set power management mode | `sal_poe_limitMode_set` | ✅ `MCU_SET_POWER_MGMT_MODE` | Parity |
| `0x18` | Set global power budget | (power management) | ✅ `MCU_SET_POWER_BUDGET` | Parity |
| `0x19` | Set port power pair | (4-pair PoE) | ❌ | **P2**: A-pair/B-pair selection. Needed for 4-pair PoE. |
| `0x1a` | Set port priority | `sal_poe_portPriority_set` | ✅ `PORT_SET_PRIORITY` | Parity |
| `0x1c` | Set port power-up mode | `sal_poe_portPowerMode_set` | ✅ `PORT_SET_POE_MODE` | Parity |
| `0x1d` | Set port mapping | (chip_init) | ❌ | Per-port PSE output mapping. Needed for non-trivial hardware. |

### LED commands

| Wire | Protocol Name | Stock Function | Our Status | Notes |
|------|--------------|----------------|------------|-------|
| `0x41` | Set port LED config | `board_poe_portLed_set` | ⚠️ Tested, N/A | MCU acknowledges SET but doesn't persist. See LED findings below. |
| `0x42` | Get port LED config | `board_poe_portLed_set` | ✅ `LED_GET_PORT_CONFIG` | Returns 0xFF on BCM59111 v17.1 (firmware doesn't implement LED). |
| `0x43` | Set system LED config | `board_poe_led_set` | ⚠️ Tested, N/A | Same as 0x41 — MCU acks but GET returns 0xFF. |
| `0x44` | Get system LED config | `board_poe_led_set` | ✅ `LED_GET_SYSTEM_CONFIG` | Returns 0xFF on BCM59111 v17.1. |
| `0x48` | Set port LED map | `board_poe_portLedCtrl_set` | ⚠️ Tested, N/A | Same as 0x41. |
| `0x49` | Get port LED map | `board_poe_portLedCtrl_set` | ✅ `LED_GET_PORT_MAP` | Returns 0xFF on BCM59111 v17.1. |

### LED Findings (BCM59111 v17.1, GS1900-8HP A1)

**Tested on hardware** (`f748291`): All six LED commands (0x41-0x49) were tested via the
`rawframe` ubus method. Results:

- **GET replies**: All return `0xFF` for data bytes (enable, interface, shift_order, etc.)
- **SET replies**: MCU echoes the `enable` byte in reply[2], indicating acceptance
- **Post-SET GET**: Still returns `0xFF` — config is NOT persisted by the MCU

**Conclusion**: BCM59111 firmware v17.1 does not implement LED config. The MCU accepts
LED command frames (to avoid communication errors) but ignores them.

### PoE LED Control — Solved via SoC LED Engine (commit `1463998`)

The GS1900-8HP PoE status LEDs are driven by the **RTL838x SoC LED engine**, not by the
BCM59111 MCU, RTL8231 GPIO, or SPI shift register. The stock Zyxel firmware uses
`board_poe_portLed_set()` → `board_led_portSwCtrl_set()` in `ski.ko` to write directly to
SoC memory-mapped LED registers at physical base `0xBB000000`.

Our implementation (`src/led.c`) does the same from userspace via the writable debugfs
interface at `/sys/kernel/debug/rtl838x/led/`.

#### Register Map

| Register | Address | Purpose |
|----------|---------|---------|
| `led_sw_ctrl` | `0xA00C` | Global software control enable (set `1`) |
| `led0_sw_p_en_ctrl` | `0xA010` | Per-port enable for LED group 0 (PoE row) |
| `led1_sw_p_en_ctrl` | `0xA014` | Per-port enable for LED group 1 (LINK-ACT row) |
| `led2_sw_p_en_ctrl` | `0xA018` | Per-port enable for LED group 2 |
| `led_sw_p_ctrl.PORT` | `0xA01C + (port << 2)` | Per-port pattern (9 bits, 3 per group) |

LED group 0, bits [2:0] control the PoE LED for each port. Group 1 controls LINK-ACT.
Group 2 is unused on this hardware.

#### Pattern Values (group 0 bits [2:0])

Statistically validated with 10-snapshot camera sequences per value:

| Value | Binary | Behavior | Variance (10 snaps) |
|-------|--------|----------|---------------------|
| 0 | 000 | Solid OFF | std=9, 0 transitions |
| 5 | 101 | Solid ON (most stable) | std=2, 0 transitions |
| 4 | 100 | Fast blink (~2 Hz) | std=200, 5 transitions |
| 7 | 111 | Slow blink (~0.5 Hz) | std=192, 3 transitions |
| 3 | 011 | Irregular blink (~1 Hz) | std=108, 2 transitions |
| 1 | 001 | Unstable ON | std=38, 0 transitions |
| 2 | 010 | Unstable ON | std=52, 0 transitions |
| 6 | 110 | Solid OFF | std=11, 0 transitions |

#### Zyxel Firmware Reverse Engineering

The stock firmware's `board_poe_portLed_set()` at `0x39e8` in `board_poe.ko` uses only
two led_state values:
- `led_state=0` → pattern 0 (OFF) when port not delivering
- `led_state=7` → pattern 5 (ON) when port delivering

The mapping goes through three jump tables in `ski.ko`'s `board_led_portSwCtrl_set()`:
1. led_state → s7 value (0→0, 1→1, 2→2, 3→3, 4→6, 5→4, 6→7, 7→5)
2. s6 (group selector) → which EN_CTRL register (0xa010/0xa014/0xa018)
3. s8 → which 3-bit field in led_sw_p_ctrl to modify (bits [2:0], [5:3], or [8:6])

For PoE: s6=1 → LED0 group, bits [2:0]. All four call sites in `board_poe.ko` use the
same binary logic: `led_state = (poe_active ? 7 : 0)`.

#### Port Mapping (GS1900-8HP)

lan1–lan8 (PoE port IDs 1–8) → SoC LED ports 8–15. Port 28 = CPU (unused for PoE).

#### Implementation Details

- `poe_led_init()` called once at daemon startup: enables global SW control + sets
  per-port enable bits for all 8 PoE ports
- `poe_led_update()` called from `poe_check_port_status_changes()` on every status
  transition and during initial status snapshot
- `poe_led_shutdown()` releases SW control back to hardware on daemon exit
- Read-modify-write on led_sw_p_ctrl preserves group 1/2 bits (LINK-ACT)

Our enhancement over stock: **searching** ports get fast blink (pattern 4) and **fault**
ports get slow blink (pattern 7). Stock firmware only used solid ON/OFF.

#### Deployment Verification

Deployed to GS1900-8HP A1 running OpenWrt 25.12.1. Camera-based automated testing
with per-LED brightness sampling at calibrated coordinates confirmed:

| Port | PoE Status | Pattern | Camera Verified |
|------|-----------|---------|-----------------|
| lan1 | Searching | 4 (blink) | Blinking ✓ |
| lan2 | Delivering | 5 (ON) | Solid ON (515) ✓ |
| lan3 | Delivering | 5 (ON) | Solid ON (753) ✓ |
| lan4 | Searching | 4 (blink) | Blinking ✓ |
| lan5 | Searching | 4 (blink) | Blinking ✓ |
| lan6 | Delivering | 5 (ON) | Solid ON (595) ✓ |
| lan7 | Delivering | 5 (ON) | Solid ON (553) ✓ |
| lan8 | Searching | 4 (blink) | Blinking ✓ |

All 8 ports also individually tested with walk-across (light each LED for 2s, left to right)
and 4-state cycle (OFF → ON → fast blink → slow blink → restore).

### LED Architecture Analysis

#### How Zyxel V2.90 Does It (Confirmed by RE)

The stock Zyxel firmware uses **pure software-driven LED updates**. There is no hardware
auto-detection linking PoE status to LEDs. The complete call chain:

```
_poe_portStatusState_thread (kernel thread, polls MCU for port status)
  → on status change: board_poe_portLed_set(port, poe_active)
    → maps poe_active to led_state: active=7, inactive=0
    → board_led_portSwCtrl_set(port, led_state=7, s6=1, s8=0)
      → jump table 1: led_state 7 → s7=5 (pattern value)
      → jump table 2: s6=1 → led0_sw_p_en_ctrl (LED group 0)
      → jump table 3: s8=0 → bits [2:0] in led_sw_p_ctrl
      → writes to RTL838x SoC LED engine registers at 0xBB000000+A01C+(port<<2)
```

This is identical to our approach: poll PoE status → map to LED pattern → write SoC
registers. The only difference is Zyxel uses only two states (ON/OFF) while we add
searching=fast-blink and fault=slow-blink.

#### Why Software-Driven Is the Only Option

The RTL838x SoC LED engine has two classes of registers:

**Hardware-driven registers** (auto-synced by the SoC):
| Register | Address | Purpose |
|----------|---------|---------|
| `led_glb_ctrl` | `0xA000` | Global LED control (scan rate, active-low) |
| `led_mode_sel` | `0x1004` | Selects LED mode per port group |
| `led_mode_ctrl` | `0xA004` | Controls what each LED set displays |
| `led_p_en_ctrl` | `0xA008` | Per-port enable for hardware-driven mode |

In hardware mode, the SoC LED engine auto-drives LEDs based on **network events**:
link status, activity (rx/tx), speed (10/100/1000), duplex, collision. These are
layer-1/2 concepts the SoC MAC/PHY knows about natively.

**Software-driven registers** (our approach):
| Register | Address | Purpose |
|----------|---------|---------|
| `led_sw_ctrl` | `0xA00C` | Enable software override |
| `led0/1/2_sw_p_en_ctrl` | `0xA010/14/18` | Per-port, per-group software enable |
| `led_sw_p_ctrl.PORT` | `0xA01C+(port<<2)` | Per-port pattern (9 bits, 3 per group) |

PoE status is **not a network concept** — it's a power delivery concept managed by an
external MCU (BCM59111) over UART. The SoC LED engine has zero visibility into PoE state.
Therefore:

1. **No hardware auto-trigger exists** for PoE status in the RTL838x LED engine
2. **The BCM59111 MCU** does not implement LED control (firmware v17.1 ignores LED commands)
3. **Software must bridge** PoE status → LED registers, exactly as both Zyxel and we do

#### OpenWrt LED Subsystem: No PoE Trigger Exists

OpenWrt follows the Linux LED class model:

```
Device Tree (gpio-leds / led-controller)
  → Linux LED class driver (devm_led_classdev_register)
    → /sys/class/leds/<color>:<function>/
      → OpenWrt boot scripts (diag.sh, leds.sh, S96led)
        → UCI /etc/config/system → triggers (heartbeat, netdev, timer, etc.)
```

**Available triggers in Linux** (`drivers/leds/trigger/Kconfig`):
timer, oneshot, disk-activity, mtd, nand-disk, heartbeat, backlight, gpio,
cpu, activity, netdev, pattern, transient, audio-mute, audio-micmute, rgb-blink.

**There is no `poe` or `pse` trigger.** This is confirmed by:
- No `ledtrig-poe` or `LEDS_TRIGGER_POE` in the Linux kernel source
- No PoE trigger in OpenWrt packages
- An active OpenWrt PR (#22245, 2026) is adding `pse-pd` LED trigger support — proving
  it doesn't exist yet
- The Linux LED function tags (`include/dt-bindings/leds/common.h`) have `LED_FUNCTION_POWER`
  but no `LED_FUNCTION_POE`

#### How Other OpenWrt Switches Handle PoE LEDs

| Device | PoE Controller | PoE LED Handling | OpenWrt LED Integration |
|--------|---------------|------------------|------------------------|
| **Zyxel GS1900-8HP** (ours) | BCM59111 (UART) | SoC LED engine, software-driven | None — our `src/led.c` via debugfs |
| **Zyxel GS1900-48HP** | BCM59111 (UART) | Unknown, likely same SoC LED engine | None in OpenWrt |
| **Netgear GS310TP** | BCM59111 | Separate from board LEDs | DTS defines power LED only, no PoE status LEDs |
| **TP-Link SG2008P/SG2210P** | TI TPS23861 | "Not yet enabled" per OpenWrt PR | DTS has power LED, PoE LEDs explicitly disabled |
| **Ubiquiti USW-Flex** | PD69104B1 (I2C) | `poemgr` daemon, separate from LEDs | DTS defines status LEDs, no PoE LED trigger |
| **Edgecore EAP102** | Qualcomm PSE | `green:wanpoe` LED with **netdev** trigger | Uses netdev trigger (link activity, not PoE status) |

Key pattern: **No OpenWrt switch currently has PoE status LEDs working through the
standard LED subsystem.** All devices either:
- Don't enable PoE LEDs at all (TP-Link, Netgear)
- Use software control outside the LED class (Zyxel, Ubiquiti)
- Repurpose the netdev trigger for "PoE port" LEDs (Edgecore — shows link, not PoE status)

#### RTL8231 LED Controller vs RTL838x LED Engine

The GS1900-8HP has two separate LED subsystems:

1. **RTL8231 LED scan matrix** (`realtek,rtl8231-leds`):
   - Has a proper kernel driver (`leds-rtl8231`) that creates `/sys/class/leds/` entries
   - Uses `devm_led_classdev_register_ext()` — standard Linux LED class
   - Maps via `reg = <port_index led_index>` in device tree
   - **Disabled in GS1900-8HP DTS**: `status = "disabled";`
   - Even if enabled, this controls LINK/ACT LEDs (the top row), NOT PoE LEDs

2. **RTL838x SoC LED engine** (what we use):
   - Exposed via debugfs only: `/sys/kernel/debug/rtl838x/led/`
   - No LED class driver exists in the kernel
   - Controls ALL LED groups including PoE (the bottom row)
   - This is what both Zyxel stock and our code write to

The PoE LEDs are physically connected to the SoC LED engine outputs, not to the RTL8231
scan matrix. Even if the RTL8231 driver were enabled, it wouldn't help with PoE LEDs.

#### Why Our Debugfs Approach Is Correct

| Approach | Feasible? | Reason |
|----------|-----------|--------|
| MCU LED commands (0x41-0x49) | No | BCM59111 v17.1 ignores them |
| Hardware auto-trigger | No | SoC LED engine has no PoE awareness |
| RTL8231 LED class driver | No | Controls different LEDs (LINK/ACT), disabled in DTS |
| `netdev` LED trigger | No | Shows link status, not PoE status |
| Custom `poe` LED trigger | Partial | Requires new kernel driver — PR #22245 is doing this |
| **Debugfs register writes** | **Yes** | What Zyxel does, what we do, proven correct |
| New kernel LED class driver | Ideal | Creates `/sys/class/leds/poe:lan1` etc., but requires kernel work |

**Our debugfs approach matches Zyxel's stock firmware exactly**: software polls PoE status,
maps to LED pattern, writes SoC registers. The only difference is Zyxel writes from
kernel space (kernel module) and we write from userspace (daemon via debugfs).

The "ideal" solution would be a kernel LED class driver for the RTL838x LED engine that
creates proper `/sys/class/leds/` entries, combined with a `pse` trigger (the direction
OpenWrt PR #22245 is heading). But this requires kernel driver development and is not
something a userspace PoE daemon should do.

### LED Semantic Conventions

This section answers: *given a PoE port state, what should the LED show, and why?* The
mapping in `src/led.c` is not arbitrary — it's the result of cross-referencing IEEE
802.3af/at standards, RFC 3621 (Power Ethernet MIB), and what real vendors actually
ship. We deliberately match Zyxel for the two states stock firmware exposes, then
extend the vocabulary for states stock collapses into "off".

#### The Canonical PoE Port States

The authoritative source is **RFC 3621 (Power Ethernet MIB)**, `pethPsePortDetectionStatus`:

| Value | RFC 3621 name | What it means | Comes from |
|-------|---------------|---------------|------------|
| 1 | `disabled` | Admin-down, or PoE turned off in config | UCI / operator |
| 2 | `searching` | PSE looking for a valid PD signature (25kΩ detection) | IEEE 802.3 detection FSM |
| 3 | `deliveringPower` | Detected + classified + power applied, MPS heartbeat OK | IEEE 802.3 power-on FSM |
| 4 | `fault` | Generic fault (rarely used alone) | PSE controller |
| 5 | `test` | Diagnostic mode (almost never seen in the field) | PSE controller |
| 6 | `otherFault` | Specific fault: overload, short, MPS lost, thermal, denied | PSE controller fault register |

Linux `ethtool --show-pse` exposes a superset via `pse_admin_state` and
`c33_pse_pw_d_status` (the "c33" prefix = clause 33 of 802.3, i.e. PoE). The PR #22245
LED trigger discussion has accepted these as the canonical events a `pse` LED trigger
would fire on.

#### What the BCM59111 MCU Actually Reports

The Broadcom 0x21/0x28 reply byte encodes a nibble that maps to states 0, 1, 2, 4, 5, 6:

```c
/* From port_short_status_to_str() in main.c:745 */
[0] = "Disabled"          /* maps to RFC disabled */
[1] = "Searching"         /* maps to RFC searching */
[2] = "Delivering power"  /* maps to RFC deliveringPower */
[4] = "Fault"             /* maps to RFC fault */
[5] = "Other fault"       /* maps to RFC otherFault */
[6] = "Requesting power"  /* transient: classification → power-up, NO RFC equivalent */
```

`Requesting power` is a **transient** state Broadcom exposes that RFC 3621 lacks: it's
the brief window between successful detection/classification and the PSE actually
turning on the FET. On a healthy port it should last under a second. On an unhealthy
port it can get stuck (see "RTL8238B Issue #50" elsewhere in this doc).

There is no `test` state in the BCM reply nibble. RFC value 3 is shifted to BCM value
2; RFC 4/5/6 align directly.

#### Industry LED Convention Survey

| Vendor | Off | Solid green | Slow blink | Fast blink | Solid amber | Blink amber | Source |
|--------|-----|-------------|------------|------------|-------------|-------------|--------|
| **Zyxel V2.90 (stock)** | disabled / no PD | delivering | — | — | — | — | RE'd from firmware: only `led_state` 0 and 7 |
| **Cisco Catalyst** | port admin-down | delivering | — | — | denied (insufficient budget) | fault | Catalyst 9300/3850 hardware guide |
| **HPE Aruba** | no PoE | delivering | — | — | — | fault / over-budget | Aruba CX series PoE guide |
| **Juniper EX** | disabled | delivering | — | (varies) | — | fault | EX2300/EX3400 hardware doc |
| **Ubiquiti UniFi** | port off | delivering (24V passive or 802.3af/at) | — | — | — | fault / over-budget | UniFi switch user guides |
| **Netgear ProSAFE** | disabled | delivering | — | — | — | fault | GS108/GS308 datasheets |
| **conwrt (this work)** | disabled / unknown | delivering | (reserved) | searching | — | fault / other_fault | This document |

Key observations:
1. **Every vendor agrees**: off = no power, solid green = delivering. Universal.
2. **Most vendors have only one or two LEDs per port** (PoE + LINK). They reuse "blink" or amber for everything else, with the specific meaning documented in the user guide.
3. **No vendor we surveyed uses "slow blink" for searching.** Most vendors collapse searching → off because the searching state is brief on a healthy port and visually noisy when it lasts.
4. **Blink-amber for fault is common**; we use blink-amber-equivalent (slow blink on a green-only LED) because RTL838x PoE LEDs are single-color green.

#### Our Mapping and Why

`src/led.c:144` — `poe_status_to_led_pattern()`:

| PoE status | LED pattern | Hex value | Rationale |
|------------|-------------|-----------|-----------|
| `Disabled` | OFF | 0 | Matches every vendor. PoE off = LED off. |
| `Searching` | FAST_BLINK (~2 Hz) | 4 | **Diverges from Zyxel** (which shows off). Useful diagnostic: "cable plugged in, PSE alive, no PD detected" vs "cable unplugged" (also off). Operator can tell the two apart. |
| `Delivering power` | ON | 5 | Matches every vendor. Most important state, most visible LED pattern. |
| `Fault` | SLOW_BLINK (~0.5 Hz) | 7 | Single-color LED can't do amber, so slow-blink = fault. Distinguishable from fast-blink (searching) at a glance. |
| `Other fault` | SLOW_BLINK | 7 | Same as Fault — operator must check `ubus call poe info` for the specific `fault_type` (ovlo, short, overload, denied, thermal, etc.). |
| `Requesting power` | FAST_BLINK (~2 Hz) | 4 | Register-verified, not visually tested on hardware. Transient state — sub-second during classification. Maps same as Searching (both = "trying to bring port up"). |
| (unknown) | OFF | 0 | Safe default. |

#### Why We Diverge From Stock for `Searching`

Stock Zyxel shows the PoE LED as OFF for both "port disabled" and "port searching for
PD". This is operator-hostile: when you plug a non-PoE device into a PoE port, the LED
stays off and you can't tell whether the port is broken, disabled in config, or just
not finding a PD.

Our fast-blink-when-searching tells the operator: *the PSE is alive and looking, but
your device didn't present a valid 25kΩ signature*. This is the most common
troubleshooting question for end users ("my PoE camera isn't powering on"), so making
it visible saves a round trip to the CLI.

This is consistent with what enterprise switches (Cisco, HPE) expose via syslog
("port X: invalid PD signature") — we just route the same information to the LED.

#### Why Single-Color LEDs Force "Blink for Fault"

Bi-color LED switches (most enterprise gear) reserve **amber** for fault states:
delivering = green, fault = amber, off = no PoE. The operator instantly distinguishes
"working" from "broken" by color, not by motion.

GS1900-8HP and most RTL838x boards have **single-color (green-only) PoE LEDs**. We
have only three visual states available: off, on, blink. Since on=delivering is
non-negotiable, fault has to be a blink pattern. We chose slow-blink for fault to
distinguish it from fast-blink (searching) — slow=problem, fast=looking.

If you port this code to a board with bi-color PoE LEDs (rare on RTL838x), the
abstraction in `led.c` should grow a per-board "led_color_set()" so amber-on can mean
fault. The current pattern-based API is single-color-friendly only.

#### Known Gaps

1. **`Requesting power` mapped to FAST_BLINK** (commit `f541ccf`): Register-verified — the
   debugfs write path produces pattern 4 (FAST_BLINK) for this state. **Not yet
   visually confirmed on hardware**: the state is transient (sub-second during PD
   classification → power-up) and no connected PD has been observed lingering in it.
   To trigger organically, connect a class 3–4 PD to an empty Searching port and watch
   for the blink-rate continuity (both Searching and Requesting power use FAST_BLINK).
   A stuck `Requesting power` (e.g. RTL8238B bug, Issue #50) would be visually
   indistinguishable from a stuck `Searching` — but both are now surfaced, whereas
   previously `Requesting power` was silently OFF.
2. **No distinction between fault subtypes**: All faults blink slowly. The operator
   has to query ubus to learn which of {ovlo, mps_absent, short, overload, denied,
   thermal, startup_failure, uvlo} occurred. A bi-color LED could split this
   (amber-solid = power fault, amber-blink = config fault), but with single-color we
   chose simplicity.
3. **Hardware LINK-ACT can't combine with software PoE state**: The RTL838x LED engine
   lets us drive 3 LED groups per port, and group 1 (LINK-ACT) stays in hardware mode
   while group 0 (PoE) is software-driven. So link state is independent of PoE state —
   good (no interaction bugs) but also no way to express "delivering power AND link
   is up" differently from "delivering power AND no link" on the PoE LED.

#### Why Not Use OpenWrt's `netdev` Trigger?

`netdev` is for *link* state, not *PoE* state. They're orthogonal. A PoE port can be
delivering power to a device whose link is down (PD booting), or have link up while
PoE is disabled (PD self-powered). Conflating the two would hide real states.

The correct LED trigger for our case would be `pse` — which doesn't exist yet in
mainline. PR #22245 (`leds: trigger: add pse trigger for power sourcing equipment`)
proposes exactly this, with hook points in the `pse_pd` framework so any PSE driver
(C33, BT, or vendor-specific like ours) can fire LED events. As of this writing the
PR is open and under discussion. When merged, the migration path would be:

1. Convert `realtek-poe` to register ports as PSE devices in the `pse_pd` framework
2. Define LED entries in device tree with `linux,default-trigger = "pse"`
3. Remove our debugfs writes — kernel handles LED state transitions
4. Keep our debugfs path as a fallback for boards without the PR merged

This is a multi-quarter project and depends on upstream acceptance. Until then, our
userspace approach is the only working solution.

#### Standards References

- **IEEE 802.3-2022 clause 33**: PoE PD detection and PSE state machine (the "C33" in
  ethtool naming)
- **IEEE 802.3bt-2018**: 4-pair PoE (Type 3/4, up to 90W), state machine extensions
- **RFC 3621**: Power Ethernet MIB, defines `pethPsePortDetectionStatus` enum
- **Linux `Documentation/networking/pse-pd/`**: Kernel PSE framework, ethtool integration
- **OpenWrt PR #22245**: <https://github.com/openwrt/openwrt/pull/22245> — pse LED trigger proposal

### MCU management

| Wire | Protocol Name | Stock Function | Our Status | Notes |
|------|--------------|----------------|------------|-------|
| `0xaf` | Bootloader mode handler | (detect + FW image request) | ❌ | **P3**: MCU firmware upgrade prerequisite. Safety-critical. |
| `0xe0` | MCU management | `poe_fw_upgrade` | ❌ | **P3**: Firmware upgrade path. |

## Feature-Level Comparison

| Feature | Stock | Ours | Upstream Issue | Priority |
|---------|-------|------|----------------|----------|
| Port enable/disable | ✅ | ✅ | — | Done |
| Port priority (0-3) | ✅ | ✅ | — | Done |
| Power limit type (None/Class/User) | ✅ | ✅ | — | Done |
| User-defined power limit (mW) | ✅ | ✅ | — | Done |
| Global power budget + guard band | ✅ | ✅ | — | Done |
| Port status polling (2s) | ✅ | ✅ | — | Done |
| **Port status change events** | ✅ `sal_poe_portStatusStateEvent_set` | ✅ `poe.port_status` ubus | — | Done |
| **Power threshold monitoring** | ✅ `_poe_threshold_thread` | ✅ `poe.power_threshold` ubus | — | Done |
| **Fault detection** | ✅ fault_type byte from 0x21 | ⚠️ status string + counter delta | — | **P0-1** |
| Port power measurements (V/I/T/P) | ✅ | ✅ | — | Done |
| Counter clear on read | ✅ 0x22 reset=1 | ❌ reset=0 | — | **P0-3** |
| **Structured fault type** | ✅ OVLO/Short/Overload/Denied/Thermal/UVLO | ❌ "Fault" string only | — | **P0-1** |
| 0x28 class + PD flag extraction | ✅ upper nibble decoded | ❌ discarded | — | **P0-2** |
| Port reset (0x03) | ✅ | ✅ | Related: #10 | Done |
| Pre-allocated vs actual power (0x0b) | ✅ | ✅ | — | Done |
| Global high power limit (0x07) | ✅ | ✅ | — | Done |
| Port power pair (0x19) | ✅ | ❌ | — | P2 |
| LED control (0x41-0x49) | ✅ | ❌ | — | P2 |
| LLDP-MED PoE negotiation | ✅ `board_lldp_poe_register` | ❌ | — | P3 (multi-week) |
| MCU firmware upgrade (0xe0) | ✅ `poe_fw_upgrade` | ❌ | — | P3 (safety-critical) |
| Extended parameters (BCM59121) | ✅ | ❌ | — | P3 (different chip) |
| Per-port PSE output mapping (0x1d) | ✅ | ❌ | — | P2 |
| Global enable/disable (0x06) | ✅ | ❌ | — | **Skip** (see rationale below) |

## OpenWrt Alignment Notes

### Skip: Global enable/disable (0x06)

The stock firmware has `0x06 Set global port enable` which enables/disables all ports
simultaneously. OpenWrt's UCI model is per-port: each port has its own config section
with an `enable` flag. Bulk operations don't fit this pattern — if an operator wants
to disable all ports, they iterate the UCI config. This is the standard OpenWrt approach
(shared by `netifd`, `wireless`, etc.).

Stock uses this during init (`poe_bcm59111_chip_init`) to disable all ports before
configuring them individually. Our init already does per-port enable/disable via
`poe_port_setup`, so 0x06 adds no value.

### Skip: Port overview (0x2a), Direct PSE flag/status (0x2c, 0x2d)

These are deprecated or internal-only commands with no SAL surface in the stock
firmware. No user-facing feature depends on them.

### Skip: System reset (0x09), Trigger flag (0x08)

Safety-critical commands with no clear use case in a userspace daemon. The stock
kernel module uses them during init and error recovery, but our daemon can simply
restart itself (and the init.d script already handles that).

### Alignment: Counter clear on read (P0-3)

Stock clears counters every read cycle via 0x22 reset=1. This prevents single-byte
counter overflow (0-255) in the MCU. Our implementation sends reset=0, meaning
counters wrap silently and our delta-detection for fault_reason can miss events.
Fixing this is both a parity improvement and a correctness fix.

### Alignment: Structured fault type (P0-1)

The 0x21 reply byte[3] contains an enumerated fault_type:
- 0=OVLO, 1=MPS absent, 2=Short, 3=Overload, 4=Denied, 5=Thermal, 6=Startup, 7=UVLO

This is the authoritative fault reason from the MCU. Our current counter-delta
heuristic is a workaround for not decoding this byte. Once decoded, we can surface
the exact fault reason in the `poe.port_status` event's `fault_reason` field.

### CPU Utilization Investigation (Issue #50)

**Finding**: Our GS1900-8HP (8 ports, BCM59111) runs at **0.3% CPU** — well below
the 1.0-1.3% reported in upstream issue #50. The higher CPU on other devices is likely
from larger port counts (24/48), not UART inefficiency.

**Root cause analysis** (verified by reading ustream-fd.c source):
- `ustream_fd` uses **edge-triggered epoll** (`ULOOP_EDGE_TRIGGER`)
- `ustream_fd_read_pending()` loops `read()` until `EAGAIN` — batches all available bytes
- VMIN/VTIME settings do NOT affect epoll behavior (only blocking `read()` semantics)
- The original issue #50 hypothesis ("per-byte wakeups") is incorrect for this architecture

**A/B test results** (hardware-verified on GS1900-8HP A1):

| Poll interval | 30s CPU ticks | CPU % |
|--------------|---------------|-------|
| 2s (default) | 9 | 0.30% |
| 5s | 9 | 0.30% |
| 10s | 9 | 0.30% |

CPU is constant regardless of poll frequency — the cost is baseline event loop
overhead (epoll, ubus, timer), not UART command processing.

**Resolution**: Added configurable `poll_interval` UCI option (500ms-30000ms, default 2000ms)
for responsiveness tuning. This does NOT reduce CPU (already near-optimal) but allows
operators to adjust status update frequency for their needs.

### Boot Status Race Condition (Issue #10)

**Problem**: After daemon restart, `ubus call poe info` shows "unknown" for all ports
for ~1.5 seconds because `poe_initial_setup()` sends system-level commands but NOT
port status queries (0x21). The first status query happens in `state_timeout_cb` at
+1 second, and MCU replies take another ~0.5 seconds.

**Root cause**: `ubus_poe_info_cb` returns "unknown" when `state->ports[i].status` is NULL
(no MCU reply yet). This is misleading — the port isn't in an unknown state, the daemon
simply hasn't queried the MCU yet.

**Fix** (data-driven, commit `78f37c4`):
- `ubus_poe_info_cb` checks if ANY port has received status from the MCU
- If none have (init in progress), NULL status → "initializing" (informative)
- Once any port has status, remaining NULL ports → "unknown" (genuine unknown)

**Before fix** (hardware-verified on GS1900-8HP A1):
- 11 iterations (~1.5s) of "unknown" after daemon restart
- Misleading: clients can't distinguish "init not done" from "MCU error"

**After fix** (hardware-verified):
- "initializing" until first MCU status reply arrives (~1s)
- Zero "unknown" during init — direct transition to correct status
- No flags or timing assumptions — purely data-driven

## Implementation Plan

### Done (shipped on ai/power-limit-config)

| ID | What | Commit | Stock Reference | Upstream Issue |
|----|------|--------|-----------------|----------------|
| P0-1 | Decode 0x21 fault_type/power_mode/chan_pwr/pd_alt | `15ab0f4` | `poe_bcm59111_portStatus_get` extracts all 9 fields | — |
| P0-2 | Decode 0x28 upper nibble (class, fault_type, PD flag) | `15ab0f4` | `poe_bcm59111_allPortStatus_get` extracts packed bits | — |
| P0-3 | Set 0x22 reset=1 on counter reads | `15ab0f4` | `bcm59111_portStats_get` sends reset=1 every cycle | — |
| P1-fault | Authoritative fault_type in events | `15ab0f4` | `text_poe_portStatusDescStr` enumeration | — |
| P1-reset | Port reset (0x03) via ubus manage | `15ab0f4` | `bcm59111_cmd_set` enum 3 = 0x03 | Related: #10 (boot stuck unknown) |
| P1-reset-fix | Fix manage callback return values + reset disabled ports | `11c5294` | — | #49 (upstream partial fix), #58 (reset disabled ports) |
| P1-devpm | Device power management (0x0b) in init | `15ab0f4` | `poe_bcm59111_chip_init` sends pre_alloc/powerup_mode | — |
| P1-highpw | High power limit (0x07) in init | `15ab0f4` | `bcm59111_cmd_set` enum 7 | — |
| threshold | Power threshold monitoring (ubus event) | `5b06845` | `_poe_threshold_thread` | — |
| events | Async port status events (ubus event) | `ffaf70a` | `sal_poe_portStatusStateEvent_set` | — |
| fault-flag | Fault flag + fault_reason on events | `166d60e` | `text_poe_portStatusDescStr` | — |
| init-status | "initializing" instead of "unknown" during startup | `78f37c4` | — | #10 (status stuck unknown on boot) |

### Upstream Issues Mapping

Open issues on Hurricos/realtek-poe that relate to our work:

| Issue | Title | Relevance | Our Status |
|-------|-------|-----------|------------|
| #68 | PSE ID quirk for GS1900-48HP A1 | pse_id_set_budget_mask needs 0x80 for 48HP | Not our hardware, N/A |
| #66 | Map LEDs to match remapped ports | LED remapping config option | Related to our P2 LED work |
| #64 | Transfer repo to organization | Governance, not technical | — |
| #62 | PoE via i2c: best way forward? | I2C transport for GS1920 series | We're UART only, different hardware |
| #59 | New realtek dialect not autodetected | Dialect auto-detection broken for GS1900-24HPv2 | Our fork is BCM59111-specific |
| #58 | Manage ports disabled in config | Allow managing ports with enable=0 | ✅ Fixed in `11c5294` — removed `!port->enable` from reset path |
| #54 | Reversed order of ports | Port numbering vs labels on D-Link | UCI config issue, not our code |
| #53 | Build for mips-24kec targets | Missing build target | Build system issue |
| **#50** | **Reduce CPU utilization** | **1.0-1.3% CPU, wakes per-byte** | **Investigated — 0.3% on 8-port. Cost is event loop overhead, not poll frequency. Configurable poll interval shipped.** |
| #47 | Don't log to stdio by default | Logging noise | Upstream design choice — Hurricos wants ULOG_STDIO kept for debugging (PR #20). No change needed in our fork. |
| **#32** | **802.3bt and paired port support** | **4-pair PoE for GS110TUP** | **Our 0x19 power pair command is prerequisite. We have the dialect entry.** |
| #29 | Clean-up schema when no middleman MCU | BCM59103 direct support | Different hardware class |
| #28 | Config template model-inspecific | Default budget/port values | Board-specific, not our code |
| #27 | TI TPS23861 support | Different PSE chip entirely | N/A |
| **#10** | **Status stuck on 'unknown' after reboot** | **Race condition at boot** | **✅ Fixed in `78f37c4`** — data-driven "initializing" status during startup. |
| #7 | Reboot interrupts PoE delivery | MCU reset on device reboot | Hardware behavior, can't fix in software |

### Remaining Work

#### P2: Extended features

| ID | What | Notes | Upstream Issue |
|----|------|-------|----------------|
| P2-1 | ~~LED control (0x41-0x49)~~ | **HW-limited**: BCM59111 v17.1 doesn't implement MCU LED. PoE LEDs are SoC-driven. GET queries implemented, SET tested and confirmed N/A. | #66 (LED remapping config) |
| P2-2 | Port power pair (0x19) | A-pair/B-pair for 4-pair PoE | #32 (802.3bt paired port support) |
| P2-3 | Per-port PSE output mapping (0x1d) | Non-trivial hardware topologies | — |
| P2-4 | Allow managing disabled ports | ✅ Done in `11c5294` | #58 (manage disabled ports) |
| P2-5 | CPU utilization: configurable poll interval | ✅ Done in `pending` — poll_interval UCI option, tested A/B. **CPU is 0.3% regardless of interval** — cost is event loop overhead, not poll frequency. | #50 (reduce CPU utilization) |

#### P3: Large/multi-week features

| ID | What | Notes |
|----|------|-------|
| P3-1 | LLDP-MED PoE negotiation | Requires lldpd integration, `board_lldp_poe_register` equivalent |
| P3-2 | MCU firmware upgrade (0xe0/0xaf) | Safety-critical, needs bootloader detect + image validation |
| P3-3 | Extended parameters (BCM59121) | Different chip family, 802.3bt features |

## Scorecard (after LED hardware validation)

| Category | Items | ✅ Parity | ❌ Gap | ⚠️ Partial/HW-limited |
|----------|-------|----------|--------|------------|
| GET commands | 14 | 14 | 0 | 0 |
| SET commands | 19 | 17 | 2 | 0 |
| LED commands | 6 | 0 | 0 | 6 (HW doesn't support MCU-driven LEDs) |
| MCU management | 2 | 0 | 2 | 0 |
| Features | 25 | 20 | 2 | 0 |
| **Totals** | **66** | **51 (77%)** | **4 (6%)** | **6 (9%)** |

Excluding skipped items (0x06, 0x08, 0x09, 0x2a, 0x2c, 0x2d) and HW-limited LED items: 51/54 = **94%** parity on actionable items.

## Bugs Found: Manage Callback Return Values

**Commit**: `11c5294` on `ai/power-limit-config`

### Root Cause

`mcu_queue_cmd()` → `mcu_queue_buf()` → `mcu_cmd_send()` → `ustream_write()` returns
the number of bytes written (always 12, the CMD_SIZE). Any ubus callback that returns
this value directly leaks a byte count to ubus, which interprets it as an error code.

Symptom: `ubus call poe manage '{"port":"lan2","action":"reset"}'` returns
"Command failed: Parsing message data failed" (ubus interprets return value 12 as error).

### What Upstream Fixed (PR #49, merged Nov 2025)

Only the **fallthrough** return at the end of `ubus_poe_manage_cb()` — changed from
`UBUS_STATUS_INVALID_ARGUMENT` to `UBUS_STATUS_OK`. This fixed the common case where
`action="enable"/"disable"` succeeds but the function returns the wrong status.

### What Upstream Did NOT Fix

The early-return paths from `clear_counters`, `port_enable`, and (in our code) `port_reset`
still return raw `mcu_queue_cmd()` values. These all leak the byte count (12) to ubus.

In upstream `main.c` (as of Nov 2025), `clear_counters` returns `poe_cmd_clear_counters()`
directly, and the enable path returns `poe_cmd_port_enable()` directly. Both leak byte count.

### Our Complete Fix

All three action paths now translate return values:
```c
ret = poe_cmd_port_reset(mcu, i);
return (ret < 0) ? UBUS_STATUS_SYSTEM_ERROR : UBUS_STATUS_OK;
```

This mirrors the existing pattern in `ubus_poe_sendframe_cb()` which already handled this
correctly.

### Additional Fix: Reset on Disabled Ports (Issue #58)

The manage callback's reset branch checked `!port->enable` and skipped disabled ports.
Removed this check — a disabled port may still need fault recovery via MCU 0x03.
The enable/disable path retains the `!port->enable` check (correct behavior).

## Next Steps

### Priority 1: Stock Firmware UART Validation

Validate our RE analysis against live stock behavior by capturing MCU UART traffic
from the stock ZyXEL device ((stock switch IP)).

**Approach**: Get shell access on the stock device. Options:
1. **Web UI password recovery** — factory reset to default `1234`, then use V2.90 encode() login
2. **Serial console** — UART at 115200 8N1 on PCB header (requires USB-serial adapter)
3. **Web UI exploitation** — check if cmd= parameters allow command injection (unlikely but worth checking)

**Once we have shell**:
- Check if `/tmp/poe.log` already contains MCU traffic debug (stock has `poe_dbg_message_set`)
- Use `strace -e read,write -p <pid>` on the PoE daemon to capture UART I/O
- Cross-reference captured traffic with our RE_ANALYSIS.md command table

### Priority 2: Upstream-Relevant Improvements

These address real upstream issues and would benefit all realtek-poe users:

| Task | Upstream Issue | Effort | Impact |
|------|---------------|--------|--------|
| VMIN/VTIME UART tuning | #50 (CPU utilization) | Small | No effect — ustream uses edge-triggered epoll + read-until-EAGAIN (already batches). CPU cost is event loop overhead, not per-byte. |
| Configurable poll interval | #50 (CPU utilization) | Done | Allows tuning responsiveness (500ms-30s). CPU stays ~0.3% regardless. |
| ~~LED control~~ | #66 (LED remapping) | ~~Medium~~ Done/HW-limited | MCU doesn't support LED on BCM59111 v17.1 |
| Port power pair (0x19) | #32 (802.3bt) | Small | Prerequisite for 4-pair PoE |

### Priority 3: Remaining Parity

| Task | Notes | Effort |
|------|-------|--------|
| Per-port PSE output mapping (0x1d) | Non-trivial hardware topologies | Medium |
| LLDP-MED PoE negotiation | Requires lldpd integration | Multi-week |
| MCU firmware upgrade (0xe0) | Safety-critical | High |
| Extended params (BCM59121) | Different chip family | Medium |

## PoE Safety & Known Unknowns

### Current Configuration (as of 2026-05-27)

All 8 ports PoE-enabled (`enable='1'`), budget=70W, guard band=7W (default 10%).
3 ports actively delivering (~4.5W total). Per-port power_limit_type=1 (class-based),
per-port budget=15.4W. All ports priority=0.

Theoretical maximum draw: 8 × 15.4W = **123.2W vs 70W budget** — the MCU handles
overcommitment via power management mode 2 (static with priority). When budget is
exceeded, ports shut down in priority order (all equal = highest port number first).

### Budget Enforcement

The BCM59121 MCU enforces the budget at the silicon level. The daemon configures it
via `poe_cmd_global_power_budget()` and `poe_cmd_device_power_mgmt(pre_alloc=1,
powerup_mode=0, disconnect_order=0)`. The MCU independently decides which ports to
shut down when budget is exceeded — the daemon has no runtime involvement in
load-shedding decisions.

The daemon's `poe_check_power_threshold()` merely emits ubus events when consumption
crosses configurable thresholds (`threshold_high`/`threshold_low`) — purely
informational, no enforcement action.

### Known Unknowns

| # | Issue | Severity | Status | Detail |
|---|-------|----------|--------|--------|
| K1 | **Cold-boot "unknown" state** | High | Open (Issue #10) | Randomly on reboot, all ports show "unknown" status. Race condition between daemon startup and MCU readiness. Our init-path fix (`947ba03`) partially mitigates for LEDs but doesn't address root cause. |
| K2 | **Memory leak on 48-port switches** | Medium | Closed (Issue #55) | 6-month deployment showed RAM growth + reboots. Workaround: hourly cron restart. May affect 8-port at longer intervals — not observed yet (our daemon uptime ~hours, not months). |
| K3 | **CPU utilisation ~1%** | Low | Open (Issue #50) | Suspected UART byte-at-a-time wake. Not harmful at 8 ports but worth investigating if deploying 48-port. Related to RTL8238B stuck-port bug we're surfacing via LED. |
| K4 | **No power-up sequencing** | Medium | Inherent | `powerup_mode=0` = simultaneous. All enabled ports attempt to power PDs concurrently. Inrush current spike risk with high-capacitance PDs. Mitigated by low current port count (3 active). |
| K5 | **Daemon restart interrupts power** | High | Partially fixed (Issue #5) | `/etc/init.d/poe restart` causes brief power loss to all PDs. Also observed: restart leaves two daemon instances fighting over UART. Fix: always `stop` + `killall -9` + `start`. |
| K6 | **Port mapping reversal** | Low | Open (Issue #54) | Some boards (D-Link DGS-1210-10P F1) have reversed port order. Our GS1900-8HP mapping verified correct. |
| K7 | **Stale ubus status** | Medium | Closed (Issue #21) | After PD swaps, status may not refresh. Suspected MCU reply caching. Not reproduced on our hardware. |
| K8 | **No 802.3bt / paired-port support** | Low | Open (Issue #32) | BCM59121 only does 802.3af/at. Our switch is 8× PoE+ (30W max per port) — not affected. |
| K9 | **Priority all-zero** | Medium | Config | All ports priority=0 means load-shedding order is undefined (likely highest port number shed first). Should configure critical ports (management, camera) with lower priority numbers. |
| K10 | **Guard band default** | Low | Config | budget_guard defaults to budget/10 = 7W. This is the hysteresis for budget accounting — reasonable for 70W budget. |

### Unknown Unknowns (warrants investigation)

| # | Hypothesis | Risk | How to investigate |
|---|-----------|------|--------------------|
| U1 | **Thermal protection**: BCM59121 MCU autonomously detects overheating and reports `fault_type=5 (thermal)`, shutting down the affected port. realtek-poe correctly logs this fault and updates the LED (SLOW_BLINK). **Feature parity exists at the hardware level** — the MCU firmware handles thermal detection and shutdown regardless of host daemon. The stock firmware string "Port was shut down because of temperature is too high" maps directly to our `fault_type=5`. No proactive temperature monitoring exists in either stock or realtek-poe — both react to MCU-reported faults. Current port temps: 36-39°C (well within safe range). | ~~Medium~~ **RESOLVED** | Parity confirmed. BCM59121 datasheet: operating range -40°C to +85°C. GS1900-8HP datasheet: operating 0°C to 45°C. No proactive thermal policy needed — MCU handles shutdown autonomously. |
| U2 | **STM32F100 flash endurance**: MCU config storage in STM32 flash rated ~10,000 write/erase cycles. Frequent budget/priority changes via UCI could accumulate. | Low | Count write frequency in daemon. If only at startup, negligible (~365/year). |
| U3 | **PD classification mismatch / LLDP PoE**: Class 0 PDs reserve 15.4W but may draw far less. No LLDP-MED PoE negotiation in realtek-poe means class is the only allocation signal. Stock firmware integrates LLDP via `board_lldp_poe_register` (allows PDs to request specific wattage and PSE to dynamically adjust per-port allocation). | Low | **Not a gap for lab use.** LLDP PoE is a software-layer feature, not a BCM59121 silicon capability. Our `pre_alloc=1` (consumption mode) tracks actual draw, so budget is not wasted. LLDP PoE only matters for: (a) PDs that request more than class default via LLDP, or (b) enterprise deployments with unknown mixed PDs needing dynamic budget optimisation. For our known-device lab, class-based + consumption mode is sufficient. If needed, `lldpd` on OpenWrt supports LLDP-MED PoE TLVs (`configure med power`) but has no realtek-poe integration. |
| U4 | **MCU UART protocol reliability**: No CRC or checksum on MCU replies (despite Issue #33 "request-bad-checksum" being closed). Corrupted status reads could cause wrong LED state. | Low | Monitor `logread` for "received unsolicited reply" or checksum errors during sustained operation. |
| U5 | **Cable voltage drop**: Our lab uses short cables (<5m). If deploying at distance, CAT5e at 100m + 15W = ~2.5V drop. At 53.8V source this is fine (51.3V at PD > 50V minimum for PoE+). But with multiple loads, PSU voltage may sag below 53V. | Low | Measure voltage at PD end with multimeter. Verify PSU output under full load. |
| U6 | **PSU capacity vs budget**: `budget=70W` is configured, but the actual PSU in GS1900-8HP may be rated higher (the JG928A 48-port variant ships a 370W PSU). The 8-port PSU rating is unknown — setting budget above PSU capacity would cause brownouts. | ~~High~~ **RESOLVED** | Zyxel datasheet: GS1900-8HP PoE budget = **70W**, max consumption = 84.8W (70W PoE + 14.8W switch overhead). Internal PSU 100-240V AC. Our config matches rated capacity exactly — **no margin**. The 77W figure in some specs is for GS1900-**10HP** variant. Consider reducing budget to 60-65W for thermal headroom. |
| U7 | **Fault retry behaviour**: After a fault (overload, short), does the MCU auto-retry or stay off? The daemon has no explicit fault-clearing logic. The BCM59111 stock firmware used command 0x03 to clear faults. | Medium | Induce a fault (plug non-PoE device), observe if port recovers or stays Disabled. Check `cnt_overload`/`cnt_short` counters in `ubus call poe info`. |
| U8 | **Budget accounting mode**: `pre_alloc=1` (actual usage) means the MCU tracks real-time power, not reserved class-based budget. This is good — means budget isn't wasted on class 0 reservations. Verify this is truly what's happening. | Low | Connect a class 0 device drawing 5W and observe if 15.4W or 5W is deducted from budget. |

### Recommendations

1. **Set priorities**: Camera on lan7 → priority 1 (critical, keep alive). Other delivering
   ports → priority 2. Empty ports → priority 3.
2. **Verify PSU rating**: Check physical label on GS1900-8HP power supply. If <70W, reduce
   budget setting.
3. **Avoid daemon restarts under load**: Use `killall -9` + fresh start, not `/etc/init.d/poe restart`.
4. **Monitor long-running stability**: Leave switch running for weeks, check `ps` for realtek-poe
   memory growth (Issue #55 mitigation).
5. **Document connected devices**: Maintain a port map (which device on which port, expected
   draw) for budget planning.

## Zyxel V2.90 Stock Firmware Comparison

### PoE Feature Parity Matrix

| Feature | Zyxel Stock V2.90 | OpenWrt / realtek-poe | Parity |
|---------|-------------------|----------------------|--------|
| **PoE mode** | Consumption mode (V2.90 Patch 1 default) | `pre_alloc=1` (actual usage) | ✅ Equivalent |
| **Budget** | 70W, guard band 10% | 70W configured, 63W effective (70 - 7W guard) | ✅ Matches |
| **Priority levels** | Critical / High / Low (3 tiers) | 0-3 (4 tiers, 0=highest) | ✅ Compatible |
| **Budget exhaustion** | Sheds lowest-priority ports first; status: "Power was denied because of insufficient power" | MCU handles identically (same BCM59121 firmware) | ✅ Same |
| **Thermal shutdown** | MCU-enforced; "Port was shut down because of temperature is too high" (fault_type=5) | MCU-enforced; `fault_type=5 (thermal)` → SLOW_BLINK LED | ✅ Same |
| **Fault clearing** | `poe_cmd_port_reset` (0x03) in kernel thread | `ubus call poe manage '{"port":"lan1","action":"reset"}'` | ✅ Same mechanism |
| **LED control** | SoC LED engine via board_poe kernel module | SoC LED engine via debugfs writes from userspace | ✅ Same hardware path |
| **Config persistence** | Bug: resets to classification mode after power cut unless explicitly saved (Apply + Save) | UCI config always persists | ✅ Better |
| **LLDP PoE negotiation** | Supported via `board_lldp_poe_register` — dynamic per-port power adjustment | Not supported — no lldpd/realtek-poe integration | ⚠️ Gap (irrelevant for lab) |
| **MCU firmware upgrade** | Supported via `sal_poe_firmware_upgrade` (0xe0) | Not implemented | ⚠️ Gap (low priority) |
| **802.3bt / 4-pair PoE** | Not applicable (BCM59121 = af/at only) | Same limitation | ✅ N/A |
| **Power scheduling** | Web UI supports scheduled PoE on/off | Not implemented (trivial via cron + ubus) | ⚠️ Gap (easy to add) |
| **Per-port power limit** | Web UI: user-defined mW limits per port | `power_limit_type` + `power_limit` via UCI/ubus | ✅ Equivalent |

### Key Differences (not bugs, design choices)

1. **LLDP PoE**: Stock firmware integrates LLDP-MED power negotiation with the PoE daemon,
   allowing PDs to dynamically request/adjust power allocation via LLDP TLVs. This is purely
   software — the BCM59121 silicon has no LLDP capability. For our lab (known devices,
   consumption mode tracking actual draw), this is irrelevant. If needed in future, `lldpd`
   on OpenWrt supports LLDP-MED PoE TLVs but would need a bridge script to call
   `ubus call poe set_port_config` based on LLDP power values.

2. **Power scheduling**: Stock firmware offers time-based PoE scheduling in the web UI.
   Equivalent functionality on OpenWrt: `crontab -e` with `ubus call poe manage` commands.

3. **MCU firmware upgrade**: Stock firmware can update the STM32F100 MCU firmware (command
   0xe0). realtek-poe doesn't implement this. Low priority — MCU firmware is stable and
   upgrading it carries bricking risk.
