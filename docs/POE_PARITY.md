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
