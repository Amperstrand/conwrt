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
| `0x03` | Port reset | (disconnect/reconnect) | ❌ | **P1-1**: Clear fault states. |
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
| `0x41` | Set port LED config | `board_poe_portLed_set` | ❌ | **P2**: MCU-driven PoE status LEDs. Needs hardware-specific LED map. |
| `0x42` | Get port LED config | `board_poe_portLed_set` | ❌ | |
| `0x43` | Set system LED config | `board_poe_led_set` | ❌ | |
| `0x44` | Get system LED config | `board_poe_led_set` | ❌ | |
| `0x48` | Set port LED map | `board_poe_portLedCtrl_set` | ❌ | |
| `0x49` | Get port LED map | `board_poe_portLedCtrl_set` | ❌ | |

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
| Port reset (0x03) | ✅ | ❌ | — | **P1-1** |
| Pre-allocated vs actual power (0x0b) | ✅ | ❌ | — | **P1-2** |
| Global high power limit (0x07) | ✅ | ❌ | — | **P1-3** |
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

## Implementation Plan

### P0: Under-decoding fixes (existing wire replies, no new commands)

| ID | What | Files | Stock Reference | Upstream Issue |
|----|------|-------|-----------------|----------------|
| P0-1 | Decode 0x21 fault_type/power_mode/chan_pwr/pd_alt | main.c, tek-poe.h | `poe_bcm59111_portStatus_get` extracts all 9 fields | TBD |
| P0-2 | Decode 0x28 upper nibble (class, fault_type, PD flag) | main.c | `poe_bcm59111_allPortStatus_get` extracts packed bits | TBD |
| P0-3 | Set 0x22 reset=1 on counter reads | main.c | `bcm59111_portStats_get` sends reset=1 every cycle | TBD |

### P1: Missing SET commands

| ID | What | Files | Stock Reference | Upstream Issue |
|----|------|-------|-----------------|----------------|
| P1-1 | Port reset (0x03) | tek-poe.h, dialect_bcm.c, main.c | `bcm59111_cmd_set` enum 3 = 0x03 | TBD |
| P1-2 | Device power management (0x0b) | tek-poe.h, dialect_bcm.c, main.c | `poe_bcm59111_chip_init` sends pre_alloc/powerup_mode/disconnect_order | TBD |
| P1-3 | Global high power limit (0x07) | tek-poe.h, dialect_bcm.c, main.c | `bcm59111_cmd_set` enum 7 | TBD |

### P2: Extended features

| ID | What | Notes |
|----|------|-------|
| P2-1 | LED control (0x41-0x49) | Needs hardware-specific LED map for GS1900-8HP A1 |
| P2-2 | Port power pair (0x19) | A-pair/B-pair for 4-pair PoE |
| P2-3 | Per-port PSE output mapping (0x1d) | Non-trivial hardware topologies |

### P3: Large/multi-week features

| ID | What | Notes |
|----|------|-------|
| P3-1 | LLDP-MED PoE negotiation | Requires lldpd integration, `board_lldp_poe_register` equivalent |
| P3-2 | MCU firmware upgrade (0xe0/0xaf) | Safety-critical, needs bootloader detect + image validation |
| P3-3 | Extended parameters (BCM59121) | Different chip family, 802.3bt features |

## Scorecard

| Category | Items | ✅ Parity | ❌ Gap | ⚠️ Partial |
|----------|-------|----------|--------|------------|
| GET commands | 14 | 11 | 0 | 3 |
| SET commands | 19 | 11 | 8 | 0 |
| LED commands | 6 | 0 | 6 | 0 |
| MCU management | 2 | 0 | 2 | 0 |
| Features | 25 | 13 | 8 | 4 |
| **Totals** | **66** | **35 (53%)** | **27 (41%)** | **4 (6%)** |

Excluding skipped items (0x06, 0x08, 0x09, 0x2a, 0x2c, 0x2d): actionable gap is 21 items.
P0 fixes (3 items) would bring us to 41/63 = 65% parity on core PoE functionality.
