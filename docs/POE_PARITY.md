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
| **#50** | **Reduce CPU utilization** | **1.0-1.3% CPU, wakes per-byte** | **Our 2s poll cycle + reset-on-read helps. VMIN/VTIME tuning would help further.** |
| #47 | Don't log to stdio by default | Logging noise | We use ulog which already goes to syslog |
| **#32** | **802.3bt and paired port support** | **4-pair PoE for GS110TUP** | **Our 0x19 power pair command is prerequisite. We have the dialect entry.** |
| #29 | Clean-up schema when no middleman MCU | BCM59103 direct support | Different hardware class |
| #28 | Config template model-inspecific | Default budget/port values | Board-specific, not our code |
| #27 | TI TPS23861 support | Different PSE chip entirely | N/A |
| **#10** | **Status stuck on 'unknown' after reboot** | **Race condition at boot** | **Our init sends 0x0b+0x07 which may help. Port reset (0x03) could also recover.** |
| #7 | Reboot interrupts PoE delivery | MCU reset on device reboot | Hardware behavior, can't fix in software |

### Remaining Work

#### P2: Extended features

| ID | What | Notes | Upstream Issue |
|----|------|-------|----------------|
| P2-1 | LED control (0x41-0x49) | Needs hardware-specific LED map for GS1900-8HP A1 | #66 (LED remapping config) |
| P2-2 | Port power pair (0x19) | A-pair/B-pair for 4-pair PoE | #32 (802.3bt paired port support) |
| P2-3 | Per-port PSE output mapping (0x1d) | Non-trivial hardware topologies | — |
| P2-4 | Allow managing disabled ports | ✅ Done in `11c5294` | #58 (manage disabled ports) |
| P2-5 | CPU utilization: VMIN/VTIME tuning | Reduce per-byte wakeups in UART read loop | #50 (reduce CPU utilization) |

#### P3: Large/multi-week features

| ID | What | Notes |
|----|------|-------|
| P3-1 | LLDP-MED PoE negotiation | Requires lldpd integration, `board_lldp_poe_register` equivalent |
| P3-2 | MCU firmware upgrade (0xe0/0xaf) | Safety-critical, needs bootloader detect + image validation |
| P3-3 | Extended parameters (BCM59121) | Different chip family, 802.3bt features |

## Scorecard (after manage callback fix)

| Category | Items | ✅ Parity | ❌ Gap | ⚠️ Partial |
|----------|-------|----------|--------|------------|
| GET commands | 14 | 14 | 0 | 0 |
| SET commands | 19 | 17 | 2 | 0 |
| LED commands | 6 | 0 | 6 | 0 |
| MCU management | 2 | 0 | 2 | 0 |
| Features | 25 | 20 | 2 | 0 |
| **Totals** | **66** | **51 (77%)** | **10 (15%)** | **0** |

Excluding skipped items (0x06, 0x08, 0x09, 0x2a, 0x2c, 0x2d): 51/60 = **85%** parity on actionable items.

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
from the stock ZyXEL device (192.168.13.3).

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
| VMIN/VTIME UART tuning | #50 (CPU utilization) | Small | Reduces CPU from 1.0-1.3% to near-zero |
| LED control | #66 (LED remapping) | Medium | Visual PoE status on front panel |
| Port power pair (0x19) | #32 (802.3bt) | Small | Prerequisite for 4-pair PoE |

### Priority 3: Remaining Parity

| Task | Notes | Effort |
|------|-------|--------|
| Per-port PSE output mapping (0x1d) | Non-trivial hardware topologies | Medium |
| LLDP-MED PoE negotiation | Requires lldpd integration | Multi-week |
| MCU firmware upgrade (0xe0) | Safety-critical | High |
| Extended params (BCM59121) | Different chip family | Medium |
