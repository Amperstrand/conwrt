# Stock Firmware Reverse Engineering Analysis

## board_poe.ko — Stock PoE Kernel Module

**File**: ELF 32-bit MSB relocatable, MIPS, MIPS32 version 1, NOT STRIPPED
**Kernel**: 2.6.19 preempt mod_unload MIPS32_R1 32BIT
**Dependencies**: ski, rtcore, board_conf, ksi
**License**: Realtek Semiconductor Corp.
**Description**: Switch PoE Host Module

### Supported PoE Chips

| Chip | Init Function | UART Xmit | SMI Xmit |
|------|--------------|-----------|----------|
| BCM59111 | `poe_bcm59111_chip_init` | `bcm59111_uart_xmit` | `bcm59111_smi_xmit` |
| BCM59121 | `poe_bcm59121_chip_init` | `bcm59121_uart_xmit` | `bcm59121_smi_xmit` |
| RTL8238B | `poe_bcm59011_chip_init` | `rtl8238b_uart_xmit` | `rtl8238b_smi_xmit` |

### Thread Architecture

- **PoE Port Thread** (`_poe_portStatusState_thread`): Main polling loop for port status
- **PoE Misc Thread** (`_poe_threshold_thread`): Power threshold monitoring

### BCM59111 Command Set (from bcm59111_cmd_set disassembly)

#### SET commands (wire bytes extracted from `li v0, N` instructions):

| Internal Enum | Wire Byte | Description |
|--------------|-----------|-------------|
| 1 | 0x00 | Set port enable |
| 2 | 0x02 | MCU enable port mapping |
| 3 | 0x03 | Set disconnect type |
| 4 | 0x05 | Set power limit type (MCU_CLEAR_COUNTERS?) |
| 5 | 0x06 | Set power limit (individual) |
| 6 | 0x07 | Set high power mode |
| 7 | 0x09 | Set dynamic priority |
| 8 | 0x10 (16) | Set port enable (all-ports format, up to 9 ports) |
| 9 | 0x15 (21) | Set port limit mode (all-ports format, up to 9 ports) |
| 10 | 0x10 | Set port mapping (4-port format) |
| 11 | 0x15 | Set disconnect type (4-port format) |
| 12 | 0x10 | Set auto power-up (4-port format) |
| 13 | 0x15 | Set power limit type (4-port format) |
| 14-18 | various | Set LED, power and guard band, etc. |
| 19 | 0x17 (23) | Set system config |
| 20 | 0x18 (24) | Set system config extended |
| 21-27 | various | Enable/disable features |

#### GET commands (from bcm59111_cmd_get disassembly):

| Internal Enum | Wire Byte | Description |
|--------------|-----------|-------------|
| 29 (cmd-29=0) | 0x20 (32) | Get system info |
| 30 (cmd-29=1) | 0x21 (33) | Get port status |
| 31 (cmd-29=2) | 0x22 (34) | Get port counters |
| 32 (cmd-29=3) | 0x23 (35) | Get power stats |
| 33 (cmd-29=4) | 0x25 (37) | Get port config |
| 34 (cmd-29=5) | 0x26 (38) | Get extended port config |
| 35 (cmd-29=6) | 0x27 (39) | Get power management mode |
| 36 (cmd-29=7) | 0x28 (40) | Get all-port status |
| 37 (cmd-29=8) | 0x30 (48) | Get port power/voltage/current/temp |

### Key String Messages

```
power budget: %u mW, allocated: %u mW, consumed: %u mW
Power usage goes over Threshold: %d%%
Power usage goes below Threshold: %d%%
Port %d might be power down (delivering %u mW, limit to %u mW).
Port %d change power limit to %u mW by LLDP request
PoE usage threshold set to %u
Power budget is set to %u mW, guard band is set to %u mW
PoE chip 0x%x is %s
Retry counts: %u / %u
```

### UART Communication Protocol

```
H->M: %s          (Host to MCU formatted hex)
M->H: %s          (MCU to Host formatted hex)
```

Error handling strings:
```
Host <-> PoE: communication failed
PoE -> Host: checksum validation failed
PoE -> Host: controller is in BOOTROM, requesting image
PoE -> Host: not ready to response
PoE -> Host: checksum invalid in request
PoE -> Host: incomplete command received
PoE -> Host: negative Acknowledgement
PoE controller: command received with wrong checksum
```

### BCM59111 Function Addresses

| Function | Address |
|----------|---------|
| `poe_bcm59111_init` | 0x4200 |
| `poe_bcm59111_power_get` | 0x4994 |
| `poe_bcm59111_status_get` | 0x4a64 |
| `poe_bcm59111_portStatus_get` | 0x58d8 |
| `poe_bcm59111_allPortStatus_get` | 0x63f4 |
| `bcm59111_portStats_get` | 0x5ab0 |
| `poe_bcm59111_allPortStats_get` | 0x6758 |
| `bcm59111_cmd_set` | 0x6d30 |
| `bcm59111_cmd_get` | 0x764c |
| `bcm59111_uart_xmit` | 0x7c20 |
| `bcm59111_uart_exchange` | 0x7e64 |
| `poe_bcm59111_portEventMon_register` | 0x695c |

### LED Control Functions

- `board_poe_led_init` (0x37e0)
- `board_poe_led_set` (0x3920)
- `board_poe_portLed_set` (0x39e8)
- `board_poe_portLedCtrl_set` (0x3cc4)
- `board_poe_portLedEnable_set` (0x3d6c)
- `board_poe_btn_led_monitor` (0x3ea8)

### Reset/Disable Functions

- `board_poe_dis_init` (0x3174) — PoE disabled GPIO initialization
- `board_poe_disable_set` (0x?)
- `board_poe_reset_init` (0x3ff0) — PoE reset GPIO initialization
- `board_poe_reset_set` (0x40e0) — Trigger PoE reset

---

## libsal.so.0.0 — Stock SAL Library

**File**: ELF 32-bit MSB shared object, MIPS, MIPS32 version 1, STRIPPED

### PoE SAL API Functions (from strings)

#### Configuration Layer (cfg_*)
```
cfg_poe_enable_get/set
cfg_poe_extParamEnable_get/set
cfg_poe_limitMode_get/set
cfg_poe_portAdminEnable_get/set
cfg_poe_portLegacyEnable_get/set
cfg_poe_portLimitMode_get/set
cfg_poe_portPowerLimit_get/set
cfg_poe_portPowerMode_get/set
cfg_poe_portPriority_get/set
cfg_poe_sched_get/set
```

#### SAL Layer (sal_poe_*)
```
sal_poe_enable_get/set
sal_poe_extParamEnable_get/set
sal_poe_limitMode_get/set
sal_poe_portAdminEnable_get/set
sal_poe_portAdminLegacyEnable_get
sal_poe_portAdminPowerLimit_get
sal_poe_portAdminPowerMode_get
sal_poe_portL2Data_get
sal_poe_portLegacyEnable_get/set
sal_poe_portLimitMode_get/set
sal_poe_portPowerLimit_get/set
sal_poe_portPowerMode_get/set
sal_poe_portPowerStatus_get
sal_poe_portPower_get
sal_poe_portPriority_get/set
sal_poe_portStatsClear_set
sal_poe_portStats_get
sal_poe_portStatusStateEvent_set
sal_poe_portStatus_get
sal_poe_power_get
sal_poe_status_get
sal_poe_boardClassLimit_get
sal_poe_boardLedEnable_get
sal_poe_boardPortConf_get
sal_poe_dbg_message_set
sal_poe_dbg_raw_set
sal_poe_init_set
sal_poe_firmware_upgrade
sal_poe_sched_get/set
```

### CLI PoE Commands (from libsal strings)

```
show power inline           → displays port PoE status
show power inline consumption → displays power consumption
Port %s poe admin state is set to %s
Port %s poe power limit is set to %d
Port %s poe priority is set to %s
PoE mode is set to %s
```

### Text/Display Functions
```
text_poe_chip         → Chip type display strings
text_poe_class        → PD class display strings (class0-class4)
text_poe_limitMode    → Limit mode display strings
text_poe_portPowerMode → Power mode display strings
text_poe_portStatus   → Port status display strings
text_poe_portStatusDescStr → Detailed status descriptions
text_poe_pri          → Priority display strings
```

### PoE Status Descriptions (from strings)
```
802.3af-compliant PD was detected and power is delivering
802.3af-compliant PD was detected and requesting power
PSE functionality was turn off by administrative configuration
Power allocation exceeds the power limit defined by classification or user-defined
Power disconnected from the main power supply
Power up sequence operation failure
Power was denied because of insufficient power, or administrative operation
Short circuit condition was detected
Port is trying to detect a PD connect
Port link down
Port was shut down because of temperature is too high
```

### Counter Headers
```
Port Overload | Short Current | Power Denied | MPS Absent | Invalid Sig.
```

### Key Architecture Insights

1. **Three-layer architecture**: CLI → SAL (libsal.so) → Kernel Module (board_poe.ko)
2. **`ski_poe_cmd_mux`**: Central command multiplexer that routes to chip-specific handlers
3. **Event-driven**: `poe_portStatusStateEvent_set` and `poe_portEventMon_register` for async notifications
4. **LLDP integration**: `board_lldp_poe_register` for LLDP-MED PoE power negotiation
5. **Firmware upgrade**: `poe_fw_upgrade` / `bcm59121_firmware_upgrade` / `rtl8238b_firmware_upgrade`
6. **Debug infrastructure**: `poe_dbg_message_set`, `poe_dbg_raw_set`, `poe_dbg_readonly_set`, `bcm59111_message_debug`
7. **PoE log file**: `cat /tmp/poe.log` — stock writes PoE debug to this file

---

## Key Findings for Our Implementation

### Already Implemented ✅
- 0x20 (Get system info)
- 0x21 (Get port status)
- 0x22 (Get port counters)
- 0x23 (Get power stats)
- 0x25 (Get port config)
- 0x26 (Get extended port config)
- 0x27 (Get power management mode)
- 0x28 (Get all-port status)
- 0x29 (PSE consumed power — custom, not in stock)
- 0x30 (Get port power/voltage/current/temp)
- 0x00 (Set port enable)
- 0x02 (MCU enable port mapping)
- 0x03 (Set disconnect type)
- 0x05 (MCU clear counters)
- 0x16 (Set power limit)
- 0x17 (Set system config)
- 0x18 (Set system config extended)

### Stock Features We Should Consider Adding
1. **`sal_poe_portStatsClear_set`** → Our 0x05 clear counters
2. **`sal_poe_portStatusStateEvent_set`** → Async port status change notifications
3. **`sal_poe_portL2Data_get`** → L2 data (LLDP PoE)
4. **`sal_poe_firmware_upgrade`** → MCU firmware upgrade path
5. **`sal_poe_extParamEnable_get/set`** → Extended parameters (BCM59121 feature)
6. **Power threshold monitoring** → The `_poe_threshold_thread` monitors % usage
7. **LED control** → Port LED activity for PoE status
8. **LLDP PoE** → `board_lldp_poe_register` for LLDP-MED power negotiation

### Power Budget Calculation
From string: `power budget: %u mW, allocated: %u mW, consumed: %u mW`
- Stock uses milliwatts (mW) internally
- Three distinct values: budget, allocated, consumed
- Our 0x29 gives consumed/allocated, 0x23 gives budget
- The "allocated" in stock likely comes from 0x29 accumulated across ports

### Chip Detection
From string: `PoE chip 0x%x is %s` / `found` / `unsupported`
- Stock detects chip type at init
- BCM59111, BCM59121, RTL8238B, BCM59011 all supported

---

# Part 2: Timeout / Retry / Recovery Analysis (2026-09-23)

Full disassembly pass over `board_poe.ko` with capstone (MIPS32 BE) +
SHT_REL relocation resolution. All addresses are `.text` section-relative
(symbol table has size-0 entries; static helpers located by call-target
analysis). Companion scripts and raw findings live in the analysis session;
every value below was read directly from instruction immediates.

## Q1 — Stock MCU response timeout

**Per-byte RX timeouts** (RX helper at `0xf820`, called from
`rtl8238b_uart_xmit` at `0xf944` with `$a3 = 0x32`):

| Stage | Budget | Evidence |
|---|---|---|
| First response byte | **150 ms** | `0xf850: addiu $a2, $a3, 0x64` (0x32 + 0x64 = 0x96 = 150) |
| Each subsequent byte (up to 12) | **50 ms** | `0xf83c..0xf88c` loop, `$a3 = 0x32` |
| Absolute worst RX window per attempt | 150 + 11×50 = **700 ms** | |
| Wire time per 12-byte frame @19200/8N1 | ~6.25 ms | |

TX is blocking byte-by-byte `drv_uart_putc` (helper at `0xf8cc`), no timeout.

**Command retry budget** (`rtl8238b_cmd_set` `0xe86c` tail at `0xf268`,
identical in `rtl8238b_cmd_get` `0xf2f8` tail at `0xf624`):

- Max attempts: **16** — `0xf268: sltiu $v0, $s4, 0x10`
- Sleep between attempts: **50 ms** — `0xf27c: ori $a0, $zero, 0xc350` (50000 µs) via `osal_time_usleep`
- Fresh sequence number per attempt (regenerated from `0xe610`)
- Final failure: `sys_log(0, 9, "Retry counts: %u / %u")`, return −1

So a single synchronous `cmd_set`/`cmd_get` ioctl blocks for:
- Typical (healthy MCU): **< 100 ms**
- Absolute worst case: 16 × (700 ms + 50 ms) ≈ **12 s**

**There is no 30-second constant anywhere in the stock module.**

**State-change visibility** (`_poe_portStatusState_thread`, entry `0x17d4`):
- Base tick: `osal_time_sleep(1)` — 1 s
- `poe_allPortStatus_get` on `tick & 3 == 0` → **every 4 s**, diffed against
  cache, changes fire the registered event callback + `sys_dbg` (line 0x9b)
- `poe_allPortStats_get` on `tick % 0x14 == 0` → every 20 s
- `_poe_threshold_thread` (entry `0x1b10`): `board_poe_ctrl_thread()` every
  tick, power/threshold check every 5 s (`tick % 5`)

Stock "port disabled → status shows it" latency: **typically < 1 s, worst
~5 s** (4 s poll period + 1 s phase). Threads created by `poe_ctrl_init`
(`0x2504`) via `osal_thread_create(name, 0x8000 stack, 0x42 prio, entry, 0)`.

## Q2 — Host↔MCU protocol (RTL8238B / STM32F100 path)

- **Transport**: UART, `drv_uart_baudrate_set(0, 4)` in `rtl8238b_uart_init`
  (`0xfc8c`). Baud index 4 = **19200** (cross-checked: our fork's default on
  this exact hardware is 19200, `src/main.c:2133`; BCM59111 boards use index
  1 = different rate). Kernel console is separately 115200
  (`console=ttyS0,115200` in .bix vmlinux).
- **Dispatch**: `rtl8238b_smi_init` (`0xf690`) reads
  `board_poe_smiConf_get()`; when the board config selects UART it installs
  the ops table at `.data+0x330` = {`rtl8238b_uart_init`,
  `rtl8238b_uart_xmit`, `rtl8238b_uart_xmit_timeout`, `rtl8238b_uart_exchange`}
  into global `0x1190`. `cmd_set`/`cmd_get` frame builders → `0xe67c` →
  `rtl8238b_smi_exchange` (`0xf7ec`) → `uart_exchange` → `uart_xmit`.
- **Frame** (12 bytes, matches our fork exactly):
  - `[0]` command byte
  - `[1]` sequence: rolling counter at `.data+0x320`, wraps 0xFE→0 (gen at `0xe610`)
  - `[2..10]` args
  - `[11]` checksum = low byte of sum of bytes 0..10 (checksum slot zeroed
    first; calc at `0xe63c`, append in `cmd_set` at `0xefd4`)
- **Exchange sequence** (`rtl8238b_uart_xmit` `0xf944`):
  `mutex_lock(&g_rtl8238b_uart_mutex @ .data+0x11a4)` →
  `drv_uart_clearfifo(0)` → TX 12 bytes → RX 12 bytes (timeouts above) →
  `mutex_unlock`.
- **Validation** of the reply (cmd_set lines 0x1cf–0x21a): checksum recompute,
  command-echo match, per-record parsing for multi-port formats; failures log
  `Host <-> PoE: communication failed`, `PoE -> Host: checksum validation
  failed`, `controller is in BOOTROM, requesting image`, `not ready to
  response`, `negative Acknowledgement (%d)`, etc. and trigger the retry.
- Debug hexdump helper at `0xe6a4` prints `H->M: %s` / `M->H: %s` frames —
  only at retry 0 or retry 16 (final).

## Q3 — Retry/recovery mechanisms vs our fork

| Mechanism | Stock | Fork (ai-experiments) |
|---|---|---|
| Command retry | 16 attempts, 50 ms apart, fresh seq each, synchronous | Single attempt, 2 s async response timeout |
| On no response | Retry 15 more times; command still returns error only after ~12 s | `mcu_no_response`: **drops entire pending queue** + software reset (cmd `0x02`) |
| Hardware MCU reset | `board_poe_reset_set` (`0x40e0`): GPIO assert `period_ms`, release, wait `restart_ms` (values from board config, ms×1000 → µs), then `poe_init_status_check()` re-handshake; `sys_log` "PoE has been reset" | none (GPIO line unused) |
| Errdisable recovery | Userspace `sal_port_errDisableRecovery_set` / `errDisableTime_set` / `errDisable_recover` (libsal/cli) — auto re-enable of faulted ports | none |
| Port status events | 4 s poll diff → event callback + ksi msg (0x401/0x402/0x18/0x24 params) | 1 s poll diff → ubus `poe.port_status` event (fork is FASTER here) |
| Threshold monitor | every 5 s, ksi events, hysteresis flag | every poll (~1 s), ubus event (equivalent) |
| Serialization | mutex per UART | single-command queue (equivalent) |

The "wedged daemon" failure mode documented in `labgrid/conwrt_poe.py`'s
docstring (manage rc=0 but command silently dropped) maps exactly to the
fork's `mcu_no_response` dropping the queue — stock never drops a command
without 16 delivery attempts, and can always fall back to the GPIO reset.

## Q4 — Maximum expected latency for port enable/disable

- Stock SET ack round trip: typical < 150 ms, worst ~12 s (16 × 700 ms + 15 × 50 ms)
- Status reflecting the change: +0–5 s (4 s poll cadence)
- **Practical worst-case confirmed state change: ~5 s typical-path, ~17 s pathological**
- A 30 s confirmation delay is NOT stock behavior. If the STM32 takes 30 s,
  stock would have long since (a) retried 16×, (b) logged
  `Retry counts: 16 / 16`, (c) returned −1 to the CLI, and (d) left the
  state to be discovered by the next 4 s poll.

## Recommended backend/fork changes

1. **`labgrid/conwrt_poe.py` is currently broken (local uncommitted edit)**:
   `def power_set` got re-indented inside `_verify_manage` — module-level
   `power_set` no longer exists (`hasattr(conwrt_poe, 'power_set') == False`),
   so every labgrid power op fails regardless of MCU speed. Revert to
   `bf32cf9` or fix the indentation before tuning any timeouts.
2. **VERIFY_TIMEOUT_S = 20 is already generous** vs stock's ~5 s worst-case
   visibility; keep 20 s (or drop to ~10 s once the fork is healthy) with the
   existing FROZEN_GRACE_S = 6 wedge detector — that detector is the right
   analog of stock's "Retry counts exhausted" signal.
3. Fork improvements worth porting from stock (priority order):
   - Retry N× with fresh sequence before declaring no-response (stock: 16×/
     50 ms; even 3×/500 ms would eliminate most wedge-triggered resets).
   - Never drop the whole pending queue on one timeout — retry the head.
   - Consider the hardware reset GPIO as the escalation after retries fail
     (stock: `board_poe_reset_set`), instead of the software chicken-reset
     which the MCU may ignore when wedged.

## Key address map (board_poe.ko `.text`)

| Addr | Function |
|---|---|
| 0x1494 | poe_init_status_check (checks init flag @ .bss+0x284) |
| 0x17d4 | _poe_portStatusState_thread |
| 0x1b10 | _poe_threshold_thread |
| 0x2504 | poe_ctrl_init (thread creation) |
| 0x40e0 | board_poe_reset_set (GPIO MCU reset) |
| 0xe610 | seq number generator (counter @ .data+0x320) |
| 0xe63c | frame checksum (12-byte additive sum) |
| 0xe67c | exchange dispatch → smi_exchange |
| 0xe6a4 | H->M/M->H hexdump (retry 0/16 only) |
| 0xe86c | rtl8238b_cmd_set (16×50 ms retry) |
| 0xf2f8 | rtl8238b_cmd_get (16×50 ms retry) |
| 0xf690 | rtl8238b_smi_init (installs UART ops @ .data+0x330 → global 0x1190) |
| 0xf820 | uart RX helper (150 ms first byte / 50 ms per byte) |
| 0xf8cc | uart TX helper (blocking putc loop) |
| 0xf944 | rtl8238b_uart_xmit (cmd transport, timeout 0x32=50) |
| 0xfad0 | rtl8238b_uart_xmit_timeout (explicit-timeout variant, ops slot 2) |
| 0xfc5c | rtl8238b_uart_exchange |
| 0xfc8c | rtl8238b_uart_init (baud idx 4 = 19200) |

Magic numbers: `0x32`=50 ms per-byte timeout, `0x64`=+100 ms first-byte grace,
`0xC350`=50000 µs retry sleep, `0x10`=16 max retries, `0x254`=596 module
error code, poll divisors 4 (status) / 5 (threshold) / 20 (stats), `0x3E8`
ms→µs multiplier in reset timing.

## .bix image note

`data/runtime-GS1900-8HPv2.1-V2.90(AAHI.0).bix` = 0x40-byte header +
gzip(vmlinux, 7.68 MB) + ASCII version table at 0x5cd6a7. **No rootfs and no
STM32 firmware image inside** — kernel cmdline `console=ttyS0,115200
mem=64M`. The STM32 firmware and rtcore.ko (baud table) live in the
rootfs partition, which is not present in the .zip; the binaries in this
directory (board_poe.ko, cli, libsal.so.0.0) remain the analysis surface.
