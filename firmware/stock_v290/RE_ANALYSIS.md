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
