# EdgeOS Userspace Protocol — ubnt-hal-e Analysis

**Binary**: `/tmp/edgeos-chroot/usr/sbin/ubnt-hal-e`
**Format**: ELF 32-bit MSB PIE executable, MIPS32 rel2, dynamically linked, stripped
**Size**: 145,800 bytes
**BuildID**: ff5218fe6b274ed969c5e6faaf750f83c49ad3f0
**Linked libs**: libboost_thread.so.1.62.0, libpthread, libc
**Date**: 2026-05-20

---

## Executive Summary

**The HAL communicates with the kernel via DIRECT SYSFS WRITES — NOT via unix socket.**

There is **zero evidence** of `ubnt.socket.platd`, `AF_UNIX`, `connect`, `send`, or `recv` in this binary. The HAL writes PoE mode values (0-5) to `/sys/module/ubnt_platform/eth%d/poe` using standard C `fopen`/`fprintf`/`fclose`. The kernel module's `poe_st` sysfs store handler receives the value and dispatches GPIO writes.

---

## Table of Contents

1. [Communication Architecture](#communication-architecture)
2. [HAL Class Structure](#hal-class-structure)
3. [pportSetPoe — Full Disassembly](#pportsetpoe--full-disassembly)
4. [pportPowerOn / pportPowerOff](#pportpoweron--pportpoweroff)
5. [allPortsPoeOff / allPortsPowerOff](#allportspoeoff--allportspoweroff)
6. [Helper Functions](#helper-functions)
7. [Sysfs Path Format](#sysfs-path-format)
8. [port_poe_t Enum](#port_poe_t-enum)
9. [Full Call Chain: CLI to GPIO](#full-call-chain-cli-to-gpio)
10. [Cross-Reference with A1](#cross-reference-with-a1)
11. [String Constants](#string-constants)
12. [Symbol Table](#symbol-table)

---

## Communication Architecture

```
┌─────────────────────┐
│  EdgeOS CLI / WebUI │
│  (PHP/Vyatta conf)  │
└──────────┬──────────┘
           │ system("ubnt-hal-e ...")
           ▼
┌─────────────────────┐
│   ubnt-hal-e        │  (THIS BINARY)
│   hal::HwAccess     │
│   pportSetPoe()     │
└──────────┬──────────┘
           │ fopen("/sys/module/ubnt_platform/eth%d/poe", "w")
           │ fprintf(file, "%d\n", mode_value)
           │ fclose(file)
           ▼
┌─────────────────────┐
│  sysfs filesystem   │
│  /sys/module/       │
│  ubnt_platform/     │
│  eth0/poe           │  ← sysfs attribute
└──────────┬──────────┘
           │ store handler callback
           ▼
┌─────────────────────┐
│  ubnt_platform.ko   │  (A1 analyzed)
│  poe_st()           │  ← sysfs store handler
│  er_gen2_set_poe_*  │
└──────────┬──────────┘
           │ *(uint64_t*)GPIO_TX_SET = (1 << pin)
           ▼
┌─────────────────────┐
│  Hardware GPIOs     │
│  1-10, 16           │
│  24V/48V enable     │
└─────────────────────┘
```

**No socket layer exists between HAL and kernel module.** The `/tmp/ubnt.socket.platd` path is used by other EdgeOS components (likely `ubnt-util` or `lighttpd` CGI), NOT by `ubnt-hal-e`.

---

## HAL Class Structure

The binary is C++ with a single main class: `hal::HwAccess`.

### Object Layout (from constructor at 0x172d4)

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| 0x00-0x0C | Various | Internal containers | Maps/vectors for port data |
| 0x24 | ptr | Linked list / container | |
| 0x2C | ptr | Pointer to secondary data | |
| 0x3C | ptr | Virtual table or function ptr | |
| 0x44-0x49 | bytes | Per-port state arrays | Zeroed in constructor |
| 0x4A | uint8 | Unknown flag | |
| 0x4B | uint8 | **port_count** | Number of ports |
| 0x4E-0x4F | bytes | More flags | |
| 0x50 | uint8 | Unknown | |
| 0x51 | uint8 | Unknown (poe_cap?) | |
| 0x53 | uint8 | Unknown flag | |
| 0x58-0x63 | Various | Monitoring data | |
| 0x64 | uint8 | Port state | |
| 0x68-0xB3 | Various | Temperature/voltage structs | |
| 0xB4-0xF7 | Various | Monitoring entries | |
| 0xF8+ | Various | More monitoring data | |

### Key Methods (from dynamic symbol table)

| Address | Size | Method | Purpose |
|---------|------|--------|---------|
| 0x10008 | 296 | `pportSetPoe(int, port_poe_t)` | Set PoE mode on a port |
| 0x102ac | 112 | `pportPowerOn(int)` | Enable power on a port |
| 0x101b8 | 112 | `pportPowerOff(int)` | Disable power on a port |
| 0x10130 | 136 | `allPortsPoeOff()` | Turn off PoE on all ports |
| 0x10228 | 132 | `allPortsPowerOff()` | Turn off power on all ports |
| 0x10a70 | 596 | `pportGetMac(int, vector<uint8_t>&)` | Get port MAC address |
| 0x0afe8 | 264 | `pportOnSwitch(int) const` | Check if port is on switch |
| 0x10cc4 | 460 | `sportGetMac(vector<uint8_t>&)` | Get switch MAC |
| 0x0f8dc | 112 | `allSwitchPortsSwitched()` | Check all ports switched |
| 0x0fe54 | 28 | `check_port_idx(int) const` | Validate port index |
| 0x172d4 | 1204 | `HwAccess(bool)` | Constructor |
| 0x152f8 | 8156 | `refresh()` | Refresh all hardware state |
| 0x130e0 | 4764 | `getTemp(vector<string>&)` | Get temperature readings |
| 0x17788 | 760 | `get(bool)` | Get hardware info |
| 0x091f4 | 1944 | `main` | CLI entry point |

---

## pportSetPoe — Full Disassembly

### Function Signature

```cpp
bool hal::HwAccess::pportSetPoe(int port, hal::port_poe_t mode);
// MIPS O32: $a0 = this, $a1 = port, $a2 = mode
// Returns: true (1) if mode was set and verified, false (0) otherwise
```

### Annotated Disassembly

```
# === PROLOGUE ===
0x10008: lui     $gp, 3                    # Set up $gp for PIC access
0x1000c: addiu   $gp, $gp, -0x69d8
0x10010: addu    $gp, $gp, $t9
0x10014: lbu     $v1, 0x51($a0)           # v1 = this->has_poe (capability check)
0x10018: bnez    $v1, 0x10028             # if port has PoE capability: proceed
0x1001c: move    $v0, $zero               # [DELAY SLOT] return 0
0x10020: jr      $ra                      # RETURN: no PoE capability
0x10024: nop

# === HAS POE: SET UP ===
0x10028: addiu   $sp, $sp, -0xa0          # Allocate 160-byte stack frame
0x1002c: lw      $t9, -0x7fc4($gp)        # t9 = check_port_idx function
0x10030: sw      $gp, 0x10($sp)           # Save $gp
0x10034: sw      $s1, 0x90($sp)           # Save callee-saved
0x10038: move    $s1, $a1                 # s1 = port number
0x1003c: sw      $s0, 0x8c($sp)
0x10040: move    $s0, $a2                 # s0 = mode (port_poe_t enum)
0x10044: sw      $ra, 0x9c($sp)
0x10048: sw      $s3, 0x98($sp)
0x1004c: bal     0xfe54                   # CALL: this->check_port_idx(port)
0x10050: sw      $s2, 0x94($sp)           # [DELAY SLOT] save $s2

# === CHECK PORT INDEX RESULT ===
0x10054: bnez    $v0, 0x1007c             # if port index valid: proceed
0x10058: lw      $gp, 0x10($sp)

# Port index invalid - return 0
0x1005c: lw      $ra, 0x9c($sp)
0x10060: move    $v0, $zero               # return 0 (failure)
0x10064: lw      $s3, 0x98($sp)
0x10068: lw      $s2, 0x94($sp)
0x1006c: lw      $s1, 0x90($sp)
0x10070: lw      $s0, 0x8c($sp)
0x10074: jr      $ra
0x10078: addiu   $sp, $sp, 0xa0

# === VALIDATE MODE RANGE ===
0x1007c: sltiu   $v0, $s0, 6              # v0 = (mode < 6) ? 1 : 0
0x10080: beqz    $v0, 0x10060             # if mode >= 6: return 0 (invalid mode)
0x10084: lw      $ra, 0x9c($sp)           # [DELAY SLOT] preload $ra

# === BUILD SYSFS PATH ===
0x10088: lw      $s2, -0x7fcc($gp)        # s2 = GOT entry (base for helpers)
0x1008c: addiu   $s3, $sp, 0x18           # s3 = stack buffer (path output)
0x10090: addiu   $a1, $zero, 7            # a1 = 7 (max path length / attribute selector)
0x10094: move    $a2, $s3                 # a2 = output buffer pointer
0x10098: addiu   $s2, $s2, -0x135c        # s2 = helper_build_path function
0x1009c: move    $t9, $s2
0x100a0: bal     0xeca4                   # CALL: build_path(port, 7, buffer)
                                        # Builds: "/sys/module/ubnt_platform/eth%d/poe"
0x100a4: move    $a0, $s1                 # [DELAY SLOT] a0 = port

# === WRITE MODE TO SYSFS ===
0x100a8: move    $a1, $s0                 # a1 = mode value
0x100ac: lw      $gp, 0x10($sp)
0x100b0: lw      $t9, -0x7fcc($gp)
0x100b4: addiu   $t9, $t9, -0x1524        # t9 = helper_write_val function
0x100b8: bal     0xeadc                   # CALL: write_val(path, mode)
                                        # Opens sysfs file, writes "%d\n", closes
0x100bc: move    $a0, $v0                 # [DELAY SLOT] a0 = file handle or result

# === OPEN FILE FOR READ-BACK ===
0x100c0: lui     $v0, 0xee6               # Load address of string constant
0x100c4: lw      $gp, 0x10($sp)
0x100c8: addiu   $a0, $sp, 0x7c           # a0 = stack buffer for readback path
0x100cc: move    $a1, $zero               # a1 = 0 (O_RDONLY or "r" mode)
0x100d0: sw      $zero, 0x7c($sp)         # Clear buffer
0x100d4: ori     $v0, $v0, 0xb280         # v0 = string address (resolved at runtime)
0x100d8: lw      $t9, -0x7da8($gp)        # t9 = fopen function
0x100dc: jalr    $t9                      # CALL: fopen(path, mode)
0x100e0: sw      $v0, 0x80($sp)           # [DELAY SLOT] store string address

# === REBUILD PATH FOR READ-BACK ===
0x100e4: addiu   $a1, $zero, 7            # a1 = 7 (same attribute selector)
0x100e8: move    $a2, $s3                 # a2 = path buffer
0x100ec: move    $t9, $s2                 # t9 = build_path
0x100f0: bal     0xeca4                   # CALL: build_path(port, 7, buffer) again
0x100f4: move    $a0, $s1                 # [DELAY SLOT] a0 = port

# === READ BACK VALUE ===
0x100f8: lw      $gp, 0x10($sp)
0x100fc: lw      $t9, -0x7fcc($gp)
0x10100: addiu   $t9, $t9, -0x1670        # t9 = helper_read_val function
0x10104: bal     0xe990                   # CALL: read_val(path)
                                        # Opens sysfs file, reads integer value
0x10108: move    $a0, $v0                 # [DELAY SLOT] a0 = result

# === VERIFY: COMPARE WRITTEN vs READ ===
0x1010c: lw      $ra, 0x9c($sp)
0x10110: xor     $v0, $s0, $v0            # v0 = mode ^ read_value
0x10114: lw      $s3, 0x98($sp)
0x10118: sltiu   $v0, $v0, 1              # v0 = (mode == read_value) ? 1 : 0
                                        # SUCCESS: returns 1 if write verified
0x1011c: lw      $s2, 0x94($sp)
0x10120: lw      $s1, 0x90($sp)
0x10124: lw      $s0, 0x8c($sp)
0x10128: jr      $ra
0x1012c: addiu   $sp, $sp, 0xa0
```

### pportSetPoe Pseudocode

```cpp
bool HwAccess::pportSetPoe(int port, port_poe_t mode) {
    if (!this->has_poe)           // offset 0x51 check
        return false;
    
    if (!this->check_port_idx(port))
        return false;
    
    if (mode >= 6)                // valid modes: 0-5
        return false;
    
    // Build sysfs path: /sys/module/ubnt_platform/eth%d/poe
    char path[64];
    build_sysfs_path(port, "poe", path, sizeof(path));
    
    // Write mode value to sysfs attribute
    sysfs_write_int(path, (int)mode);
    
    // Read back and verify
    int readback = sysfs_read_int(path);
    
    return (mode == readback);    // true if write was successful
}
```

---

## pportPowerOn / pportPowerOff

### pportPowerOn(int port) — 0x102ac, 112 bytes

```
# Prologue
0x102ac: lui/addiu/addu $gp setup
0x102b8: addiu   $sp, $sp, -0x88          # Allocate 136-byte stack
0x102cc: bal     0xfe54                   # CALL: check_port_idx(port)
0x102d0: move    $s0, $a1                 # [DELAY SLOT] s0 = port

# If check failed, skip
0x102d4: beqz    $v0, 0x1030c

# Build path with attribute selector 8 (="power")
0x102e0: addiu   $a2, $sp, 0x18           # output buffer
0x102e4: addiu   $a1, $zero, 8            # a1 = 8 → selects "power" attribute
0x102f0: bal     0xeca4                   # CALL: build_path(port, 8, buffer)

# Write value 1 (enable)
0x102f4: addiu   $a1, $zero, 1            # a1 = 1 (ENABLE)
0x10304: bal     0xeadc                   # CALL: write_val(path, 1)

# Epilogue
0x1030c: restore and return
```

### pportPowerOff(int port) — 0x101b8, 112 bytes

Identical structure to pportPowerOn, except:
```
0x10200: move    $a1, $zero               # a1 = 0 (DISABLE)
0x10210: bal     0xeadc                   # CALL: write_val(path, 0)
```

### Pseudocode

```cpp
bool HwAccess::pportPowerOn(int port) {
    if (!check_port_idx(port)) return false;
    char path[64];
    build_sysfs_path(port, "power", path, sizeof(path));  // selector=8
    return sysfs_write_int(path, 1);  // write "1"
}

bool HwAccess::pportPowerOff(int port) {
    if (!check_port_idx(port)) return false;
    char path[64];
    build_sysfs_path(port, "power", path, sizeof(path));  // selector=8
    return sysfs_write_int(path, 0);  // write "0"
}
```

---

## allPortsPoeOff / allPortsPowerOff

### allPortsPoeOff() — 0x10130, 136 bytes

```
0x10154: lbu     $v0, 0x4b($a0)           # v0 = port_count
0x10158: beqz    $v0, 0x101b0             # if port_count == 0: skip
0x1015c: move    $s0, $zero               # s0 = 0 (loop counter)
0x10160: addiu   $s2, $zero, 1            # s2 = 1 (success flag)

# LOOP:
0x10168: lw      $t9, ...                 # load pportSetPoe address
0x1016c: move    $a2, $zero               # a2 = 0 (POE_OFF)
0x10170: move    $a1, $s0                 # a1 = port index
0x10174: bal     0x10008                  # CALL: pportSetPoe(this, port, POE_OFF)
0x10178: move    $a0, $s1                 # [DELAY SLOT] a0 = this
0x1017c: addiu   $s0, $s0, 1             # s0++ (next port)
0x10180: lbu     $v1, 0x4b($s1)           # v1 = port_count
0x10188: slt     $v1, $s0, $v1            # v1 = (port < port_count)
0x1018c: bnez    $v1, 0x10168             # if more ports: continue loop
0x10190: movz    $s2, $zero, $v0          # [DELAY SLOT] if pportSetPoe returned 0: clear success
```

### allPortsPowerOff() — 0x10228, 132 bytes

Same loop structure, but calls `pportPowerOff(this, port)` instead of `pportSetPoe`.

### Pseudocode

```cpp
bool HwAccess::allPortsPoeOff() {
    bool success = true;
    for (int i = 0; i < this->port_count; i++) {
        if (!pportSetPoe(i, POE_OFF))
            success = false;
    }
    return success;
}

bool HwAccess::allPortsPowerOff() {
    bool success = true;
    for (int i = 0; i < this->port_count; i++) {
        if (!pportPowerOff(i))
            success = false;
    }
    return success;
}
```

---

## Helper Functions

### helper_build_path — 0xeca4

Builds the sysfs path from a port number and attribute name.

**Signature**: `char* build_path(int port, int attr_selector, char* buffer)`

**Operation**:
1. Validates `attr_selector < 11` (there are ≤11 possible attributes)
2. Calls a setup function (likely `snprintf` or `memset`) with buffer size 16
3. Formats the port name using `eth%d` format string
4. Appends the attribute name from a string table indexed by `attr_selector`
5. Returns the buffer pointer

**String table** (attribute names indexed by selector):
| Selector | String | Used by |
|----------|--------|---------|
| 7 | `poe` | pportSetPoe |
| 8 | `power` | pportPowerOn/Off |

Other attribute names in the binary (selectors unknown):
`autoneg`, `carrier`, `change_sda`, `duplex`, `speed`, `on_switch`, `poe_cap`, `temp`, `power_mon`, `input48v`, `fan_ctrl`, `fan_tach`, `locate_led`, `system_led`, `reset`, `sfp_present`, `sfp_data`

### helper_write_val — 0xeadc

Writes an integer value to a sysfs file.

**Signature**: `bool sysfs_write_int(char* path, int value)`

**Operation**:
1. `fopen(path, "w")` — opens sysfs attribute for writing
2. If NULL: return false
3. `fprintf(file, "%d", value)` — writes the integer value
4. `fclose(file)` — closes the file
5. Returns true

**Called via GOT entries**: `fopen` at `-0x7c74($gp)`, `fprintf/fwrite` at `-0x7dd0($gp)`, `fclose` at `-0x7cfc($gp)`

### helper_read_val — 0xe990

Reads an integer value from a sysfs file.

**Signature**: `int sysfs_read_int(char* path)`

**Operation**:
1. `fopen(path, "r")` — opens sysfs attribute for reading
2. If NULL: return -1
3. `fgets(buffer, 16, file)` — reads the string value
4. `strtol(buffer, NULL, 10)` or `atoi` — parses to integer
5. `fclose(file)` — closes the file
6. Returns parsed integer value, or -1 on error

---

## Sysfs Path Format

### Confirmed Path Template

```
/sys/module/ubnt_platform/eth%d/<attribute>
```

Where:
- Base: `/sys/module/ubnt_platform/` (string at `.rodata+0x1cda4`)
- Port name: `eth%d` formatted with port index (string at `.rodata+0x1cdcc`)
- Attribute: one of `poe`, `power`, `poe_cap`, `temp`, etc.

### Example Paths

| Path | Purpose | Read/Write |
|------|---------|------------|
| `/sys/module/ubnt_platform/eth0/poe` | PoE mode (0-5) | R/W |
| `/sys/module/ubnt_platform/eth0/power` | Power on/off (0/1) | R/W |
| `/sys/module/ubnt_platform/eth0/poe_cap` | PoE capability bitmap | R |
| `/sys/module/ubnt_platform/eth0/on_switch` | Switch port status | R |
| `/sys/module/ubnt_platform/eth0/speed` | Link speed | R |
| `/sys/module/ubnt_platform/eth0/duplex` | Duplex mode | R |

### /proc/octeon_info

The HAL also reads `/proc/octeon_info` (string at `.rodata+0x1cf10`) for:
- `processor_id`
- `dram_size`
- `eclock_hz`
- `io_clock_hz`
- `dclock_hz`
- `board_type`
- `board_serial_number`
- `mac_addr_base` (format: `%x:%x:%x:%x:%x:%x`)
- `mac_addr_count`

---

## port_poe_t Enum

From pportSetPoe validation (`sltiu $v0, $s0, 6` — mode must be < 6):

```cpp
enum port_poe_t {
    POE_OFF     = 0,    // PoE disabled
    POE_48V     = 1,    // 802.3af/at (48V)
    POE_24V     = 2,    // 24V passive
    POE_UNKNOWN = 3,    // Unknown/reserved
    POE_UNKNOWN = 4,    // Unknown/reserved
    POE_BOTH    = 5,    // Both 24V+48V (4-pair)
};
```

Cross-referenced with A1's `poe_st` value dispatch table:
- **Value 0**: Both `er_gen2_set_poe_48v(port, 0)` and `er_gen2_set_poe_24v(port, 0)` → all off
- **Value 1**: `er_gen2_set_poe_24v(port, 0)` + `er_gen2_set_poe_48v(port, 1)` → 48V mode
- **Value 2**: `er_gen2_set_poe_48v(port, 0)` + `er_gen2_set_poe_24v(port, 1)` → 24V passive
- **Value 5**: `er_gen2_set_poe_24v(port, 1)` + `er_gen2_set_poe_48v(port, 1)` → both on

---

## Full Call Chain: CLI to GPIO

### PoE Mode Change (e.g., 24V on port 3)

```
1. EdgeOS CLI:  set interfaces ethernet eth3 poe output 24v
2. Config daemon invokes: ubnt-hal-e (or via Vyatta config backend)
3. hal::HwAccess::pportSetPoe(this=hw, port=3, mode=POE_24V=2)
4.   ├── check_port_idx(3) → true
5.   ├── validate: mode(2) < 6 → true
6.   ├── build_sysfs_path(3, "poe", buf) → "/sys/module/ubnt_platform/eth3/poe"
7.   ├── fopen("/sys/module/ubnt_platform/eth3/poe", "w") → fd
8.   ├── fprintf(fd, "%d", 2) → writes "2" to sysfs
9.   └── fclose(fd)
10. Kernel: poe_st() sysfs store handler triggered with "2"
11.   ├── sscanf("2", "%d", &value) → value=2
12.   ├── Validate against port capability bitmap
13.   ├── er_gen2_set_poe_48v(port, 0) → clear 48V GPIO
14.   ├── er_gen2_set_poe_24v(port, 1) → set 24V GPIO
15.   │   └── *(volatile uint64_t*)GPIO_TX_SET = (1 << gpio_pin)
16.   └── Store state: interface->poe_state = 2
17. HAL readback verification:
18.   ├── fopen("/sys/module/ubnt_platform/eth3/poe", "r")
19.   ├── fgets(buf, 16, fd) → reads "2"
20.   ├── strtol("2") → 2
21.   └── return (mode == readback) → true (success)
```

### Power On/Off

```
1. hal::HwAccess::pportPowerOn(this=hw, port=3)
2.   ├── build_sysfs_path(3, "power", buf) → "/sys/module/ubnt_platform/eth3/power"
3.   ├── fopen(..., "w")
4.   ├── fprintf(fd, "%d", 1)
5.   └── fclose(fd)
```

---

## Cross-Reference with A1

### A1 Findings Confirmed

| Finding | A1 (kernel module) | A3 (HAL) | Status |
|---------|-------------------|----------|--------|
| poe_st is sysfs store handler | Yes — function at 0x1718 | Writes to `/sys/.../poe` | **Confirmed** |
| Value 0=off, 1=48V, 2=24V, 5=both | Yes — dispatch table | `mode < 6` validation, same values | **Confirmed** |
| HAL writes "0"/"1"/"2"/"5" to sysfs | Inferred | Directly observed via fopen/fprintf | **Confirmed** |
| No socket communication needed | — | Zero socket strings/references | **Confirmed** |
| No I2C for ER-6P (e301) | E301 path uses GPIO only | HAL doesn't distinguish by board | **Confirmed** |

### New Findings from A3

1. **HAL writes `poe` attribute, not `poe_st`**: The sysfs attribute file name is `poe`, not `poe_st`. The `_st` suffix is the kernel convention for "store handler" — it's the function name, not the file name.

2. **Write-then-verify pattern**: The HAL reads back the value after writing to confirm success. This is a common pattern for hardware control.

3. **Two separate attributes**: `poe` (mode: 0-5) vs `power` (on/off: 0/1). The `power` attribute likely maps to a different kernel handler.

4. **Attribute selector system**: The HAL uses integer selectors (0-10) to pick attribute names from a table, enabling code reuse across all sysfs attributes.

5. **Board identification**: The HAL identifies boards by reading `/proc/octeon_info` fields. The ER-6P is board ID `e301`.

---

## String Constants

### Key Strings from .rodata

| Address | String | Purpose |
|---------|--------|---------|
| 0x1cda4 | `/sys/module/ubnt_platform/` | Sysfs base path for kernel module |
| 0x1cdcc | `eth%d` | Port name format |
| 0x1cec8 | `eth` | Port name prefix (for parsing) |
| 0x1d468 | `poe` | PoE mode attribute name |
| 0x1d460 | `poe_cap` | PoE capability attribute |
| 0x1d46c | `power` | Power on/off attribute |
| 0x1d454 | `on_switch` | Switch port attribute |
| 0x1cf10 | `/proc/octeon_info` | Board info procfs file |
| 0x1cfc8 | `/sys/spi/spi_lock` | SPI bus lock |
| 0x1d028 | `/dev/sda1` | USB storage device |
| 0x1d0a8 | `/dev/mmcblk0p1` | eMMC storage device |
| 0x1cee4 | `power_slot` | Power slot name |

### Board Identity Strings

| Code | Model | Full Name |
|------|-------|-----------|
| e100 | ERLite-3 | EdgeRouter Lite 3-Port |
| e101 | ERPoe-5 | EdgeRouter PoE 5-Port |
| e102 | — | — |
| e200 | ERPro-8 | EdgeRouter Pro 8-Port |
| e201 | ER-8 | EdgeRouter 8-Port |
| e202 | EP-R8 | EdgePoint Router 8-Port |
| e300 | ER-4 | EdgeRouter 4 |
| **e301** | **ER-6P** | **EdgeRouter 6P** |
| e302 | — | (E302 variant) |
| e303 | — | (E303 variant) |
| e50 | ER-X | EdgeRouter X 5-Port |
| e51 | ER-X-SFP | EdgeRouter X SFP 6-Port |
| e52 | EP-R6 | EdgePoint Router 6-Port |
| e53 | EP-ON | EdgePoint Router Instant |
| e55 | ER-10X | EdgeRouter 10X |
| e1000 | ER-8-XG | EdgeRouter Infinity |
| e600 | — | U Fiber OLT |

### Monitoring Attribute Names

`RPM`, `FAN 1/2/3`, `System voltage`, `System current`, `System power consumption`, `System input voltage`, `Terminal block current`, `POE-IN ETH0 current`, `POE-IN ETH8 current`, `CPU`, `Board 1/2`, `PHY 1/2`, `Board (CPU)`, `Board (PHY)`, `PHY`

### Sysfs Attribute Names

`input48v`, `freset`, `last_led`, `fan_ctrl`, `temp`, `power_mon`, `fan_tach`, `locate_led`, `system_led`, `autoneg`, `carrier`, `change_sda`, `duplex`, `speed`, `on_switch`, `poe_cap`, `poe`, `power`, `sfp_present`, `sfp_data`, `switched_ports`, `switch0`, `reset`, `port_vlans`, `vlan_aware`, `global`

---

## Symbol Table

### Demangled Exported Functions

```
hal::HwAccess::HwAccess(bool)                          @ 0x172d4 (1204 bytes)
hal::HwAccess::allPortsPoeOff()                        @ 0x10130 (136 bytes)
hal::HwAccess::allPortsPowerOff()                      @ 0x10228 (132 bytes)
hal::HwAccess::allSwitchPortsSwitched()                @ 0x0f8dc (112 bytes)
hal::HwAccess::check_port_idx(int) const               @ 0x0fe54 (28 bytes)
hal::HwAccess::get(bool)                               @ 0x17788 (760 bytes)
hal::HwAccess::getTemp(vector<string>&)                @ 0x130e0 (4764 bytes)
hal::HwAccess::pportGetMac(int, vector<uint8_t>&)      @ 0x10a70 (596 bytes)
hal::HwAccess::pportOnSwitch(int) const                @ 0x0afe8 (264 bytes)
hal::HwAccess::pportPowerOff(int)                      @ 0x101b8 (112 bytes)
hal::HwAccess::pportPowerOn(int)                       @ 0x102ac (112 bytes)
hal::HwAccess::pportSetPoe(int, hal::port_poe_t)       @ 0x10008 (296 bytes)
hal::HwAccess::refresh()                               @ 0x152f8 (8156 bytes)
hal::HwAccess::sportGetMac(vector<uint8_t>&)           @ 0x10cc4 (460 bytes)
main                                                   @ 0x091f4 (1944 bytes)
```

### Dynamic Library Dependencies

```
libboost_thread.so.1.62.0
libboost_serialization.so.1.62.0
libpthread.so.0
libc.so.6 (GLIBC_2.0)
libstdc++.so (GLIBCXX_3.4, CXXABI_1.3)
libm.so (ceil, floor)
```

---

## Key Conclusions

1. **NO socket protocol**: The HAL uses **direct sysfs file I/O** (fopen/fprintf/fclose) to communicate with `ubnt_platform.ko`. There is no unix socket, no `ubnt.socket.platd`, no message struct, no opcode system.

2. **The "protocol" is just a number**: Writing "0", "1", "2", or "5" to `/sys/module/ubnt_platform/eth%d/poe` triggers the kernel's `poe_st` handler.

3. **Write-then-verify**: The HAL reads back the value after writing to confirm the kernel accepted it.

4. **For OpenWrt implementation**: Writing directly to the sysfs attribute (or equivalently, calling the GPIO writes that `poe_st` performs) is the correct approach. The sysfs path may differ on OpenWrt since `ubnt_platform.ko` is not loaded — direct GPIO register writes are needed instead.
