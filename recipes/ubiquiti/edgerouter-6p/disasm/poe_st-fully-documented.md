# poe_st — Full Disassembly & Analysis

**Binary**: `ubnt_platform.ko` (ELF64 MSB MIPS64, EdgeOS v2.0.6, kernel 4.9.79-UBNT)
**Function**: `poe_st` at offset 0x1718, size 700 bytes (0x1718–0x19D4)
**Section**: `.text` (section index 2)
**Date**: 2026-05-20

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Function Signature & Register Convention](#function-signature--register-convention)
3. [Register Allocation](#register-allocation)
4. [Control Flow Graph](#control-flow-graph)
5. [Full Annotated Disassembly](#full-annotated-disassembly)
6. [er_gen2_set_poe_48v Disassembly](#er_gen2_set_poe_48v-disassembly)
7. [GPIO Operations Summary](#gpio-operations-summary)
8. [I2C Operations (E303 Path)](#i2c-operations-e303-path)
9. [Function Call Map](#function-call-map)
10. [Value Dispatch Table](#value-dispatch-table)
11. [Comparison: poe_st vs er_gen2_set_poe_24v](#comparison-poe_st-vs-er_gen2_set_poe_24v)
12. [Key Questions Answered](#key-questions-answered)
13. [Relocation Table](#relocation-table)

---

## Executive Summary

`poe_st` is the sysfs store handler for the `poe` attribute. It is the **top-level PoE control function** that:

1. Parses the user-written string (via `sscanf` with `"%d"`)
2. Validates the requested mode against the port's PoE capability bitmap
3. For **E301/E302** (ER-6P): Calls **both** `er_gen2_set_poe_24v` **and** `er_gen2_set_poe_48v` in a two-call sequence
4. For **E303** (newer models): Does read-modify-write on an I2C register via `i2c_smbus_read_byte_data` / `i2c_smbus_write_byte_data`
5. Stores the new state in the port's interface object

**Critical finding**: `poe_st` calls TWO sub-functions for E301/E302:
- `er_gen2_set_poe_24v` (loaded into `$s1`) — controls **even-indexed** GPIO entries (GPIOs 2, 4, 6, 10, 16) = **power-enable**
- `er_gen2_set_poe_48v` (loaded into `$s2`) — controls **odd-indexed** GPIO entries (GPIOs 1, 3, 5, 7, 9) = **pair-mode / 48V enable**

Neither sub-function touches GPIO_BIT_CFG (tx_oe configuration).

---

## Function Signature & Register Convention

```c
ssize_t poe_st(struct kobject *kobj, struct kobj_attribute *attr,
               const char *buf, size_t count);
```

MIPS64 n64 ABI:
- `$a0` = 1st arg: `struct kobject *kobj` (pointer to port's interface object)
- `$a1` = 2nd arg: `const char *buf` (user-written string)
- `$a2` = 3rd arg: `struct kobj_attribute *attr`
- `$a3` = 4th arg: `size_t count`
- Return: `$v0` = ssize_t (not explicitly set — inherits from sub-calls)

---

## Register Allocation

| Register | Role | Notes |
|----------|------|-------|
| `$s0` | `struct kobject *kobj` (port interface object) | Saved from `$a0`, used throughout |
| `$s1` | Function pointer → `er_gen2_set_poe_24v` | Loaded at 0x17fc/0x1804 |
| `$s2` | Function pointer → `er_gen2_set_poe_48v` | Loaded at 0x17ec/0x17f4 |
| `$s3` | Scratch (E303: I2C bit position) | |
| `$s4` | Scratch (E303: `i2c_poe` client pointer) | |
| `$s5` | Scratch (E303: I2C register number) | |
| `$sp` | Stack frame (80 bytes: 0x50) | Stores parsed value at `$sp+0` |
| `$sp+0` | Parsed integer value from sscanf | Written by sscanf, read for dispatch |

### Port Interface Object (`$s0`) Structure Offsets

| Offset | Type | Field |
|--------|------|-------|
| `0x48` | `uint8_t` | Port number (1-indexed) |
| `0x50` | `uint8_t` | Current PoE state (stored value) |
| `0x51` | `uint8_t` | PoE capability bitmap |

---

## Control Flow Graph

```
ENTRY (0x1718)
  │
  ├─ Prologue: save regs, load board_type
  │
  ├─ board_type == 3? ──YES──► E303 Path (0x1880)
  │                                │
  │                                ├─ simple_strtol(buf, NULL, 10)
  │                                ├─ Validate: value < 6
  │                                ├─ Lookup I2C client from _intf_obj table
  │                                ├─ i2c_smbus_read_byte_data(i2c_poe, reg)
  │                                ├─ Read-modify-write: set/clear bit
  │                                └─ i2c_smbus_write_byte_data(i2c_poe, reg, val)
  │
  │  NO (E301/E302 path)
  │
  ├─ sscanf(buf, "%d", &sp[0])
  ├─ Validate mode against port capability bitmap
  ├─ If current_state == requested: return (no change)
  ├─ E302 GPIO check (board_type == 2): read GPIO_RX_DAT
  │
  ├─ DISABLE BOTH FIRST (0x17e8):
  │   er_gen2_set_poe_48v(port, 0)
  │   er_gen2_set_poe_24v(port, 0)
  │
  ├─ Dispatch on parsed value:
  │   ├─ value == 0 ──► (already disabled, store & return)
  │   ├─ value == 1 ──► er_gen2_set_poe_24v(port, 0) + er_gen2_set_poe_48v(port, 1)
  │   ├─ value == 2 ──► er_gen2_set_poe_48v(port, 0) + er_gen2_set_poe_24v(port, 1)
  │   └─ value == 5 ──► er_gen2_set_poe_24v(port, 1) + er_gen2_set_poe_48v(port, 1)
  │
  └─ Store new state, return
```

---

## Full Annotated Disassembly

### Prologue & Board Type Check (0x1718–0x174C)

```
# === FUNCTION PROLOGUE ===
0x1718: daddiu  $sp, $sp, -0x50       # Allocate 80-byte stack frame
0x171c: addiu   $v1, $zero, 3          # v1 = 3 (E303 board type constant)
0x1720: sd      $s1, 0x20($sp)         # Save callee-saved registers
0x1724: lui     $s1, 0                 # [RELOC] HI16 → board_rev_major (.data+0x0)
0x1728: lw      $v0, ($s1)             # v0 = board_rev_major (= board_type)
                                       # NOTE: board_rev_major IS the board_type for E-series
0x172c: sd      $s0, 0x18($sp)         # Save $s0
0x1730: move    $s0, $a0               # s0 = kobj (port interface object)
0x1734: sd      $ra, 0x48($sp)         # Save return address
0x1738: move    $a0, $a1               # a0 = buf (for upcoming sscanf call)
0x173c: sd      $s5, 0x40($sp)         # Save $s5
0x1740: sd      $s4, 0x38($sp)         # Save $s4
0x1744: sd      $s3, 0x30($sp)         # Save $s3
0x1748: beq     $v0, $v1, 0x1880       # if board_type == 3: goto E303_PATH
                                       # (newer models use I2C-based PoE)
0x174c: sd      $s2, 0x28($sp)         # [DELAY SLOT] Save $s2
```

**Basic block summary**: Sets up stack frame, saves 6 callee-saved registers ($s0–$s5, $ra), loads board_type global, checks if E303.

### E301/E302 Path: Parse Input & Validate (0x1750–0x1784)

```
# === E301/E302 PATH: PARSE USER INPUT ===
0x1750: lui     $a1, 0                 # [RELOC] HI16 → "%d" string (.rodata.str1.8+0x78)
0x1754: lui     $v0, 0                 # [RELOC] HI16 → sscanf (external)
0x1758: daddiu  $a1, $a1, 0            # [RELOC] LO16 → "%d" string
0x175c: daddiu  $v0, $v0, 0            # [RELOC] LO16 → sscanf
0x1760: jalr    $v0                    # CALL: sscanf(buf, "%d", &sp[0])
                                       # Parses user's string to integer at stack[0]
0x1764: move    $a2, $sp               # [DELAY SLOT] a2 = &sp[0] (output int pointer)

# === VALIDATE AGAINST PORT CAPABILITY ===
0x1768: lw      $v0, ($sp)             # v0 = parsed integer value
0x176c: lbu     $v1, 0x51($s0)         # v1 = port's PoE capability bitmap
                                       # (from _intf_poe_cap_e301, e.g. 0x25 = 37 = 0b100101)
0x1770: srav    $v1, $v1, $v0          # v1 = capability >> value
                                       # Shifts capability bitmap right by requested mode
                                       # If bit 0 of result is set, this mode is supported
0x1774: bbit0   $v1, 0, 0x179c         # if bit 0 clear: mode NOT supported → goto EPILOG
                                       # Validation: requested mode must be supported by this port
0x1778: ld      $ra, 0x48($sp)         # [DELAY SLOT] preload $ra (for epilog)

# === CHECK IF STATE CHANGE NEEDED ===
0x177c: lbu     $v1, 0x50($s0)         # v1 = current PoE state
0x1780: bne     $v1, $v0, 0x17e8       # if current != requested: goto STATE_CHANGE (0x17e8)
0x1784: lw      $v1, ($s1)             # [DELAY SLOT] v1 = board_type (reload)
```

**Basic block summary**: Calls `sscanf(buf, "%d", &result)` to parse user input. Validates the requested mode against the port's capability bitmap. If current state equals requested, checks board_type for E302 GPIO read (falls through to 0x1788).

### E302 GPIO State Check (0x1788–0x17E4)

```
# === E302 GPIO READ CHECK ===
# (Only reached when current_state == requested and board_type < 2)
0x1788: addiu   $v0, $zero, 2          # v0 = 2
0x178c: beq     $v1, $v0, 0x17c0       # if board_type == 2 (E302): goto GPIO_READ
0x1790: lui     $v1, 0xff80            # [DELAY SLOT] v1 = 0xFFFFFFFFFF800000

# board_type < 2 (E301): no GPIO read needed, just return
0x1794: nop

# === COMMON EPILOG ===
0x1798: ld      $ra, 0x48($sp)         # (alternate entry from various early returns)
0x179c: ld      $s5, 0x40($sp)         # Restore $s5
0x17a0: ld      $s4, 0x38($sp)         # Restore $s4
0x17a4: ld      $s3, 0x30($sp)         # Restore $s3
0x17a8: ld      $s2, 0x28($sp)         # Restore $s2
0x17ac: ld      $s1, 0x20($sp)         # Restore $s1
0x17b0: ld      $s0, 0x18($sp)         # Restore $s0
0x17b4: jr      $ra                    # Return
0x17b8: daddiu  $sp, $sp, 0x50         # [DELAY SLOT] Deallocate stack

# === E302 GPIO READ PATH ===
# Reads current GPIO state to verify before returning
0x17bc: nop
0x17c0: lui     $v0, 0                 # [RELOC] HI16 → er_gen2_gpio_info (.data+0x3c9)
                                       # Wait — addend 0x3c9... this is POE_GPIO_E302 + some offset?
                                       # Actually: board_port_cfg_table or similar
0x17c4: lbu     $v0, ($v0)             # v0 = GPIO pin number for this port
0x17c8: ori     $v1, $v1, 0x107        # v1 = 0xFFFFFFFFFF800107
0x17cc: dsll32  $v1, $v1, 8            # v1 = XKPHYS: 0x8001070000000000
0x17d0: ori     $v1, $v1, 0x880        # v1 = 0x8001070000000880 = GPIO_RX_DAT register
0x17d4: ld      $v1, ($v1)             # v1 = *GPIO_RX_DAT (read all GPIO input states)
0x17d8: dsrlv   $v0, $v1, $v0          # v0 = GPIO_RX_DAT >> pin_number
0x17dc: bbit0   $v0, 0, 0x179c         # if GPIO bit is 0: state mismatch → return
0x17e0: ld      $ra, 0x48($sp)         # [DELAY SLOT] preload $ra
0x17e4: nop
```

**Basic block summary**: For E302 (board_type == 2), reads GPIO_RX_DAT register to verify current GPIO state matches expected. For E301 (board_type < 2), returns directly.

### State Change: Disable Both Modes First (0x17E8–0x1810)

```
# === STATE CHANGE: DISABLE BOTH 48V AND 24V FIRST ===
# This is the "reset to known state" sequence before enabling requested mode
0x17e8: lbu     $a0, 0x48($s0)         # a0 = port number (from interface object)
0x17ec: lui     $s2, 0                 # [RELOC] HI16 → er_gen2_set_poe_48v (.text+0x250)
0x17f0: move    $a1, $zero             # a1 = 0 (DISABLE)
0x17f4: daddiu  $s2, $s2, 0            # [RELOC] LO16 → er_gen2_set_poe_48v
0x17f8: jalr    $s2                    # CALL: er_gen2_set_poe_48v(port, 0)
                                       # Disables 48V / pair-mode GPIO (even-indexed entries)
0x17fc: lui     $s1, 0                 # [DELAY SLOT] [RELOC] HI16 → er_gen2_set_poe_24v (.text+0x148)

0x1800: lbu     $a0, 0x48($s0)         # a0 = port number (reload)
0x1804: daddiu  $s1, $s1, 0            # [RELOC] LO16 → er_gen2_set_poe_24v
0x1808: jalr    $s1                    # CALL: er_gen2_set_poe_24v(port, 0)
                                       # Disables 24V / power-enable GPIO (odd-indexed entries)
0x180c: move    $a1, $zero             # [DELAY SLOT] a1 = 0 (DISABLE)

# === DISPATCH ON PARSED VALUE ===
0x1810: lw      $v0, ($sp)             # v0 = parsed value (reload from stack)
0x1814: beqz    $v0, 0x1950            # if value == 0: goto MODE_0 (both off — already done)
0x1818: addiu   $v1, $zero, 2          # [DELAY SLOT] v1 = 2
0x181c: beq     $v0, $v1, 0x1978       # if value == 2: goto MODE_2
0x1820: addiu   $v1, $zero, 1          # [DELAY SLOT] v1 = 1
0x1824: beq     $v0, $v1, 0x19a0       # if value == 1: goto MODE_1
0x1828: addiu   $v1, $zero, 5          # [DELAY SLOT] v1 = 5
0x182c: bne     $v0, $v1, 0x179c       # if value != 5: goto EPILOG (invalid mode)
0x1830: ld      $ra, 0x48($sp)         # [DELAY SLOT] preload $ra (for epilog path)
```

**Basic block summary**: **Critical two-call disable sequence**: first disables 48V (pair-mode GPIOs via `er_gen2_set_poe_48v`), then disables 24V (power-enable GPIOs via `er_gen2_set_poe_24v`). Then dispatches based on parsed value: 0=off, 1=48V, 2=24V, 5=both on.

### MODE 5: Both 24V and 48V Enable (0x1834–0x1878)

```
# === MODE 5: ENABLE BOTH 24V AND 48V ===
# (4-pair / double-enable mode)
0x1834: lbu     $a0, 0x48($s0)         # a0 = port number
0x1838: jalr    $s1                    # CALL: er_gen2_set_poe_24v(port, 1)
                                       # Enable 24V power-enable GPIO
0x183c: addiu   $a1, $zero, 1          # [DELAY SLOT] a1 = 1 (ENABLE)

0x1840: lbu     $a0, 0x48($s0)         # a0 = port number (reload)
0x1844: jalr    $s2                    # CALL: er_gen2_set_poe_48v(port, 1)
                                       # Enable 48V pair-mode GPIO
0x1848: addiu   $a1, $zero, 1          # [DELAY SLOT] a1 = 1 (ENABLE)

# Store new state and return
0x184c: lw      $v0, ($sp)             # v0 = parsed value
0x1850: sb      $v0, 0x50($s0)         # Store new state: interface->poe_state = value
0x1854: nop

# === STORE-AND-RETURN EPILOG (shared by modes 5, 0, 2, 1) ===
0x1858: ld      $ra, 0x48($sp)         # Restore $ra
0x185c: ld      $s5, 0x40($sp)         # Restore $s5
0x1860: ld      $s4, 0x38($sp)         # Restore $s4
0x1864: ld      $s3, 0x30($sp)         # Restore $s3
0x1868: ld      $s2, 0x28($sp)         # Restore $s2
0x186c: ld      $s1, 0x20($sp)         # Restore $s1
0x1870: ld      $s0, 0x18($sp)         # Restore $s0
0x1874: jr      $ra                    # Return
0x1878: daddiu  $sp, $sp, 0x50         # [DELAY SLOT] Deallocate stack
```

### E303 Path: I2C-Based PoE Control (0x1880–0x194C)

```
# === E303 PATH (board_type == 3): I2C-BASED POE ===
# Used by newer EdgeRouter models with I2C PoE controllers
0x187c: nop
0x1880: lui     $v0, 0                 # [RELOC] HI16 → simple_strtol (external)
0x1884: move    $a1, $zero             # a1 = NULL (endptr)
0x1888: daddiu  $v0, $v0, 0            # [RELOC] LO16 → simple_strtol
0x188c: jalr    $v0                    # CALL: simple_strtol(buf, NULL, 10)
0x1890: addiu   $a2, $zero, 0xa        # [DELAY SLOT] a2 = 10 (base)

# Validate range: value must be 0–5
0x1894: sll     $v1, $v0, 0            # v1 = (int32)value
0x1898: move    $s1, $v0               # s1 = parsed value
0x189c: sltiu   $v0, $v1, 6            # v0 = (value < 6) ? 1 : 0
0x18a0: beqz    $v0, 0x1798            # if value >= 6: goto EPILOG (invalid)
0x18a4: lui     $v0, 0                 # [RELOC] HI16 → _intf_obj (.bss+0x8)

# Look up I2C client for this port
0x18a8: lbu     $a1, 0x48($s0)         # a1 = port number
0x18ac: ld      $a0, ($v0)             # a0 = _intf_obj base pointer
0x18b0: dsll    $v0, $a1, 2            # v0 = port * 4
0x18b4: ld      $a2, 0x18($a0)         # a2 = _intf_obj->i2c_client_table (offset 0x18)
0x18b8: lwx     $v0, $v0($a2)          # v0 = i2c_client_table[port] (I2C client pointer)
0x18bc: beqz    $v0, 0x1798            # if NULL: goto EPILOG (no client for this port)
0x18c0: srav    $v0, $v0, $v1          # [DELAY SLOT] v0 = table_entry >> value
0x18c4: bbit0   $v0, 0, 0x1798         # if bit 0 clear: mode not supported → EPILOG

# Check if state already matches
0x18c8: move    $s2, $v1               # s2 = value (for enable/disable check)
0x18cc: lbu     $v0, 0x50($s0)         # v0 = current PoE state
0x18d0: beq     $v0, $v1, 0x1798       # if current == requested: goto EPILOG (no change)
0x18d4: daddiu  $a1, $a1, 0xc          # a1 = port + 0xc (table entry offset)

# Look up I2C register/bit position from port config table
0x18d8: addiu   $v0, $zero, 0xff       # v0 = 0xFF (invalid marker)
0x18dc: dsll    $a1, $a1, 2            # a1 = (port + 0xc) * 4
0x18e0: daddu   $a0, $a0, $a1          # a0 = table_base + offset
0x18e4: lbu     $s3, 0xb($a0)          # s3 = I2C bit position from config table
0x18e8: beq     $s3, $v0, 0x1798       # if bit_pos == 0xFF: invalid → EPILOG
0x18ec: sltiu   $v0, $s3, 8            # v0 = (bit_pos < 8) ? 1 : 0
0x18f0: beqz    $v0, 0x19c8            # if bit_pos >= 8: goto ALTERNATE_I2C_REG
0x18f4: addiu   $s5, $zero, 3          # [DELAY SLOT] s5 = 3 (alt register number)

# === I2C READ-MODIFY-WRITE: Register 2 ===
0x18f8: addiu   $s5, $zero, 2          # s5 = 2 (I2C register number for PoE control)
0x18fc: lui     $s4, 0                 # [RELOC] HI16 → i2c_poe (.bss+0x1ca8)
0x1900: lui     $v0, 0                 # [RELOC] HI16 → i2c_smbus_read_byte_data (external)
0x1904: daddiu  $a0, $s4, 0            # [RELOC] LO16: a0 = i2c_poe (I2C client)
0x1908: daddiu  $v0, $v0, 0            # [RELOC] LO16 → i2c_smbus_read_byte_data
0x190c: jalr    $v0                    # CALL: i2c_smbus_read_byte_data(i2c_poe, 2)
                                       # Read current register 2 value
0x1910: move    $a1, $s5               # [DELAY SLOT] a1 = 2 (register number)

# Compute new value: set or clear the target bit
0x1914: addiu   $v1, $zero, 1          # v1 = 1
0x1918: sllv    $s3, $v1, $s3          # s3 = 1 << bit_position
0x191c: bnez    $s2, 0x1930            # if value != 0 (enable): goto SET_BIT
0x1920: or      $a2, $s3, $v0          # [DELAY SLOT] a2 = read_val | (1<<bit) [for enable]

# CLEAR_BIT path (value == 0, disable):
0x1924: nor     $s3, $zero, $s3        # s3 = ~(1 << bit_position)
0x1928: and     $v0, $s3, $v0          # v0 = read_val & ~(1<<bit) [clear the bit]
0x192c: move    $a2, $v0               # a2 = new_value (bit cleared)

# === I2C WRITE ===
0x1930: lui     $v0, 0                 # [RELOC] HI16 → i2c_smbus_write_byte_data (external)
0x1934: daddiu  $a0, $s4, 0            # [RELOC] LO16: a0 = i2c_poe (I2C client)
0x1938: move    $a1, $s5               # a1 = register number (2 or 3)
0x193c: daddiu  $v0, $v0, 0            # [RELOC] LO16 → i2c_smbus_write_byte_data
0x1940: jalr    $v0                    # CALL: i2c_smbus_write_byte_data(i2c_poe, reg, value)
                                       # Write modified byte back to I2C register
0x1944: andi    $a2, $a2, 0xff         # [DELAY SLOT] mask to byte

# Store state and return
0x1948: j       0x1858                 # JUMP → store-and-return epilog
0x194c: sb      $s1, 0x50($s0)         # [DELAY SLOT] interface->poe_state = value
```

### MODE 0: Full Disable (0x1950–0x1974)

```
# === MODE 0: FULL DISABLE ===
# Both modes already disabled by the pre-disable sequence at 0x17e8
# Just need to store the new state
0x1950: lbu     $a0, 0x48($s0)         # a0 = port number
0x1954: jalr    $s2                    # CALL: er_gen2_set_poe_48v(port, 0)
                                       # Redundant: already disabled, but ensures state
0x1958: move    $a1, $zero             # [DELAY SLOT] a1 = 0 (DISABLE)

0x195c: lbu     $a0, 0x48($s0)         # a0 = port number
0x1960: jalr    $s1                    # CALL: er_gen2_set_poe_24v(port, 0)
                                       # Redundant: already disabled, but ensures state
0x1964: move    $a1, $zero             # [DELAY SLOT] a1 = 0 (DISABLE)

0x1968: lw      $v0, ($sp)             # v0 = parsed value (0)
0x196c: j       0x1858                 # JUMP → store-and-return epilog
0x1970: sb      $v0, 0x50($s0)         # [DELAY SLOT] interface->poe_state = 0
```

### MODE 2: 24V Enable (0x1978–0x19A0 prefix)

```
# === MODE 2: 24V PASSIVE PoE ===
0x1978: lbu     $a0, 0x48($s0)         # a0 = port number
0x197c: jalr    $s2                    # CALL: er_gen2_set_poe_48v(port, 0)
                                       # Ensure 48V/pair-mode is OFF
0x1980: move    $a1, $zero             # [DELAY SLOT] a1 = 0 (DISABLE)

0x1984: lbu     $a0, 0x48($s0)         # a0 = port number
0x1988: jalr    $s1                    # CALL: er_gen2_set_poe_24v(port, 1)
                                       # Enable 24V power-enable GPIO
0x198c: addiu   $a1, $zero, 1          # [DELAY SLOT] a1 = 1 (ENABLE)

0x1990: lw      $v0, ($sp)             # v0 = parsed value (2)
0x1994: j       0x1858                 # JUMP → store-and-return epilog
0x1998: sb      $v0, 0x50($s0)         # [DELAY SLOT] interface->poe_state = 2
```

### MODE 1: 48V Enable (0x19A0–0x19C8 prefix)

```
# === MODE 1: 48V PoE (pair-mode) ===
0x19a0: lbu     $a0, 0x48($s0)         # a0 = port number
0x19a4: jalr    $s1                    # CALL: er_gen2_set_poe_24v(port, 0)
                                       # Ensure 24V power-enable is OFF
0x19a8: move    $a1, $zero             # [DELAY SLOT] a1 = 0 (DISABLE)

0x19ac: lbu     $a0, 0x48($s0)         # a0 = port number
0x19b0: jalr    $s2                    # CALL: er_gen2_set_poe_48v(port, 1)
                                       # Enable 48V pair-mode GPIO
0x19b4: addiu   $a1, $zero, 1          # [DELAY SLOT] a1 = 1 (ENABLE)

0x19b8: lw      $v0, ($sp)             # v0 = parsed value (1)
0x19bc: j       0x1858                 # JUMP → store-and-return epilog
0x19c0: sb      $v0, 0x50($s0)         # [DELAY SLOT] interface->poe_state = 1
```

### E303 Alternate I2C Register (0x19C8–0x19D4)

```
# === E303 ALTERNATE: I2C Register 3 (for bit_pos >= 8) ===
0x19c8: addiu   $s3, $s3, -8           # s3 = bit_pos - 8 (adjust for register 3)
0x19cc: j       0x18f8                 # JUMP → I2C read-modify-write path (uses s5=3)
                                       # Note: s5 was set to 3 at delay slot of 0x18f0
0x19d0: andi    $s3, $s3, 0xff         # [DELAY SLOT] mask to byte
# Falls through to 0x18f8 which uses register 3 (s5=3) instead of register 2
```

---

## er_gen2_set_poe_48v Disassembly

This function is the second half of the PoE control pair. It controls the **pair-mode / 48V GPIO pins**.

```
# Function: er_gen2_set_poe_48v
# Address: 0x250, Size: 176 bytes
# Signature: int er_gen2_set_poe_48v(int port, int enable)
# $a0 = port (1-indexed), $a1 = enable (0=off, nonzero=on)

0x0250: daddiu  $sp, $sp, -0x10        # Allocate stack frame
0x0254: beqz    $a0, 0x2f8             # Guard: if port == 0 → error return -1
0x0258: sd      $ra, 8($sp)            # Save return address

# Load board_type and dispatch
0x025c: lui     $v0, 0                 # [RELOC] HI16 → board_rev_major
0x0260: lw      $v1, ($v0)             # v1 = board_type
0x0264: bltz    $v1, 0x280             # if board_type < 0: error path
0x0268: slti    $v0, $v1, 2            # v0 = (board_type < 2) ? 1 : 0
0x026c: bnez    $v0, 0x2a8             # if board_type < 2 (E301): goto E301_PATH
0x0270: addiu   $a0, $a0, -1           # [DELAY SLOT] a0 = port - 1

# board_type >= 2 (not E301)
0x0274: addiu   $a0, $zero, 2          # a0 = 2
0x0278: beq     $v1, $a0, 0x29c        # if board_type == 2 (E302): goto E302_PATH
0x027c: addiu   $v0, $zero, -1         # [DELAY SLOT] v0 = -1

# Error: unsupported board_type
0x0280: lui     $a0, 0                 # [RELOC] format string
0x0284: lui     $v0, 0                 # [RELOC] → printk
0x0288: daddiu  $a0, $a0, 0            # [RELOC]
0x028c: daddiu  $v0, $v0, 0            # [RELOC]
0x0290: jalr    $v0                    # printk("board type %d not supported...")
0x0294: move    $a1, $v1               # [DELAY SLOT] a1 = board_type
0x0298: addiu   $v0, $zero, -1         # return -1

# Error/epilog return
0x029c: ld      $ra, 8($sp)
0x02a0: jr      $ra
0x02a4: daddiu  $sp, $sp, 0x10

# ====== E301 PATH (board_type < 2) ======
# At this point: $a0 = port - 1 (from delay slot 0x0270)
0x02a8: lui     $v0, 0xff80            # v0 = 0xFFFFFFFFFF800000
0x02ac: sll     $a0, $a0, 1            # a0 = (port - 1) * 2
0x02b0: ori     $v0, $v0, 0x107        # v0 = 0xFFFFFFFFFF800107
0x02b4: lui     $v1, 0                 # [RELOC] HI16 → POE_GPIO_E301 (.data+0x3d0)
0x02b8: dsll    $a0, $a0, 3            # a0 = (port - 1) * 2 * 8 = (port - 1) * 16
0x02bc: daddiu  $v1, $v1, 0            # [RELOC] LO16 → POE_GPIO_E301
0x02c0: dsll32  $v0, $v0, 8            # XKPHYS: 0x8001070000000000
0x02c4: ori     $v0, $v0, 0x888        # GPIO_TX_SET address

# Read GPIO pin from POE_GPIO_E301 table — EVEN-INDEXED entries
0x02c8: daddu   $a0, $a0, $v1          # a0 = POE_GPIO_E301 + (port-1) * 16
0x02cc: lbu     $a0, 1($a0)            # a0 = table entry byte[1] = GPIO pin number

# Select TX_SET (enable) or TX_CLEAR (disable)
0x02d0: daddiu  $v1, $v0, 8            # v1 = GPIO_TX_CLEAR (TX_SET + 8)
0x02d4: movn    $v1, $v0, $a1          # if enable: v1 = TX_SET; else v1 = TX_CLEAR

# Write the GPIO bitmask
0x02d8: addiu   $a1, $zero, 1          # a1 = 1
0x02dc: move    $v0, $zero             # return 0 (success)
0x02e0: dsllv   $a0, $a1, $a0          # a0 = 1 << gpio_pin
0x02e4: sd      $a0, ($v1)             # WRITE: (1 << pin) to TX_SET or TX_CLEAR

# Epilog
0x02e8: ld      $ra, 8($sp)
0x02ec: jr      $ra
0x02f0: daddiu  $sp, $sp, 0x10

# Error return (port == 0)
0x02f8: j       0x29c                  # Jump to epilog
0x02fc: addiu   $v0, $zero, -1         # [DELAY SLOT] return -1
```

**KEY DIFFERENCE from er_gen2_set_poe_24v**:

| Function | Table Index Formula | Entries Used | GPIO Pins |
|----------|-------------------|--------------|-----------|
| `er_gen2_set_poe_24v` | `(port * 2 - 1) * 8` | ODD (1,3,5,7,9) | 2, 4, 6, 16, 10 |
| `er_gen2_set_poe_48v` | `(port - 1) * 16` | EVEN (0,2,4,6,8) | 1, 3, 5, 7, 9 |

Both functions use the same POE_GPIO_E301 table but read different entries. Both write to the same GPIO_TX_SET/TX_CLEAR registers.

---

## GPIO Operations Summary

### GPIOs Touched by poe_st (via sub-functions)

| GPIO | Function | Table Entry | Port Mapping | Direction | Purpose |
|------|----------|-------------|-------------|-----------|---------|
| 1 | er_gen2_set_poe_48v | Entry 0 (offset 0) | Port 1 (eth0) | Output | 48V/pair-mode enable |
| 2 | er_gen2_set_poe_24v | Entry 1 (offset 8) | Port 1 (eth0) | Output | 24V power-enable |
| 3 | er_gen2_set_poe_48v | Entry 2 (offset 16) | Port 2 (eth1) | Output | 48V/pair-mode enable |
| 4 | er_gen2_set_poe_24v | Entry 3 (offset 24) | Port 2 (eth1) | Output | 24V power-enable |
| 5 | er_gen2_set_poe_48v | Entry 4 (offset 32) | Port 3 (eth2) | Output | 48V/pair-mode enable |
| 6 | er_gen2_set_poe_24v | Entry 5 (offset 40) | Port 3 (eth2) | Output | 24V power-enable |
| 7 | er_gen2_set_poe_48v | Entry 6 (offset 48) | Port 4 (eth3) | Output | 48V/pair-mode enable |
| 9 | er_gen2_set_poe_48v | Entry 8 (offset 64) | Port 5 (eth4) | Output | 48V/pair-mode enable |
| 10 | er_gen2_set_poe_24v | Entry 9 (offset 72) | Port 5 (eth4) | Output | 24V power-enable |
| 16 | er_gen2_set_poe_24v | Entry 7 (offset 56) | Port 4 (eth3) | Output | 24V power-enable |

### Register Write Pattern

```
// Enable a GPIO pin:
*(volatile uint64_t *)0x8001070000000888 = (1ULL << gpio_pin);  // GPIO_TX_SET

// Disable a GPIO pin:
*(volatile uint64_t *)0x8001070000000890 = (1ULL << gpio_pin);  // GPIO_TX_CLEAR
```

### GPIO_BIT_CFG Status

**Neither `er_gen2_set_poe_24v` nor `er_gen2_set_poe_48v` touches GPIO_BIT_CFG.** Both functions only write to TX_SET/TX_CLEAR. The tx_oe (output enable) must be configured elsewhere — either during module initialization or by the kernel's GPIO framework.

---

## I2C Operations (E303 Path)

### I2C Devices

| Device | Purpose | Register | Operation |
|--------|---------|----------|-----------|
| `i2c_poe` (at `.bss+0x1ca8`) | PoE control I2C client | Register 2 (bit_pos < 8) | Read-modify-write |
| `i2c_poe` | PoE control I2C client | Register 3 (bit_pos >= 8) | Read-modify-write |

### I2C Sequence

```
1. i2c_smbus_read_byte_data(i2c_poe, register_number)
   → Read current register value

2. Compute new value:
   - Enable:  new_val = old_val | (1 << bit_position)
   - Disable: new_val = old_val & ~(1 << bit_position)

3. i2c_smbus_write_byte_data(i2c_poe, register_number, new_val)
   → Write modified register value
```

### E303 I2C Bit Positions

Looked up from `board_port_cfg_table` at offset `(port + 0xc) * 4 + 0xb`:
- If bit_pos < 8: uses I2C register 2
- If bit_pos >= 8: uses I2C register 3, bit_pos = bit_pos - 8
- If bit_pos == 0xFF: port doesn't support PoE

---

## Function Call Map

| Address | Target | Arguments | Purpose |
|---------|--------|-----------|---------|
| 0x1760 | `sscanf` | (buf, "%d", &sp[0]) | Parse user input |
| 0x17F8 | `er_gen2_set_poe_48v` | (port, 0) | Disable 48V/pair-mode |
| 0x1808 | `er_gen2_set_poe_24v` | (port, 0) | Disable 24V/power-enable |
| 0x1838 | `er_gen2_set_poe_24v` | (port, 1) | Enable 24V (mode 5) |
| 0x1844 | `er_gen2_set_poe_48v` | (port, 1) | Enable 48V (mode 5) |
| 0x188C | `simple_strtol` | (buf, NULL, 10) | Parse input (E303) |
| 0x190C | `i2c_smbus_read_byte_data` | (i2c_poe, reg) | Read I2C register (E303) |
| 0x1940 | `i2c_smbus_write_byte_data` | (i2c_poe, reg, val) | Write I2C register (E303) |
| 0x1954 | `er_gen2_set_poe_48v` | (port, 0) | Disable 48V (mode 0) |
| 0x1960 | `er_gen2_set_poe_24v` | (port, 0) | Disable 24V (mode 0) |
| 0x197C | `er_gen2_set_poe_48v` | (port, 0) | Disable 48V (mode 2) |
| 0x1988 | `er_gen2_set_poe_24v` | (port, 1) | Enable 24V (mode 2) |
| 0x19A4 | `er_gen2_set_poe_24v` | (port, 0) | Disable 24V (mode 1) |
| 0x19B0 | `er_gen2_set_poe_48v` | (port, 1) | Enable 48V (mode 1) |

---

## Value Dispatch Table

| Value | Call 1 | Call 2 | Meaning | GPIOs Affected |
|-------|--------|--------|---------|----------------|
| 0 | `set_poe_48v(port, 0)` | `set_poe_24v(port, 0)` | Full off | All cleared |
| 1 | `set_poe_24v(port, 0)` | `set_poe_48v(port, 1)` | 48V mode (pair) | 48V pins set, 24V cleared |
| 2 | `set_poe_48v(port, 0)` | `set_poe_24v(port, 1)` | 24V mode (standard) | 24V pins set, 48V cleared |
| 5 | `set_poe_24v(port, 1)` | `set_poe_48v(port, 1)` | Both on (4-pair?) | Both sets set |

**Pre-disable sequence** (runs for all state changes before dispatch):
1. `er_gen2_set_poe_48v(port, 0)` — disable pair-mode GPIOs
2. `er_gen2_set_poe_24v(port, 0)` — disable power-enable GPIOs

Then the mode-specific calls re-enable the appropriate pins.

---

## Comparison: poe_st vs er_gen2_set_poe_24v

| Aspect | poe_st | er_gen2_set_poe_24v |
|--------|--------|---------------------|
| **Role** | Top-level sysfs store handler | Low-level GPIO write function |
| **Size** | 700 bytes | 264 bytes |
| **GPIOs touched** | ALL 10 (via two sub-calls) | 5 even-indexed (2,4,6,10,16) |
| **GPIO selection** | Delegates to sub-functions | Reads POE_GPIO_E301 odd entries |
| **Pair-mode GPIOs** | YES (via er_gen2_set_poe_48v) | NO |
| **GPIO_BIT_CFG** | NO (neither sub-function does) | NO |
| **I2C operations** | YES (E303 path only) | NO |
| **Timing delays** | NONE | NONE |
| **Input validation** | Capability bitmap check | Port range check only |
| **Board type dispatch** | E301, E302, E303 | E301, E302, E303 error |
| **Two-call sequence** | YES: 48v first, then 24v (or vice versa) | Single GPIO write |
| **Mode support** | 0, 1, 2, 5 (4 modes) | Binary on/off |

---

## Key Questions Answered

### Q1: Does poe_st call er_gen2_set_poe_24v?

**YES.** `er_gen2_set_poe_24v` is loaded into `$s1` at 0x17fc/0x1804 (relocation: `.text+0x148`) and called via `jalr $s1` at multiple points (0x1808, 0x1838, 0x1960, 0x1988, 0x19A4).

### Q2: Does poe_st touch pair-mode (odd-indexed) GPIOs?

**YES.** `poe_st` calls `er_gen2_set_poe_48v` (loaded into `$s2`), which reads **even-indexed entries** (0,2,4,6,8) from POE_GPIO_E301. These correspond to GPIOs **1, 3, 5, 7, 9** — the pair-mode / 48V enable pins that `er_gen2_set_poe_24v` does NOT touch.

### Q3: Does poe_st configure GPIO_BIT_CFG (tx_oe)?

**NO.** Neither `poe_st` nor either of its sub-functions (`er_gen2_set_poe_24v`, `er_gen2_set_poe_48v`) writes to GPIO_BIT_CFG registers. All three functions only write to GPIO_TX_SET and GPIO_TX_CLEAR. The tx_oe (output enable) must be configured elsewhere — either during `ubnt_platform.ko` module initialization, or by the kernel's GPIO framework when pins are exported.

### Q4: Does poe_st do I2C writes?

**YES, but only in the E303 path** (board_type == 3, for newer models like ER-4). The E303 path uses `i2c_smbus_read_byte_data` and `i2c_smbus_write_byte_data` to do a read-modify-write on the `i2c_poe` I2C client's register 2 or 3. The E301/E302 path (ER-6P) does NOT use I2C — it uses direct GPIO writes only.

### Q5: What timing delays exist?

**NONE.** There are no `mdelay`, `udelay`, or any delay calls in `poe_st` or its sub-functions. The two sub-calls happen back-to-back with no delay between them.

### Q6: What is the two-call sequence theory?

**CONFIRMED.** `poe_st` calls TWO sub-functions in sequence for each state change:
1. **Pre-disable**: Both 48V and 24V are disabled first (known starting state)
2. **Mode-specific re-enable**: The appropriate sub-function(s) are called to enable the requested mode

The "two calls" observed in prior analysis are `er_gen2_set_poe_48v` and `er_gen2_set_poe_24v` — one for pair-mode/48V GPIOs, one for power-enable/24V GPIOs. The sequence (0/0, 1/0, 0/1, 1/1) maps to modes 0, 2, 1, 5 respectively.

### Q7: Why does the OpenWrt implementation only work for 24V?

The current OpenWrt PoE script (`/usr/sbin/poe`) only calls the equivalent of `er_gen2_set_poe_24v` — it only toggles the power-enable GPIOs (2, 4, 6, 10, 16). It does NOT toggle the pair-mode GPIOs (1, 3, 5, 7, 9) via the equivalent of `er_gen2_set_poe_48v`. For standard 2-pair 24V passive PoE, only the power-enable GPIO is needed. The pair-mode GPIO is likely for 4-pair or 48V configurations.

---

## Relocation Table

All relocations within `poe_st` (0x1718–0x19D4), resolved to symbols:

### Function Pointers (HI16/LO16 pairs)

| Address Pair | Symbol | Section | Addend | Purpose |
|-------------|--------|---------|--------|---------|
| 0x17EC/0x17F4 | `.text` | 2 | 0x0250 | `er_gen2_set_poe_48v` → `$s2` |
| 0x17FC/0x1804 | `.text` | 2 | 0x0148 | `er_gen2_set_poe_24v` → `$s1` |

### External Function Calls

| Address | Symbol | Purpose |
|---------|--------|---------|
| 0x1754/0x175C | `sscanf` | Parse user input string |
| 0x1880/0x1888 | `simple_strtol` | Parse integer (E303 path) |
| 0x1900/0x1908 | `i2c_smbus_read_byte_data` | Read I2C register (E303) |
| 0x1930/0x193C | `i2c_smbus_write_byte_data` | Write I2C register (E303) |

### Data References

| Address | Symbol | Section | Addend | Purpose |
|---------|--------|---------|--------|---------|
| 0x1724/0x1728 | `.data` | 17 | 0x0000 | `board_rev_major` (board_type) |
| 0x1750/0x1758 | `.rodata.str1.8` | 13 | 0x0078 | `"%d"` format string |
| 0x18A4/0x18AC | `.bss` | 25 | 0x0008 | `_intf_obj` base pointer |
| 0x18FC/0x1904 | `.bss` | 25 | 0x1CA8 | `i2c_poe` I2C client |

### Intra-function Jumps (R_MIPS_26)

| Address | Target | Purpose |
|---------|--------|---------|
| 0x1948 | 0x1858 | Mode 5 → store-and-return |
| 0x196C | 0x1858 | Mode 0 → store-and-return |
| 0x1994 | 0x1858 | Mode 2 → store-and-return |
| 0x19BC | 0x1858 | Mode 1 → store-and-return |
| 0x19CC | 0x18FC | E303 alt register → I2C RMW |
