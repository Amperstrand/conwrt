# PoE Helper Functions — Full Disassembly & Analysis

**Binary**: `ubnt_platform.ko` (ELF64 MSB MIPS64, EdgeOS v2.0.6, kernel 4.9.79-UBNT)
**Date**: 2026-05-20
**Method**: Python + capstone 5.0.7, pyelftools, relocation resolution via .rela.text addend matching

---

## Table of Contents

1. [Symbol Inventory](#symbol-inventory)
2. [er_gen2_set_poe_48v](#1-er_gen2_set_poe_48v)
3. [er_gen2_set_poe_24v](#2-er_gen2_set_poe_24v)
4. [ethphy_power_control](#3-ethphy_power_control)
5. [i2c_poe (data object)](#4-i2c_poe-data-object)
6. [phy_805x_power_on](#5-phy_805x_power_on)
7. [phy_8031a_power_on](#6-phy_8031a_power_on)
8. [dal_phy_power_on](#7-dal_phy_power_on)
9. [Missing Symbols](#8-missing-symbols)
10. [Cross-Reference Call Graph](#cross-reference-call-graph)
11. [Hardware Operations Summary](#hardware-operations-summary)

---

## Symbol Inventory

| # | Function | Address | Size | Section | Present |
|---|----------|---------|------|---------|---------|
| 1 | `er_gen2_set_poe_48v` | 0x0250 | 176 | .text | YES |
| 2 | `er_gen2_set_poe_24v` | 0x0148 | 264 | .text | YES |
| 3 | `ethphy_power_control` | 0x0528 | 248 | .text | YES |
| 4 | `i2c_poe` | .bss+0x1CA8 | 456 | .bss | YES (object, not function) |
| 5 | `phy_805x_power_on` | 0x4F810 | 176 | .text | YES |
| 6 | `phy_8031a_power_on` | 0x1172D8 | 212 | .text | YES |
| 7 | `dal_phy_power_on` | 0x110E78 | 404 | .text | YES |
| 8 | `allPortsPoeOff` | — | — | — | NOT FOUND |
| 9 | `hasPoeE` | — | — | — | NOT FOUND |
| 10 | `getPowerSlot` | — | — | — | NOT FOUND |

Symbols 8–10 not present in `ubnt_platform.ko` or any file under `/tmp/edgeos-root/`. They may belong to a different binary version or userspace tool.

---

## 1. er_gen2_set_poe_48v

**Address**: 0x0250–0x0300 (176 bytes)
**Signature**: `int er_gen2_set_poe_48v(int port, int enable)`
**Role**: Controls **pair-mode / 48V GPIO pins** (GPIOs 1, 3, 5, 7, 9) via TX_SET/TX_CLEAR.
**CRITICAL**: This is the missing function in the OpenWrt PoE implementation — it controls the second set of GPIO pins needed for 4-pair/48V mode.

### Basic Blocks

| Block | Address Range | Purpose |
|-------|---------------|---------|
| ENTRY | 0x0250–0x0258 | Prologue, port==0 guard |
| BOARD_CHECK | 0x025C–0x026C | Load board_type, dispatch E301/E302/error |
| ERROR_PRINT | 0x0280–0x0298 | printk("board type %d not supported"), return -1 |
| EPILOG | 0x029C–0x02A4 | Restore regs, return |
| E301_PATH | 0x02A8–0x02F0 | GPIO TX_SET/TX_CLEAR write (main logic) |
| PORT0_ERR | 0x02F8–0x02FC | port==0 error return |

### Full Annotated Disassembly

```
# === PROLOGUE ===
0x0250: daddiu  $sp, $sp, -0x10        # Allocate 16-byte stack frame
0x0254: beqz    $a0, 0x2f8             # Guard: if port == 0 → error return -1
0x0258: sd      $ra, 8($sp)            # Save return address

# === BOARD TYPE DISPATCH ===
0x025c: lui     $v0, 0                 # [RELOC → board_rev_major (.data+0x0)]
0x0260: lw      $v1, ($v0)             # v1 = board_type
0x0264: bltz    $v1, 0x280             # if board_type < 0: error path
0x0268: slti    $v0, $v1, 2            # v0 = (board_type < 2) ? 1 : 0
0x026c: bnez    $v0, 0x2a8             # if board_type < 2 (E301): goto E301_PATH
0x0270: addiu   $a0, $a0, -1           # [DELAY SLOT] a0 = port - 1

# board_type >= 2
0x0274: addiu   $a0, $zero, 2          # a0 = 2
0x0278: beq     $v1, $a0, 0x29c        # if board_type == 2 (E302): goto EPILOG
0x027c: addiu   $v0, $zero, -1         # [DELAY SLOT] v0 = -1

# === ERROR: unsupported board type ===
0x0280: lui     $a0, 0                 # [RELOC → format string]
0x0284: lui     $v0, 0                 # [RELOC → printk]
0x0288: daddiu  $a0, $a0, 0            # [RELOC]
0x028c: daddiu  $v0, $v0, 0            # [RELOC]
0x0290: jalr    $v0                    # printk("board type %d not supported...")
0x0294: move    $a1, $v1               # [DELAY SLOT] a1 = board_type
0x0298: addiu   $v0, $zero, -1         # return -1

# === EPILOG ===
0x029c: ld      $ra, 8($sp)
0x02a0: jr      $ra
0x02a4: daddiu  $sp, $sp, 0x10

# === E301 PATH (board_type < 2, ER-6P) ===
# At entry: $a0 = port - 1 (from delay slot at 0x0270)
0x02a8: lui     $v0, 0xff80            # v0 = 0xFFFFFFFFFF800000
0x02ac: sll     $a0, $a0, 1            # a0 = (port - 1) * 2
0x02b0: ori     $v0, $v0, 0x107        # v0 = 0xFFFFFFFFFF800107
0x02b4: lui     $v1, 0                 # [RELOC → POE_GPIO_E301 (.data+0x3d0)]
0x02b8: dsll    $a0, $a0, 3            # a0 = (port - 1) * 2 * 8 = (port - 1) * 16
0x02bc: daddiu  $v1, $v1, 0            # [RELOC → POE_GPIO_E301]
0x02c0: dsll32  $v0, $v0, 8            # XKPHYS: 0x8001070000000000
0x02c4: ori     $v0, $v0, 0x888        # GPIO_TX_SET address

# Read GPIO pin from POE_GPIO_E301 table — EVEN-INDEXED entries
0x02c8: daddu   $a0, $a0, $v1          # a0 = POE_GPIO_E301 + (port-1) * 16
0x02cc: lbu     $a0, 1($a0)            # a0 = table[entry].gpio_pin (byte[1])

# Select TX_SET (enable) or TX_CLEAR (disable)
0x02d0: daddiu  $v1, $v0, 8            # v1 = GPIO_TX_CLEAR (TX_SET + 8 = 0x890)
0x02d4: movn    $v1, $v0, $a1          # if enable: v1 = TX_SET (0x888); else TX_CLEAR (0x890)

# Write the GPIO bitmask
0x02d8: addiu   $a1, $zero, 1          # a1 = 1
0x02dc: move    $v0, $zero             # return 0 (success)
0x02e0: dsllv   $a0, $a1, $a0          # a0 = 1 << gpio_pin
0x02e4: sd      $a0, ($v1)             # WRITE: (1 << pin) to TX_SET or TX_CLEAR

# Success epilog
0x02e8: ld      $ra, 8($sp)
0x02ec: jr      $ra
0x02f0: daddiu  $sp, $sp, 0x10

# Port 0 error
0x02f8: j       0x29c                  # Jump to epilog
0x02fc: addiu   $v0, $zero, -1         # [DELAY SLOT] return -1
```

### Call Targets

| Address | Target | Purpose |
|---------|--------|---------|
| 0x0290 | `printk` | Error: unsupported board type |

No other calls — leaf function for E301 path (GPIO register writes are direct memory-mapped).

### GPIO Operations

| Register | Address | Operation | Condition |
|----------|---------|-----------|-----------|
| GPIO_TX_SET | 0x8001070000000888 | Write `(1 << pin)` | When `enable != 0` |
| GPIO_TX_CLEAR | 0x8001070000000890 | Write `(1 << pin)` | When `enable == 0` |

### Table Access Pattern

```
entry_addr = POE_GPIO_E301 + (port - 1) * 16
gpio_pin   = *(uint8_t *)(entry_addr + 1)    # byte[1] of each 16-byte entry
```

Maps to EVEN-indexed entries (0, 2, 4, 6, 8) → GPIOs **1, 3, 5, 7, 9**.

### Key Insights

- **No E302 path**: Unlike `er_gen2_set_poe_24v`, this function has no E302-specific code path. `board_type == 2` jumps straight to epilog (returns -1).
- **No GPIO_BIT_CFG**: Only writes TX_SET/TX_CLEAR. tx_oe must be pre-configured.
- **No delays**: Back-to-back write, no timing constraints.

---

## 2. er_gen2_set_poe_24v

**Address**: 0x0148–0x0250 (264 bytes)
**Signature**: `int er_gen2_set_poe_24v(int port, int enable)`
**Role**: Controls **power-enable / 24V GPIO pins** (GPIOs 2, 4, 6, 10, 16) via TX_SET/TX_CLEAR.

### Basic Blocks

| Block | Address Range | Purpose |
|-------|---------------|---------|
| ENTRY | 0x0148–0x0150 | Prologue, port==0 guard |
| BOARD_CHECK | 0x0154–0x0168 | Load board_type, dispatch |
| ERROR_PRINT | 0x0178–0x019C | printk, return -1 |
| E301_PATH | 0x01A0–0x01E8 | GPIO TX_SET/TX_CLEAR write (E301 main logic) |
| E302_PATH | 0x01F0–0x0244 | GPIO TX_CLEAR + TX_SET dual-write (E302) |
| PORT0_ERR | 0x0248–0x024C | port==0 error return |

### Full Annotated Disassembly

```
# === PROLOGUE ===
0x0148: daddiu  $sp, $sp, -0x10        # Allocate 16-byte stack frame
0x014c: beqz    $a0, 0x248             # Guard: if port == 0 → error return -1
0x0150: sd      $ra, 8($sp)            # Save return address

# === BOARD TYPE DISPATCH ===
0x0154: lui     $v0, 0                 # [RELOC → board_rev_major (.data+0x0)]
0x0158: lw      $v0, ($v0)             # v0 = board_type
0x015c: bltz    $v0, 0x178             # if board_type < 0: error path
0x0160: slti    $v1, $v0, 2            # v1 = (board_type < 2) ? 1 : 0
0x0164: bnez    $v1, 0x1a0             # if board_type < 2 (E301): goto E301_PATH
0x0168: sll     $a0, $a0, 1            # [DELAY SLOT] a0 = port * 2

# board_type >= 2
0x016c: addiu   $v1, $zero, 2          # v1 = 2
0x0170: beq     $v0, $v1, 0x1f0        # if board_type == 2 (E302): goto E302_PATH
0x0174: lui     $v1, 0xff80            # [DELAY SLOT] v1 = 0xFFFFFFFFFF800000

# === ERROR: unsupported board type ===
0x0178: move    $a1, $v0               # a1 = board_type (for printk)
0x017c: lui     $a0, 0                 # [RELOC → format string]
0x0180: lui     $v0, 0                 # [RELOC → printk]
0x0184: daddiu  $v0, $v0, 0            # [RELOC]
0x0188: jalr    $v0                    # printk("board type %d not supported...")
0x018c: daddiu  $a0, $a0, 0            # [RELOC]
0x0190: addiu   $v0, $zero, -1         # return -1

# Epilog
0x0194: ld      $ra, 8($sp)
0x0198: jr      $ra
0x019c: daddiu  $sp, $sp, 0x10

# === E301 PATH (board_type < 2, ER-6P) ===
# At entry: $a0 = port * 2 (from delay slot at 0x0168)
0x01a0: lui     $v0, 0xff80            # v0 = 0xFFFFFFFFFF800000
0x01a4: addiu   $a0, $a0, -1           # a0 = port * 2 - 1
0x01a8: ori     $v0, $v0, 0x107        # v0 = 0xFFFFFFFFFF800107
0x01ac: lui     $v1, 0                 # [RELOC → POE_GPIO_E301 (.data+0x3d0)]
0x01b0: dsll    $a0, $a0, 3            # a0 = (port * 2 - 1) * 8
0x01b4: daddiu  $v1, $v1, 0            # [RELOC → POE_GPIO_E301]
0x01b8: dsll32  $v0, $v0, 8            # XKPHYS: 0x8001070000000000
0x01bc: ori     $v0, $v0, 0x888        # GPIO_TX_SET address

# Read GPIO pin from POE_GPIO_E301 table — ODD-INDEXED entries
0x01c0: daddu   $a0, $a0, $v1          # a0 = POE_GPIO_E301 + (port*2-1) * 8
0x01c4: lbu     $a0, 1($a0)            # a0 = table[entry].gpio_pin (byte[1])

# Select TX_SET (enable) or TX_CLEAR (disable)
0x01c8: daddiu  $v1, $v0, 8            # v1 = GPIO_TX_CLEAR (0x890)
0x01cc: movn    $v1, $v0, $a1          # if enable: v1 = TX_SET (0x888); else TX_CLEAR (0x890)

# Write the GPIO bitmask
0x01d0: addiu   $a1, $zero, 1          # a1 = 1
0x01d4: move    $v0, $zero             # return 0 (success)
0x01d8: dsllv   $a0, $a1, $a0          # a0 = 1 << gpio_pin
0x01dc: sd      $a0, ($v1)             # WRITE: (1 << pin) to TX_SET or TX_CLEAR

# Success epilog
0x01e0: ld      $ra, 8($sp)
0x01e4: jr      $ra
0x01e8: daddiu  $sp, $sp, 0x10

# === E302 PATH (board_type == 2) ===
0x01f0: lui     $a2, 0                 # [RELOC → POE_GPIO_E302 (.data+0x3b8)]
0x01f4: ori     $v1, $v1, 0x107        # v1 = 0xFFFFFFFFFF800107
0x01f8: daddiu  $a2, $a2, 0            # [RELOC → POE_GPIO_E302]
0x01fc: dsll32  $v1, $v1, 8            # XKPHYS: 0x8001070000000000
0x0200: addiu   $a0, $zero, 1          # a0 = 1 (bit value)
0x0204: lbu     $t0, 9($a2)            # t0 = POE_GPIO_E302[9] = GPIO pin #2
0x0208: ori     $v1, $v1, 0x890        # GPIO_TX_CLEAR address
0x020c: lbu     $a3, 1($a2)            # a3 = POE_GPIO_E302[1] = GPIO pin #1
0x0210: daddiu  $t1, $v1, -8           # t1 = GPIO_TX_SET (TX_CLEAR - 8 = 0x888)
0x0214: movz    $t1, $v1, $a1          # if enable==0: t1 = TX_CLEAR; else TX_SET
0x0218: addiu   $v0, $zero, -1         # v0 = -1 (error default)
0x021c: dsllv   $t0, $a0, $t0          # t0 = 1 << pin_2
0x0220: sd      $t0, ($v1)             # WRITE: (1 << pin_2) to TX_CLEAR (always clear pin 2)
0x0224: dsllv   $a3, $a0, $a3          # a3 = 1 << pin_1
0x0228: sd      $a3, ($t1)             # WRITE: (1 << pin_1) to TX_SET or TX_CLEAR

# Read back for verification (E302)
0x022c: lbu     $a1, 9($a2)            # a1 = pin_2 (reload)
0x0230: dsllv   $a0, $a0, $a1          # a0 = 1 << pin_2
0x0234: sd      $a0, -8($v1)           # WRITE: (1 << pin_2) to TX_SET (always set pin 2 back)

# E302 epilog
0x0238: ld      $ra, 8($sp)
0x023c: jr      $ra
0x0240: daddiu  $sp, $sp, 0x10

# Port 0 error
0x0248: j       0x194                  # Jump to epilog
0x024c: addiu   $v0, $zero, -1         # [DELAY SLOT] return -1
```

### Call Targets

| Address | Target | Purpose |
|---------|--------|---------|
| 0x0188 | `printk` | Error: unsupported board type |

No other calls — leaf function for both E301 and E302 paths.

### GPIO Operations

**E301 Path:**

| Register | Address | Operation | Condition |
|----------|---------|-----------|-----------|
| GPIO_TX_SET | 0x8001070000000888 | Write `(1 << pin)` | When `enable != 0` |
| GPIO_TX_CLEAR | 0x8001070000000890 | Write `(1 << pin)` | When `enable == 0` |

**E302 Path:**

| Register | Address | Operation | Notes |
|----------|---------|-----------|-------|
| GPIO_TX_CLEAR | 0x8001070000000890 | Write `(1 << pin_2)` | Always clears pin_2 first |
| GPIO_TX_SET or TX_CLEAR | 0x888 or 0x890 | Write `(1 << pin_1)` | Enable or disable pin_1 |
| GPIO_TX_SET | 0x8001070000000888 | Write `(1 << pin_2)` | Always sets pin_2 back |

### Table Access Pattern

**E301:**
```
entry_addr = POE_GPIO_E301 + (port * 2 - 1) * 8
gpio_pin   = *(uint8_t *)(entry_addr + 1)    # byte[1] of each 8-byte entry
```
Maps to ODD-indexed entries (1, 3, 5, 7, 9) → GPIOs **2, 4, 6, 16, 10**.

**E302:**
```
pin_1 = POE_GPIO_E302[1]    # byte at offset 1
pin_2 = POE_GPIO_E302[9]    # byte at offset 9
```

### Key Insights

- **E302 has 3 GPIO writes** (vs E301's 1): clear pin_2, set/clear pin_1, set pin_2 back. This is a toggle sequence.
- **E302 always restores pin_2** after clearing it — appears to be a pulse/clock mechanism.
- **No GPIO_BIT_CFG**: Same as `er_gen2_set_poe_48v`, tx_oe must be pre-configured.

---

## 3. ethphy_power_control

**Address**: 0x0528–0x0620 (248 bytes)
**Signature**: `int ethphy_power_control(void *iface, int enable)`
**Role**: Controls Ethernet PHY power state via MDIO bus and switch configuration.

### Basic Blocks

| Block | Address Range | Purpose |
|-------|---------------|---------|
| ENTRY | 0x0528–0x0558 | Prologue, load PHY data, first MDIO read |
| MDIO_READ_1 | 0x0554–0x0560 | mdiobus_read(iface->phy_dev, ...) |
| CHECK_RESULT | 0x055C–0x0588 | If result != 7: normal path |
| POWER_ON | 0x0590–0x05A8 | mdiobus_read (power on sequence) |
| ERROR_PATH | 0x05F8–0x061C | Error cleanup, printk, tail-call to printk |
| EPILOG | 0x05B0–0x05C4 | Restore regs, return |
| PHY_INIT_8031 | 0x05D8–0x05F4 | phy_8031a_init → phy_8031a_power_on path |

### Call Targets

| Address | Target | Purpose |
|---------|--------|---------|
| 0x0554 | `mdiobus_read` (via $s1) | Read PHY register via MDIO |
| 0x0570 | `mdiobus_read` (via $s1) | Read PHY register (power check) |
| 0x05F0 | `phy_8031a_power_on` | Power on 8031A PHY |
| 0x0604/0x060C | `printk` | Error logging |
| 0x0610 | `phy_8031a_ability_get` | Get PHY abilities |
| 0x0614 | `ubnt_switch_set_port_pvid` | Set port VLAN PVID |

### Indirect Call Targets (via $s1 = mdiobus_read function pointer)

The function loads a function pointer into `$s1` early on and uses it for MDIO operations. Based on the relocation addends, `$s1` resolves to either `mdiobus_read` or the generic MDIO read wrapper.

### GPIO/I2C Operations

None. This function operates entirely through kernel MDIO/PHY subsystem calls.

### Key Insights

- Controls PHY power through the kernel's MDIO subsystem, not direct GPIO writes.
- Has a special path for 8031A PHYs: `phy_8031a_init` → `phy_8031a_power_on`.
- Checks MDIO read result against value 7 (likely a PHY ID or status register check).
- Sets port PVID (VLAN ID) as part of the power-on sequence.
- Not directly involved in PoE GPIO control — this is Ethernet PHY power management.

---

## 4. i2c_poe (data object)

**Address**: `.bss` section + 0x1CA8
**Size**: 456 bytes (0x1C8)
**Type**: STT_OBJECT (not a function)
**Section**: .bss (section index 25)

### Description

`i2c_poe` is a global variable in the BSS section that stores an `i2c_client` structure (or pointer). It is used exclusively by the **E303 path** in `poe_st` for I2C-based PoE control on newer EdgeRouter models.

### Usage in poe_st

```c
// In poe_st, E303 path (board_type == 3):
struct i2c_client *client = i2c_poe;

// Read current register value:
val = i2c_smbus_read_byte_data(client, register_number);

// Modify: set or clear the target bit
if (enable)
    val |= (1 << bit_position);
else
    val &= ~(1 << bit_position);

// Write back:
i2c_smbus_write_byte_data(client, register_number, val);
```

### Relocation References

Referenced by relocations at addresses within `poe_st`:
- 0x18FC/0x1904: Load address of `i2c_poe` for `i2c_smbus_read_byte_data` call
- 0x1930/0x1934: Load address of `i2c_poe` for `i2c_smbus_write_byte_data` call

### Key Insights

- **Not relevant for ER-6P** — ER-6P uses board_type 0/1 (E301), not E303.
- The I2C PoE controller is only present on newer EdgeRouter models (board_type 3).
- On ER-6P, this pointer is likely NULL or uninitialized.

---

## 5. phy_805x_power_on

**Address**: 0x4F810–0x4F8C0 (176 bytes)
**Signature**: `int phy_805x_power_on(uint32_t unit, uint32_t port)`
**Role**: Powers on a Vitesse/MaxLinear 805x-series Ethernet PHY via MDIO register manipulation.

### Basic Blocks

| Block | Address Range | Purpose |
|-------|---------------|---------|
| ENTRY | 0x4F810–0x4F850 | Prologue, resolve phy_805x_mdio_reg_read pointer |
| MDIO_READ | 0x4F84C–0x4F860 | Read MDIO register 0 |
| CHECK | 0x4F854–0x4F860 | If error (ret & 0x1FF): skip write |
| MDIO_WRITE | 0x4F860–0x4F8AC | Clear bit 11 (0x0800), write back |
| EPILOG | 0x4F8AC–0x4F8BC | Restore regs, return |

### Full Annotated Disassembly

```
# === PROLOGUE ===
0x4f810: lui     $v0, 0                 # [RELOC → phy_805x_mdio_reg_read HI16]
0x4f814: lui     $v1, 0                 # [RELOC → phy_805x_mdio_reg_read LO16]
0x4f818: daddiu  $v0, $v0, 0            # [RELOC → phy_805x_mdio_reg_read]
0x4f81c: daddiu  $sp, $sp, -0x30        # Allocate 48-byte stack frame
0x4f820: daddiu  $v1, $v1, 0            # [RELOC → phy_805x_mdio_reg_read]
0x4f824: dsll32  $v0, $v0, 0            # Combine HI/LO for 64-bit address
0x4f828: sd      $s1, 0x20($sp)         # Save $s1
0x4f82c: daddu   $v0, $v0, $v1          # v0 = full 64-bit function pointer
0x4f830: sd      $s0, 0x18($sp)         # Save $s0
0x4f834: move    $a2, $zero             # a2 = 0 (reg addr HI)
0x4f838: sd      $ra, 0x28($sp)         # Save $ra
0x4f83c: move    $a3, $zero             # a3 = 0 (reg addr LO)
0x4f840: sh      $zero, ($sp)           # Clear stack variable (for read value)
0x4f844: move    $t0, $sp               # t0 = &stack_var (output pointer)
0x4f848: move    $s1, $a0               # s1 = unit
0x4f84c: jalr    $v0                    # CALL: phy_805x_mdio_reg_read(unit, port, 0, 0, &val)
0x4f850: move    $s0, $a1               # [DELAY SLOT] s0 = port

# === CHECK READ RESULT ===
0x4f854: andi    $v1, $v0, 0x1ff        # v1 = ret & 0x1FF (error check)
0x4f858: bnez    $v1, 0x4f8b0           # If error: goto epilog (return error)
0x4f85c: ld      $ra, 0x28($sp)         # [DELAY SLOT] preload $ra

# === MDIO WRITE: Clear bit 11 (power-down bit) ===
0x4f860: lhu     $t0, ($sp)             # t0 = register value (from read)
0x4f864: lui     $v0, 0                 # [RELOC → phy_805x_mdio_reg_write HI16]
0x4f868: lui     $v1, 0                 # [RELOC → phy_805x_mdio_reg_write LO16]
0x4f86c: daddiu  $v0, $v0, 0            # [RELOC]
0x4f870: daddiu  $v1, $v1, 0            # [RELOC]
0x4f874: dsll32  $v0, $v0, 0            # Combine HI/LO
0x4f878: andi    $t0, $t0, 0xf7ff       # t0 = val & ~0x0800 (clear bit 11 = power-down)
0x4f87c: daddu   $v0, $v0, $v1          # v0 = full function pointer
0x4f880: move    $a0, $s1               # a0 = unit
0x4f884: move    $a1, $s0               # a1 = port
0x4f888: move    $a2, $zero             # a2 = 0 (reg addr HI)
0x4f88c: move    $a3, $zero             # a3 = 0 (reg addr LO)
0x4f890: jalr    $v0                    # CALL: phy_805x_mdio_reg_write(unit, port, 0, 0, val)
0x4f894: sh      $t0, ($sp)             # [DELAY SLOT] store modified value

# === RETURN RESULT ===
0x4f898: andi    $v1, $v0, 0x1ff        # Check error
0x4f89c: sltu    $v1, $zero, $v1        # v1 = (error != 0) ? 1 : 0
0x4f8a0: negu    $v1, $v1               # v1 = (error != 0) ? -1 : 0
0x4f8a4: and     $v1, $v1, $v0          # v1 = error ? -ret : 0
0x4f8a8: move    $v0, $v1               # return value

# === EPILOG ===
0x4f8ac: ld      $ra, 0x28($sp)
0x4f8b0: ld      $s1, 0x20($sp)
0x4f8b4: ld      $s0, 0x18($sp)
0x4f8b8: jr      $ra
0x4f8bc: daddiu  $sp, $sp, 0x30
```

### Call Targets

| Address | Target | Purpose |
|---------|--------|---------|
| 0x4F84C | `phy_805x_mdio_reg_read` | Read PHY register (MDIO clause 22/45) |
| 0x4F890 | `phy_805x_mdio_reg_write` | Write PHY register |

### GPIO/I2C Operations

None. Operates entirely through MDIO register access.

### Key Insights

- **Power-on = clear bit 11** of MDIO register 0 (standard IEEE 802.3 PHY control register).
- Bit 11 in register 0.0 is the "power-down" bit per IEEE 802.3. Clearing it powers up the PHY.
- Simple read-modify-write pattern: read register, clear bit 11, write back.
- No timing delays — assumes MDIO access is synchronous.

---

## 6. phy_8031a_power_on

**Address**: 0x1172D8–0x1173AC (212 bytes)
**Signature**: `int phy_8031a_power_on(uint32_t unit, uint32_t port)`
**Role**: Powers on a Broadcom 8031A-series Ethernet PHY via BT/BX register manipulation and common PHY power-on.

### Basic Blocks

| Block | Address Range | Purpose |
|-------|---------------|---------|
| ENTRY | 0x1172D8–0x117320 | Prologue, resolve phy_8031a_bt_bx_register_set |
| BT_BX_SET | 0x117310–0x117320 | Call phy_8031a_bt_bx_register_set(unit, port, 1) |
| ERROR_CHECK_1 | 0x117318–0x117320 | If error: goto epilog |
| COMMON_POWER | 0x117340–0x117368 | Call phy_common_power_on(unit, port) |
| BT_BX_RESTORE | 0x11736C–0x117384 | On success: call bt_bx_register_set(unit, port, 0) |
| COMMON_RETRY | 0x117388–0x1173A8 | Call phy_common_power_on again for verification |

### Call Targets

| Address | Target | Purpose |
|---------|--------|---------|
| 0x117310 | `phy_8031a_bt_bx_register_set` | Set BT/BX register (enable=1) |
| 0x117358 | `phy_common_power_on` | Common PHY power-on sequence |
| 0x117374 | `phy_8031a_bt_bx_register_set` | Restore BT/BX register (enable=0) |

### Control Flow

```
1. phy_8031a_bt_bx_register_set(unit, port, enable=1)
   if (error) return error;

2. phy_common_power_on(unit, port)
   if (error) return error;

3. phy_8031a_bt_bx_register_set(unit, port, enable=0)  // restore
   if (error) return error;

4. phy_common_power_on(unit, port)  // verify
   return result;
```

### GPIO/I2C Operations

None. Operates through PHY driver abstraction layer.

### Key Insights

- Three-step sequence: enable BT/BX register → common power on → disable BT/BX register → verify.
- `phy_8031a_bt_bx_register_set` likely controls a Broadcom-specific shadow register bank.
- Uses `$s0` as a function pointer cache for `phy_8031a_bt_bx_register_set` (resolved once, called twice).
- Uses `$s3` as a function pointer cache for `phy_common_power_on` (resolved once, called twice).

---

## 7. dal_phy_power_on

**Address**: 0x110E78–0x11100C (404 bytes)
**Signature**: `int dal_phy_power_on(uint32_t unit, uint32_t port)`
**Role**: DAL (Device Abstraction Layer) wrapper for PHY power-on. Dispatches to the correct PHY driver through the DAL node tree.

### Basic Blocks

| Block | Address Range | Purpose |
|-------|---------------|---------|
| ENTRY | 0x110E78–0x110EB8 | Prologue, resolve dal_dev_all_dev_num_get |
| BOUNDS_CHECK | 0x110EBC–0x110EE8 | Validate unit < total_devices |
| NODE_LOOKUP | 0x110EF0–0x110F1C | Look up DAL node, indirect call to power_on handler |
| ERROR_CHECK | 0x110F20–0x110F28 | If power_on failed: goto error path |
| FALLBACK_LOOKUP | 0x110F2C–0x110F4C | Look up internal function at 0x110320 |
| PHY_NULL_CHECK | 0x110F50–0x110F74 | Check if driver is null driver, find alternate |
| MUTEX_LOCK | 0x110F90–0x110FB4 | __osal_mutex_take(mutex) |
| INDIRECT_CALL | 0x110FB8–0x110FC4 | Call driver's power_on through function pointer |
| MUTEX_UNLOCK | 0x110FC8–0x110FE8 | __osal_mutex_give(mutex) |
| EPILOG | 0x110FEC–0x111008 | Restore regs, return |

### Call Targets

| Address | Target | Purpose |
|---------|--------|---------|
| 0x110EB4 | `dal_dev_all_dev_num_get` | Get total device count for bounds check |
| 0x110F18 | Indirect (via dal_node[unit]) | Dispatch to driver's power_on handler |
| 0x110F48 | Internal (0x110320) | Fallback/alternate power_on path |
| 0x110FB0 | `__osal_mutex_take` | Lock mutex before PHY operation |
| 0x110FE4 | `__osal_mutex_give` | Unlock mutex after PHY operation |

### Control Flow

```
1. total = dal_dev_all_dev_num_get()
   if (unit >= total) return 0x800000C2;  // error: invalid unit

2. node = dal_node[unit * 128 + 0x28]  // dispatch table
   result = node->power_on(unit, port)  // indirect call
   if (!error) return result;

3. // Fallback path:
   alt_func = lookup(0x110320)  // alternate driver
   if (phy_null_drv match) use alt_func

4. mutex = &global_mutex[unit * 24 + offset]
   __osal_mutex_take(mutex)
   result = driver->power_on(unit, port)  // through function pointer
   __osal_mutex_give(mutex)
   return result;
```

### GPIO/I2C Operations

None. Pure software dispatch layer.

### Key Insights

- **DAL dispatch pattern**: Uses a node tree indexed by unit number to find the correct PHY driver.
- **Mutex protection**: PHY power-on operations are mutex-protected to prevent concurrent access.
- **Fallback mechanism**: If the primary driver lookup fails, falls back to an alternate driver (at address 0x110320).
- **Null driver check**: Compares against `phy_null_drv` to detect unpopulated PHY slots.
- Error code 0x800000C2 is `SW_NOT_INITIALIZED` or similar DAL error.
- This is the **top-level entry point** called by the higher-level switch management code.

---

## 8. Missing Symbols

The following symbols from the task list were **not found** in the binary:

### allPortsPoeOff
- **Status**: NOT FOUND in `ubnt_platform.ko`
- **Searched**: All symbol tables, case-insensitive substring match for "poeoff", "allport"
- **Likely location**: May be in `ubnt-hal` userspace binary (not available in extracted firmware), or may be a function name from a different firmware version.
- **Alternative names checked**: `poe_off_all`, `poe_all_off`, `all_poe_off`, `ports_poe_off` — none found.

### hasPoeE
- **Status**: NOT FOUND in `ubnt_platform.ko`
- **Searched**: All symbol tables, case-insensitive substring match for "haspoe"
- **Likely location**: May be in a different module or userspace tool.
- **Alternative names checked**: `has_poe`, `poe_present`, `poe_supported` — none found.

### getPowerSlot
- **Status**: NOT FOUND in `ubnt_platform.ko`
- **Searched**: All symbol tables, case-insensitive substring match for "powerslot", "getpower"
- **Likely location**: May be in a different module or userspace tool.
- **Alternative names checked**: `power_slot`, `get_power_slot` — none found.

**Note**: The EdgeOS firmware extracted from `ER-e300.v2.0.6.5208554.tar` contains only two kernel modules: `ubnt_platform.ko` and `ubnt_nf_app.ko`. The userspace `ubnt-hal-e` binary was not found in the extracted filesystem (likely in a separate package or different partition).

---

## Cross-Reference Call Graph

### Complete PoE Call Graph (rooted at `poe_st`)

```
poe_st (0x1718, 700 bytes)
├── sscanf(buf, "%d", &value)                    # Parse user input
├── er_gen2_set_poe_48v(port, enable)            # Pair-mode / 48V GPIOs
│   └── printk()                                 # Error only
│   # Direct GPIO writes: TX_SET/TX_CLEAR
│   # Targets: GPIOs 1, 3, 5, 7, 9 (EVEN entries, POE_GPIO_E301)
│
├── er_gen2_set_poe_24v(port, enable)            # Power-enable / 24V GPIOs
│   └── printk()                                 # Error only
│   # Direct GPIO writes: TX_SET/TX_CLEAR
│   # Targets: GPIOs 2, 4, 6, 16, 10 (ODD entries, POE_GPIO_E301)
│   # E302: Additional TX_CLEAR+TX_SET pulse on secondary pin
│
├── simple_strtol(buf, NULL, 10)                 # E303 path only
├── i2c_smbus_read_byte_data(i2c_poe, reg)       # E303 path only
└── i2c_smbus_write_byte_data(i2c_poe, reg, val) # E303 path only
```

### Caller → Callee Table (PoE-relevant only)

| Caller | Callee | Path | Mechanism |
|--------|--------|------|-----------|
| `poe_st` | `er_gen2_set_poe_48v` | E301/E302 | Function pointer ($s2), jalr |
| `poe_st` | `er_gen2_set_poe_24v` | E301/E302 | Function pointer ($s1), jalr |
| `poe_st` | `sscanf` | All | Direct call |
| `poe_st` | `simple_strtol` | E303 | Direct call |
| `poe_st` | `i2c_smbus_read_byte_data` | E303 | Direct call |
| `poe_st` | `i2c_smbus_write_byte_data` | E303 | Direct call |
| `er_gen2_set_poe_48v` | `printk` | Error | Direct call |
| `er_gen2_set_poe_24v` | `printk` | Error | Direct call |

### PHY Power-On Call Chain (not PoE-related)

```
ethphy_power_control (0x528)
├── mdiobus_read (via $s1)
├── phy_8031a_power_on (0x1172D8)
│   ├── phy_8031a_bt_bx_register_set(unit, port, 1)
│   ├── phy_common_power_on(unit, port)
│   └── phy_8031a_bt_bx_register_set(unit, port, 0)
├── phy_8031a_init
├── phy_8031a_ability_get
└── ubnt_switch_set_port_pvid

dal_phy_power_on (0x110E78)
├── dal_dev_all_dev_num_get
├── [indirect via dal_node tree]
├── __osal_mutex_take
├── [driver]->power_on (function pointer)
│   └── phy_805x_power_on (0x4F810)
│       ├── phy_805x_mdio_reg_read
│       └── phy_805x_mdio_reg_write (clear bit 11 = power-down)
├── __osal_mutex_give
└── (fallback to internal 0x110320)
```

### Data Dependency Graph

```
board_rev_major (.data+0x0) ──► poe_st, er_gen2_set_poe_24v, er_gen2_set_poe_48v
POE_GPIO_E301 (.data+0x3D0) ──► er_gen2_set_poe_24v, er_gen2_set_poe_48v
POE_GPIO_E302 (.data+0x3B8) ──► er_gen2_set_poe_24v (E302 path only)
i2c_poe (.bss+0x1CA8) ──► poe_st (E303 path only)
_intf_obj (.bss+0x8) ──► poe_st (E303 path: I2C client lookup)
_intf_poe_cap_e301 (.data+0xAE8) ──► poe_st (capability bitmap)
```

---

## Hardware Operations Summary

### TX_SET / TX_CLEAR (GPIO Register Writes)

| Function | TX_SET (0x888) | TX_CLEAR (0x890) | GPIO Pins | Path |
|----------|:-:|:-:|-----------|------|
| `er_gen2_set_poe_48v` | YES | YES | 1, 3, 5, 7, 9 | E301 |
| `er_gen2_set_poe_24v` | YES | YES | 2, 4, 6, 16, 10 | E301 |
| `er_gen2_set_poe_24v` | YES | YES | pin_1 + pin_2 | E302 |

### GPIO_BIT_CFG

**NONE of the documented functions write GPIO_BIT_CFG.** The tx_oe (output enable) for all PoE GPIOs must be configured during module initialization, not during PoE control operations.

### I2C Operations

| Function | I2C Read | I2C Write | Target | Path |
|----------|:--------:|:---------:|--------|------|
| `poe_st` | YES | YES | `i2c_poe` @ reg 2/3 | E303 |

`i2c_poe` is a BSS object (not a function) holding the I2C client pointer. Only used in E303 path.

### MDIO Operations

| Function | MDIO Read | MDIO Write | Target | Details |
|----------|:---------:|:----------:|--------|---------|
| `phy_805x_power_on` | YES | YES | Reg 0.0 | Clear bit 11 (power-down) |
| `ethphy_power_control` | YES | — | Various | Read PHY status |

### Timing / Delays

**No timing delays** in any of the documented functions. No `mdelay`, `udelay`, `ndelay`, or `msleep` calls.

---

## Register Reference

| Address | Register | Function |
|---------|----------|----------|
| 0x8001070000000880 | GPIO_RX_DAT | Read GPIO input state |
| 0x8001070000000888 | GPIO_TX_SET | Set GPIO output bit (atomically) |
| 0x8001070000000890 | GPIO_TX_CLEAR | Clear GPIO output bit (atomically) |

All addresses are in XKPHYS unmapped cached segment (0x8000000000000000 base).
