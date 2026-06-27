<!--
  conwrt — serial-02-bootloader-explore
  DISCLAIMER: Read-only bootloader exploration. Do NOT flash, write, or erase.
  You MUST have legal authority to access the target device.
-->

# Serial 02: Bootloader Exploration

**Role**: You are a serial console diagnostician exploring a router's bootloader.
Your goal is to enter the bootloader command interface, enumerate its capabilities,
and inspect the device's internal state — all without modifying anything.

---

## ⚠️ Safety Rules (NON-NEGOTIABLE)

- **DO NOT** flash firmware (no `tftpboot`, `flwrite`, `loadb`, etc.)
- **DO NOT** write to flash (no `nand write`, `spi write`, `flwrite`)
- **DO NOT** erase partitions (no `nand erase`, `erase`)
- **DO NOT** modify bootloader environment (no `setenv` + `saveenv`, no `setenv bootargs`)
- **DO NOT** reset the device from bootloader (no `reset`, `reboot`)
- **DO NOT** execute boot commands (no `bootm`, `boot`, `go`)
- **ONLY USE** read-only commands: `help`, `printenv`, `md.b`, `nand read`, `fis list`
- If a command is not in the read-only allowlist, STOP and ask the operator

---

## Prerequisites

- serial-01 completed: bootloader type, baud rate, and interrupt key identified
- Serial adapter connected and working (verified in serial-01)
- Device accessible via serial console

---

## Procedure

### Step 1: Interrupt Autoboot

Power cycle the device and send the interrupt key during the boot delay window.

The interrupt key and window are identified in serial-01 findings. Common keys:

| Bootloader | Interrupt Key | Typical Window |
|---|---|---|
| U-Boot | Space or Enter or Ctrl-C | 1-5 seconds |
| Z-Loader (ZyXEL) | ESC | 1 second |
| CFE (Broadcom) | Ctrl-C | 2-3 seconds |
| RedBoot | Ctrl-C | 2-5 seconds |

**Using serial-console.py command FIFO:**

```bash
# Start monitor
python3 scripts/serial-console.py /dev/cu.usbserial-XXXX --baud <rate> --monitor --session bootloader-explore &

# Power cycle the device, then immediately send interrupt:
printf 'ESCAPE' > /tmp/conwrt-serial-cmd
# Or for repeated sends during the window:
for i in 1 2 3 4 5; do printf 'ESCAPE' > /tmp/conwrt-serial-cmd; sleep 0.2; done
```

**Using direct pyserial:**

```python
import serial, time
s = serial.Serial('/dev/cu.usbserial-XXXX', <baud>, timeout=0.1)
# Send ESC repeatedly during boot
for _ in range(20):
    s.write(b'\x1b')
    time.sleep(0.05)
# Read response
time.sleep(1)
data = s.read(4096)
print(data.decode('ascii', errors='replace'))
```

**Success indicators:**
- U-Boot: `=>` prompt
- Z-Loader: `#` or `Z-LOADER>` prompt
- CFE: `CFE>` prompt
- RedBoot: `RedBoot>` prompt

**If interrupt fails:**
- Try a different key (some U-Boot builds use Space instead of Enter)
- Send the key more rapidly (every 50ms)
- Check that the interrupt window hasn't been disabled (`bootdelay=0` in env)

### Step 2: Enumerate Commands

List all available bootloader commands:

```bash
printf 'help\r' > /tmp/conwrt-serial-cmd
# Or for Z-Loader/CFE:
printf '?\r' > /tmp/conwrt-serial-cmd
```

Capture the full command list. For each command, note:
- Command name
- Brief description
- Whether it's read-only or write (flash/erase/reset)

**Common bootloader commands by type:**

| Category | U-Boot | Z-Loader | CFE | RedBoot |
|---|---|---|---|---|
| Help | `help` / `?` | `?` | `help` / `?` | `help` |
| Print env | `printenv` | `printenv` | `nvram show` | `fconfig -l` |
| Memory read | `md.b <addr> <len>` | `md.b` | `dm <addr> <len>` | `x -b <addr> <len>` |
| NAND info | `nand info` | — | — | `fis list` |
| NAND read | `nand read <addr> <off> <len>` | — | — | — |
| Partition list | `mtdparts` / `printenv mtdparts` | — | — | `fis list` |
| Network | `printenv ipaddr` | `printenv` | `ifconfig` | `ip_address` |
| TFTP | `tftpboot` ⚠️ | — | `load -tftp` ⚠️ | `load -tftp` ⚠️ |
| Boot | `bootm` ⚠️ | — | `boot` ⚠️ | `go` / `fis load` ⚠️ |

⚠️ = Write/execute command — DO NOT USE in this step.

### Step 3: Inspect Bootloader Environment

Read all environment variables (READ-ONLY — do not setenv):

```bash
printf 'printenv\r' > /tmp/conwrt-serial-cmd
```

**Key variables to document:**

| Variable | Meaning |
|---|---|
| `bootargs` / `bootcmd` | Kernel command line / boot command |
| `bootdelay` | Seconds before autoboot |
| `baudrate` | Console baud rate |
| `ethaddr` | MAC address |
| `ipaddr` / `serverip` | Bootloader network config (for TFTP) |
| `mtdparts` | Partition layout (U-Boot) |
| `BootingFlag` / `Image1Stable` | Dual-partition boot selection (ZyXEL) |
| `serial#` | Device serial number |
| `ver` | Bootloader version |

**For Broadcom CFE (nvram):**
```bash
printf 'nvram show\r' > /tmp/conwrt-serial-cmd
```

**For RedBoot (fconfig):**
```bash
printf 'fconfig -l\r' > /tmp/conwrt-serial-cmd
```

### Step 4: Inspect Partition Layout

Determine the flash partition map:

**U-Boot with mtdparts:**
```bash
printf 'printenv mtdparts\r' > /tmp/conwrt-serial-cmd
```

**U-Boot with NAND:**
```bash
printf 'nand info\r' > /tmp/conwrt-serial-cmd
printf 'nand device\r' > /tmp/conwrt-serial-cmd
```

**RedBoot FIS:**
```bash
printf 'fis list\r' > /tmp/conwrt-serial-cmd
```

**If no partition command available:** Read the partition table from the bootloader
environment variables, or from the boot log (some bootlogs print partition info during boot).

### Step 5: Read Memory (Optional — For Hardware Inspection)

Read raw flash memory contents at specific offsets. Useful for:
- Reading the partition table from flash
- Checking firmware headers (magic bytes)
- Reading factory/calibration data (CAUTION: do not dump to console — save to file)

```bash
# U-Boot: read 256 bytes from flash offset 0x0
printf 'md.b 0x9f000000 0x100\r' > /tmp/conwrt-serial-cmd
```

**Memory base addresses vary by SoC:**
| SoC | Flash Base | RAM Base |
|---|---|---|
| MediaTek MT7621 | 0x1e000000 | 0x80000000 |
| Atheros AR9344 | 0x9f000000 | 0x80000000 |
| Broadcom BCM47xx | 0x1c000000 | 0x80000000 |

### Step 6: Document Boot Flags (Dual-Partition Devices)

For devices with dual firmware partitions (ZyXEL, some TP-Link):

Check which partition is active and whether the boot is stable:

```bash
printf 'printenv BootingFlag\r' > /tmp/conwrt-serial-cmd
printf 'printenv Image1Stable\r' > /tmp/conwrt-serial-cmd
printf 'printenv Image2Stable\r' > /tmp/conwrt-serial-cmd
```

**ZyXEL boot flag values:**
- `BootingFlag=0`: Boot from Image1 (Kernel partition)
- `BootingFlag=1`: Boot from Image2 (Kernel2 partition)
- After successful boot: firmware sets `ImageNStable=1`
- After failed boot: bootloader tries the other partition

---

## Output Contract

Write `$STEP_DIR/findings.json`:

```json
{
  "step": "serial-02-bootloader-explore",
  "bootloader_prompt": "Z-LOADER>",
  "commands_available": ["help", "printenv", "setenv", "saveenv", "md.b", "reset", "tftpboot", "..."],
  "commands_readonly": ["help", "printenv", "md.b"],
  "commands_write": ["setenv", "saveenv", "tftpboot", "reset"],
  "environment": {
    "bootdelay": "1",
    "baudrate": "57600",
    "ethaddr": "<REDACTED:MAC>",
    "ipaddr": "192.168.1.1",
    "serverip": "192.168.1.10",
    "BootingFlag": "0",
    "Image1Stable": "1",
    "Image2Stable": "0"
  },
  "partitions": [
    {"name": "Bootloader", "offset": "0x00000", "size": "0x80000"},
    {"name": "Config", "offset": "0x80000", "size": "0x80000"},
    {"name": "Factory", "offset": "0x100000", "size": "0x40000", "irreplaceable": true},
    {"name": "Kernel", "offset": "0x140000", "size": "0x1F40000"},
    {"name": "Kernel2", "offset": "0x2080000", "size": "0x1F40000"}
  ],
  "active_partition": "Kernel (Image1)",
  "dual_partition": true,
  "boot_stable": true,
  "notes": "Z-Loader V1.30 entered via ESC. 15 commands available. Dual-partition layout with BootingFlag=0 (Image1 active, stable). Factory partition at 0x100000 is irreplaceable.",
  "next_step_input": {
    "recommendation": "serial-03-backup",
    "parameters": {
      "partitions_to_dump": ["Bootloader", "Config", "Factory"],
      "flash_base_address": "0x1e000000"
    }
  }
}
```
