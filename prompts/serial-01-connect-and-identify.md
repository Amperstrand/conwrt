<!--
  conwrt — serial-01-connect-and-identify
  DISCLAIMER: This is a serial console troubleshooting framework. You MUST have legal
  authority to access and modify the target device. Serial access provides low-level
  hardware control — use with caution. Read-only by default. Do NOT flash or modify
  device state in this step.
-->

# Serial 01: Connect & Identify

**Role**: You are a serial console diagnostician operating inside the conwrt framework.
Your goal is to establish a serial connection to a router, capture its boot sequence,
and identify the hardware, bootloader, and firmware state.

---

## ⚠️ Safety Rules (NON-NEGOTIABLE)

- **DO NOT** flash firmware or upload any files to the device
- **DO NOT** write to flash partitions or modify bootloader environment
- **DO NOT** send commands that erase or reset device state
- **DO NOT** connect VCC pin — device is powered by PoE/DC, not the serial adapter
- **DO** verify serial adapter voltage (3.3V typical) matches device UART before connecting
- When in doubt, capture output only — do not send keystrokes

---

## Prerequisites

- USB-serial adapter (FTDI/CP2102/CH340) connected to host
- Serial header identified on target device (TX, RX, GND pins)
- Wiring: adapter TX → device RX, adapter RX → device TX, GND → GND
- Device powered (PoE injector or DC power)

---

## Procedure

### Step 1: Adapter Diagnostics

Before connecting to the device, verify the serial adapter is healthy:

```bash
python3 scripts/serial-console.py --diagnose
```

This checks:
- Adapter detected and identified (VID/PID, chip type)
- Port opens successfully
- Signal line states (CTS/DSR/CD/RI)
- RX buffer is empty (no floating-pin noise)
- Detects macOS port aliases (multiple /dev/cu.* nodes for one adapter)

**If diagnostics fail**: Check USB connection, try a different USB port, verify driver is loaded.

### Step 2: Loopback Test (RECOMMENDED before first connection)

Verify the adapter can send AND receive by bridging TX→RX with a jumper wire:

```bash
python3 scripts/serial-console.py /dev/cu.usbserial-XXXX --loopback
```

**If loopback fails**: The adapter itself may be faulty. Try a different adapter.

**After loopback**: Remove the jumper wire before connecting to the device.

### Step 3: Determine Baud Rate

Never assume baud rate. Check these sources in order:

1. **conwrt model JSON** (if device is known):
   ```bash
   python3 -c "import json; m=json.load(open('models/<model>.json')); print(m['hardware']['serial'])"
   ```

2. **OpenWrt device tree** (for supported devices):
   - Search the OpenWrt git commit/patch that added device support
   - Check the `chosen` node: `stdout-path = "serial0:57600n8"`
   - Common rates: 57600 (ZyXEL MT7621), 115200 (most others), 38400 (some older)

3. **Auto-detect** (if baud rate unknown):
   ```bash
   python3 scripts/serial-console.py /dev/cu.usbserial-XXXX --auto-baud
   ```

### Step 4: Capture Boot Sequence

The boot sequence is the richest source of device information. It appears only
during the first ~10 seconds after power-on.

**Method A — Fresh boot capture (most informative):**

1. Start serial monitor BEFORE power-on:
   ```bash
   python3 scripts/serial-console.py /dev/cu.usbserial-XXXX --baud <rate> --monitor --session <model>-boot
   ```

2. Power cycle the device (disconnect and reconnect power)

3. Capture should show: DDR calibration → bootloader banner → boot log → firmware handoff

**Method B — Silent device probing (if already booted):**

If the device is already running and not producing serial output:

1. Send `\r\n` (Enter) — some firmware/shells respond with a prompt
2. Send `\x03` (Ctrl-C) — may interrupt a hanging process
3. If no response after both, the firmware likely doesn't use serial console
4. Power cycle to capture the boot sequence (which always uses serial)

**Method C — Auto-baud capture (if baud unknown):**

```bash
python3 scripts/serial-console.py /dev/cu.usbserial-XXXX --auto-baud
```
This sweeps common baud rates and picks the one with the most valid data.

### Step 5: Parse Boot Output

From the captured boot log, extract:

**Bootloader identification:**
| Pattern in output | Bootloader | Notes |
|---|---|---|
| `U-Boot 20xx.xx` | Das U-Boot | Most common, GPL |
| `Z-LOADER Vx.xx` | ZyXEL Z-Loader | ZyXEL devices, multicast flash support |
| `CFE Bootloader` | Broadcom CFE | Broadcom-based devices |
| `RedBoot>` | RedBoot | Older devices, Marvell |
| `BootBase` | ZyNOS BootBase | Very old ZyXEL devices |
| `MT7621 stage1` | MediaTek preloader | MT7621 stage 1 before main bootloader |

**Hardware identification:**
| Pattern | Information |
|---|---|
| `ASIC MT7621A` / `MT7628` / etc. | SoC model |
| `DRAM: 256 MB` / `estimate memory size` | RAM size |
| `NAND ID [...]` / `SPI NOR` | Flash type and chip ID |
| `CPU freq = 880 MHZ` | CPU clock speed |
| `Flash component: 128 MBytes` | Flash size |

**Firmware state assessment:**
| Observation | Interpretation |
|---|---|
| Boot log shows `Linux version...` then shell prompt | OpenWrt or Linux firmware, functional |
| Boot log ends at firmware handoff, no kernel output | Stock firmware (doesn't use serial console) |
| Boot log repeats every N seconds | Boot loop — firmware crashes, watchdog resets |
| DDR calibration fails | Hardware fault (RAM issue) |
| `NAND: ... bad blocks` | Flash degradation |
| `*** Warning - bad CRC ***` | Corrupted bootloader env or firmware partition |

### Step 6: Boot Timing Analysis

If timestamps are available, record key timing milestones:

- **DDR calibration duration**: from `do DDR setting` to `calibration passed`
- **Bootloader total duration**: from first output to `Starting application` / `Booting Linux`
- **Autoboot interrupt window**: duration of the `Hit ESC key to stop autoboot` countdown
- **Multiboot/multicast listen window** (Z-Loader only): `Multiboot Listening...` countdown
- **Firmware boot time**: from handoff to first network activity or shell prompt

---

## Output Contract

Write `$STEP_DIR/findings.json`:

```json
{
  "step": "serial-01-connect-and-identify",
  "serial_config": {
    "adapter_type": "FTDI FT232R",
    "adapter_vid_pid": "0403:6001",
    "port": "/dev/cu.usbserial-XXXX",
    "baud_rate": 57600,
    "wiring": "TX→Pin4, RX→Pin3, GND→Pin1"
  },
  "bootloader": {
    "type": "Z-Loader",
    "version": "V1.30",
    "build_date": "2020-06-03",
    "interrupt_key": "ESC",
    "interrupt_window_seconds": 1,
    "multiboot_listening": true,
    "multiboot_window_seconds": 6
  },
  "hardware": {
    "soc": "MT7621A",
    "cpu_freq_mhz": 880,
    "ram_mb": 256,
    "ram_type": "DDR3",
    "flash_type": "NAND",
    "flash_size_mb": 128,
    "flash_chip_id": "C2 F1 80 95 02"
  },
  "firmware_state": "stock_silent",
  "firmware_type": "stock_zyxel",
  "boot_timing": {
    "ddr_calibration_ms": 3000,
    "bootloader_total_ms": 10000,
    "autoboot_window_seconds": 1,
    "firmware_handoff_at_ms": 10000
  },
  "boot_log_file": "raw/boot-console.log",
  "notes": "Device boots through Z-Loader, enters Multiboot Listening for ~6s, then hands off to silent stock firmware. No kernel serial output after handoff. No network activity.",
  "next_step_input": {
    "recommendation": "serial-02-bootloader-explore",
    "parameters": {
      "interrupt_key": "ESC",
      "interrupt_window_seconds": 1
    }
  }
}
```
