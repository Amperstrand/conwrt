# Serial Console in conwrt

Serial console access is the most powerful tool for router flashing — it provides
ground-truth visibility into device state, bootloader interaction, and recovery
capabilities that no network-based method can match.

## Why Serial?

| Situation | Network-only | Serial |
|-----------|-------------|--------|
| Device won't boot | Blind — no feedback | Full boot log, error messages |
| Bootloader recovery mode | Can't trigger without buttons | Press key during boot delay |
| Firmware corrupt | Device unreachable | Bootloader still works |
| Debug flash failure | Guess from symptoms | See exact error in boot log |
| Identify unknown device | Port scan + guess | Boot banner tells you everything |
| Verify flash success | Wait for SSH | Watch kernel boot in real-time |

## Tooling

### `scripts/serial-console.py`

A bidirectional serial monitor with session logging, boot stage detection, and
command injection. Based on pyserial's miniterm pattern.

```bash
# Interactive mode (terminal keyboard → serial)
python3 scripts/serial-console.py /dev/cu.usbserial-BG02QAPG

# Monitor mode (background/tmux — command injection only)
python3 scripts/serial-console.py /dev/cu.usbserial-BG02QAPG --monitor

# Auto-detect baud rate, then start monitoring
python3 scripts/serial-console.py /dev/cu.usbserial-BG02QAPG --auto-baud

# Adapter health check (no device needed)
python3 scripts/serial-console.py --diagnose

# Loopback test (requires TX-RX jumper wire)
python3 scripts/serial-console.py /dev/cu.usbserial-BG02QAPG --loopback

# List available ports
python3 scripts/serial-console.py --list

# Named session (for organized logging)
python3 scripts/serial-console.py /dev/cu.usbserial-BG02QAPG --session nr7101-flash-attempt-1
```

### Auto-Baud Detection

When the baud rate is unknown, `--auto-baud` sweeps 9 common rates and picks the
best one based on three signals:

| Metric | What it measures | Score weight |
|--------|-----------------|-------------|
| Printable ASCII ratio | Percentage of bytes in 0x20-0x7E range | 0-100 points |
| Boot pattern hits | Known bootloader signatures ("U-Boot", "Z-Loader", etc.) | 50 points each |
| Byte entropy | Shannon entropy of byte distribution (lower = structured text) | Up to 30 bonus |

At the wrong baud rate, received bytes are uniformly distributed garbage (high
entropy, low ASCII ratio). At the correct baud rate, bytes form readable text
(low entropy, high ASCII ratio, pattern matches).

### Adapter Diagnostics (`--diagnose`)

Runs without a device connected. Checks:
- Adapter detection (VID/PID → chip type: FTDI FT232R, CP2102, CH340, etc.)
- Device node aliasing (multiple `/dev/cu.*` for same physical adapter)
- Signal line states (CTS, DSR, CD, RI)
- RX buffer noise (floating-pin detection)

### Loopback Test (`--loopback`)

Tests the adapter's TX→RX path. **Requires a physical jumper wire** between the
adapter's TX and RX pins. Sends four test patterns:
- ASCII text ("Hello, Serial!")
- Clock pattern (0x55 = alternating bits)
- All 256 byte values
- CRLF-terminated command

All four must echo correctly for a pass.

**Sending keystrokes** (while running in tmux/monitor mode):

```bash
# Send Escape key (to interrupt bootloader autoboot)
printf 'ESCAPE' > /tmp/conwrt-serial-cmd

# Send a command + Enter
printf 'printenv\r' > /tmp/conwrt-serial-cmd

# Send Ctrl-C
printf 'CTRLC' > /tmp/conwrt-serial-cmd

# Send raw bytes
printf '\x1b[2J' > /tmp/conwrt-serial-cmd
```

**Log output** — each session writes to `serial/<session-name>/`:

| File | Contents |
|------|----------|
| `console.log` | Human-readable with timestamps and `[RX]`/`[TX]` direction markers |
| `console.raw` | Exact raw bytes (for replay, analysis, diff) |
| `session.json` | Session metadata: port, baud, byte counts, boot stage transitions |

### Boot Stage Detection

The monitor automatically detects boot stages from serial output:

| Stage | Signatures |
|-------|-----------|
| `uboot` | "U-Boot", "Hit any key to stop autoboot", "bootmenu" |
| `zloader` | "Z-Loader", "ZyNOS", "BootBase", "Multiboot" |
| `kernel` | "Linux version", "Starting kernel", "Decompressing Linux" |
| `openwrt` | "OpenWrt", "BusyBox", "dropbear" |
| `panic` | "Kernel panic", "not syncing" |

Stage transitions are logged to both console and `session.json`:

```
[15:38:50] BOOT STAGE: unknown → zloader
[15:39:12] BOOT STAGE: zloader → kernel
[15:39:18] BOOT STAGE: kernel → openwrt
```

## Serial Use Cases in conwrt

### 1. Boot Signature Discovery (Model Onboarding)

When onboarding a new device, capture the boot sequence via serial:

```bash
python3 scripts/serial-console.py /dev/cu.usbserial-BG02QAPG \
  --session onboarding-<model> --monitor
# Reboot the device
# The console.log + session.json become the boot signature for the model JSON
```

### 2. Serial-Triggered Zycast (Zyxel Devices)

Many Zyxel bootloaders only enter multicast listen mode when Z-Loader is active.
Serial is required to trigger this:

```
1. Start zycast sender (multicast firmware)
2. Open serial console in monitor mode
3. Power-cycle device
4. When "Press any key" or boot delay appears, send Escape via serial
5. Z-Loader enters multicast listen mode
6. Zycast firmware is received and flashed
7. Watch for kernel boot on serial — confirms flash success
8. Kill zycast
```

### 3. Serial TFTP Recovery (U-Boot Devices)

For devices with U-Boot, serial + TFTP is the standard recovery method:

```
1. Connect serial + ethernet
2. Power-cycle, send key during boot delay
3. At U-Boot prompt: setenv serverip, tftpboot, bootm
4. Initramfs boots, then sysupgrade for permanent install
```

conwrt's existing `serial-tftp` flash method handles this automatically
(see `handlers_serial.py` + `SerialUBootDriver`).

### 4. Low-Level Debugging

When a flash fails or the device behaves unexpectedly:

```bash
# Capture full boot sequence
python3 scripts/serial-console.py /dev/cu.usbserial-BG02QAPG \
  --session debug-boot-failure --monitor
# Reboot and capture everything
# Analyze console.log for error messages, partition issues, boot loops
```

### 5. XMODEM Recovery (ZyNOS BootBase)

Some Zyxel switches (GS1920 series) use ZyNOS BootBase which only accepts
firmware via XMODEM over serial. This is a last-resort recovery method.

## Hardware Setup

### USB-Serial Adapters

| Adapter | Voltage | Notes |
|---------|---------|-------|
| FTDI FT232R | 3.3V or 5V (jumper) | Most common, reliable |
| CP2102 | 3.3V | Cheap, widely available |
| CH340 | 3.3V/5V | Very cheap, slightly less reliable |

**Always use 3.3V for router UART headers.** 5V can damage the device.

### Wiring

```
USB-Serial Adapter          Router UART Header
├── RX  ──────────────────→ TX   (device transmits, adapter receives)
├── TX  ──────────────────→ RX   (adapter transmits, device receives)
├── GND ──────────────────→ GND  (must be connected)
└── VCC ──── NOT CONNECTED       (device is powered by PoE/DC)
```

**Common mistake:** RX→RX and TX→TX (both devices listen on the same pin,
nobody talks). If you see zero output, swap RX and TX.

### Baud Rates

| Device Family | Baud | Notes |
|---------------|------|-------|
| **Zyxel NR7101** | **57600** | Confirmed from OpenWrt patch. NOT 115200! |
| Most OpenWrt routers | 115200 | 8N1, no flow control |
| Zyxel ZyNOS (GS1920) | 9600 → 115200 | Starts at 9600, change via ATBA5 |
| Some older devices | 38400 | Check device wiki |
| Bare-metal debug | 4800 | Rare |

### NR7101 UART Header (J5)

From Bjørn Mork's OpenWrt device support patch (2021-06):

```
J5 Header (5-pin, 2.54mm pitch, populated):

Pin 1: [o] GND
Pin 2: [ ] key (no pin — alignment key)
Pin 3: [o] RX     ← connect adapter TX here
Pin 4: [o] TX     ← connect adapter RX here
Pin 5: [o] 3.3V   ← do NOT connect (device powered by PoE)
```

**Baud: 57600 8N1** (NOT 115200 — confirmed from OpenWrt device tree)

**Access**: Remove SIM/button/LED cover, WLAN button, and 12 screws to expose PCB.

## Integration with conwrt Framework

### Current State

- `handlers_serial.py` — Handles serial-TFTP mode (U-Boot devices)
- `infrastructure.py` — `SerialUBootDriver` class for U-Boot interaction
- `flash_dispatcher.py` — "serial" mode dispatches to serial-TFTP handlers
- **No logging** of serial data during flash (gap — `serial-console.py` fills this)

### Planned Improvements

1. **Serial logging in all serial handlers** — Wire `serial-console.py`'s
   `SerialSession` into `SerialUBootDriver` so every flash attempt produces
   a complete serial log.

2. **Serial+Zycast mode** — New flash mode for Zyxel devices where serial
   triggers Z-Loader, then zycast delivers firmware via multicast.

3. **Boot stage awareness** — State machine reacts to boot stage transitions
   detected from serial (e.g., wait for "kernel" stage before probing SSH).

4. **Serial boot signature export** — After onboarding a new device, export
   the serial boot log as model JSON boot signature data.
