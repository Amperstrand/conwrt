# Serial Integration Improvement Plan

## Current State

conwrt has a functional serial-TFTP flash method for U-Boot devices, but serial
support is incomplete for the broader flashing workflow. Key gaps identified:

| Gap | Impact |
|-----|--------|
| No session logging in SerialUBootDriver | No persistent record of serial interaction |
| Only U-Boot supported, not Z-Loader | Zyxel devices with Z-Loader can't use serial mode |
| serial-console.py not integrated | Standalone tool, framework doesn't benefit from boot detection |
| No serial+zykast mode | Can't trigger Z-Loader via serial then flash via multicast |
| No boot stage tracking | State machine blind to what's happening on serial |
| Stale process risk | Multiple consumers can't share one serial port |

## Architecture: Serial Broker Pattern

### Problem

Serial ports are exclusive — one process opens the port. Current design means
either the state machine OR the monitoring tool can use serial, never both.

### Solution: Single-Owner Broker

```
 serial port (exclusive)
        │
 ┌──────┴──────┐
 │ SerialBroker │  ← owns port, logs everything, detects boot stages
 │  (daemon)    │
 └──────┬──────┘
        │ Unix domain socket: /tmp/conwrt-serial.sock
   ┌────┼────────┬────────────┬─────────────┐
   │    │        │            │             │
 state  log     boot        interactive   zycast
 machine file   detector    terminal      sender
```

**Broker responsibilities:**
- Own the serial port exclusively (clean lifecycle — opens on start, closes on exit)
- Log ALL data to `serial/<session>/` (raw bytes + human-readable + session.json)
- Detect boot stages (U-Boot, Z-Loader, kernel, OpenWrt, panic)
- Accept read subscribers (pub/sub for RX data)
- Accept write commands from any client (TX queue)
- Track session metadata (byte counts, boot stage timeline, timing)

**Client responsibilities:**
- State machine: send keystrokes, react to boot stage events
- Zycast sender: trigger when Z-Loader detected
- Interactive terminal: keyboard I/O for manual debugging
- Boot detector: pattern matching for boot signatures

### Implementation Path

This is evolutionary — `serial-console.py` is already 80% of this design:

1. **Phase 1** (current): `serial-console.py` as standalone monitor with FIFO commands
2. **Phase 2**: Add Unix socket server to `serial-console.py` for multi-client access
3. **Phase 3**: Wire `SerialUBootDriver` to connect to broker socket instead of opening port directly
4. **Phase 4**: State machine subscribes to boot stage events from broker

## New Flash Mode: serial+zykast

### Problem

Zyxel devices (NR7101, GS1900) require Z-Loader mode for zycast. Z-Loader only
activates via serial interrupt or failed boot. Without serial, zycast is useless
against a device with healthy firmware.

### Solution: Combined Serial + Zycast Flash Mode

```
State.SERIAL_ZYCAST_WAITING     → Open serial, wait for Z-Loader banner
State.SERIAL_ZYCAST_INTERRUPT   → Send Escape key during boot delay
State.SERIAL_ZYCAST_LISTENING   → Z-Loader confirms "Multiboot Listening..."
State.ZYCAST_SENDING            → Start multicast sender (existing zycast handler)
State.REBOOTING                 → Watch serial for kernel boot, then kill zycast
```

**Model JSON addition:**
```json
"flash_methods": {
  "serial-zykast": {
    "description": "Serial-triggered zycast. Use serial to enter Z-Loader, then multicast delivers firmware.",
    "serial_baud": 115200,
    "bootloader_banner": "Z-LOADER",
    "interrupt_key": "escape",
    "interrupt_timing": "during_boot_delay",
    "zycast_confirmation": "Multiboot Listening...",
    "flash_time_seconds": 180
  }
}
```

**State machine flow:**
1. Operator connects serial + ethernet, starts conwrt with `--flash-method serial-zykast`
2. `SERIAL_ZYCAST_WAITING`: Monitor serial for bootloader banner
3. On banner detected → `SERIAL_ZYCAST_INTERRUPT`: Send Escape key
4. On "Multiboot Listening..." → `ZYCAST_SENDING`: Start multicast sender
5. Watch serial for kernel boot messages → `REBOOTING`
6. Kill zycast, verify SSH

## Integration: serial-console.py → SerialUBootDriver

### Problem

`SerialUBootDriver` in `infrastructure.py` logs to stdout only. No persistent
record of serial interaction. `serial-console.py` has full logging but runs
separately.

### Solution: Shared SerialSession Class

Extract the `SerialSession` class from `serial-console.py` into a shared module
that both the standalone tool and `SerialUBootDriver` use:

```
scripts/conwrt/
  serial_session.py     ← Shared: SerialSession, boot detection, logging
  infrastructure.py     ← Uses SerialSession internally
  handlers_serial.py    ← Uses SerialSession events
scripts/
  serial-console.py     ← CLI wrapper around SerialSession
```

**SerialSession provides:**
- `open(port, baud)` → opens port, starts logging
- `read()` → returns bytes (thread-safe)
- `write(data)` → sends bytes, logs as TX
- `on_boot_stage(callback)` → notifies when boot stage changes
- `session_log` → path to console.log, console.raw, session.json
- `close()` → finalizes session metadata, releases port

**SerialUBootDriver changes:**
- Constructor takes `SerialSession` instead of raw port/baud
- `wait_for_bootmenu()` uses `on_boot_stage()` instead of pattern matching
- All reads/writes go through session (automatically logged)
- Boot stage transitions trigger events in the state machine

## Boot Stage Detection

### Pattern Library

From `serial-console.py`, extended with device-specific patterns:

```python
BOOT_SIGNATURES = {
    "uboot": [
        b"U-Boot", b"u-boot", b"Hit any key to stop autoboot",
        b"bootmenu", b"Net:   ", b"ethaddr=",
    ],
    "zloader": [
        b"Z-Loader", b"Z-LOADER", b"ZyNOS", b"BootBase",
        b"Multiboot", b"Press ENTER to debug mode",
    ],
    "edk2": [
        b"EDK II", b"UEFI", b"Shell>",
    ],
    "barebox": [
        b"barebox", b"BareBox",
    ],
    "kernel": [
        b"[    0.000000] Linux version", b"Starting kernel",
        b"Booting Linux", b"Decompressing Linux",
        b"Starting kernel ...",
    ],
    "openwrt": [
        b"OpenWrt", b"LEDE", b"BusyBox", b"dropbear",
    ],
    "panic": [
        b"Kernel panic", b"not syncing",
    ],
    "boot_loop": [
        b"System will restart", b"Watchdog reset",
        b"Booting from",  # repeated 3+ times
    ],
}
```

### State Machine Integration

Boot stage events feed into the state machine:

| Stage Event | State Machine Action |
|-------------|---------------------|
| `uboot` detected | Ready to send bootmenu interrupt |
| `zloader` detected | Ready to send Escape for Z-Loader |
| `kernel` detected | Flash succeeded, device booting |
| `openwrt` detected | Device ready for SSH |
| `panic` detected | Flash failed, enter recovery |
| `boot_loop` detected | Firmware corrupt, retry flash |

## Session Recording

### What Gets Recorded

Every serial interaction produces three files in `serial/<session-name>/`:

1. **`console.log`** — Human-readable, timestamped, with `[RX]`/`[TX]` markers
2. **`console.raw`** — Exact bytes received (for replay, diff, analysis)
3. **`session.json`** — Metadata: port, baud, timing, byte counts, boot stages

### Integration Points

- **During flash** (`handlers_serial.py`): SerialSession records everything
- **During onboarding** (prompts): Boot capture saved as model JSON boot_signatures
- **During debugging**: Operator reviews console.log for error messages
- **Post-mortem**: session.json shows exactly what happened and when

### Gitignore

All serial logs are gitignored (`serial/` directory) — they may contain device
MAC addresses, serial numbers, and boot output with PII.

## Testing Improvements

Current: Good state transition tests, no SerialUBootDriver unit tests.

Add:
1. **SerialUBootDriver tests** with mocked pyserial (fake serial port)
2. **Boot stage detection tests** with sample boot logs
3. **SerialSession tests** for logging and command injection
4. **Serial broker tests** for multi-client access

## Priority Order

| Priority | Task | Effort | Unblocks |
|----------|------|--------|----------|
| P0 | SerialSession shared class | Medium | Everything else |
| P0 | Integrate logging into SerialUBootDriver | Small | Session recording |
| P1 | serial+zykast flash mode | Medium | NR7101 flashing |
| P1 | Boot stage detection in state machine | Small | Automated recovery |
| P2 | Serial broker (multi-client) | Large | Parallel monitoring |
| P2 | SerialUBootDriver unit tests | Medium | CI coverage |
| P3 | Z-Loader support in SerialUBootDriver | Medium | Zyxel serial-TFTP |
