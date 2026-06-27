#!/usr/bin/env python3
"""Serial boot capture tool — waits for device boot, captures everything with timestamps.

Designed for power-cycle-when-ready workflow:
1. Start this tool (it waits indefinitely for serial data)
2. Power cycle the device whenever you want
3. The tool detects boot start, captures everything, and prints a timing report

Usage:
    python3 scripts/serial-boot-capture.py [PORT] [BAUD] [OPTIONS]

Options:
    --session NAME     Session name for log directory (default: boot-capture)
    --esc              Send ESC repeatedly during boot to interrupt autoboot
    --timeout SECS     Stop after N seconds of silence (default: 15)
    --max-wait SECS    Maximum time to wait for first byte (default: unlimited)
    --send-cr          Send CR after capture to check for shell prompt

Examples:
    # Basic boot capture — power cycle whenever ready
    python3 scripts/serial-boot-capture.py /dev/cu.usbserial-BG02QAPG 57600

    # Capture and interrupt autoboot to enter bootloader
    python3 scripts/serial-boot-capture.py /dev/cu.usbserial-BG02QAPG 57600 --esc

    # Named session for organized logs
    python3 scripts/serial-boot-capture.py /dev/cu.usbserial-BG02QAPG 57600 --session nr7101-boot-1
"""
import argparse
import os
import re
import serial
import sys
import time
from pathlib import Path

# Boot stage markers — (stage_name, pattern, is_milestone)
BOOT_MARKERS = [
    ("POWER_ON",         b"\xbf\x00\x00",         False),  # MT7621 preloader magic
    ("DDR_CAL_START",    b"do DDR setting",         True),
    ("DDR_CAL_DONE",     b"calibration passed",     True),
    ("STAGE1_DONE",      b"stage1 code done",       True),
    ("UBOOT_BANNER",     b"U-Boot 1.1.3",           True),
    ("UBOOT_VERSION",    b"Ralink UBoot Version",   True),
    ("CPU_FREQ",         b"CPU freq = ",            True),
    ("APP_HANDOFF",      b"Starting application",   True),
    ("ZLOADER_BANNER",   b"Z-LOADER",               True),
    ("ESC_PROMPT",       b"Hit ESC key",            True),
    ("MULTIBOOT_LISTEN", b"Multiboot Listening",    True),
    ("NETBOOT_START",    b"NetLoop",                True),
    ("ETH_INIT",         b"ETH_STATE_ACTIVE",       True),
    ("KERNEL_LINUX",     b"Linux version",          True),
    ("KERNEL_STARTING",  b"Starting kernel",        True),
    ("KERNEL_DECOMP",    b"Decompressing Kernel",   True),
    ("OPENWRT_BANNER",   b"OpenWrt",                True),
    ("BUSYBOX_INIT",     b"Starting init",          True),
    ("DROPBEAR_START",   b"dropbear",               True),
    ("SHELL_PROMPT",     b"root@",                  True),
    # CFE bootloaders
    ("CFE_BANNER",       b"CFE version",            True),
    ("CFE_PROMPT",       b"CFE>",                   True),
    # RedBoot
    ("REDBOOT_BANNER",   b"RedBoot",                True),
    ("REDBOOT_PROMPT",   b"RedBoot>",               True),
    # Generic U-Boot
    ("UBOOT_GENERIC",    b"U-Boot 20",              True),
    ("UBOOT_PROMPT",     b"=>",                      True),
    # Boot failures
    ("BAD_CRC",          b"bad CRC",                True),
    ("NAND_BAD_BLOCK",   b"bad block",              True),
    ("KERNEL_PANIC",     b"Kernel panic",           True),
    ("BOOT_FAIL",        b"BOOT FAIL",              True),
]


def capture_boot(port: str, baud: int, session: str, send_esc: bool,
                 silence_timeout: int, max_wait: int, send_cr: bool):
    """Wait for boot data, capture everything, return boot analysis."""
    log_dir = Path("serial") / session
    log_dir.mkdir(parents=True, exist_ok=True)

    console_log = log_dir / "console.log"
    raw_file = log_dir / "console.raw"
    timing_file = log_dir / "timing.json"

    s = serial.Serial(port, baud, timeout=0.5)

    print(f"╔══════════════════════════════════════════════════╗")
    print(f"║  Serial Boot Capture                            ║")
    print(f"║  Port: {port:<42s}║")
    print(f"║  Baud: {baud:<42d}║")
    print(f"║  Log:  serial/{session:<42s}║")
    if send_esc:
        print(f"║  ESC:  WILL interrupt autoboot                   ║")
    print(f"╠══════════════════════════════════════════════════╣")
    print(f"║  >>> POWER CYCLE THE DEVICE NOW <<<             ║")
    print(f"║  Waiting for first byte... (Ctrl-C to abort)    ║")
    print(f"╚══════════════════════════════════════════════════╝")
    sys.stdout.flush()

    # Phase 1: Wait for first byte (device power-on)
    raw_data = bytearray()
    first_byte_time = None
    wait_start = time.time()

    while True:
        chunk = s.read(4096)
        if chunk:
            first_byte_time = time.time()
            break
        if max_wait > 0 and (time.time() - wait_start) > max_wait:
            print(f"\nNo data after {max_wait}s. Device may already be booted.")
            s.close()
            return None
        # Print a dot every 5 seconds to show we're alive
        elapsed = int(time.time() - wait_start)
        if elapsed > 0 and elapsed % 5 == 0:
            print(f"\r  Waiting... {elapsed}s", end="", flush=True)

    print(f"\n\n✓ Boot data detected at {time.strftime('%H:%M:%S')}!")
    print()

    # Phase 2: Capture boot sequence with timestamps
    raw_data.extend(chunk)
    markers_found = []
    last_data_time = first_byte_time
    esc_sent = False

    # Check first chunk for markers
    for name, pattern, is_milestone in BOOT_MARKERS:
        if pattern in chunk:
            t_rel = 0.0
            markers_found.append((t_rel, name))
            print(f"  [{t_rel:7.3f}s] >>> {name}")

    # Write initial data to logs
    with open(raw_file, "wb") as f:
        f.write(chunk)
    with open(console_log, "w") as f:
        f.write(f"=== Boot capture {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        f.write(f"=== Port: {port} @ {baud} baud ===\n\n")
        text = chunk.decode("ascii", errors="replace")
        f.write(text)
        f.flush()

    while True:
        chunk = s.read(4096)
        now = time.time()

        if chunk:
            t_rel = now - first_byte_time
            last_data_time = now
            raw_data.extend(chunk)

            # Check for boot markers
            for name, pattern, is_milestone in BOOT_MARKERS:
                if pattern in chunk and name not in [m[1] for m in markers_found]:
                    markers_found.append((t_rel, name))
                    print(f"  [{t_rel:7.3f}s] >>> {name}")

            # Send ESC if we see the ESC prompt and haven't sent yet
            if send_esc and not esc_sent:
                if b"Hit ESC" in chunk or b"Hit any key" in chunk or b"stop autoboot" in chunk:
                    for _ in range(10):
                        s.write(b'\x1b')
                        time.sleep(0.02)
                    esc_sent = True
                    print(f"  [{t_rel:7.3f}s] >>> ESC_SENT (autoboot interrupt)")

            # Print non-empty lines
            text = chunk.decode("ascii", errors="replace")
            for line in text.split('\n'):
                line = line.strip()
                if line and len(line) > 1:
                    # Skip DDR calibration table rows
                    if re.match(r'^[0-9A-F]{4}:\|', line):
                        continue
                    print(f"  [{t_rel:7.3f}s] {line[:150]}")

            # Append to log files
            with open(raw_file, "ab") as f:
                f.write(chunk)
            with open(console_log, "a") as f:
                f.write(text)
                f.flush()

        # Check silence timeout
        if now - last_data_time > silence_timeout:
            print(f"\n  [{now - first_byte_time:.3f}s] === {silence_timeout}s silence — boot capture complete ===")
            break

    # Phase 3: Post-capture — try to get a shell prompt
    if send_cr:
        s.write(b'\r\n\r\n')
        time.sleep(2)
        response = s.read(4096)
        if response:
            t_rel = time.time() - first_byte_time
            text = response.decode("ascii", errors="replace").strip()
            print(f"\n  [{t_rel:.3f}s] Shell probe response: {text[:200]}")
            with open(console_log, "a") as f:
                f.write(f"\n\n=== Shell probe ===\n{text}\n")

    s.close()

    # Phase 4: Print timing report
    print()
    print("=" * 60)
    print("BOOT TIMING REPORT")
    print("=" * 60)

    if markers_found:
        first_t = markers_found[0][0]
        for t, name in markers_found:
            delta = t - first_t
            print(f"  {name:25s}  T+{delta:7.3f}s")

        # Calculate key durations
        times = {name: t for t, name in markers_found}
        print()
        if "DDR_CAL_START" in times and "DDR_CAL_DONE" in times:
            d = times["DDR_CAL_DONE"] - times["DDR_CAL_START"]
            print(f"  DDR3 calibration:     {d:.3f}s")
        if "UBOOT_BANNER" in times and "APP_HANDOFF" in times:
            d = times["APP_HANDOFF"] - times["UBOOT_BANNER"]
            print(f"  U-Boot total:         {d:.3f}s")
        if "ESC_PROMPT" in times and "MULTIBOOT_LISTEN" in times:
            d = times["MULTIBOOT_LISTEN"] - times["ESC_PROMPT"]
            print(f"  ESC window:           {d:.3f}s")
        if "MULTIBOOT_LISTEN" in times:
            # Find when the countdown ended
            listen_end = None
            for t, name in markers_found:
                if name == "APP_HANDOFF" and t > times["MULTIBOOT_LISTEN"]:
                    listen_end = t
                    break
            if listen_end:
                d = listen_end - times["MULTIBOOT_LISTEN"]
                print(f"  Multiboot window:     {d:.3f}s")
        if "APP_HANDOFF" in times:
            total = times["APP_HANDOFF"]
            print(f"  Bootloader total:     {total:.3f}s")
        if "KERNEL_LINUX" in times:
            print(f"  Kernel boot start:    T+{times['KERNEL_LINUX']:.3f}s")
    else:
        print("  No boot markers detected.")

    total_data = len(raw_data)
    total_time = last_data_time - first_byte_time if first_byte_time else 0
    print(f"\n  Total data:           {total_data:,} bytes")
    print(f"  Total duration:       {total_time:.3f}s")
    if esc_sent:
        print(f"  ESC sent:             YES (autoboot interrupted)")
    print(f"  Log files:            serial/{session}/")
    print("=" * 60)

    return markers_found


def main():
    parser = argparse.ArgumentParser(
        description="Serial boot capture — power-cycle-when-ready workflow"
    )
    parser.add_argument("port", nargs="?", default="/dev/cu.usbserial-BG02QAPG",
                        help="Serial port (default: from diagnose)")
    parser.add_argument("baud", nargs="?", type=int, default=57600,
                        help="Baud rate (default: 57600)")
    parser.add_argument("--session", default="boot-capture",
                        help="Session name for log directory")
    parser.add_argument("--esc", action="store_true",
                        help="Send ESC to interrupt autoboot")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Seconds of silence before stopping (default: 15)")
    parser.add_argument("--max-wait", type=int, default=0,
                        help="Max seconds to wait for first byte (0=unlimited)")
    parser.add_argument("--send-cr", action="store_true",
                        help="Send CR after capture to check for shell prompt")
    args = parser.parse_args()

    result = capture_boot(
        port=args.port,
        baud=args.baud,
        session=args.session,
        send_esc=args.esc,
        silence_timeout=args.timeout,
        max_wait=args.max_wait,
        send_cr=args.send_cr,
    )

    sys.exit(0 if result is not None else 1)


if __name__ == "__main__":
    main()
