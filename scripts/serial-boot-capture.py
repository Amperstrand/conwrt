#!/usr/bin/env python3
"""Serial boot capture with power-transition recovery.

Detects the UART break condition (0x00 byte) from PoE power-off,
closes the serial port, waits for the device to boot, then reopens
fresh and captures the boot sequence.

This fixes the issue where the FT232R adapter gets stuck after
a break condition and stops delivering data.

Usage:
    python3 scripts/serial-boot-capture2.py [PORT] [BAUD] [OPTIONS]

Options:
    --session NAME     Session name for log directory
    --timeout SECS     Silence timeout after boot data starts
    --recovery-wait S  Seconds to wait after break before reopening (default: 3)
"""
import argparse
import serial
import sys
import time
from pathlib import Path

BOOT_MARKERS = [
    ("DDR3_CAL_START",   b"do DDR setting"),
    ("DDR3_CAL_DONE",    b"calibration passed"),
    ("UBOOT_BANNER",     b"U-Boot 1.1.3"),
    ("ZLOADER_BANNER",   b"Z-LOADER"),
    ("ESC_PROMPT",       b"Hit ESC key"),
    ("MULTIBOOT_LISTEN", b"Multiboot Listening"),
    ("APP_HANDOFF",      b"Starting application"),
    ("KERNEL_LINUX",     b"Linux version"),
    ("KERNEL_STARTING",  b"Starting kernel"),
    ("OPENWRT_BANNER",   b"OpenWrt"),
    ("BUSYBOX_INIT",     b"Starting init"),
    ("DROPBEAR_START",   b"dropbear"),
    ("SHELL_PROMPT",     b"root@"),
    ("KERNEL_PANIC",     b"Kernel panic"),
    ("BAD_CRC",          b"bad CRC"),
]


def wait_for_break(port, baud, max_wait=0):
    """Phase 1: Wait for the power-off break byte."""
    s = serial.Serial(port, baud, timeout=0.5)
    print("Phase 1: Waiting for power cycle (break byte)...")
    print(">>> POWER CYCLE THE DEVICE NOW <<<")
    start = time.time()
    while True:
        chunk = s.read(1)
        if chunk:
            if chunk == b'\x00' or chunk == b'\xff':
                t = time.time() - start
                print(f"\n✓ Break detected at T+{t:.1f}s — power transition!")
                s.close()
                return time.time()
            else:
                # Got real data without break — device was already booting
                t = time.time() - start
                print(f"\n✓ Boot data at T+{t:.1f}s (no break — device already on)")
                return s, chunk  # Return port and first byte
        if max_wait > 0 and (time.time() - start) > max_wait:
            print(f"\nTimeout after {max_wait}s")
            s.close()
            return None
        elapsed = int(time.time() - start)
        if elapsed > 0 and elapsed % 10 == 0:
            print(f"\r  Waiting... {elapsed}s", end="", flush=True)


def capture_boot(port, baud, log_dir, silence_timeout, recovery_wait, existing_port=None, first_byte=None):
    """Phase 2: Capture boot sequence with timestamps."""
    if existing_port:
        s = existing_port
    else:
        # Reopen serial port fresh — resets FT232R internal state
        time.sleep(recovery_wait)
        print(f"Reopening serial port (after {recovery_wait}s recovery wait)...")
        s = serial.Serial(port, baud, timeout=0.5)
        s.reset_input_buffer()  # Clear any stale data
        print("✓ Port reopened, buffers flushed")

    log_dir.mkdir(parents=True, exist_ok=True)
    raw_file = log_dir / "console.raw"
    console_log = log_dir / "console.log"

    start = time.time()
    raw_data = bytearray()
    markers_found = []
    last_data_time = start

    if first_byte:
        raw_data.extend(first_byte)
        last_data_time = time.time()

    print("\nCapturing boot sequence...\n")

    while True:
        chunk = s.read(4096)
        now = time.time()

        if chunk:
            t_rel = now - start
            last_data_time = now
            raw_data.extend(chunk)

            # Check markers
            for name, pattern in BOOT_MARKERS:
                if pattern in chunk and name not in [m[1] for m in markers_found]:
                    markers_found.append((t_rel, name))
                    print(f"  [{t_rel:7.3f}s] >>> {name}")

            # Print lines
            text = chunk.decode("ascii", errors="replace")
            for line in text.split('\n'):
                line = line.strip()
                if line and len(line) > 1 and not line.startswith('000'):
                    print(f"  [{t_rel:7.3f}s] {line[:150]}")

            # Write to files
            with open(raw_file, "ab") as f:
                f.write(chunk)
            with open(console_log, "a") as f:
                f.write(text)
                f.flush()

        # Silence timeout
        if now - last_data_time > silence_timeout:
            print(f"\n  {silence_timeout}s silence — capture complete")
            break

    s.close()

    # Print timing report
    print("\n" + "=" * 60)
    print("BOOT TIMING REPORT")
    print("=" * 60)
    if markers_found:
        first_t = markers_found[0][0]
        for t, name in markers_found:
            delta = t - first_t
            print(f"  {name:25s}  T+{delta:7.3f}s")

        times = {name: t for t, name in markers_found}
        print()
        for a, b in [("DDR3_CAL_START", "DDR3_CAL_DONE"),
                      ("UBOOT_BANNER", "APP_HANDOFF"),
                      ("ESC_PROMPT", "MULTIBOOT_LISTEN")]:
            if a in times and b in times:
                d = times[b] - times[a]
                print(f"  {a} → {b}: {d:.3f}s")
    else:
        print("  No boot markers detected.")
    print(f"\n  Total data: {len(raw_data):,} bytes")
    print("=" * 60)

    return markers_found


def main():
    parser = argparse.ArgumentParser(description="Serial boot capture with power-transition recovery")
    parser.add_argument("port", nargs="?", default="/dev/cu.usbserial-BG02QAPG")
    parser.add_argument("baud", nargs="?", type=int, default=57600)
    parser.add_argument("--session", default="boot-capture")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--recovery-wait", type=float, default=3.0)
    parser.add_argument("--max-wait", type=int, default=0)
    args = parser.parse_args()

    log_dir = Path("serial") / args.session

    # Phase 1: Wait for power transition
    result = wait_for_break(args.port, args.baud, args.max_wait)
    if result is None:
        sys.exit(1)

    # Phase 2: Capture boot
    if isinstance(result, tuple):
        # Got data without break — device already on
        existing_port, first_byte = result
        capture_boot(args.port, args.baud, log_dir, args.timeout,
                     args.recovery_wait, existing_port, first_byte)
    else:
        # Break detected — close, wait, reopen
        capture_boot(args.port, args.baud, log_dir, args.timeout,
                     args.recovery_wait)


if __name__ == "__main__":
    main()
