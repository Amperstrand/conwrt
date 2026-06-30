#!/usr/bin/env python3
"""Dump device partitions over serial when SSH is unavailable.

Reads flash partitions via serial console using base64 encoding:
  cat /dev/mtdX | base64
Captures the base64 output and decodes it on the host.

Usage:
    python3 scripts/serial-backup.py PORT BAUD [OPTIONS]

Options:
    --partition NAME    Dump specific partition (e.g., Factory, Kernel)
    --all               Dump all partitions listed in /proc/mtd
    --output-dir DIR    Output directory (default: ./backups/serial)
    --list              List partitions and exit

Examples:
    # List partitions
    python3 scripts/serial-backup.py /dev/cu.usbserial-XXXX 57600 --list

    # Backup Factory partition (irreplaceable)
    python3 scripts/serial-backup.py /dev/cu.usbserial-XXXX 57600 --partition Factory

    # Backup all partitions (takes a long time)
    python3 scripts/serial-backup.py /dev/cu.usbserial-XXXX 57600 --all
"""
import argparse
import base64
import re
import serial
import sys
import time
from pathlib import Path


def send_and_wait(s: serial.Serial, command: str, wait: float = 2.0) -> str:
    """Send command and read response."""
    s.write((command + "\r\n").encode())
    time.sleep(wait)
    resp = b""
    end = time.time() + 1.0
    while time.time() < end:
        if s.in_waiting:
            resp += s.read(8192)
            time.sleep(0.1)
        else:
            time.sleep(0.1)
    return resp.decode("ascii", errors="replace")


def parse_partitions(output: str) -> list[dict]:
    """Parse /proc/mtd output into partition list."""
    partitions = []
    for line in output.split("\n"):
        m = re.match(r'(mtd\d+):\s+([0-9a-f]+)\s+[0-9a-f]+\s+"([^"]+)"', line.strip())
        if m:
            partitions.append({
                "device": m.group(1),
                "size": int(m.group(2), 16),
                "name": m.group(3),
            })
    return partitions


def dump_partition(s: serial.Serial, partition: dict, output_file: Path) -> bool:
    """Dump a single partition via base64 over serial."""
    dev = f"/dev/{partition['device']}"
    name = partition["name"]
    size = partition["size"]

    print(f"Dumping {name} ({dev}, {size:,} bytes / {size / 1024:.0f}KB)...")
    est_lines = size / 48  # base64 encodes 3 bytes per 4 chars, ~48 bytes/line
    est_time = est_lines * 0.05  # ~50ms per line at 57600 baud
    print(f"  Estimated time: {est_time:.0f}s ({est_time / 60:.1f} min)")

    # Send the dump command
    s.write(f"cat {dev} | base64\r\n".encode())

    # Capture base64 output — read until we see the shell prompt again
    b64_data = ""
    start = time.time()
    timeout = max(30, est_time * 3)  # 3x estimated time as timeout

    while time.time() - start < timeout:
        chunk = s.read(8192)
        if chunk:
            text = chunk.decode("ascii", errors="replace")
            for line in text.split("\n"):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("root@") or line.startswith("#"):
                    # Shell prompt — end of output
                    continue
                if "cat " in line and "base64" in line:
                    # Echo of the command
                    continue
                # Check if it looks like base64
                if re.match(r'^[A-Za-z0-9+/=]+$', line):
                    b64_data += line

                    # Progress update
                    decoded_size = len(b64_data) * 3 // 4
                    if decoded_size % (16 * 1024) < 48:  # every ~16KB
                        pct = decoded_size / size * 100
                        elapsed = time.time() - start
                        print(f"  {decoded_size:,}/{size:,} bytes ({pct:.1f}%) "
                              f"— {elapsed:.0f}s", flush=True)

            # Check if we've received enough data
            decoded_size = len(b64_data) * 3 // 4
            if decoded_size >= size:
                break
        else:
            time.sleep(0.1)

    if not b64_data:
        print("  ✗ No data received")
        return False

    # Decode base64
    try:
        raw_data = base64.b64decode(b64_data)
    except Exception as e:
        print(f"  ✗ Base64 decode error: {e}")
        return False

    # Verify size
    if len(raw_data) != size:
        print(f"  ⚠ Size mismatch: expected {size:,}, got {len(raw_data):,}")
        if len(raw_data) < size * 0.95:
            print("  ✗ Dump appears incomplete (less than 95% of expected size)")
            return False

    # Write to file
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "wb") as f:
        f.write(raw_data)

    elapsed = time.time() - start
    print(f"  ✓ Dumped {len(raw_data):,} bytes in {elapsed:.0f}s → {output_file}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Dump device partitions over serial via base64"
    )
    parser.add_argument("port", help="Serial port")
    parser.add_argument("baud", type=int, help="Baud rate")
    parser.add_argument("--partition", metavar="NAME",
                        help="Dump specific partition by name (e.g., Factory)")
    parser.add_argument("--all", action="store_true",
                        help="Dump all partitions")
    parser.add_argument("--output-dir", default="./backups/serial",
                        help="Output directory (default: ./backups/serial)")
    parser.add_argument("--list", action="store_true",
                        help="List partitions and exit")
    args = parser.parse_args()

    s = serial.Serial(args.port, args.baud, timeout=1)

    # Break to clean prompt
    s.write(b"\x03\r\n")
    time.sleep(1)
    s.read(4096)

    # Get partition list
    print("Reading partition table...")
    output = send_and_wait(s, "cat /proc/mtd", wait=2)
    partitions = parse_partitions(output)

    if not partitions:
        print("ERROR: Could not parse /proc/mtd", file=sys.stderr)
        print(f"Raw output: {output}")
        sys.exit(1)

    print(f"\nFound {len(partitions)} partitions:")
    for p in partitions:
        irreplaceable = " (IRREPLACEABLE)" if p["name"] == "Factory" else ""
        print(f"  {p['device']}: {p['name']:12s} {p['size']:>10,} bytes "
              f"({p['size'] / 1024:.0f}KB){irreplaceable}")

    if args.list:
        s.close()
        return

    output_dir = Path(args.output_dir)

    if args.partition:
        targets = [p for p in partitions if p["name"].lower() == args.partition.lower()]
        if not targets:
            print(f"ERROR: Partition '{args.partition}' not found", file=sys.stderr)
            sys.exit(1)
    elif args.all:
        targets = partitions
    else:
        # Default: dump Factory only (most critical)
        targets = [p for p in partitions if p["name"] == "Factory"]
        if not targets:
            print("No Factory partition found. Use --partition or --all.")
            sys.exit(1)
        print("\nDefaulting to Factory partition (use --all for everything)")

    print(f"\nDumping {len(targets)} partition(s) to {output_dir}/...")

    success_count = 0
    for p in targets:
        output_file = output_dir / f"{p['name'].lower()}.bin"
        print()
        if dump_partition(s, p, output_file):
            success_count += 1

    print(f"\n{'=' * 50}")
    print(f"Backup complete: {success_count}/{len(targets)} partitions dumped")
    print(f"Files in: {output_dir}/")

    s.close()


if __name__ == "__main__":
    main()
