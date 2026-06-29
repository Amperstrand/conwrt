#!/usr/bin/env python3
"""Transfer firmware to a device over serial using base64 encoding.

Works with any OpenWrt serial console — no special protocol support needed.
Splits the image into base64 chunks, sends each as an echo append, then
decodes on the device.

Usage:
    python3 scripts/serial-flash.py PORT BAUD --base64 IMAGE_PATH [OPTIONS]

Options:
    --chunk-size BYTES  Raw bytes per serial line (default: 512)
    --delay SECONDS     Delay between chunks (default: 0.15)
    --verify            Verify file size after transfer
    --sysupgrade        Run sysupgrade -n after successful transfer
    --dry-run           Show plan without sending

Examples:
    # Transfer and verify
    python3 scripts/serial-flash.py /dev/cu.usbserial-XXXX 57600 \
        --base64 images/firmware.bin --verify

    # Transfer, verify, and flash
    python3 scripts/serial-flash.py /dev/cu.usbserial-XXXX 57600 \
        --base64 images/firmware.bin --verify --sysupgrade
"""
import argparse
import base64
import math
import serial
import sys
import time
from pathlib import Path


def send_and_wait(s: serial.Serial, command: str, wait: float = 1.0) -> str:
    """Send command and read response."""
    s.write((command + "\r\n").encode())
    time.sleep(wait)
    resp = b""
    end = time.time() + 0.5
    while time.time() < end:
        if s.in_waiting:
            resp += s.read(4096)
            time.sleep(0.05)
        else:
            time.sleep(0.05)
    return resp.decode("ascii", errors="replace")


def transfer_base64(s: serial.Serial, image_path: str, chunk_size: int,
                    delay: float, dry_run: bool = False) -> bool:
    """Transfer firmware image via base64 encoding over serial."""
    with open(image_path, "rb") as f:
        data = f.read()

    total = len(data)
    chunks = math.ceil(total / chunk_size)
    est_time = chunks * delay

    print(f"Image: {image_path}")
    print(f"  Size: {total:,} bytes ({total / 1024 / 1024:.1f} MB)")
    print(f"  Chunks: {chunks} (at {chunk_size} bytes/chunk)")
    print(f"  Estimated time: {est_time / 60:.1f} minutes at {delay}s/chunk")
    print()

    if dry_run:
        print("[DRY RUN] Would send {} chunks".format(chunks))
        return True

    # Break to clean prompt
    s.write(b"\x03\r\n")
    time.sleep(1)
    s.read(4096)

    # Clear any existing file
    print("Clearing /tmp/fw.b64 on device...")
    send_and_wait(s, "rm -f /tmp/fw.b64", wait=0.5)

    # Transfer chunks
    print("Transferring...")
    start = time.time()
    offset = 0
    chunk_num = 0

    while offset < total:
        chunk = data[offset:offset + chunk_size]
        b64 = base64.b64encode(chunk).decode()
        s.write(f"echo '{b64}' >> /tmp/fw.b64\r\n".encode())
        time.sleep(delay)
        s.read(4096)  # drain echo

        offset += chunk_size
        chunk_num += 1

        if chunk_num % 50 == 0 or offset >= total:
            elapsed = time.time() - start
            pct = min(offset / total * 100, 100)
            rate = chunk_num / elapsed if elapsed > 0 else 0
            remaining = (chunks - chunk_num) / rate if rate > 0 else 0
            print(f"  {min(offset, total):,}/{total:,} bytes ({pct:.1f}%) "
                  f"— {elapsed:.0f}s elapsed, ~{remaining:.0f}s remaining",
                  flush=True)

    elapsed = time.time() - start
    print(f"\nTransfer complete: {chunk_num} chunks in {elapsed:.0f}s "
          f"({elapsed / 60:.1f} min)")

    # Decode on device
    print("Decoding base64 on device...")
    send_and_wait(s, "base64 -d /tmp/fw.b64 > /tmp/fw.bin", wait=5)

    return True


def verify_size(s: serial.Serial, expected_size: int) -> bool:
    """Verify the transferred file size matches."""
    print("Verifying file size...")
    resp = send_and_wait(s, "wc -c /tmp/fw.bin", wait=2)
    print(f"  Device reports: {resp.strip()}")

    # Parse size from response
    for line in resp.split("\n"):
        line = line.strip()
        if "/tmp/fw.bin" in line:
            parts = line.split()
            if parts:
                actual = int(parts[0])
                if actual == expected_size:
                    print(f"  ✓ Size matches: {actual:,} bytes")
                    return True
                else:
                    print(f"  ✗ SIZE MISMATCH: expected {expected_size:,}, "
                          f"got {actual:,}")
                    return False

    print("  ⚠ Could not parse size from response")
    return False


def run_sysupgrade(s: serial.Serial) -> None:
    """Run sysupgrade on the device."""
    print("Running sysupgrade -n /tmp/fw.bin...")
    print("  (device will reboot after flashing — watch serial for boot log)")
    s.write(b"sysupgrade -n /tmp/fw.bin\r\n")
    # Don't wait — sysupgrade takes a while and reboots


def main():
    parser = argparse.ArgumentParser(
        description="Transfer firmware to device over serial via base64"
    )
    parser.add_argument("port", help="Serial port (e.g., /dev/cu.usbserial-XXXX)")
    parser.add_argument("baud", type=int, help="Baud rate (e.g., 57600)")
    parser.add_argument("--base64", metavar="IMAGE",
                        help="Transfer image via base64 encoding")
    parser.add_argument("--chunk-size", type=int, default=512,
                        help="Raw bytes per serial line (default: 512)")
    parser.add_argument("--delay", type=float, default=0.15,
                        help="Delay between chunks in seconds (default: 0.15)")
    parser.add_argument("--verify", action="store_true",
                        help="Verify file size after transfer")
    parser.add_argument("--sysupgrade", action="store_true",
                        help="Run sysupgrade -n after successful transfer")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show plan without sending")
    args = parser.parse_args()

    if not args.base64:
        parser.error("--base64 IMAGE is required")

    image_path = Path(args.base64)
    if not image_path.exists():
        print(f"ERROR: Image not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    expected_size = image_path.stat().st_size

    if args.dry_run:
        s = None
    else:
        s = serial.Serial(args.port, args.baud, timeout=1)

    try:
        # Transfer
        success = transfer_base64(
            s or _DummySerial(), str(image_path),
            args.chunk_size, args.delay, args.dry_run
        )

        if not success or args.dry_run:
            return

        # Verify
        if args.verify:
            if not verify_size(s, expected_size):
                print("Transfer verification FAILED — aborting", file=sys.stderr)
                sys.exit(1)

        # Sysupgrade
        if args.sysupgrade:
            run_sysupgrade(s)
        else:
            print("\nImage transferred to /tmp/fw.bin on device.")
            print("Run 'sysupgrade -n /tmp/fw.bin' to flash.")

    finally:
        if s:
            s.close()


class _DummySerial:
    """Mock serial for dry-run mode."""
    def write(self, data):
        pass

    def read(self, size):
        return b""

    @property
    def in_waiting(self):
        return 0

    def close(self):
        pass


if __name__ == "__main__":
    main()
