#!/usr/bin/env python3
"""Provision a USB disk for the MAAS portable lab use case.

Handles: image verification, disk flashing with serial-whitelist safety,
partition resizing, and cloud-init injection. Designed to run on any
Linux host with the USB disk attached.

Usage:
    maas_flash.py --disk /dev/sdX --image image.img.xz \\
        --expected-sha256 <publisher-sha256-of-the-image-file> \\
        --user-data user-data.yaml --network-config netcfg.yaml

Safety:
    - Verifies the image file digest against the publisher-supplied
      expected sha256 BEFORE any write (archive checksum, then
      decompress — same gate as the Rust flash path, #393)
    - Requires a non-empty USB serial whitelist matching the live disk
    - Checks disk size, read-only status, and mount state
    - Never writes to a disk that doesn't pass ALL guards
"""

from __future__ import annotations

import argparse
import hashlib
import shlex
import subprocess
import sys
import time
from pathlib import Path

# Module-level so tests can point it at a fake sysfs tree.
SYS_BLOCK = Path("/sys/block")
# Module-level so tests can redirect the cloud-injection mount point.
MOUNT_POINT = "/tmp/maas-flash-boot"


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, returning the result."""
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def get_disk_info(dev: str) -> dict[str, str]:
    """Get transport, serial, size, ro status for a disk.

    ``-b`` makes lsblk print SIZE in bytes; without it standard
    util-linux prints human-readable values ("32G") that cannot be
    int()-parsed.
    """
    info = {}
    for prop in ["TRAN", "SERIAL", "SIZE", "RO", "MODEL"]:
        r = run(["lsblk", "-d", "-n", "-b", "-o", prop, dev])
        info[prop.lower()] = r.stdout.strip()
    return info


def resolve_size_bytes(info: dict[str, str], dev: str) -> int:
    """Disk size in bytes: lsblk -b output, with sysfs fallback.

    Tolerates human-readable SIZE output from lsblk versions/flags that
    ignore ``-b``: an unparseable value falls through to
    ``/sys/block/<dev>/size`` (512-byte sectors) instead of raising.
    """
    raw = info.get("size", "0").replace(",", "")
    try:
        return int(raw)
    except ValueError:
        pass
    sysfs = SYS_BLOCK / dev.split("/")[-1] / "size"
    if sysfs.exists():
        try:
            return int(sysfs.read_text().strip()) * 512
        except ValueError:
            return 0
    return 0


def verify_disk(dev: str, whitelist: list[str] | None = None) -> tuple[bool, str]:
    """Verify a disk is safe to write to. Returns (ok, message)."""
    info = get_disk_info(dev)

    if info.get("tran") != "usb":
        return False, f"ABORT: {dev} is {info.get('tran', 'unknown')}, not USB"

    if whitelist:
        serial = info.get("serial", "")
        if serial not in whitelist:
            return False, f"ABORT: serial {serial!r} not in whitelist {whitelist}"

    size_bytes = resolve_size_bytes(info, dev)
    if size_bytes < 30 * 10**9:
        return False, f"ABORT: {dev} too small ({size_bytes / 10**9:.0f}GB, need ≥30GB)"

    ro_path = SYS_BLOCK / dev.split("/")[-1] / "ro"
    if ro_path.exists() and ro_path.read_text().strip() == "1":
        return False, f"ABORT: {dev} is read-only"

    r = run(["lsblk", "-no", "MOUNTPOINTS", dev])
    if r.stdout.strip():
        return False, f"ABORT: {dev} has mounted filesystems: {r.stdout.strip()}"

    return True, f"verified: {dev} usb serial={info.get('serial')} {size_bytes / 10**9:.0f}GB rw"


def sha256_file(path: str, chunk_mb: int = 256) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_mb * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_device_offset(dev: str, offset_bytes: int, length_bytes: int) -> str:
    """Compute SHA-256 of a byte range on a block device (or file)."""
    h = hashlib.sha256()
    with open(dev, "rb") as f:
        f.seek(max(offset_bytes, 0))
        remaining = length_bytes
        while remaining > 0:
            chunk = f.read(min(256 * 1024 * 1024, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
    return h.hexdigest()


def _pipeline_sha256(script: str) -> str | None:
    """sha256 of a bash pipeline's stdout, or None when it fails."""
    r = run(["bash", "-c", script])
    parts = r.stdout.split()
    if r.returncode != 0 or not parts:
        return None
    return parts[0]


def flash_and_provision(args: argparse.Namespace) -> int:
    """Main flash + provision pipeline."""
    disk = args.disk
    image = Path(args.image).expanduser().resolve()

    if not image.exists():
        print(f"error: image not found: {image}", file=sys.stderr)
        return 1

    # Image authenticity gate: the expected digest comes from the
    # publisher (out of band) and is required — checking the disk
    # against an unverified image file proves nothing about intent.
    expected = (args.expected_sha256 or "").strip().lower()
    if not expected:
        print(
            "error: --expected-sha256 is required: verify the downloaded image "
            "against the publisher's checksum before any disk write",
            file=sys.stderr,
        )
        return 1
    print("checksumming image...")
    actual = sha256_file(str(image))
    if actual != expected:
        print(
            f"error: image sha256 mismatch: expected {expected}, got {actual}",
            file=sys.stderr,
        )
        return 1
    print("verify: image sha256 MATCH")

    # Serial whitelist gate: never flash an unenumerated disk.
    whitelist = (
        [s.strip() for s in args.serial_whitelist.split(",") if s.strip()]
        if args.serial_whitelist
        else []
    )
    if not whitelist:
        print(
            "error: --serial-whitelist is required (comma-separated USB serials); "
            "refusing to flash without a non-empty whitelist",
            file=sys.stderr,
        )
        return 1

    # Safety checks
    ok, msg = verify_disk(disk, whitelist)
    print(msg)
    if not ok:
        return 1

    # Decompressed image size (for verification offsets)
    img_size_known = True
    if image.suffix == ".xz":
        print("decompressing image for size info...")
        r = run(["xz", "--list", "--robot", str(image)])
        img_size = 5 * 10**9  # fallback
        for line in r.stdout.splitlines():
            if line.startswith("file\t"):
                parts = line.split("\t")
                if len(parts) > 4:
                    img_size = int(parts[4])
                    break
        else:
            img_size_known = False
        # Stream the decompressed image to the disk: never buffer a
        # multi-GB image in RAM, and abort (not half-provision) when
        # xzcat reports a truncated or corrupt archive.
        print(f"flashing {img_size / 10**9:.1f}GB to {disk}...")
        try:
            with open(disk, "wb") as dst:
                subprocess.run(["xzcat", str(image)], stdout=dst, check=True)
        except subprocess.CalledProcessError as e:
            print(
                f"error: image decompression failed (xzcat rc={e.returncode}); "
                f"{disk} is NOT provisioned",
                file=sys.stderr,
            )
            return 1
        subprocess.run(["sync"])
    else:
        img_size = image.stat().st_size
        print(f"flashing {img_size / 10**9:.1f}GB to {disk}...")
        with open(image, "rb") as src, open(disk, "wb") as dst:
            while True:
                chunk = src.read(4 * 1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
            dst.flush()
            subprocess.run(["sync"])

    # Reread partition table
    run(["partprobe", disk])
    time.sleep(3)

    # Verify: first 256MB + last 256MB of the written image
    print("verifying written data...")
    verify_len = 256 * 1024 * 1024

    disk_first = sha256_device_offset(disk, 0, verify_len)
    disk_last = sha256_device_offset(disk, img_size - verify_len, verify_len)

    if image.suffix == ".xz":
        # Compare against decompressed stream at matching offsets
        qimg = shlex.quote(str(image))
        img_first = _pipeline_sha256(
            f"xzcat {qimg} | head -c {verify_len} | sha256sum"
        )
        img_last = (
            _pipeline_sha256(f"xzcat {qimg} | tail -c {verify_len} | sha256sum")
            if img_size_known
            else None
        )
        if img_last is None:
            print(
                "warning: image size/tail not verifiable; checking first chunk only",
                file=sys.stderr,
            )
    else:
        h = hashlib.sha256()
        with open(image, "rb") as f:
            h.update(f.read(verify_len))
        img_first = h.hexdigest()
        h = hashlib.sha256()
        with open(image, "rb") as f:
            f.seek(max(0, img_size - verify_len))
            h.update(f.read(verify_len))
        img_last = h.hexdigest()

    if disk_first != img_first:
        print("VERIFY FAILED: first 256MB mismatch")
        print(f"  disk: {disk_first}")
        print(f"  image: {img_first}")
        return 1
    print("verify: first 256MB MATCH")

    if img_last is not None and disk_last != img_last:
        print("VERIFY FAILED: last 256MB mismatch (truncated write?)")
        print(f"  disk: {disk_last}")
        print(f"  image: {img_last}")
        return 1
    if img_last is not None:
        print("verify: last 256MB MATCH")

    # Resize partition if requested
    if args.partition_size:
        part_num = "2"  # Ubuntu raspi images use partition 2 for root
        print(f"resizing partition {part_num} to {args.partition_size}...")
        r = run(
            [
                "bash",
                "-c",
                f"echo {shlex.quote(',' + args.partition_size)} "
                f"| sfdisk -N {part_num} {shlex.quote(disk)}",
            ]
        )
        if r.returncode != 0:
            print(
                f"error: sfdisk resize failed (rc={r.returncode}): {r.stderr}",
                file=sys.stderr,
            )
            return 1
        run(["partprobe", disk])
        time.sleep(2)
        r = run(["e2fsck", "-fy", f"{disk}{part_num}"])
        # e2fsck rc 0 = clean, rc 1 = errors corrected; >=2 = real failure
        if r.returncode not in (0, 1):
            print(
                f"error: e2fsck failed (rc={r.returncode}): {r.stderr}",
                file=sys.stderr,
            )
            return 1
        r = run(["resize2fs", f"{disk}{part_num}"])
        if r.returncode != 0:
            print(
                f"error: resize2fs failed (rc={r.returncode}): {r.stderr}",
                file=sys.stderr,
            )
            return 1
        r = run(["tune2fs", "-l", f"{disk}{part_num}"])
        for line in r.stdout.splitlines():
            if "Block count" in line:
                print(f"filesystem: {line.strip()}")
                break

    # Inject cloud-init files
    boot_part = f"{disk}1"
    print("injecting cloud-init files...")
    run(["mkdir", "-p", MOUNT_POINT])
    r = run(["mount", boot_part, MOUNT_POINT])
    if r.returncode != 0:
        print(f"error: cannot mount {boot_part}: {r.stderr}", file=sys.stderr)
        return 1

    injected = 0
    if args.user_data:
        r = run(["cp", args.user_data, f"{MOUNT_POINT}/user-data"])
        if r.returncode != 0:
            print(
                f"error: copying user-data failed: {r.stderr}", file=sys.stderr
            )
            run(["umount", MOUNT_POINT])
            return 1
        injected += 1
    if args.network_config:
        r = run(["cp", args.network_config, f"{MOUNT_POINT}/network-config"])
        if r.returncode != 0:
            print(
                f"error: copying network-config failed: {r.stderr}",
                file=sys.stderr,
            )
            run(["umount", MOUNT_POINT])
            return 1
        injected += 1

    # Always write meta-data
    meta = f"instance-id: maas-lab-{int(time.time())}\nlocal-hostname: maas\n"
    with open(f"{MOUNT_POINT}/meta-data", "w") as f:
        f.write(meta)
    injected += 1

    subprocess.run(["sync"])
    run(["umount", MOUNT_POINT])

    print(f"injected: {injected} files")
    print("=== USB DISK READY ===")
    print(f"Move to the Pi's blue USB 3.0 port and power on.")
    print(f"First boot: ~15 min (snap install + MAAS init)")
    beacon = f" on {args.beacon_ip}" if args.beacon_ip else ""
    print(f"Watch beacons: udp/6667{beacon}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--disk", required=True, help="target block device (e.g. /dev/sdc)")
    p.add_argument("--image", required=True, help="path to .img or .img.xz")
    p.add_argument(
        "--expected-sha256",
        required=True,
        help="publisher's sha256 of the IMAGE FILE (for .xz: of the archive itself)",
    )
    p.add_argument("--user-data", help="path to cloud-init user-data")
    p.add_argument("--network-config", help="path to netplan config")
    p.add_argument("--partition-size", default="50G",
                   help="root partition size (default: 50G for fast fsck)")
    p.add_argument("--serial-whitelist",
                   help="comma-separated list of allowed USB serial numbers (required)")
    p.add_argument("--beacon-ip",
                   help="IP for boot progress beacons (operator-specific)")
    args = p.parse_args()
    return flash_and_provision(args)


if __name__ == "__main__":
    sys.exit(main())
