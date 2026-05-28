#!/usr/bin/env python3
"""Wrap an OpenWrt FIT image in an ASUS U-Boot legacy header for Lyra MAP-AC2200.

The stock firmware format is:
  - 64-byte U-Boot legacy image header (magic 0x27051956)
  - FIT image payload (starts with 0xD00DFEED)

The bootloader validates only:
  - Magic number (0x27051956)
  - Header CRC32 (ih_hcrc)
  - Data CRC32 (ih_dcrc)
  - No RSA signatures, no hash16 check on this device

This tool reads a FIT image (e.g., openwrt-*-initramfs-uImage.itb) and prepends
a valid U-Boot header with ASUS product metadata, producing a factory-compatible
image that the bootloader should accept via rescue mode or ASUS Firmware Restore.

Usage:
    python3 asus-uimage-wrap.py -i initramfs.itb -o factory.trx

Based on reverse engineering of stock firmware MAP-AC2200_3.0.0.4_384_46630
and asusuimage.c from openwrt/firmware-utils.
"""

import argparse
import struct
import zlib
import sys

# U-Boot constants
IH_MAGIC = 0x27051956
IH_OS_LINUX = 5
IH_ARCH_ARM = 2
IH_ARCH_ARM64 = 22
IH_TYPE_KERNEL = 2
IH_COMP_NONE = 0
IH_COMP_LZMA = 3  # Stock Lyra firmware uses 3 (LZMA), bootloader handles it

# Stock firmware field values (from MAP-AC2200_3.0.0.4_384_46630)
STOCK_LOAD_ADDR = 0x80208000
STOCK_ENTRY_POINT = 0x80208000
STOCK_KERNEL_VER = (3, 0)  # firmware major.minor
STOCK_FS_VER = (0, 4)      # firmware minor version
STOCK_PRODUCT = "MAP-AC2200"

# trx2 tail fields from stock firmware
STOCK_SN = 0x8001        # build number (uint16 BE)
STOCK_EN = 0x26B6        # extended build number (uint16 BE)
STOCK_FS_PREFIX = 0xA9   # fs_offset prefix byte
STOCK_FS_OFFSET = (0x22, 0x5A, 0x41)  # 24-bit BE fs_offset


def crc32(data: bytes) -> int:
    """Compute CRC32 matching zlib/binascii (unsigned)."""
    return zlib.crc32(data) & 0xFFFFFFFF


def build_header(data: bytes, product: str = STOCK_PRODUCT,
                 kernel_ver: tuple = STOCK_KERNEL_VER,
                 fs_ver: tuple = STOCK_FS_VER,
                 load_addr: int = STOCK_LOAD_ADDR,
                 entry_point: int = STOCK_ENTRY_POINT,
                 comp: int = IH_COMP_LZMA) -> bytes:
    """Build a 64-byte U-Boot legacy image header with ASUS product metadata.

    Header layout (64 bytes, packed):
      Offset  Size  Field
      0x00    4     ih_magic     (0x27051956)
      0x04    4     ih_hcrc      (header CRC32, computed last)
      0x08    4     ih_time      (timestamp)
      0x0C    4     ih_size      (data size)
      0x10    4     ih_load      (load address)
      0x14    4     ih_ep        (entry point)
      0x18    4     ih_dcrc      (data CRC32)
      0x1C    1     ih_os        (5 = Linux)
      0x1D    1     ih_arch      (2 = ARM)
      0x1E    1     ih_type      (2 = Kernel)
      0x1F    1     ih_comp      (3 = LZMA, matches stock)
      0x20    2     kernel_ver   (major, minor)
      0x22    2     fs_ver       (major, minor)
      0x24   28     trx2 tail    (product metadata)
    """
    # Build the ih_name field: kernel_ver(2) + fs_ver(2) + trx2_tail(28) = 32 bytes
    # trx2 tail: prod_name[12] + sn(2) + en(2) + dummy(1) + key(1) + unk[6] + fs_prefix(1) + fs_offset[3]
    prod_name = product.encode("ascii")[:12].ljust(12, b"\x00")

    trx2_tail = struct.pack(">12sHHBB6sB3s",
        prod_name,
        STOCK_SN,
        STOCK_EN,
        0x00,       # dummy
        0x00,       # key
        b"\x00" * 6,  # unk[6]
        STOCK_FS_PREFIX,
        bytes(STOCK_FS_OFFSET),
    )

    # ih_name = kernel_ver(2) + fs_ver(2) + trx2_tail(28) = 32 bytes
    ih_name = struct.pack("BB", kernel_ver[0], kernel_ver[1])
    ih_name += struct.pack("BB", fs_ver[0], fs_ver[1])
    ih_name += trx2_tail

    assert len(ih_name) == 32, f"ih_name must be 32 bytes, got {len(ih_name)}"

    # Data CRC
    data_crc = crc32(data)

    # Build header with ih_hcrc = 0 (placeholder for CRC computation)
    header = struct.pack(">IIIIIII",
        IH_MAGIC,
        0,              # ih_hcrc (placeholder)
        0x60000000,     # ih_time (arbitrary timestamp)
        len(data),      # ih_size
        load_addr,      # ih_load
        entry_point,    # ih_ep
        data_crc,       # ih_dcrc
    )
    header += struct.pack("BBBB", IH_OS_LINUX, IH_ARCH_ARM, IH_TYPE_KERNEL, comp)
    header += ih_name

    assert len(header) == 64, f"Header must be 64 bytes, got {len(header)}"

    # Compute header CRC (over header with ih_hcrc = 0)
    header_crc = crc32(header)

    # Patch ih_hcrc (offset 4-7, not 0-3)
    header = header[:4] + struct.pack(">I", header_crc) + header[8:]

    return header


def parse_header(data: bytes) -> dict:
    """Parse a 64-byte U-Boot legacy image header."""
    if len(data) < 64:
        return {"error": "data too short"}

    fields = struct.unpack(">IIIIIII", data[0:28])
    os_t, arch, img_type, comp = struct.unpack("4B", data[28:32])
    ih_name = data[32:64]

    kv_major, kv_minor = ih_name[0], ih_name[1]
    fv_major, fv_minor = ih_name[2], ih_name[3]
    prod_name = ih_name[4:16].split(b"\x00")[0].decode("ascii", errors="replace")

    return {
        "magic": f"0x{fields[0]:08X}",
        "magic_valid": fields[0] == IH_MAGIC,
        "header_crc": f"0x{fields[1]:08X}",
        "timestamp": f"0x{fields[2]:08X}",
        "data_size": fields[3],
        "load_addr": f"0x{fields[4]:08X}",
        "entry_point": f"0x{fields[5]:08X}",
        "data_crc": f"0x{fields[6]:08X}",
        "os": os_t,
        "arch": arch,
        "type": img_type,
        "comp": comp,
        "kernel_ver": f"{kv_major}.{kv_minor}",
        "fs_ver": f"{fv_major}.{fv_minor}",
        "product": prod_name,
    }


def verify_header(header: bytes, data: bytes) -> list[str]:
    """Verify header integrity. Returns list of errors (empty = valid)."""
    errors = []

    if len(header) != 64:
        errors.append(f"Header is {len(header)} bytes, expected 64")
        return errors

    fields = struct.unpack(">IIIIIII", header[0:28])

    if fields[0] != IH_MAGIC:
        errors.append(f"Bad magic: 0x{fields[0]:08X}, expected 0x{IH_MAGIC:08X}")

    # Verify header CRC
    header_zeroed = header[0:4] + b"\x00" * 4 + header[8:]
    expected_hcrc = crc32(header_zeroed)
    if fields[1] != expected_hcrc:
        errors.append(f"Header CRC mismatch: 0x{fields[1]:08X}, expected 0x{expected_hcrc:08X}")

    # Verify data CRC
    expected_dcrc = crc32(data)
    if fields[6] != expected_dcrc:
        errors.append(f"Data CRC mismatch: 0x{fields[6]:08X}, expected 0x{expected_dcrc:08X}")

    # Verify data size
    if fields[3] != len(data):
        errors.append(f"Data size mismatch: header says {fields[3]}, actual {len(data)}")

    return errors


def main():
    parser = argparse.ArgumentParser(
        description="Wrap OpenWrt FIT image in ASUS U-Boot header for Lyra MAP-AC2200"
    )
    parser.add_argument("-i", "--input", help="Input FIT image (e.g., initramfs.itb)")
    parser.add_argument("-o", "--output", help="Output file (default: <input>-factory.trx)")
    parser.add_argument("-n", "--product", default=STOCK_PRODUCT, help="Product name (default: MAP-AC2200)")
    parser.add_argument("--no-comp", action="store_true", help="Set compression to NONE instead of LZMA")
    parser.add_argument("-x", "--inspect", help="Inspect an existing factory image header")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    # Inspect mode
    if args.inspect:
        with open(args.inspect, "rb") as f:
            raw = f.read()
        info = parse_header(raw[:64])
        print("=== Image Header ===")
        for k, v in info.items():
            print(f"  {k}: {v}")

        if info.get("magic_valid") and len(raw) > 64:
            data = raw[64:]
            errors = verify_header(raw[:64], data)
            if errors:
                print("\n=== Verification FAILED ===")
                for e in errors:
                    print(f"  ERROR: {e}")
            else:
                print("\n=== Verification PASSED ===")
                print(f"  Payload: {len(data)} bytes")
                print(f"  Payload magic: 0x{struct.unpack('>I', data[:4])[0]:08X}")
        return

    if not args.input:
        parser.error("-i/--input is required when not using -x")

    # Wrap mode
    with open(args.input, "rb") as f:
        payload = f.read()

    # Verify input is a FIT image
    fit_magic = struct.unpack(">I", payload[:4])[0]
    if fit_magic != 0xD00DFEED:
        print(f"WARNING: Input does not start with FIT magic (0xD00DFEED). Got 0x{fit_magic:08X}")
        print("         Continuing anyway — input may not be a valid FIT image.")

    comp = IH_COMP_NONE if args.no_comp else IH_COMP_LZMA
    header = build_header(payload, product=args.product, comp=comp)

    # Verify our own output
    errors = verify_header(header, payload)
    if errors:
        print("ERROR: Self-verification failed!")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)

    outfile = args.output or args.input.rsplit(".", 1)[0] + "-factory.trx"
    with open(outfile, "wb") as f:
        f.write(header)
        f.write(payload)

    if args.verbose:
        info = parse_header(header)
        print("=== Created ASUS Factory Image ===")
        for k, v in info.items():
            print(f"  {k}: {v}")

    print(f"Output: {outfile}")
    print(f"  Header: 64 bytes")
    print(f"  Payload: {len(payload)} bytes")
    print(f"  Total:   {64 + len(payload)} bytes")
    print(f"  Self-verification: PASSED")


if __name__ == "__main__":
    main()
