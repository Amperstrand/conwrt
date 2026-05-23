#!/usr/bin/env python3
"""Validate a GS1920 ZyNOS-wrapped OpenWrt initramfs image before FTP upload."""

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

ROMBIN_HDR_SIZE = 48
EXPECTED_SLOT_GAP = 0x800000
EXPECTED_BOOT_ADDR = 0x80014000
EXPECTED_MMAP_ADDR = 0xB40E0000
EXPECTED_RASCODE_OFFSET = 0x0B2400
EXPECTED_UIMAGE_LOAD = 0x80100000
EXPECTED_UIMAGE_ENTRY = 0x80100000


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        if total > 0xFFFF:
            total = (total & 0xFFFF) + 1
    return total & 0xFFFF


@dataclass(frozen=True)
class RombinHeader:
    offset: int
    addr: int
    sig: bytes
    type: int
    osize: int
    csize: int
    flags: int
    ocsum: int
    ccsum: int
    ver: bytes
    mmap_addr: int


def parse_header(data: bytes, offset: int) -> RombinHeader:
    raw = data[offset : offset + ROMBIN_HDR_SIZE]
    if len(raw) != ROMBIN_HDR_SIZE:
        raise ValueError(f"header at 0x{offset:x} is truncated")
    return RombinHeader(
        offset=offset,
        addr=struct.unpack_from(">I", raw, 0)[0],
        sig=raw[6:9],
        type=raw[9],
        osize=struct.unpack_from(">I", raw, 10)[0],
        csize=struct.unpack_from(">I", raw, 14)[0],
        flags=raw[18],
        ocsum=struct.unpack_from(">H", raw, 20)[0],
        ccsum=struct.unpack_from(">H", raw, 22)[0],
        ver=raw[24:39].rstrip(b"\0"),
        mmap_addr=struct.unpack_from(">I", raw, 39)[0],
    )


def find_sections(data: bytes) -> list[RombinHeader]:
    sections = []
    pos = 0
    while True:
        sig = data.find(b"SIG", pos)
        if sig < 0:
            break
        offset = sig - 6
        if offset >= 0 and offset + ROMBIN_HDR_SIZE <= len(data):
            header = parse_header(data, offset)
            if header.sig == b"SIG" and header.type in (3, 4):
                sections.append(header)
        pos = sig + 3
    return sections


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)


def check(condition: bool, message: str) -> None:
    if not condition:
        fail(message)
    print(f"OK: {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument("--expected-payload", type=Path)
    args = parser.parse_args()

    data = args.image.read_bytes()
    print(f"Image: {args.image}")
    print(f"Size: {len(data)} bytes (sha256={hashlib.sha256(data).hexdigest()})")

    check(len(data) < EXPECTED_SLOT_GAP, f"image fits one 8MiB GS1920 firmware slot with {EXPECTED_SLOT_GAP - len(data)} bytes headroom")

    sections = find_sections(data)
    check(len(sections) == 3, "exactly three ZyNOS sections found")

    boot, romdef, ras = sections
    check(boot.offset == 0, "BOOTEXT section starts at offset 0")
    check(boot.type == 3, "BOOTEXT type is 3")
    check(boot.addr == EXPECTED_BOOT_ADDR, "BOOTEXT load address is GS1920 RTL839x code start")
    check(boot.mmap_addr == EXPECTED_MMAP_ADDR, "BOOTEXT mmap_addr is stock slot-1 address for FTP patching")
    check(boot.flags == 0x40, "BOOTEXT uses uncompressed checksum flag")
    check(boot.osize == len(data) - ROMBIN_HDR_SIZE, "BOOTEXT osize covers full image after header")
    check(internet_checksum(data[ROMBIN_HDR_SIZE:]) == boot.ocsum, "BOOTEXT ocsum validates")

    check(romdef.offset == 0x32400, "RomDefa section remains at stock offset")
    check(romdef.type == 4, "RomDefa type is 4")
    romdef_len = romdef.csize if romdef.flags & 0x80 else romdef.osize
    romdef_data = data[romdef.offset + ROMBIN_HDR_SIZE : romdef.offset + ROMBIN_HDR_SIZE + romdef_len]
    check(internet_checksum(romdef_data) == romdef.ccsum, "RomDefa compressed checksum validates")

    check(ras.offset == EXPECTED_RASCODE_OFFSET, "RasCode section remains at stock offset")
    check(ras.type == 4, "RasCode type is 4")
    compressed = bool(ras.flags & 0x80)
    check(ras.flags in (0x40, 0xE0), f"RasCode flags valid (0x{ras.flags:02x}: {'compressed' if compressed else 'uncompressed'})")
    payload_offset = ras.offset + ROMBIN_HDR_SIZE

    if compressed:
        # LZMA-compressed RasCode: validate ccsum against compressed data,
        # then decompress to validate ocsum and uImage structure
        compressed_payload = data[payload_offset : payload_offset + ras.csize]
        check(len(compressed_payload) == ras.csize, "RasCode compressed payload length matches csize")
        check(internet_checksum(compressed_payload) == ras.ccsum, "RasCode ccsum (compressed) validates")

        import lzma
        try:
            payload = lzma.decompress(compressed_payload)
        except Exception as e:
            fail(f"RasCode LZMA decompression failed: {e}")
        check(len(payload) == ras.osize, f"RasCode decompressed size matches osize ({len(payload)} vs {ras.osize})")
        check(internet_checksum(payload) == ras.ocsum, "RasCode ocsum (decompressed) validates")
        print(f"OK: RasCode LZMA decompressed {ras.csize} -> {ras.osize} bytes ({ras.csize/ras.osize*100:.1f}% ratio)")
    else:
        # Uncompressed RasCode: validate ocsum directly
        payload = data[payload_offset : payload_offset + ras.osize]
        check(len(payload) == ras.osize, "RasCode payload length matches osize")
        check(internet_checksum(payload) == ras.ocsum, "RasCode ocsum validates")

    magic_offset = payload.find(bytes.fromhex("27051956"))
    check(magic_offset == 0x3E60, "uImage header appears at expected rt-loader offset 0x3e60")
    uimage = payload[magic_offset : magic_offset + 64]
    magic, _, _, size, load, entry, _, os_, arch, image_type, comp = struct.unpack(">7I4B", uimage[:32])
    name = uimage[32:64].split(b"\0", 1)[0]
    check(magic == 0x27051956, "uImage magic is valid")
    check(load == EXPECTED_UIMAGE_LOAD, "uImage load address is 0x80100000")
    check(entry == EXPECTED_UIMAGE_ENTRY, "uImage entry address is 0x80100000")
    check((os_, arch, image_type, comp) == (5, 5, 2, 3), "uImage is Linux/MIPS/kernel/lzma")
    check(name.startswith(b"MIPS OpenWrt"), "uImage name identifies MIPS OpenWrt")
    check(magic_offset + 64 + size == len(payload), "uImage payload ends exactly at RasCode end")

    if args.expected_payload:
        expected = args.expected_payload.read_bytes()
        check(payload == expected, "RasCode payload exactly matches expected official initramfs")

    print("PASS: GS1920 ZyNOS-wrapped OpenWrt image passed safety validation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
