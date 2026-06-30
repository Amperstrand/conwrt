#!/usr/bin/env python3
"""
Repack Zyxel GS1920-24 official firmware with OpenWrt initramfs.

Takes the official multi-section ZyNOS firmware (BootExt + RomDefa + RasCode)
and replaces the RasCode section with an OpenWrt initramfs kernel image.

The firmware format is a raw binary with three sections, each preceded by a
48-byte zyn_rombin_hdr (big-endian):

  [BootExt header (48B)] [BootExt data (raw loader)]
  [RomDefa header (48B)]  [RomDefa data (LZMA compressed config defaults)]
  [RasCode header (48B)]  [RasCode data (firmware main code, LZMA compressed)]

Header layout (struct zyn_rombin_hdr, 48 bytes, big-endian fields):
  Offset  Size  Field
  0x00    4     addr         (load address)
  0x04    2     res0         (unknown)
  0x06    3     sig          ("SIG")
  0x09    1     type         (0x03=BOOTEXT, 0x04=ROMBIN)
  0x0A    4     osize        (uncompressed data size)
  0x0E    4     csize        (compressed data size)
  0x12    1     flags        (0x40=OCSUM, 0x80=COMP, 0x20=CCSUM)
  0x13    1     res1
  0x14    2     ocsum        (Internet checksum of data after header)
  0x16    2     ccsum        (Internet checksum of compressed data)
  0x18    15    ver          (version string)
  0x27    4     mmap_addr    (memory map table address)
  0x2B    4     res2
  0x2F    1     res3

Checksum algorithm: Internet checksum (16-bit one's complement sum).
This matches mkzynfw.c's csum_buf() function.

Based on research from:
  - /Users/macbook/src/jtag/ (WX5600-T0 firmware validation RE)
  - OpenWrt firmware-utils: zynsig.c, mkzynfw.c
  - Binary analysis of official 450AAOB3C0.bin
"""

import argparse
import struct
import sys
import os
import lzma

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from checksum_utils import internet_checksum  # noqa: E402


# --- ROMBIN header (48 bytes, big-endian) ---

ROMBIN_HDR_SIZE = 48
ROMBIN_HDR_FMT = '>I H 3s B II BB HH 15s II B'  # big-endian

def parse_rombin_header(data: bytes) -> dict:
    """Parse a 48-byte zyn_rombin_hdr from bytes."""
    if len(data) < ROMBIN_HDR_SIZE:
        raise ValueError(f"Header too short: {len(data)} bytes")

    fields = struct.unpack_from(ROMBIN_HDR_FMT, data)
    return {
        'addr':      fields[0],
        'res0':      fields[1],
        'sig':       fields[2],
        'type':      fields[3],
        'osize':     fields[4],
        'csize':     fields[5],
        'flags':     fields[6],
        'res1':      fields[7],
        'ocsum':     fields[8],
        'ccsum':     fields[9],
        'ver':       fields[10],
        'mmap_addr': fields[11],
        'res2':      fields[12],
        'res3':      fields[13],
    }


def build_rombin_header(h: dict) -> bytes:
    """Build a 48-byte zyn_rombin_hdr from a dict."""
    return struct.pack(ROMBIN_HDR_FMT,
        h['addr'],
        h['res0'],
        h['sig'],
        h['type'],
        h['osize'],
        h['csize'],
        h['flags'],
        h['res1'],
        h['ocsum'],
        h['ccsum'],
        h['ver'],
        h['mmap_addr'],
        h['res2'],
        h['res3'],
    )


def dump_header(label: str, h: dict):
    """Print a header for debugging."""
    sig = h['sig'].decode('ascii', errors='replace')
    ver = h['ver'].decode('ascii', errors='replace').rstrip('\x00')
    print(f"  {label}:")
    print(f"    sig={sig!r}  type=0x{h['type']:02x}  addr=0x{h['addr']:08x}")
    print(f"    osize=0x{h['osize']:08x} ({h['osize']:,})  csize=0x{h['csize']:08x} ({h['csize']:,})")
    print(f"    flags=0x{h['flags']:02x}  ocsum=0x{h['ocsum']:04x}  ccsum=0x{h['ccsum']:04x}")
    print(f"    mmap_addr=0x{h['mmap_addr']:08x}  ver={ver!r}")


# --- Section parsing ---

def find_sections(fw_data: bytes) -> list:
    """Parse the multi-section firmware and return list of (offset, header, data).

    The ZyNOS firmware format uses nested sections:
      - BootExt (type=0x03) is an ENVELOPE whose osize covers the entire file
        after its header. RomDefa and RasCode headers are embedded at fixed
        offsets within the BootExt data region.
      - RomDefa (type=0x04) and RasCode (type=0x04) are sub-sections whose
        data_size reflects their actual compressed/uncompressed data length.

    Because BootExt's data spans the whole file, sequential traversal (follow
    data_size → find next header) fails. Instead, we scan for all valid SIG
    headers throughout the file.
    """
    sections = []
    pos = 0

    while pos < len(fw_data) - ROMBIN_HDR_SIZE:
        # Scan for 'SIG' magic (3 bytes at header offset 6)
        sig_pos = fw_data.find(b'SIG', pos)
        if sig_pos == -1 or sig_pos - 6 + ROMBIN_HDR_SIZE > len(fw_data):
            break

        hdr_start = sig_pos - 6  # header starts 6 bytes before SIG

        # Skip if this falls inside a ROMBIN section's data (type=0x04).
        # BootExt (type=0x03) is an envelope — sub-section headers live inside it, don't skip those.
        if any(s['header']['type'] == 0x04 and
               s['offset'] + ROMBIN_HDR_SIZE <= hdr_start < s['offset'] + ROMBIN_HDR_SIZE + len(s['data'])
               for s in sections):
            pos = sig_pos + 3
            continue

        hdr_raw = fw_data[hdr_start:hdr_start + ROMBIN_HDR_SIZE]
        hdr = parse_rombin_header(hdr_raw)

        # Validate: sig must be SIG and type must be known
        if hdr['sig'] != b'SIG' or hdr['type'] not in (0x03, 0x04):
            pos = sig_pos + 3
            continue

        # For BootExt (type=0x03), osize is the envelope (whole file minus header).
        # We clamp data to file size but don't use it for next-section traversal.
        # For ROMBIN (type=0x04), data_size is the actual section data.
        if hdr['flags'] & 0x80:  # COMP flag
            data_size = hdr['csize']
        else:
            data_size = hdr['osize']

        data_start = hdr_start + ROMBIN_HDR_SIZE
        data_end = data_start + data_size

        # Clamp to file size
        if data_end > len(fw_data):
            data_end = len(fw_data)
            data_size = data_end - data_start

        section_data = fw_data[data_start:data_end]
        sections.append({
            'offset': hdr_start,
            'header': hdr,
            'data': section_data,
        })

        print(f"\n  Section at file offset 0x{hdr_start:06x}:")
        dump_header(f"type=0x{hdr['type']:02x}", hdr)
        print(f"    data: {data_size:,} bytes (0x{data_start:06x} - 0x{data_end:06x})")

        # Advance past this SIG for next scan
        pos = sig_pos + 3

    # Sort by offset
    sections.sort(key=lambda s: s['offset'])
    return sections


def main():
    parser = argparse.ArgumentParser(description='Repack Zyxel GS1920-24 firmware with OpenWrt initramfs')
    parser.add_argument('--official', '-i', required=True,
                        help='Official Zyxel firmware (e.g. 450AAOB3C0.bin)')
    parser.add_argument('--initramfs', '-k', required=True,
                        help='OpenWrt initramfs kernel image')
    parser.add_argument('--output', '-o', required=True,
                        help='Output firmware file')
    parser.add_argument('--compress', '-z', action='store_true',
                        help='LZMA-compress the initramfs (matches official format)')
    parser.add_argument('--verify', action='store_true',
                        help='Verify checksums of official firmware before repacking')
    args = parser.parse_args()

    # Read inputs
    with open(args.official, 'rb') as f:
        official = f.read()
    print(f"Official firmware: {len(official):,} bytes ({len(official)/1024/1024:.1f} MB)")

    with open(args.initramfs, 'rb') as f:
        initramfs = f.read()
    print(f"OpenWrt initramfs: {len(initramfs):,} bytes ({len(initramfs)/1024/1024:.1f} MB)")

    # Parse sections from official firmware
    print("\n=== Parsing official firmware sections ===")
    sections = find_sections(official)

    if len(sections) < 3:
        print(f"\nERROR: Expected 3 sections (BootExt, RomDefa, RasCode), found {len(sections)}")
        sys.exit(1)

    bootext = sections[0]  # type=0x03 BOOTEXT
    romdefa = sections[1]  # type=0x04 ROMBIN (RomDefa)
    rascode = sections[2]  # type=0x04 ROMBIN (RasCode)

    # Verify section types
    if bootext['header']['type'] != 0x03:
        print(f"ERROR: First section is not BOOTEXT (type=0x{bootext['header']['type']:02x})")
        sys.exit(1)
    if romdefa['header']['type'] != 0x04:
        print(f"ERROR: Second section is not ROMBIN (type=0x{romdefa['header']['type']:02x})")
        sys.exit(1)
    if rascode['header']['type'] != 0x04:
        print(f"ERROR: Third section is not ROMBIN (type=0x{rascode['header']['type']:02x})")
        sys.exit(1)

    # Verify official firmware checksums
    if args.verify:
        print("\n=== Verifying official firmware checksums ===")
        # BootExt: ocsum should match internet checksum of all data after header
        all_data_after_hdr = official[ROMBIN_HDR_SIZE:]
        computed_ocsum = internet_checksum(all_data_after_hdr)
        expected_ocsum = bootext['header']['ocsum']
        match = "OK" if computed_ocsum == expected_ocsum else "MISMATCH"
        print(f"  BootExt ocsum: computed=0x{computed_ocsum:04x}  stored=0x{expected_ocsum:04x}  {match}")

        # RasCode: ocsum = checksum of uncompressed data
        if rascode['header']['flags'] & 0x80:  # COMP
            # We can't easily verify the uncompressed checksum without decompressing
            print("  RasCode: compressed, skipping uncompressed checksum verification")
            # But we can verify compressed checksum
            computed_ccsum = internet_checksum(rascode['data'])
            expected_ccsum = rascode['header']['ccsum']
            match = "OK" if computed_ccsum == expected_ccsum else "MISMATCH"
            print(f"  RasCode ccsum: computed=0x{computed_ccsum:04x}  stored=0x{expected_ccsum:04x}  {match}")

    # --- Build new firmware ---

    print("\n=== Building repacked firmware ===")

    # Prepare new RasCode data
    if args.compress:
        print("  Compressing initramfs with LZMA...")
        compressed = lzma.compress(initramfs, format=lzma.FORMAT_ALONE,
                                    filters=[{'id': lzma.FILTER_LZMA1, 'preset': 6}])
        rascode_data = compressed
        rascode_osize = len(initramfs)
        rascode_csize = len(compressed)
        rascode_flags = 0xE0  # OCSUM + CCSUM + COMP
        print(f"  Compressed: {len(initramfs):,} -> {len(compressed):,} bytes ({len(compressed)/len(initramfs)*100:.1f}%)")
    else:
        rascode_data = initramfs
        rascode_osize = len(initramfs)
        rascode_csize = len(initramfs)
        rascode_flags = 0x40  # OCSUM only, no compression
        print(f"  Using uncompressed initramfs: {len(initramfs):,} bytes")

    # Compute RasCode checksums
    rascode_ocsum = internet_checksum(initramfs)  # checksum of original (uncompressed) data
    if args.compress:
        rascode_ccsum = internet_checksum(rascode_data)  # checksum of compressed data
    else:
        rascode_ccsum = 0

    print(f"  RasCode ocsum: 0x{rascode_ocsum:04x}")
    if args.compress:
        print(f"  RasCode ccsum: 0x{rascode_ccsum:04x}")

    # Build new RasCode header (keep original addr, mmap_addr, ver from official)
    new_rascode_hdr = dict(rascode['header'])
    new_rascode_hdr['osize'] = rascode_osize
    new_rascode_hdr['csize'] = rascode_csize
    new_rascode_hdr['flags'] = rascode_flags
    new_rascode_hdr['ocsum'] = rascode_ocsum
    new_rascode_hdr['ccsum'] = rascode_ccsum

    print("\n  New RasCode header:")
    dump_header("RasCode (new)", new_rascode_hdr)

    # Assemble the new firmware
    # Structure:
    #   [BootExt header (48B)] [BootExt data] [gap/padding] [RomDefa header (48B)] [RomDefa data] [gap/padding] [RasCode header (48B)] [RasCode data]

    # Copy everything up to RasCode section verbatim
    rascode_start_in_official = rascode['offset']
    prefix = official[:rascode_start_in_official]

    # Build new RasCode section
    new_rascode_section = build_rombin_header(new_rascode_hdr) + rascode_data

    # Assemble: prefix (BootExt + RomDefa) + new RasCode
    new_firmware = prefix + new_rascode_section

    # Now update the BootExt header's osize and ocsum
    # osize = total file size - 48 (header size)
    new_osize = len(new_firmware) - ROMBIN_HDR_SIZE

    # Compute ocsum: Internet checksum of all data after the BootExt header
    all_data = new_firmware[ROMBIN_HDR_SIZE:]
    new_ocsum = internet_checksum(all_data)

    print("\n  New BootExt header update:")
    print(f"    osize: 0x{bootext['header']['osize']:08x} -> 0x{new_osize:08x} ({new_osize:,} bytes)")
    print(f"    ocsum: 0x{bootext['header']['ocsum']:04x} -> 0x{new_ocsum:04x}")

    # Patch the BootExt header in the new firmware
    bootext_hdr = dict(bootext['header'])
    bootext_hdr['osize'] = new_osize
    bootext_hdr['ocsum'] = new_ocsum

    new_bootext_hdr_raw = build_rombin_header(bootext_hdr)
    new_firmware = bytearray(new_bootext_hdr_raw + new_firmware[ROMBIN_HDR_SIZE:])

    # Update MemMapT checksum (entries + user data from after 24-byte header to user_end)
    MMT_HDR_SIZE = 24
    mmap_addr = bootext['header']['mmap_addr']
    mmt_file_base = None

    # Locate MemMapT by scanning for its header: count(2B) + addresses near mmap_addr
    for scan_off in range(ROMBIN_HDR_SIZE, min(len(new_firmware), rascode_start_in_official), 4):
        candidate_count = struct.unpack_from('>H', new_firmware, scan_off)[0]
        if candidate_count < 5 or candidate_count > 50:
            continue
        candidate_user_start = struct.unpack_from('>I', new_firmware, scan_off + 2)[0]
        # user_start must be in the same memory region as mmap_addr
        if abs(candidate_user_start - mmap_addr) > 0x100000:
            continue
        candidate_user_end = struct.unpack_from('>I', new_firmware, scan_off + 6)[0]
        if candidate_user_end <= candidate_user_start:
            continue
        if abs(candidate_user_end - mmap_addr) > 0x100000:
            continue
        mmt_file_base = scan_off
        break

    if mmt_file_base is not None:
        user_end = struct.unpack_from('>I', new_firmware, mmt_file_base + 6)[0]
        mmt_data_start = mmt_file_base + MMT_HDR_SIZE
        mmt_data_end = mmt_file_base + (user_end - mmap_addr)
        if mmt_data_end > len(new_firmware):
            mmt_data_end = len(new_firmware)
        mmt_data = new_firmware[mmt_data_start:mmt_data_end]
        new_mmt_csum = internet_checksum(mmt_data)
        struct.pack_into('>H', new_firmware, mmt_file_base + 10, new_mmt_csum)
        print(f"\n  MemMapT csum update (at file offset 0x{mmt_file_base:06x}):")
        print(f"    range: 0x{mmt_data_start:06x} - 0x{mmt_data_end:06x} ({len(mmt_data)} bytes)")
        print(f"    csum: 0x{new_mmt_csum:04x}")

        # BootExt ocsum needs recompute after MemMapT csum change
        all_data = new_firmware[ROMBIN_HDR_SIZE:]
        new_ocsum = internet_checksum(all_data)
        bootext_hdr['ocsum'] = new_ocsum
        new_bootext_hdr_raw = build_rombin_header(bootext_hdr)
        new_firmware = new_bootext_hdr_raw + new_firmware[ROMBIN_HDR_SIZE:]
        print(f"    BootExt ocsum recalculated: 0x{new_ocsum:04x}")
    else:
        print("\n  WARNING: MemMapT header not found in firmware, skipping MMT csum update")

    # Write output
    with open(args.output, 'wb') as f:
        f.write(new_firmware)

    out_size = os.path.getsize(args.output)
    print("\n=== Output ===")
    print(f"  File: {args.output}")
    print(f"  Size: {out_size:,} bytes ({out_size/1024/1024:.1f} MB)")
    print(f"  Original: {len(official):,} bytes ({len(official)/1024/1024:.1f} MB)")
    print(f"  Change: {out_size - len(official):+,} bytes")

    # Verify the output
    print("\n=== Verification ===")
    with open(args.output, 'rb') as f:
        verify_data = f.read()

    # Re-parse and verify
    v_sections = find_sections(verify_data)
    print(f"  Sections found: {len(v_sections)}")

    if len(v_sections) >= 1:
        # Verify BootExt ocsum
        v_all_data = verify_data[ROMBIN_HDR_SIZE:]
        v_ocsum = internet_checksum(v_all_data)
        v_bootext_ocsum = v_sections[0]['header']['ocsum']
        match = "OK" if v_ocsum == v_bootext_ocsum else "MISMATCH"
        print(f"  BootExt ocsum: computed=0x{v_ocsum:04x}  stored=0x{v_bootext_ocsum:04x}  {match}")

    if len(v_sections) >= 3:
        # Verify RasCode checksums
        v_rascode = v_sections[2]
        v_data = v_rascode['data']

        # ocsum of original data (initramfs)
        if v_rascode['header']['flags'] & 0x80:  # compressed
            # Can't verify ocsum without decompression
            v_ccsum = internet_checksum(v_data)
            match = "OK" if v_ccsum == v_rascode['header']['ccsum'] else "MISMATCH"
            print(f"  RasCode ccsum: computed=0x{v_ccsum:04x}  stored=0x{v_rascode['header']['ccsum']:04x}  {match}")
        else:
            # Uncompressed: ocsum should match
            v_ocsum_ras = internet_checksum(v_data)
            match = "OK" if v_ocsum_ras == v_rascode['header']['ocsum'] else "MISMATCH"
            print(f"  RasCode ocsum: computed=0x{v_ocsum_ras:04x}  stored=0x{v_rascode['header']['ocsum']:04x}  {match}")

    print("\n=== Done! Upload via: http://admin:1234@192.168.1.1/fwUpgrade.html ===")


if __name__ == '__main__':
    main()
