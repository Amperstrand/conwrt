#!/usr/bin/env python3
"""zycast_wire_check — verify a pcap of zycast multicast frames against the wire format.

Asserts, per UDP packet: dst 225.0.0.0:5631, the 30-byte header from
conwrt-protocols::zycast::encode_packet (magic `zyx\\0`, end-around-carry
chunk checksum, be32 index/len/total, Ras bitmap at bytes 20+21, `FF`,
debug flag), 1024-byte chunks, and payload == the corresponding slice of
the source image. Exits non-zero on the first violation.

Usage: zycast_wire_check.py <capture.pcap> <image.bin> [--loops N]
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

MAGIC = b"zyx\x00"
HEADER_LEN = 30
CHUNK_LEN = 1024
GROUP = "225.0.0.0"
PORT = 5631
RAS_BITMAP = 0x04


def checksum(chunk: bytes) -> int:
    total = sum(chunk)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def parse_pcap(path: Path) -> list[bytes]:
    """UDP payloads from a classic pcap (LINKTYPE_NULL or EN10MB)."""
    data = path.read_bytes()
    magic, _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack("<IHHiIII", data[:24])
    if magic != 0xA1B2C3D4:
        raise ValueError(f"not a little-endian classic pcap (magic {magic:#x})")
    link_off = {0: 4, 1: 14}.get(linktype)
    if link_off is None:
        raise ValueError(f"unsupported linktype {linktype} (need NULL or EN10MB)")
    packets: list[bytes] = []
    off = 24
    while off + 16 <= len(data):
        (_ts_s, _ts_us, caplen, _orig) = struct.unpack("<IIII", data[off : off + 16])
        off += 16
        frame = data[off : off + caplen]
        off += caplen
        ip = frame[link_off:]
        if (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        if proto != 17:
            continue
        udp = ip[ihl:]
        _sport, dport, ulen = struct.unpack(">HHH", udp[:6])
        if dport != PORT:
            continue
        packets.append(udp[8 : 8 + (ulen - 8)])
    return packets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pcap", type=Path)
    parser.add_argument("image", type=Path)
    parser.add_argument("--loops", type=int, default=0, help="expect exactly N loops of ceil(len/1024) packets")
    args = parser.parse_args()

    image = args.image.read_bytes()
    chunks = max(1, -(-len(image) // CHUNK_LEN))
    payloads = parse_pcap(args.pcap)
    print(f"packets captured: {len(payloads)} (image {len(image)} B = {chunks} chunk(s)/loop)")

    problems: list[str] = []
    for i, payload in enumerate(payloads):
        want_loop = chunks if args.loops else None
        if len(payload) != HEADER_LEN + min(CHUNK_LEN, len(image)):
            problems.append(f"pkt {i}: payload {len(payload)} != {HEADER_LEN}+chunk")
            continue
        magic, csum, index, clen, total = struct.unpack(">4sHIII", payload[:18])
        bitmap, bitmap2, country, flag = payload[20], payload[21], payload[22:24], payload[24]
        chunk = payload[HEADER_LEN:]
        expect_idx = i % chunks if want_loop else None
        if magic != MAGIC:
            problems.append(f"pkt {i}: magic {magic!r}")
        if csum != checksum(chunk):
            problems.append(f"pkt {i}: checksum {csum:#06x} != {checksum(chunk):#06x}")
        if clen != len(chunk):
            problems.append(f"pkt {i}: chunk-len field {clen} != {len(chunk)}")
        if total != len(image):
            problems.append(f"pkt {i}: total field {total} != {len(image)}")
        if bitmap != RAS_BITMAP or bitmap2 != RAS_BITMAP:
            problems.append(f"pkt {i}: bitmap {bitmap:#04x}/{bitmap2:#04x} != Ras")
        if country != b"FF" or flag != 0x01:
            problems.append(f"pkt {i}: country/flag {country!r}/{flag:#04x}")
        if chunk != image[(index % chunks) * CHUNK_LEN : (index % chunks) * CHUNK_LEN + len(chunk)]:
            problems.append(f"pkt {i}: payload does not match image slice")
        if expect_idx is not None and index != expect_idx:
            problems.append(f"pkt {i}: index {index} != expected {expect_idx}")
        print(
            f"pkt {i}: idx={index} csum={csum:#06x} len={clen} bitmap=Ras "
            f"{'OK' if not problems or problems[-1][:5] != f'pkt {i}' else 'FAIL'}"
        )

    if args.loops and len(payloads) != chunks * args.loops:
        problems.append(f"packet count {len(payloads)} != {chunks}x{args.loops}")
    if problems:
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        return 1
    print(f"wire proof PASS: {len(payloads)} packet(s), format + payload + ordering all verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
