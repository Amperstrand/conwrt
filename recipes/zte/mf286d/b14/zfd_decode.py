#!/usr/bin/env python3
"""
ZFD01.02 per-file delta payload decoder for ZTE MF286D B14 update package.

Verified on TELIA_MF286DV1.0.0B12-TELIA_MF286DV1.0.1B02.up (2026-11-09):
Every *.p.payload stream extracted from modem.mld / system.mld is:

    [BE32 comp_len ]  length of everything after this 8-byte header
    [BE32 orig_len ]  length of the decompressed blob
    [ 5 bytes     ]  LZMA1 properties: 5D 00 00 02 00
                     (lc=3 lp=0 pb=2, dict_size LE32 = 0x00020000 = 128 KiB)
    [ comp_len-5  ]  raw LZMA1 stream, NO end-of-stream marker
                     (read exactly orig_len bytes, do not wait for EOS)

The decompressed blob is either:
  * a full replacement file (e.g. system dsi_config.xml), or
  * a bsdiff4 patch with magic b"BSDIFF40" (control block = LE u64 triples),
    to be applied with bspatch(OLD, blob) -> NEW.

Usage:
    python3 zfd_decode.py <file.p.payload> [outfile]
    python3 zfd_decode.py --classify <dir-with-.payload-files>
"""
import lzma
import struct
import sys
from pathlib import Path

LZMA_HDR = b"\x5d\x00\x00\x02\x00"


def decode_payload(data: bytes) -> bytes:
    if len(data) < 13:
        raise ValueError("payload too short: %d" % len(data))
    comp_len, orig_len = struct.unpack(">II", data[:8])
    if data[8:13] != LZMA_HDR:
        raise ValueError("unexpected LZMA props %s (want %s)"
                         % (data[8:13].hex(), LZMA_HDR.hex()))
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                filters=[{"id": lzma.FILTER_LZMA1,
                                          "dict_size": 0x20000}])
    out = dec.decompress(data[13:], max_length=orig_len)
    if len(out) != orig_len:
        raise ValueError("short decode: got %d want %d" % (len(out), orig_len))
    return out


def classify(blob: bytes) -> str:
    if blob.startswith(b"BSDIFF40"):
        return "bsdiff40"
    if blob.startswith(b"BSDIFF"):
        return "bsdiff-other"
    for magic in (b"IMGDIFF", b"NORMDIFF"):
        if blob.startswith(magic):
            return magic.decode()
    return "full-file"


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--classify":
        d = Path(sys.argv[2])
        for p in sorted(d.glob("*.payload")):
            try:
                blob = decode_payload(p.read_bytes())
                print("%-8s %8d  %s" % (classify(blob), len(blob), p.name))
            except Exception as e:
                print("ERROR    %8s  %s  (%s)" % ("-", p.name, e))
        return
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    data = Path(sys.argv[1]).read_bytes()
    blob = decode_payload(data)
    print("decoded %d bytes, class=%s, head=%r" % (len(blob), classify(blob),
                                                   blob[:48]))
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(sys.argv[1] + ".dec")
    out.write_bytes(blob)
    print("wrote %s" % out)


if __name__ == "__main__":
    main()
