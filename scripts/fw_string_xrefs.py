#!/usr/bin/env python3
"""fw_string_xrefs — find ARM32 literal-pool references to a byte string.

Purpose: bootloader/firmware RE support (e.g. attributing runtime use of a
version/identity string without full disassembly). On ARM32, code loads
address constants via 4-byte little-endian literals in pools adjacent to
functions — so a string that is *referenced by code* has its address (file
offset + image base) embedded somewhere as a literal. Occurrences of the
string that carry no pool references are inert data (e.g. an embedded
default environment block).

Usage:
    python3 scripts/fw_string_xrefs.py <image.bin> <ascii-string> [--base 0x84000000]

Prints each occurrence offset, and for each candidate base the literal-pool
hits referencing it. Raw firmware images usually map vaddr = file-offset +
text base; try the known APPSBL base, and 0x0 as the identity baseline.
"""
from __future__ import annotations

import argparse
import struct
import sys


def find_all(data: bytes, needle: bytes) -> list[int]:
    hits, i = [], data.find(needle)
    while i >= 0:
        hits.append(i)
        i = data.find(needle, i + 1)
    return hits


def pool_refs(data: bytes, addr: int) -> list[int]:
    needle = struct.pack("<I", addr)
    return find_all(data, needle)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("image", help="raw firmware image (binary)")
    ap.add_argument("string", help="ASCII string to locate")
    ap.add_argument("--base", action="append", default=[], type=lambda s: int(s, 0),
                    help="candidate text load base (repeatable; 0x0 always included)")
    args = ap.parse_args()

    data = open(args.image, "rb").read()
    needle = args.string.encode("ascii")
    hits = find_all(data, needle)
    if not hits:
        print(f"string not found: {args.string!r}")
        return 1
    print(f"{len(hits)} occurrence(s) of {args.string!r}:")
    for h in hits:
        refs = pool_refs(data, h)
        print(f"  offset 0x{h:x}  self-address-pool-refs(base 0): {len(refs)}"
              + (f" at " + ", ".join(f"0x{r:x}" for r in refs[:6]) if refs else " (inert data)"))
    for base in args.base or []:
        print(f"base 0x{base:x}:")
        for h in hits:
            refs = pool_refs(data, h + base)
            if refs:
                print(f"  offset 0x{h:x} (vaddr 0x{h + base:x}): {len(refs)} pool ref(s) at "
                      + ", ".join(f"0x{r:x}" for r in refs[:8]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
