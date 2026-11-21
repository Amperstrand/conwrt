#!/usr/bin/env python3
"""Scan ZTE ZFD01.02 containers for per-file delta records.
Record layout (empirical, BE u32s): ... [payload ...] [u32 a][u32 b][u32 namelen(+NUL)] [name NUL] [payload ...]
We scan for namelen+name patterns to locate records, payload = bytes between end of name and next record's field-a."""
import re, struct, sys, pathlib

data = pathlib.Path(sys.argv[1]).read_bytes()
out = pathlib.Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
pat = re.compile(rb"\x00\x00\x00([\x08-\xff]) ([a-zA-Z0-9_][a-zA-Z0-9_./-]{5,300}\.p)\x00".replace(b" ", b""))

records = []
for m in re.finditer(rb"\x00\x00\x00([\x09-\x80])([a-zA-Z0-9_][a-zA-Z0-9_./-]{4,300}\.p)\x00", data):
    namelen = m.group(1)[0]
    name = m.group(2).decode()
    if namelen != len(name) + 1:
        continue
    # fields: the 12 bytes before namelen = [u32 x][u32 y][u32 namelen]
    fs = m.start()
    x, y = struct.unpack_from(">II", data, fs - 8)
    payload_off = m.end()
    records.append((fs, x, y, name, payload_off))

records.sort()
print(f"{len(records)} records")
for i, (fs, x, y, name, po) in enumerate(records):
    nxt = records[i + 1][0] if i + 1 < len(records) else len(data)
    pspace = nxt - po
    # payload head: detect magic
    head = data[po:po + 12]
    tag = ""
    if head[:4] in (b"BSDI", b"bsdi"): tag = "BSDIFF?"
    if head[:2] == b"\x1f\x8b": tag = "GZIP"
    if head[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"): tag = "ZLIB"
    if head[:4] == b"PK\x03\x04": tag = "ZIP"
    print(f"{i:3d} fs={fs:#09x} x={x:#010x} y={y:#08x} space={pspace:>9} {tag:8s} {name}")
    # dump payload blob (up to next record) for selected names
    safe = name.replace("/", "_")
    if pspace > 0:
        (out / f"{safe}.payload").write_bytes(data[po:po + min(pspace, 50_000_000)])
