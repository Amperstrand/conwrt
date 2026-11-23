#!/usr/bin/env python3
"""Parse ZTE delta.package (magic 0x55AA5588 LE) from the MF286D B12->B02(.up) update.
Entry: name[32] + u32 size + u32 offset (absolute in file), 40 bytes each."""
import struct, sys, pathlib

data = pathlib.Path(sys.argv[1]).read_bytes()
out = pathlib.Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)

magic, count = struct.unpack_from("<II", data, 0)
assert magic == 0x55AA5588, hex(magic)
print(f"magic OK 0x{magic:08x}, entries={count}")

off = 16
entries = []
for i in range(count):
    name = data[off:off+32].split(b"\0")[0].decode()
    size, doff = struct.unpack_from("<II", data, off+32)
    entries.append((name, size, doff))
    print(f"{i:2d} {name:22s} size={size:#10x} ({size:>9} B) @ {doff:#x}")
    off += 40

# sanity: contiguous?
prev_end = 16 + count*40
for name, size, doff in entries:
    if doff != prev_end:
        print(f"  ! gap/overlap before {name}: expected {prev_end:#x} got {doff:#x}")
    prev_end = doff + size
print(f"end of last blob {prev_end:#x}, file size {len(data):#x}")

for name, size, doff in entries:
    blob = data[doff:doff+size]
    (out / name).write_bytes(blob)
    head = blob[:16]
    print(f"wrote {name:22s} head={head[:8].hex()} ascii={head[:8]}")
