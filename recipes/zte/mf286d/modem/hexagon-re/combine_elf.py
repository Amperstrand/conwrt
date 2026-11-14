#!/usr/bin/env python3
"""Reassemble modem.mdt + modem.bNN into a single loadable ELF (EM_QDSP6)."""
import struct, os
IMG = '/home/user/mf286d-work/evidence/modem-fw-re/live-b12/dumps/mtd9-files/image'
mdt = open(f'{IMG}/modem.mdt','rb').read()
phoff = struct.unpack_from('<I', mdt, 28)[0]
phnum = struct.unpack_from('<H', mdt, 44)[0]
phdrs = []
for i in range(phnum):
    t, off, va, pa, fsz, msz, fl, al = struct.unpack_from('<IIIIIIII', mdt, phoff+i*32)
    phdrs.append((t, off, va, fsz, msz, fl, al))

maxend = max(off+fsz for t,off,va,fsz,msz,fl,al in phdrs) + 0x1000
buf = bytearray(maxend)
# ELF header + phdrs from mdt (first phdr segment = hash/metadata: mdt[0:0x414])
buf[0:len(mdt)] = mdt
# place each segment file at its phdr offset
placed = 0
for i, (t, off, va, fsz, msz, fl, al) in enumerate(phdrs):
    p = f'{IMG}/modem.b{i:02d}'
    if fsz and os.path.exists(p):
        buf[off:off+fsz] = open(p,'rb').read()[:fsz]
        placed += 1
print(f"placed {placed} segments, image size {len(buf)} ({len(buf)/1e6:.1f} MB)")
open('/tmp/modem_combined.elf','wb').write(buf)
