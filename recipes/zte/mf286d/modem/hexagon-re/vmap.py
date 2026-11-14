#!/usr/bin/env python3
"""vaddr map + string catalog + xref scanner for the AMSS split image."""
import struct, os, re, json, sys

IMG = '/home/user/mf286d-work/evidence/modem-fw-re/live-b12/dumps/mtd9-files/image'

def load_phdrs():
    mdt = open(f'{IMG}/modem.mdt','rb').read()
    phoff = struct.unpack_from('<I', mdt, 28)[0]
    phnum = struct.unpack_from('<H', mdt, 44)[0]
    segs = []
    for i in range(phnum):
        t, off, va, pa, fsz, msz, fl, al = struct.unpack_from('<IIIIIIII', mdt, phoff+i*32)
        segs.append(dict(idx=i, type=t, off=off, vaddr=va, filesz=fsz, memsz=msz, flags=fl))
    return segs

SEGS = load_phdrs()

def file_of_segment(i):
    p = f'{IMG}/modem.b{i:02d}'
    return p if os.path.exists(p) else None

# full address space image: concatenate all segments into one buffer with vaddr map
class Space:
    def __init__(self):
        self.ranges = []  # (start_vaddr, end_vaddr, file_path)
        for s in SEGS:
            fp = file_of_segment(s['idx'])
            if fp and s['filesz']:
                self.ranges.append((s['vaddr'], s['vaddr']+s['filesz'], fp, s))
    def find_string(self, needle: bytes):
        """yield (vaddr, seginfo) for each occurrence"""
        out = []
        for start, end, fp, s in self.ranges:
            data = open(fp,'rb').read()
            for m in re.finditer(re.escape(needle), data):
                out.append((start + m.start(), s['idx'], m.start()))
        return out
    def read_vaddr(self, va, n):
        for start, end, fp, s in self.ranges:
            if start <= va < end:
                d = open(fp,'rb').read()
                o = va - start
                return d[o:o+n]
        return None
    def seg_of(self, va):
        for start, end, fp, s in self.ranges:
            if start <= va < end: return s
        return None

if __name__ == '__main__':
    sp = Space()
    print(f"{'seg':>4} {'vaddr':>12} {'filesz':>10} {'flags':>10} file")
    for start, end, fp, s in sp.ranges:
        fl = ''.join(c for c,b in zip('RWE',(4,2,1)) if s['flags'] & b)
        print(f"b{s['idx']:02d} {start:#12x} {s['filesz']:>10} {fl:>10} {os.path.basename(fp)}")
