#!/usr/bin/env python3
"""Wrap raw Hexagon code in an ELF32 (EM_QDSP6) with a .text section."""
import struct, sys

def make_elf(data: bytes, vaddr: int, out: str):
    ehsize, phentsize, phnum = 52, 32, 1
    shentsize, shnum, shstrndx = 40, 3, 2
    phoff = ehsize
    shstr_off = phoff + phentsize*phnum
    shstrtab = b'\x00.text\x00.shstrtab\x00'
    code_off = shstr_off + len(shstrtab)
    shoff = code_off + len(data)
    ehdr = struct.pack('<4sBBBB8xHHIIIIIHHHHHH',
        b'\x7fELF', 1, 1, 1, 0,
        164, 1,                    # EM_QDSP6, ET_REL
        1, vaddr, phoff, shoff, 0,
        ehsize, phentsize, phnum, shentsize, shnum, shstrndx)
    ph = struct.pack('<8I', 1, code_off, vaddr, vaddr, len(data), len(data), 7, 0x100)
    sh_null = b'\x00'*40
    sh_text = struct.pack('<10I', 1, 1, 6, vaddr, code_off, len(data), 0, 0, 4, 0)
    sh_str  = struct.pack('<10I', 7, 3, 0, 0, shstr_off, len(shstrtab), 0, 0, 1, 0)
    blob = ehdr + ph + shstrtab + data
    # pad shoff alignment
    open(out,'wb').write(blob + sh_null + sh_text + sh_str)

if __name__ == '__main__':
    d = open(sys.argv[1],'rb').read()
    make_elf(d, int(sys.argv[2],16), sys.argv[3])
