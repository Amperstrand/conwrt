#!/usr/bin/env python3
"""Decrypt ZTE *_DL.config (BusinessCfg) — 3DES-CBC.
Key from get.public.setting.dll @ VA 0x21a28040 (16B, 2-key 3DES).
Header: magic(4)=690e3214 | crc32(4, of bytes 8..end) | plainlen(4, LE) | IV(8) | ciphertext...
Usage: python3 cfg_decrypt.py file1 [file2...]
"""
import struct, sys
from Crypto.Cipher import DES3
KEY = bytes.fromhex('0dcf8cd088bb47e190f591f3a5a62a4c')

def decrypt(path):
    d = open(path, 'rb').read()
    assert d[:4] == bytes.fromhex('690e3214'), "bad magic"
    plen = struct.unpack('<I', d[8:12])[0]
    pt = DES3.new(KEY, DES3.MODE_CBC, d[12:20]).decrypt(d[20:])[:plen]
    return pt

if __name__ == '__main__':
    for p in sys.argv[1:]:
        out = p + '.dec.xml'
        open(out, 'wb').write(decrypt(p))
        print(f"{p} -> {out}")
