#!/usr/bin/env python3
"""Reconstruct B14 modem files from ZFD01.02 delta + B12 base."""
import struct, lzma, os, sys

D = open('modem.mld.delta','rb').read()
B12 = '/home/user/mf286d-work/evidence/modem-fw-re/live-b12/dumps/mtd9-files'
OUT = 'b14-tree'
os.makedirs(OUT, exist_ok=True)

def bspatch(old, patch):
    if patch[:8] != b'BSDIFF40':
        return None, 'not bsdiff: %s' % patch[:8]
    ctrl_len, diff_len, new_size = struct.unpack_from('<QQQ', patch, 8)
    ctrl = patch[32:32+ctrl_len]
    diff = patch[32+ctrl_len:32+ctrl_len+diff_len]
    extra = patch[32+ctrl_len+diff_len:]
    out = bytearray(); oldpos = 0; dp = 0; ep = 0; cp = 0
    while cp + 24 <= ctrl_len:
        x, y, zq = struct.unpack_from('<qqq', ctrl, cp); cp += 24
        zflag = (zq >> 32) & 0xFFFFFFFF
        z = zq & 0xFFFFFFFF
        if z >= 0x80000000: z -= 0x100000000
        if oldpos + x > len(old):
            return None, f'oldpos {oldpos}+{x} > {len(old)}'
        for i in range(x):
            out.append((old[oldpos+i] + diff[dp]) & 0xFF); dp += 1
        for _ in range(y):
            out.append(extra[ep]); ep += 1
        oldpos += x + z
        if len(out) > new_size + 64: return None, 'overflow'
    if len(out) != new_size: return bytes(out), f'WARN size {len(out)} != {new_size}'
    return bytes(out), 'ok'

def find_b12(name):
    hits = []
    for root, _, files in os.walk(B12):
        if name in files:
            hits.append(os.path.join(root, name))
    return hits

off = 0x2C
stats = {'patched': [], 'replaced': [], 'unchanged': [], 'zdfu': [], 'failed': []}
for i in range(163):
    A, B_, plen = struct.unpack_from('>III', D, off)
    path = D[off+12:off+12+plen].split(b'\0')[0].decode('latin1')
    p = off + 12 + plen
    blob_len = struct.unpack_from('>I', D, p)[0]
    blob = D[p+4:p+4+blob_len+4]
    off = p + 4 + blob_len
    rel = path.replace('modem.mld/mnt/modem/', '')
    fn = rel[:-2]
    if len(blob) < 8:
        stats['unchanged'].append(fn); continue
    if blob[4:8] == b'ZDFU':
        stats['zdfu'].append(fn); continue
    if blob[4:5] != b'\x5d':
        stats['failed'].append((fn, 'unknown blob')); continue
    dict_size = struct.unpack_from('<I', blob, 5)[0]
    try:
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
              filters=[{'id': lzma.FILTER_LZMA1, 'dict_size': dict_size}])
        content = dec.decompress(blob[9:], max_length=1<<27)
    except lzma.LZMAError as e:
        stats['failed'].append((fn, f'lzma {e}')); continue
    if content[:8] == b'BSDIFF40':
        cands = find_b12(os.path.basename(fn))
        if not cands:
            stats['failed'].append((fn, 'no B12 base')); continue
        old = open(cands[0], 'rb').read()
        new, status = bspatch(old, content)
        if new is None:
            stats['failed'].append((fn, status)); continue
        dst = os.path.join(OUT, fn)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        open(dst, 'wb').write(new)
        stats['patched'].append((fn, len(old), len(new), status))
    else:
        dst = os.path.join(OUT, fn)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        open(dst, 'wb').write(content)
        stats['replaced'].append((fn, len(content), content[:4]))

print(f"patched: {len(stats['patched'])}  replaced(full): {len(stats['replaced'])}  "
      f"unchanged/empty: {len(stats['unchanged'])}  zdfu-pending: {stats['zdfu']}  failed: {len(stats['failed'])}")
for fn, a, b, s in stats['patched']:
    if fn.startswith('image/'):
        print(f"  [patch] {fn}: {a} -> {b} {s if s!='ok' else ''}")
for fn, n, m in stats['replaced']:
    if 'image/' in fn:
        print(f"  [full ] {fn}: {n}B magic={m}")
for f in stats['failed'][:10]: print("  FAIL:", f)

# B12 reference copies for unchanged files needed later
import shutil
for fn in ['image/modem.b20','image/modem.mbn']:
    src = find_b12(os.path.basename(fn))
    if src:
        dst = os.path.join(OUT, fn)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy(src[0], dst)
        print(f"  [copy ] {fn} (unchanged in B14)")
