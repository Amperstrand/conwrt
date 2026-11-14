import struct, lzma, os, shutil, subprocess, sys
D = open('system.mld.delta','rb').read()
B12 = os.path.expanduser('~/mf286d-work/evidence/modem-fw-re/live-b12/dumps/mtd16-extract/375765971/rootfs')
OUT = 'b14-rootfs'

def bspatch_v4(old, patch):
    ctrl_len, diff_len, new_size = struct.unpack_from('<QQQ', patch, 8)
    ctrl = patch[32:32+ctrl_len]; diff = patch[32+ctrl_len:32+ctrl_len+diff_len]
    extra = patch[32+ctrl_len+diff_len:]
    out = bytearray(); dp = ep = 0; oldpos = 0; idx = 0
    for k in range(0, ctrl_len, 24):
        x, y, zq = struct.unpack_from('<qqq', ctrl, k)
        z = zq & 0xFFFFFFFF; flag = (zq >> 32) & 0xFFFFFFFF
        base = 0 if idx == 0 else oldpos + (-z if flag else z)
        for i in range(x):
            b = old[base+i] if 0 <= base+i < len(old) else 0
            out.append((b + diff[dp]) & 0xFF); dp += 1
        for _ in range(y):
            out.append(extra[ep]); ep += 1
        oldpos = base + x; idx += 1
        if len(out) > new_size: return None, 'overflow'
    if len(out) != new_size: return bytes(out), f'size{len(out)}!={new_size}'
    return bytes(out), ('ok' if dp == diff_len else f'd{dp}/{diff_len}')

if os.path.exists(OUT): shutil.rmtree(OUT)
subprocess.run(['cp','-a',B12,OUT], check=True)
off = 0x2C
stats = dict(dir=0, patched=0, full=0, raw=0, new=0, zdfu=0, fail=0, warn=0)
fails = []
while off + 12 <= len(D):
    A, B_, plen = struct.unpack_from('>III', D, off)
    if plen < 4 or plen > 300: break
    path = D[off+12:off+12+plen].split(b'\0')[0].decode('latin1')
    if not path: break
    p = off + 12 + plen
    bl = struct.unpack_from('>I', D, p)[0]
    blob = D[p+4:p+4+bl+4]
    off = p + 4 + bl
    if not path.endswith('.p'): continue
    rel = path.replace('system.mld/mnt/system/','')[:-2]
    if len(blob) < 8: stats['dir'] += 1; continue
    if blob[4:8] == b'ZDFU': stats['zdfu'] += 1; continue
    if blob[4:5] == b'\x5d':
        ds = struct.unpack_from('<I', blob, 5)[0]
        if ds == 0 or ds > (1<<28): ds = 1<<22
        try:
            dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{'id':lzma.FILTER_LZMA1,'dict_size':ds}])
            content = dec.decompress(blob[9:], max_length=1<<27)
        except lzma.LZMAError as e:
            stats['fail'] += 1; fails.append((rel, f'lzma {e}')); continue
    else:
        sz = struct.unpack_from('>I', blob, 0)[0]
        content = blob[4:4+sz]; stats['raw'] += 1
    dst = os.path.join(OUT, rel); os.makedirs(os.path.dirname(dst), exist_ok=True)
    src12 = os.path.join(B12, rel)
    if content[:8] == b'BSDIFF40':
        if not os.path.exists(src12):
            stats['fail'] += 1; fails.append((rel,'no base')); continue
        new, st = bspatch_v4(open(src12,'rb').read(), content)
        if new is None:
            stats['fail'] += 1; fails.append((rel, st)); continue
        if st != 'ok': stats['warn'] += 1
        open(dst,'wb').write(new); stats['patched'] += 1
    else:
        open(dst,'wb').write(content)
        stats['full' if os.path.exists(src12) else 'new'] += 1
print(stats)
for f in fails[:20]: print(" FAIL:", f)
