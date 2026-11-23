#!/usr/bin/env python3
"""ZTE ZFD01.02 delta extractor (B12->B14 modem.mld).
Format (proven on Ver_Info.txt):
  outer: header "ZFD01.02" + fields + 163 interleaved entries + trailer blob
  entry: [A u32BE][B u32BE][plen u32BE][path+NUL][blob]
  blob:  [blob_len u32BE = LZMA stream len][patch_len u32BE][LZMA1: 0x5d+dict(LE)+data]
         -> BSDIFF40 patch  (big files: ZDFU chunk table variant)
"""
import struct, lzma, sys, os

def lzma_raw(data, dict_size):
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
          filters=[{'id': lzma.FILTER_LZMA1, 'dict_size': dict_size}])
    try:
        return dec.decompress(data, max_length=1<<26), True
    except lzma.LZMAError:
        # try to salvage partial output
        return b'', False

def parse_blob(blob):
    """blob = d[p+4 : p+4+blob_len]; returns dict with patch or zdfu info."""
    if len(blob) < 8: return {'type': 'empty'}
    if blob[4:5] == b'\x5d':           # plain LZMA->BSDIFF40
        dict_size = struct.unpack_from('<I', blob, 5)[0]
        stream = blob[9:]
        patch, ok = lzma_raw(stream, dict_size)
        return {'type': 'lzma-bsdiff', 'patch': patch, 'ok': ok,
                'declared': struct.unpack_from('>I', blob, 0)[0], 'dict': dict_size}
    if blob[4:8] == b'ZDFU':
        ver, flags, nrec = struct.unpack_from('>III', blob, 8)
        return {'type': 'ZDFU', 'ver': ver, 'flags': flags, 'nrec': nrec,
                'declared': struct.unpack_from('>I', blob, 0)[0], 'raw': blob}
    return {'type': 'unknown', 'head': blob[:16].hex()}

def main():
    d = open('modem.mld.delta','rb').read()
    off = 0x2C
    outdir = 'patches'; os.makedirs(outdir, exist_ok=True)
    results = []
    for i in range(163):
        A, B, plen = struct.unpack_from('>III', d, off)
        assert 4 < plen < 200, f"bad plen {plen} at 0x{off:x}"
        path = d[off+12:off+12+plen].split(b'\0')[0].decode('latin1')
        p = off + 12 + plen
        blob_len = struct.unpack_from('>I', d, p)[0]
        blob = d[p+4 : p+4+blob_len]
        r = parse_blob(blob)
        r.update(dict(idx=i, path=path, A=A, B=B, blob_len=blob_len))
        results.append(r)
        off = p + 4 + blob_len
    # trailer blob (pathless)
    tr_blob_len = struct.unpack_from('>I', d, off)[0]
    tr_blob = d[off+4:off+4+tr_blob_len]
    print(f"trailer at 0x{off:x}: {tr_blob_len}B, head={tr_blob[:8].hex()}")
    tr = parse_blob(tr_blob); tr['path'] = '<TRAILER>'; results.append(tr)

    ok = sum(1 for r in results if r['type']=='lzma-bsdiff' and r['ok'])
    zdfu = sum(1 for r in results if r['type']=='ZDFU')
    unk = sum(1 for r in results if r['type'] in ('unknown','empty'))
    print(f"entries: {len(results)}  lzma-bsdiff ok: {ok}  ZDFU: {zdfu}  empty/unknown: {unk}")
    for r in results:
        if r['type'] == 'lzma-bsdiff':
            if r['ok'] and r['patch'][:8] == b'BSDIFF40':
                fn = r['path'].split('/')[-1][:-2] + '.bsdiff'
                open(os.path.join(outdir, fn), 'wb').write(r['patch'])
            else:
                print(f"  !! {r['path']}: ok={r['ok']} decl={r['declared']} got={len(r.get('patch',b''))} magic={r.get('patch',b'')[:8]}")
        elif r['type'] == 'ZDFU':
            print(f"  ZDFU: {r['path']} nrec={r['nrec']} declared={r['declared']}")
        elif r['type'] == 'unknown':
            print(f"  ??: {r['path']} head={r['head']}")
    import json
    with open('extract-report.json','w') as f:
        json.dump([{k:v for k,v in r.items() if k not in ('patch','raw')} for r in results], f, indent=1)
    print("report: extract-report.json")

if __name__ == '__main__':
    main()
