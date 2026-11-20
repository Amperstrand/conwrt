def bspatch(old, patch):
    """ZTE BSDIFF40 variant — PROVEN semantics:
    - entry[0] reads from old[0] (its z applies after the run like others' cumulation)
    - z (low u32) = seek applied BEFORE the run: flag 0x80000000 => backward
    - x = add-run, y = extra/literal-run
    """
    import struct
    ctrl_len, diff_len, new_size = struct.unpack_from('<QQQ', patch, 8)
    ctrl = patch[32:32+ctrl_len]; diff = patch[32+ctrl_len:32+ctrl_len+diff_len]
    extra = patch[32+ctrl_len+diff_len:]
    out = bytearray(); dp = ep = 0; oldpos = 0; idx = 0
    for k in range(0, ctrl_len, 24):
        x, y, zq = struct.unpack_from('<qqq', ctrl, k)
        z = zq & 0xFFFFFFFF; flag = (zq >> 32) & 0xFFFFFFFF
        base = 0 if idx == 0 else oldpos + (-z if flag else z)
        if base < 0 or base + x > len(old):
            return None, f'range {base}+{x} vs {len(old)} @entry{idx}'
        for i in range(x):
            out.append((old[base+i] + diff[dp]) & 0xFF); dp += 1
        for _ in range(y):
            out.append(extra[ep]); ep += 1
        oldpos = base + x
        idx += 1
        if len(out) > new_size: return None, 'overflow'
    if len(out) != new_size:
        return bytes(out), f'size {len(out)}!={new_size}'
    return bytes(out), ('ok' if dp == diff_len else f'diff {dp}/{diff_len}')
