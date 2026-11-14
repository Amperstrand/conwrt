def bspatch_v2(old, patch):
    """BSDIFF40 variant: z_low32 = ABSOLUTE old position, z_high32 = flags."""
    import struct
    ctrl_len, diff_len, new_size = struct.unpack_from('<QQQ', patch, 8)
    ctrl = patch[32:32+ctrl_len]; diff = patch[32+ctrl_len:32+ctrl_len+diff_len]
    extra = patch[32+ctrl_len+diff_len:]
    out = bytearray(); dp = ep = cp = 0; n = len(ctrl)
    while cp + 24 <= n:
        x, y, zq = struct.unpack_from('<qqq', ctrl, cp); cp += 24
        z = zq & 0xFFFFFFFF
        if z + x > len(old):
            return None, f'old abs {z}+{x} > {len(old)}'
        base = z
        for i in range(x):
            out.append((old[base+i] + diff[dp]) & 0xFF); dp += 1
        for _ in range(y):
            out.append(extra[ep]); ep += 1
        if len(out) > new_size:
            return None, f'overflow {len(out)} > {new_size}'
    if len(out) != new_size:
        return bytes(out), f'size {len(out)} != {new_size}'
    if dp != diff_len or ep != len(extra):
        return bytes(out), f'consumed d:{dp}/{diff_len} e:{ep}/{len(extra)}'
    return bytes(out), 'ok'
