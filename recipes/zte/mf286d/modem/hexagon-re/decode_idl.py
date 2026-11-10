#!/usr/bin/env python3
"""QMI IDL encoded-TLV decoder — decodes request/response layouts of the
modem's extended UIM service object (0xc32c0650) from the pristine B12 image.

Format (from quic/qmi-framework qencdec/qmi_idl_lib.c):
  message blob = sequence of TLV descriptors:
    { u8 tlv_flags [, u8 tlv_type if OPTIONAL] } element...
      tlv_flags: 0x80=LAST_TLV, 0x40=OPTIONAL (then type byte follows);
                 if required: type = tlv_flags & 0x3F
    element = flags u8 [ext u8...] offset u8|u16 [arr_sz u8|u16] [varlen u8]
              [agg u16] [range 4B]
      flags: 0x80 OFFSET_IS_16, 0x40 IS_ARRAY, 0x20 MAX_SZ_IS_16/SZ_IS_16,
             0x10 VARIABLE_LEN, 0x08 FIRST_EXTENDED, 0x07 type
             types: 0=1B 1=2B 2=4B 3=8B 4=1Benum 5=2Benum 6=STRING 7=AGGREGATE
      extended flags byte (if FIRST_EXTENDED): 0x08 SECOND_EXTENDED,
             others: SZ_IS_32, EXTENDED_OFFSET, UTF16...
"""
import sys, struct, json
sys.path.insert(0, '.')
from vmap import Space

sp = Space()

TYPES = {0: 'u8', 1: 'u16', 2: 'u32', 3: 'u64', 4: 'enum8', 5: 'enum16', 6: 'string', 7: 'aggregate'}

def read_element(d, i):
    if i >= len(d): raise ValueError('eof')
    """returns (desc_dict, next_i)"""
    flags = d[i]; i += 1
    if flags & 0x08:  # FIRST_EXTENDED
        ext = d[i]; i += 1
    else:
        ext = 0
    # offset
    if flags & 0x80:
        off = struct.unpack_from('<H', d, i)[0]; i += 2
    else:
        off = d[i]; i += 1
    arr = None
    if flags & 0x40:  # IS_ARRAY
        if flags & 0x20:
            arr = struct.unpack_from('<H', d, i)[0]; i += 2
        else:
            arr = d[i]; i += 1
    varlen = None
    if (flags & 0x10) and ((flags & 7) != 6):
        varlen = d[i]; i += 1
    agg = None
    if (flags & 7) == 7:
        agg = struct.unpack_from('<H', d, i)[0]; i += 2
    return dict(flags=flags, off=off, arr=arr, varlen=varlen, agg=agg,
                t=TYPES[flags & 7]), i

def decode_msg_blob(blob):
    """decode the TLV list of a message encoding blob"""
    out = []
    i = 0
    while i < len(blob):
        tf = blob[i]; i += 1
        if tf == 0x00:  # end
            break
        last = bool(tf & 0x80)
        opt = bool(tf & 0x40)
        if opt:
            tlv_type = blob[i]; i += 1
            valid_off = tf & 0x3F
        else:
            tlv_type = tf & 0x3F
            valid_off = None
        try:
            el, i = read_element(blob, i)
        except (ValueError, IndexError):
            out.append(dict(tlv=tlv_type, optional=opt, last=last,
                            valid_off=valid_off, t='TRUNCATED', off=-1,
                            arr=None, varlen=None, agg=None))
            break
        out.append(dict(tlv=tlv_type, optional=opt, last=last,
                        valid_off=valid_off, **el))
        if last:
            break
    return out

def fmt_el(e):
    s = e['t']
    if e['arr'] is not None:
        s += f"[{e['arr']}]"
        if e['varlen'] is not None:
            s += " varlen"
    if e['t'] == 'aggregate':
        s += f" (type#{e['agg']})"
    s += f" @0x{e['off']:x}"
    if e['optional']:
        s += " OPT"
    return f"TLV 0x{e['tlv']:02x}: {s}"

def main():
    d = sp.read_vaddr(0xc32c0650, 48)
    n0, n1, n2 = struct.unpack_from('<HHH', d, 16)
    p0, p1, p2, ptt = struct.unpack_from('<IIII', d, 24)
    tt = sp.read_vaddr(ptt, 32)
    n_types, n_msgs = struct.unpack_from('<HH', tt, 0)
    n_refs = tt[4]
    p_types, p_msgs = struct.unpack_from('<II', tt, 8)
    p_refs, p_ranges = struct.unpack_from('<II', tt, 16)

    tabs = {}
    refs = sp.read_vaddr(p_refs, n_refs * 4) if p_refs and n_refs else b''
    ref_ptrs = [struct.unpack_from('<I', refs, k*4)[0] for k in range(n_refs)] if refs else []

    def msg_entry(tidx_and_flags):
        tidx = tidx_and_flags & 0xFFF
        tbl_flag = tidx_and_flags >> 12
        me = sp.read_vaddr(p_msgs + tidx*8, 8)
        if not me: return None
        csz, pd = struct.unpack('<II', me)
        blob = sp.read_vaddr(pd, 256) if pd else None
        return csz, blob, tbl_flag

    spec = {}
    for kind, tbl, cnt in (('REQ', p0, n0), ('RESP', p1, n1), ('IND', p2, n2)):
        td = sp.read_vaddr(tbl, cnt*6)
        for i in range(cnt):
            qid, tflags, ml = struct.unpack_from('<HHH', td, i*6)
            me = msg_entry(tflags)
            if not me: continue
            csz, blob, tflag = me
            entry = spec.setdefault(f"0x{qid:02x}", {})
            entry[kind] = dict(csz=csz, maxlen=ml,
                               tlvs=[{k: v for k, v in e.items()} for e in
                                     (decode_msg_blob(blob) if blob else [])])
    json.dump(spec, open('uim-protocol-spec.json', 'w'), indent=1)
    # human summary
    with open('uim-protocol-spec.txt', 'w') as f:
        for qid in sorted(spec, key=lambda x: int(x, 16)):
            f.write(f"=== msg {qid} ===\n")
            for kind in ('REQ', 'RESP', 'IND'):
                if kind in spec[qid]:
                    e = spec[qid][kind]
                    f.write(f"  {kind}: c_struct={e['csz']} maxlen={e['maxlen']}\n")
                    for t in e['tlvs']:
                        f.write(f"    {fmt_el(t)}\n")
    print(f"decoded {len(spec)} messages -> uim-protocol-spec.json/.txt")
    # highlight the hot ids
    for qid in ('0x65', '0x67', '0x4f', '0x53', '0x6b', '0x34', '0x27'):
        if qid in spec:
            print(f"\n=== {qid} ===")
            for kind in ('REQ', 'RESP', 'IND'):
                if kind in spec[qid]:
                    e = spec[qid][kind]
                    print(f"  {kind}: csz={e['csz']} ml={e['maxlen']}")
                    for t in e['tlvs']:
                        print(f"    {fmt_el(t)}")

if __name__ == '__main__':
    main()
