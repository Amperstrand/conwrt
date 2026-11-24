"""Tests for fw_string_xrefs (#763 P2 — RE/parsing tools drift silently).

Synthesizes tiny ARM32-image-like blobs and pins the literal-pool xref
mechanic the tool exists for: a string whose address appears as a 4-byte
LE literal is CODE-REFERENCED; an occurrence with no pool hit is inert
data (the embedded-default-env discriminator from the AP3915i work).
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fw_string_xrefs as x  # noqa: E402

STR = b"V01.00.00.10"


class TestFindAll:
    def test_multiple_hits_in_order(self):
        blob = b"xx" + STR + b"yy" + STR + b"zz"
        assert x.find_all(blob, STR) == [2, 2 + len(STR) + 2]

    def test_no_hit(self):
        assert x.find_all(b"nothing here", STR) == []

    def test_overlapping_reported(self):
        # find(needle, i + 1) advances ONE byte — self-overlapping needles
        # ARE all reported (harmless for the tool's discriminator purpose).
        assert x.find_all(b"aaaa", b"aa") == [0, 1, 2]


class TestPoolRefs:
    def test_literal_found(self):
        addr = 0x84000100
        blob = struct.pack("<I", addr) + b"\x00" * 16 + struct.pack("<I", addr)
        assert x.pool_refs(blob, addr) == [0, 20]

    def test_endianness_matters(self):
        blob = struct.pack(">I", 0x84000100)  # BE literal must NOT match
        assert x.pool_refs(blob, 0x84000100) == []


class TestMain:
    def run(self, tmp_path, blob: bytes, *extra: str):
        img = tmp_path / "fw.bin"
        img.write_bytes(blob)
        saved = sys.argv
        sys.argv = ["fw_string_xrefs", str(img), STR.decode(), *extra]
        import io
        import contextlib
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = x.main()
        finally:
            sys.argv = saved
        return rc, out.getvalue()

    def build(self, referenced_off: int, inert_off: int) -> bytes:
        # referenced occurrence carries a base-0 pool literal of its own offset;
        # the inert occurrence has none anywhere.
        pool = struct.pack("<I", referenced_off)
        blob = bytearray(0x200)
        blob[referenced_off:referenced_off + len(STR)] = STR
        blob[inert_off:inert_off + len(STR)] = STR
        blob[0x180:0x184] = pool
        return bytes(blob)

    def test_referenced_vs_inert_discrimination(self, tmp_path):
        rc, out = self.run(tmp_path, self.build(referenced_off=0x40, inert_off=0xC0))
        assert rc == 0
        assert "offset 0x40" in out and "offset 0xc0" in out
        assert "self-address-pool-refs(base 0): 1 at 0x180" in out, \
            "referenced occurrence must show its pool hit"
        assert "inert data" in out, "unreferenced occurrence must be named inert"

    def test_base_arithmetic(self, tmp_path):
        # With --base B, the tool looks for literals equal to (offset + B).
        base = 0x84000000
        off = 0x40
        blob = bytearray(0x200)
        blob[off:off + len(STR)] = STR
        blob[0x180:0x184] = struct.pack("<I", off + base)
        rc, out = self.run(tmp_path, bytes(blob), f"--base={hex(base)}")
        assert rc == 0
        assert f"vaddr 0x{off + base:x}" in out
        assert "pool ref" in out

    def test_missing_string_rc1(self, tmp_path):
        rc, out = self.run(tmp_path, b"\x00" * 64)
        assert rc == 1
        assert "not found" in out
