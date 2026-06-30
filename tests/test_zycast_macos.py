from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path
from unittest import TestCase

_scripts = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_scripts))

_spec = importlib.util.spec_from_file_location(
    "zycast_macos", _scripts / "zycast_macos.py",
)
assert _spec and _spec.loader
zm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zm)


class TestZycastConstants(TestCase):
    def test_magic_value(self):
        assert zm._MAGIC == 0x7A797800

    def test_header_size(self):
        assert zm._HEADER_SIZE == 30

    def test_chunk_size(self):
        assert zm._CHUNK_SIZE == 1024

    def test_type_ras(self):
        assert zm._TYPE_RAS == 0x04

    def test_header_format_size(self):
        assert struct.calcsize(zm._HEADER_FMT) == 30


class TestZycastHeader(TestCase):
    def test_header_pack_unpack_roundtrip(self):
        checksum = 0x1234
        packet_id = 42
        chunk_len = 1024
        file_len = 7616262
        header = struct.pack(
            zm._HEADER_FMT,
            zm._MAGIC,
            checksum,
            packet_id,
            chunk_len,
            file_len,
            0,
            zm._TYPE_RAS,
            zm._TYPE_RAS,
            b"FF",
            0x01,
            b"\x00" * 5,
        )
        assert len(header) == 30

        unpacked = struct.unpack(zm._HEADER_FMT, header)
        assert unpacked[0] == zm._MAGIC
        assert unpacked[1] == checksum
        assert unpacked[2] == packet_id
        assert unpacked[3] == chunk_len
        assert unpacked[4] == file_len
        assert unpacked[6] == zm._TYPE_RAS
        assert unpacked[8] == b"FF"

    def test_magic_is_zyx_null(self):
        magic_bytes = struct.pack("!I", zm._MAGIC)
        assert magic_bytes == b"zyx\x00"
