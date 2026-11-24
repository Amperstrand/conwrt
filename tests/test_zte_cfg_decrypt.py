"""Tests for zte_cfg_decrypt (#763 P2 — RE/parsing tools drift silently).

Pins the container format and the 3DES-CBC contract using round-trips
through the module's own key — no firmware blob needed:

- header: magic | crc32 (of bytes 8..end) | plainlen LE | IV(8) | ct
- decrypt() honors plainlen (truncates padding), rejects bad magic
- round-trip: encrypt with the module KEY → decrypt → byte-equal XML
- current-behavior pin: the crc32 field is NOT verified on decrypt
  (documented so a future fix is a deliberate change, not a surprise)
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from zte_cfg_decrypt import KEY, decrypt  # noqa: E402

try:
    from Crypto.Cipher import DES3  # noqa: E402
except ModuleNotFoundError:  # bench envs without the dev extra
    pytest.skip("pycryptodome not installed (dev extra; CI installs it)",
                allow_module_level=True)

PLAIN = b"<?xml version=\"1.0\"?><businesscfg><entry>VoIP</entry></businesscfg>"
MAGIC = bytes.fromhex("690e3214")


def pad_8(data: bytes) -> bytes:
    n = 8 - (len(data) % 8)
    return data + bytes([n]) * n


def build_container(plain: bytes, iv: bytes, *, magic: bytes = MAGIC,
                    crc: int | None = None, plen: int | None = None) -> bytes:
    ct = DES3.new(KEY, DES3.MODE_CBC, iv).encrypt(pad_8(plain))
    real_crc = zlib.crc32(b"") if False else zlib.crc32(struct.pack("<I", len(plain)) + iv + ct)
    header = magic + struct.pack("<I", real_crc if crc is None else crc) \
        + struct.pack("<I", len(plain) if plen is None else plen) + iv
    return header + ct


class TestRoundTrip:
    def test_roundtrip(self, tmp_path):
        f = tmp_path / "VOICE_DL.config"
        f.write_bytes(build_container(PLAIN, bytes(range(8))))
        assert decrypt(f) == PLAIN

    def test_plaintext_longer_than_one_block(self, tmp_path):
        long_xml = b"<cfg>" + b"x" * 200 + b"</cfg>"
        f = tmp_path / "BIG_DL.config"
        f.write_bytes(build_container(long_xml, b"\xa5" * 8))
        assert decrypt(f) == long_xml


class TestHeaderContract:
    def test_bad_magic_rejected(self, tmp_path):
        f = tmp_path / "bad.config"
        f.write_bytes(build_container(PLAIN, bytes(8), magic=b"DEADBEAF"))
        with pytest.raises(AssertionError, match="magic"):
            decrypt(f)

    def test_plen_truncates(self, tmp_path):
        # plainlen smaller than the plaintext: decrypt returns exactly plen bytes
        f = tmp_path / "trunc.config"
        f.write_bytes(build_container(PLAIN, bytes(8), plen=10))
        assert decrypt(f) == PLAIN[:10]

    def test_crc_field_not_verified(self, tmp_path):
        # CURRENT BEHAVIOR PIN: decrypt() ignores the crc32 field entirely —
        # a WRONG crc still decrypts cleanly (the field is metadata the
        # tool never gates on). If this starts failing, decrypt grew a CRC
        # gate: deliberate behavior change — update the pin + changelog.
        f = tmp_path / "badcrc.config"
        f.write_bytes(build_container(PLAIN, bytes(8), crc=0xDEADBEEF))
        assert decrypt(f) == PLAIN

    def test_iv_is_carried_in_header(self, tmp_path):
        # Same plaintext, two IVs -> different ciphertexts, both round-trip.
        a, b = tmp_path / "a.config", tmp_path / "b.config"
        a.write_bytes(build_container(PLAIN, bytes(range(8))))
        b.write_bytes(build_container(PLAIN, b"\x11" * 8))
        assert a.read_bytes()[20:] != b.read_bytes()[20:]
        assert decrypt(a) == decrypt(b) == PLAIN
