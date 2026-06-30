from __future__ import annotations

import sys
from pathlib import Path
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from checksum_utils import internet_checksum


class TestInternetChecksum(TestCase):
    def test_empty_data(self):
        assert internet_checksum(b"") == 0

    def test_single_byte(self):
        assert internet_checksum(b"\xFF") == 0xFF00

    def test_two_bytes(self):
        assert internet_checksum(b"\x00\x01") == 1

    def test_sum_no_carry(self):
        assert internet_checksum(b"\x00\x01\x00\x02") == 3

    def test_carry_fold(self):
        assert internet_checksum(b"\xFF\xFF\x00\x01") == 0x0001

    def test_all_ones(self):
        assert internet_checksum(b"\xFF\xFF\xFF\xFF") == 0xFFFF

    def test_odd_length_padding(self):
        assert internet_checksum(b"\x00\x01\x00") == internet_checksum(b"\x00\x01\x00\x00")

    def test_known_data(self):
        data = bytes(range(256))
        result = internet_checksum(data)
        assert 0 <= result <= 0xFFFF

    def test_repeated_consistency(self):
        data = b"\x12\x34\x56\x78"
        assert internet_checksum(data) == internet_checksum(data)

    def test_large_data(self):
        data = b"\x00\x01" * 1000
        result = internet_checksum(data)
        assert result == 1000

    def test_returns_int(self):
        assert isinstance(internet_checksum(b"\x00\x01"), int)

    def test_max_value(self):
        assert internet_checksum(b"\xFF\xFF") == 0xFFFF
