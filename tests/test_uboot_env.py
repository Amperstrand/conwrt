"""Tests for UbootEnvBlock — U-Boot environment block parser/writer."""
import struct
import tempfile
import zlib
from pathlib import Path
from unittest import TestCase

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from uboot_env import UbootEnvBlock


def _build_block(
    vars_dict: dict,
    block_size: int = 4096,
    crc_offset: int = 4,
    padding: int = 0xFF,
    flag_byte: bytes = b"",
) -> bytes:
    """Build a valid U-Boot env block with correct CRC."""
    parts = [f"{k}={v}".encode("ascii") for k, v in vars_dict.items()]
    content = b"\x00".join(parts)
    if parts:
        content += b"\x00"
    payload_len = block_size - crc_offset - len(content)
    if payload_len < 0:
        raise ValueError("vars too large for block_size")
    payload = content + bytes([padding] * payload_len)
    crc = struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)
    header_mid = flag_byte if flag_byte else b"\x00" * (crc_offset - 4) if crc_offset > 4 else b""
    return crc + header_mid + payload


class TestFromBytesParsing(TestCase):
    """Tests for UbootEnvBlock.from_bytes()."""

    def test_minimal_valid_block(self):
        data = _build_block({"bootcmd": "bootm"})
        env = UbootEnvBlock.from_bytes(data)
        self.assertEqual(env.get("bootcmd"), "bootm")

    def test_crc_offset_5_ap3915i(self):
        data = _build_block({"ethaddr": "00:11:22:33:44:55"}, crc_offset=5, flag_byte=b"\x01")
        env = UbootEnvBlock.from_bytes(data, crc_offset=5)
        self.assertEqual(env.get("ethaddr"), "00:11:22:33:44:55")

    def test_multiple_variables(self):
        vars_dict = {
            "bootcmd": "bootm 0x9f020000",
            "bootdelay": "2",
            "baudrate": "115200",
            "ethaddr": "00:aa:bb:cc:dd:ee",
        }
        data = _build_block(vars_dict)
        env = UbootEnvBlock.from_bytes(data)
        for k, v in vars_dict.items():
            self.assertEqual(env.get(k), v)

    def test_empty_block_all_ff(self):
        data = bytes([0xFF] * 4096)
        env = UbootEnvBlock.from_bytes(data)
        self.assertIsNone(env.get("anything"))
        self.assertEqual(env.keys(), [])

    def test_value_with_equals_sign(self):
        data = _build_block({"myvar": "a=b=c"})
        env = UbootEnvBlock.from_bytes(data)
        self.assertEqual(env.get("myvar"), "a=b=c")

    def test_value_with_spaces(self):
        data = _build_block({"bootargs": "console=ttyS0,115200 root=/dev/mtdblock2"})
        env = UbootEnvBlock.from_bytes(data)
        self.assertEqual(env.get("bootargs"), "console=ttyS0,115200 root=/dev/mtdblock2")

    def test_single_variable(self):
        data = _build_block({"singleton": "val"})
        env = UbootEnvBlock.from_bytes(data)
        self.assertEqual(env.keys(), ["singleton"])
        self.assertEqual(env.get("singleton"), "val")

    def test_crc_offset_preserved(self):
        data = _build_block({"x": "1"}, crc_offset=5, flag_byte=b"\x00")
        env = UbootEnvBlock.from_bytes(data, crc_offset=5)
        output = env.to_bytes()
        self.assertEqual(len(output), len(data))

    def test_block_size_preserved(self):
        data = _build_block({"a": "b"}, block_size=8192)
        env = UbootEnvBlock.from_bytes(data)
        self.assertEqual(len(env.to_bytes()), 8192)


class TestGetSetDeleteKeys(TestCase):
    """Tests for get(), set(), delete(), keys()."""

    def _env(self, **kwargs):
        data = _build_block(kwargs)
        return UbootEnvBlock.from_bytes(data)

    def test_get_existing_key(self):
        env = self._env(bootcmd="bootm")
        self.assertEqual(env.get("bootcmd"), "bootm")

    def test_get_missing_key_returns_none(self):
        env = self._env(bootcmd="bootm")
        self.assertIsNone(env.get("nonexistent"))

    def test_set_new_key(self):
        env = self._env()
        env.set("newkey", "newval")
        self.assertEqual(env.get("newkey"), "newval")

    def test_set_updates_existing_key(self):
        env = self._env(delay="2")
        env.set("delay", "5")
        self.assertEqual(env.get("delay"), "5")

    def test_delete_existing_key_returns_true(self):
        env = self._env(bootcmd="bootm", baudrate="115200")
        self.assertTrue(env.delete("bootcmd"))
        self.assertIsNone(env.get("bootcmd"))
        self.assertEqual(env.get("baudrate"), "115200")

    def test_delete_missing_key_returns_false(self):
        env = self._env(bootcmd="bootm")
        self.assertFalse(env.delete("nonexistent"))

    def test_keys_returns_all_names(self):
        env = self._env(a="1", b="2", c="3")
        self.assertEqual(sorted(env.keys()), ["a", "b", "c"])

    def test_keys_empty(self):
        data = bytes([0xFF] * 4096)
        env = UbootEnvBlock.from_bytes(data)
        self.assertEqual(env.keys(), [])


class TestValidateCRC(TestCase):
    """Tests for validate_crc()."""

    def test_valid_block_passes(self):
        data = _build_block({"bootcmd": "bootm"})
        env = UbootEnvBlock.from_bytes(data)
        self.assertTrue(env.validate_crc())

    def test_corrupted_block_fails(self):
        data = bytearray(_build_block({"bootcmd": "bootm"}))
        # Corrupt CRC bytes — header is bytes 0..3
        data[0] ^= 0xFF
        env = UbootEnvBlock.from_bytes(bytes(data))
        self.assertFalse(env.validate_crc())

    def test_mutated_vars_invalidate_crc(self):
        data = _build_block({"bootcmd": "bootm"})
        env = UbootEnvBlock.from_bytes(data)
        self.assertTrue(env.validate_crc())
        env.set("bootcmd", "bootz")
        self.assertFalse(env.validate_crc())
        out = env.to_bytes()
        env2 = UbootEnvBlock.from_bytes(out)
        self.assertTrue(env2.validate_crc())
        self.assertEqual(env2.get("bootcmd"), "bootz")

    def test_corrupted_crc_fails(self):
        data = bytearray(_build_block({"bootcmd": "bootm"}))
        data[0] ^= 0xFF  # flip a byte in the CRC
        env = UbootEnvBlock.from_bytes(bytes(data))
        self.assertFalse(env.validate_crc())

    def test_crc_offset_5_valid(self):
        data = _build_block({"x": "y"}, crc_offset=5, flag_byte=b"\x01")
        env = UbootEnvBlock.from_bytes(data, crc_offset=5)
        self.assertTrue(env.validate_crc())

    def test_crc_offset_5_corrupted_crc_fails(self):
        data = bytearray(_build_block({"x": "y"}, crc_offset=5, flag_byte=b"\x01"))
        data[1] ^= 0xFF
        env = UbootEnvBlock.from_bytes(bytes(data), crc_offset=5)
        self.assertFalse(env.validate_crc())

    def test_empty_block_crc(self):
        # All 0xFF block — CRC of all-FF payload
        payload = bytes([0xFF] * (4096 - 4))
        expected_crc = struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)
        data = expected_crc + payload
        env = UbootEnvBlock.from_bytes(data)
        self.assertTrue(env.validate_crc())

    def test_tiny_block_too_small(self):
        # block_size < crc_offset + 4 should fail
        data = b"\x00" * 6
        env = UbootEnvBlock.from_bytes(data)
        self.assertFalse(env.validate_crc())


class TestToBytesRoundtrip(TestCase):
    """Tests for to_bytes() and roundtrip fidelity."""

    def test_parse_serialize_parse_same_vars(self):
        original = {"bootcmd": "bootm 0x9f020000", "baudrate": "115200", "bootdelay": "3"}
        data = _build_block(original)
        env1 = UbootEnvBlock.from_bytes(data)
        roundtrip = env1.to_bytes()
        env2 = UbootEnvBlock.from_bytes(roundtrip)
        for k, v in original.items():
            self.assertEqual(env2.get(k), v)

    def test_to_bytes_produces_valid_crc(self):
        data = _build_block({"a": "1", "b": "2"})
        env = UbootEnvBlock.from_bytes(data)
        output = env.to_bytes()
        env2 = UbootEnvBlock.from_bytes(output)
        self.assertTrue(env2.validate_crc())

    def test_block_size_preserved_through_roundtrip(self):
        for size in [4096, 8192, 65536]:
            data = _build_block({"k": "v"}, block_size=size)
            env = UbootEnvBlock.from_bytes(data)
            self.assertEqual(len(env.to_bytes()), size)

    def test_crc_offset_preserved_through_roundtrip(self):
        data = _build_block({"x": "y"}, crc_offset=5, flag_byte=b"\x42")
        env = UbootEnvBlock.from_bytes(data, crc_offset=5)
        output = env.to_bytes()
        env2 = UbootEnvBlock.from_bytes(output, crc_offset=5)
        self.assertTrue(env2.validate_crc())
        self.assertEqual(env2.get("x"), "y")

    def test_modified_vars_produce_valid_crc(self):
        data = _build_block({"a": "1"})
        env = UbootEnvBlock.from_bytes(data)
        env.set("a", "2")
        env.set("b", "3")
        output = env.to_bytes()
        env2 = UbootEnvBlock.from_bytes(output)
        self.assertTrue(env2.validate_crc())
        self.assertEqual(env2.get("a"), "2")
        self.assertEqual(env2.get("b"), "3")

    def test_deleted_var_absent_in_roundtrip(self):
        data = _build_block({"keep": "yes", "remove": "no"})
        env = UbootEnvBlock.from_bytes(data)
        env.delete("remove")
        output = env.to_bytes()
        env2 = UbootEnvBlock.from_bytes(output)
        self.assertEqual(env2.get("keep"), "yes")
        self.assertIsNone(env2.get("remove"))


class TestWriteFileAndFromFile(TestCase):
    """Tests for write_file() and from_file()."""

    def test_write_and_read_back(self):
        original = {"bootcmd": "bootm", "baudrate": "115200"}
        data = _build_block(original)
        env1 = UbootEnvBlock.from_bytes(data)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            path = f.name

        try:
            env1.write_file(path)
            env2 = UbootEnvBlock.from_file(path)
            for k, v in original.items():
                self.assertEqual(env2.get(k), v)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_write_read_crc_offset_5(self):
        original = {"ethaddr": "00:11:22:33:44:55"}
        data = _build_block(original, crc_offset=5, flag_byte=b"\x01")
        env1 = UbootEnvBlock.from_bytes(data, crc_offset=5)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            path = f.name

        try:
            env1.write_file(path)
            env2 = UbootEnvBlock.from_file(path, crc_offset=5)
            self.assertTrue(env2.validate_crc())
            self.assertEqual(env2.get("ethaddr"), "00:11:22:33:44:55")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_write_modified_preserves_vars(self):
        data = _build_block({"old": "value"})
        env = UbootEnvBlock.from_bytes(data)
        env.set("old", "new")
        env.set("added", "yes")

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            path = f.name

        try:
            env.write_file(path)
            env2 = UbootEnvBlock.from_file(path)
            self.assertEqual(env2.get("old"), "new")
            self.assertEqual(env2.get("added"), "yes")
            self.assertTrue(env2.validate_crc())
        finally:
            Path(path).unlink(missing_ok=True)


class TestEdgeCases(TestCase):
    """Edge cases and boundary conditions."""

    def test_long_variable_value(self):
        long_val = "A" * 1024
        data = _build_block({"longvar": long_val}, block_size=8192)
        env = UbootEnvBlock.from_bytes(data)
        self.assertEqual(env.get("longvar"), long_val)

    def test_long_variable_name(self):
        long_key = "K" * 256
        data = _build_block({long_key: "val"}, block_size=8192)
        env = UbootEnvBlock.from_bytes(data)
        self.assertEqual(env.get(long_key), "val")

    def test_value_with_multiple_equals(self):
        # Only first = is delimiter
        data = _build_block({"cmd": "setenv a=b; setenv c=d"})
        env = UbootEnvBlock.from_bytes(data)
        self.assertEqual(env.get("cmd"), "setenv a=b; setenv c=d")

    def test_crc_offset_5_no_vars(self):
        # Block with flag byte but no variables
        payload = bytes([0xFF] * (4096 - 5))
        crc = struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)
        data = crc + b"\x42" + payload
        env = UbootEnvBlock.from_bytes(data, crc_offset=5)
        self.assertEqual(env.keys(), [])
        self.assertTrue(env.validate_crc())

    def test_variable_with_hex_value(self):
        data = _build_block({"loadaddr": "0x9f020000"})
        env = UbootEnvBlock.from_bytes(data)
        self.assertEqual(env.get("loadaddr"), "0x9f020000")

    def test_empty_value(self):
        # KEY= with empty value — eq == len("KEY") which is > 0, value is ""
        raw = b"\x00".join([b"KEY="]) + b"\x00"
        raw += bytes([0xFF] * (4096 - 4 - len(raw)))
        crc = struct.pack("<I", zlib.crc32(raw) & 0xFFFFFFFF)
        data = crc + raw
        env = UbootEnvBlock.from_bytes(data)
        self.assertEqual(env.get("KEY"), "")

    def test_fresh_env_set_and_roundtrip(self):
        """Build a block from scratch via to_bytes and verify roundtrip."""
        # Start from empty, set vars, serialize
        empty_data = bytes([0xFF] * 4096)
        env = UbootEnvBlock.from_bytes(empty_data)
        env.set("a", "1")
        env.set("b", "2")
        output = env.to_bytes()
        env2 = UbootEnvBlock.from_bytes(output)
        self.assertEqual(env2.get("a"), "1")
        self.assertEqual(env2.get("b"), "2")
        self.assertTrue(env2.validate_crc())
