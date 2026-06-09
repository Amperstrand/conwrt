import importlib.util
import struct
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch


_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "gs1920_validate", _SCRIPTS / "gs1920-validate-zynos-openwrt.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["gs1920_validate"] = module
    spec.loader.exec_module(module)
    return module


gs = _load_validator()


def _make_header(
    addr=gs.EXPECTED_BOOT_ADDR,
    sig=b"SIG",
    type_=3,
    osize=0,
    csize=0,
    flags=0x40,
    ocsum=0,
    ccsum=0,
    ver=b"v1.00",
    mmap_addr=gs.EXPECTED_MMAP_ADDR,
):
    raw = bytearray(48)
    struct.pack_into(">I", raw, 0, addr)
    raw[4:6] = b"\x00\x00"
    raw[6:9] = sig
    raw[9] = type_
    struct.pack_into(">I", raw, 10, osize)
    struct.pack_into(">I", raw, 14, csize)
    raw[18] = flags
    raw[19] = 0
    struct.pack_into(">H", raw, 20, ocsum)
    struct.pack_into(">H", raw, 22, ccsum)
    raw[24:39] = ver.ljust(15, b"\0")[:15]
    struct.pack_into(">I", raw, 39, mmap_addr)
    raw[43:48] = b"\0" * 5
    return bytes(raw)


class TestInternetChecksumEven(TestCase):
    def test_empty_data(self):
        self.assertEqual(gs.internet_checksum(b""), 0)

    def test_single_word(self):
        self.assertEqual(gs.internet_checksum(b"\x00\x01"), 1)

    def test_two_words_no_overflow(self):
        self.assertEqual(gs.internet_checksum(b"\x00\x01\x00\x02"), 3)


class TestInternetChecksumOdd(TestCase):
    def test_odd_length_padded(self):
        self.assertEqual(gs.internet_checksum(b"\x00\x01\x00"), gs.internet_checksum(b"\x00\x01\x00\x00"))

    def test_odd_single_byte(self):
        self.assertEqual(gs.internet_checksum(b"\xFF"), 0xFF00)


class TestInternetChecksumOverflow(TestCase):
    def test_wraps_carry_when_sum_exceeds_16_bits(self):
        # 0xFFFF + 0x0001 = 0x10000 → carry → 0x0001
        result = gs.internet_checksum(b"\xFF\xFF\x00\x01")
        self.assertEqual(result, 0x0001)

    def test_multiple_carries(self):
        result = gs.internet_checksum(b"\xFF\xFF\xFF\xFF\x00\x02")
        # Each 0xFFFF accumulates: 0xFFFF, +0xFFFF wraps to 0xFFFF, +0x0002 = 0x10001 → 0x0002
        self.assertEqual(result, 0x0002)


class TestParseHeader(TestCase):
    def test_parses_well_formed_header(self):
        raw = _make_header(addr=0x80014000, type_=3, osize=1024, flags=0x40)
        h = gs.parse_header(raw, 0)
        self.assertEqual(h.addr, 0x80014000)
        self.assertEqual(h.sig, b"SIG")
        self.assertEqual(h.type, 3)
        self.assertEqual(h.osize, 1024)
        self.assertEqual(h.flags, 0x40)
        self.assertEqual(h.offset, 0)
        self.assertEqual(h.mmap_addr, gs.EXPECTED_MMAP_ADDR)

    def test_truncated_header_raises_value_error(self):
        raw = _make_header()[:40]
        with self.assertRaises(ValueError) as cm:
            gs.parse_header(raw, 0)
        self.assertIn("truncated", str(cm.exception))

    def test_version_strips_null_padding(self):
        raw = _make_header(ver=b"v2.50")
        h = gs.parse_header(raw, 0)
        self.assertEqual(h.ver, b"v2.50")


class TestFindSectionsEmpty(TestCase):
    def test_no_sig_marker_returns_empty_list(self):
        data = b"\x00" * 1000
        self.assertEqual(gs.find_sections(data), [])

    def test_sig_too_early_skipped(self):
        # SIG at offset < 6 → header offset would be negative
        data = b"\x00\x00SIG" + b"\x00" * 100
        self.assertEqual(gs.find_sections(data), [])


class TestFindSectionsValid(TestCase):
    def test_one_valid_section_at_offset_zero(self):
        hdr = _make_header(type_=3)
        data = hdr + b"\x00" * 1000
        sections = gs.find_sections(data)
        self.assertEqual(len(sections), 1)
        self.assertEqual(sections[0].offset, 0)
        self.assertEqual(sections[0].type, 3)

    def test_multiple_valid_sections(self):
        hdr1 = _make_header(type_=3)
        hdr2 = _make_header(type_=4)
        # pad to offset 0x100 between sections
        data = hdr1 + b"\x00" * (0x100 - 48) + hdr2 + b"\x00" * 100
        sections = gs.find_sections(data)
        self.assertEqual(len(sections), 2)
        self.assertEqual(sections[0].offset, 0)
        self.assertEqual(sections[1].offset, 0x100)
        self.assertEqual(sections[1].type, 4)

    def test_wrong_section_type_skipped(self):
        # type=99 is not in (3, 4), so the section should be filtered out
        hdr = _make_header(type_=99)
        data = hdr + b"\x00" * 100
        sections = gs.find_sections(data)
        self.assertEqual(len(sections), 0)


class TestFail(TestCase):
    def test_prints_and_raises_systemexit(self):
        with self.assertRaises(SystemExit) as cm:
            gs.fail("test failure")
        self.assertEqual(cm.exception.code, 1)


class TestCheck(TestCase):
    def test_true_condition_prints_ok(self, capsys=None):
        # No exception
        gs.check(True, "passing assertion")

    def test_false_condition_fails(self):
        with self.assertRaises(SystemExit) as cm:
            gs.check(False, "failing assertion")
        self.assertEqual(cm.exception.code, 1)


class TestMainImageTooLarge(TestCase):
    def test_image_exceeding_slot_gap_fails(self):
        oversized = b"\x00" * (gs.EXPECTED_SLOT_GAP + 1)
        with patch.object(Path, "read_bytes", return_value=oversized):
            argv = ["gs1920-validate-zynos-openwrt.py", "/tmp/fake.bin"]
            with patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit) as cm:
                    gs.main()
                self.assertEqual(cm.exception.code, 1)


class TestMainWrongSectionCount(TestCase):
    def test_zero_sections_fails(self):
        data = b"\x00" * 1024
        with patch.object(Path, "read_bytes", return_value=data):
            argv = ["gs1920-validate-zynos-openwrt.py", "/tmp/fake.bin"]
            with patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit) as cm:
                    gs.main()
                self.assertEqual(cm.exception.code, 1)

    def test_single_section_fails_three_required(self):
        hdr = _make_header(type_=3)
        data = hdr + b"\x00" * 1000
        with patch.object(Path, "read_bytes", return_value=data):
            argv = ["gs1920-validate-zynos-openwrt.py", "/tmp/fake.bin"]
            with patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit) as cm:
                    gs.main()
                self.assertEqual(cm.exception.code, 1)


class TestMainArgParsing(TestCase):
    def test_missing_image_argument_exits(self):
        argv = ["gs1920-validate-zynos-openwrt.py"]
        with patch.object(sys, "argv", argv):
            with self.assertRaises(SystemExit):
                gs.main()


class TestConstants(TestCase):
    def test_expected_constants(self):
        self.assertEqual(gs.ROMBIN_HDR_SIZE, 48)
        self.assertEqual(gs.EXPECTED_SLOT_GAP, 0x800000)
        self.assertEqual(gs.EXPECTED_BOOT_ADDR, 0x80014000)
        self.assertEqual(gs.EXPECTED_MMAP_ADDR, 0xB40E0000)
        self.assertEqual(gs.EXPECTED_RASCODE_OFFSET, 0x0B2400)
        self.assertEqual(gs.EXPECTED_UIMAGE_LOAD, 0x80100000)
        self.assertEqual(gs.EXPECTED_UIMAGE_ENTRY, 0x80100000)


class TestRombinHeaderDataclass(TestCase):
    def test_frozen_dataclass_immutable(self):
        import dataclasses
        h = gs.RombinHeader(
            offset=0, addr=0, sig=b"SIG", type=3, osize=0, csize=0,
            flags=0, ocsum=0, ccsum=0, ver=b"v1", mmap_addr=0,
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            h.offset = 99
