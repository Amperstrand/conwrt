from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import TestCase

_scripts = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_scripts))

from serial_baud import score_baud_data, detect_boot_stage  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "serial_console",
    _scripts / "serial-console.py",
)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

identify_adapter = _mod.identify_adapter


class TestScoreBaudData(TestCase):
    def test_empty_data(self):
        score, reason = score_baud_data(b"")
        assert score == 0
        assert "no data" in reason

    def test_valid_ascii_boot_log(self):
        data = b"U-Boot 2021.07 (Jan 01 2022)\nBooting from NAND...\n"
        score, reason = score_baud_data(data)
        assert score > 100, f"Expected high score for valid boot text, got {score}"
        assert "patterns=2" in reason

    def test_garbage_data_low_score(self):
        data = bytes(range(256))
        score, _ = score_baud_data(data)
        assert score < 50, f"Expected low score for all-bytes garbage, got {score}"

    def test_null_bytes_penalized(self):
        data = b"\x00\xff\x80\xfe\x01\x7f\xa5\x5a" * 15
        score, _ = score_baud_data(data)
        assert score < 30, f"Expected heavy penalty for error-byte data, got {score}"

    def test_printable_run_bonus(self):
        short_run = b"Ab\n" * 20
        long_run = b"U-Boot 2021.07 started\n" * 5
        score_short, _ = score_baud_data(short_run)
        score_long, _ = score_baud_data(long_run)
        assert score_long > score_short

    def test_newline_bonus(self):
        with_newlines = b"line1\nline2\nline3\n"
        without_newlines = b"line1line2line3"
        score_nl, _ = score_baud_data(with_newlines)
        score_no, _ = score_baud_data(without_newlines)
        assert score_nl > score_no

    def test_boot_pattern_match(self):
        data = b"Z-LOADER V1.30\nMultiboot Listening...\n"
        score, reason = score_baud_data(data)
        assert score > 100
        assert "patterns=" in reason

    def test_high_bit_bytes_penalized(self):
        data = b"Hello\x80\x90\xA0\xB0\xC0\xD0\xE0\xF0" * 5
        score, _ = score_baud_data(data)
        assert score < 80


class TestDetectBootStage(TestCase):
    def test_uboot_detected(self):
        data = b"U-Boot 2021.07 (Apr 01 2022)"
        assert detect_boot_stage(data) == "uboot"

    def test_zloader_detected(self):
        data = b"Z-LOADER V1.30\n"
        assert detect_boot_stage(data) == "zloader"

    def test_kernel_detected(self):
        data = b"[    0.000000] Linux version 5.10"
        assert detect_boot_stage(data) == "kernel"

    def test_openwrt_detected(self):
        data = b"Starting OpenWrt...\nBusyBox v1.36"
        assert detect_boot_stage(data) == "openwrt"

    def test_panic_detected(self):
        data = b"Kernel panic - not syncing: Attempted to kill init"
        assert detect_boot_stage(data) == "panic"

    def test_unknown_stays_current(self):
        assert detect_boot_stage(b"random data") == "unknown"
        assert detect_boot_stage(b"random", "kernel") == "kernel"


class TestIdentifyAdapter(TestCase):
    def test_ftdi_ft232r(self):
        result = identify_adapter("0403", "6001")
        assert "FTDI FT232R" in result

    def test_cp210x(self):
        result = identify_adapter("10C4", "EA60")
        assert "CP210x" in result

    def test_ch340(self):
        result = identify_adapter("1A86", "7523")
        assert "CH340" in result

    def test_unknown_ftdi_pid(self):
        result = identify_adapter("0403", "9999")
        assert "FTDI" in result
        assert "9999" in result

    def test_completely_unknown(self):
        result = identify_adapter("FFFF", "FFFF")
        assert result == ""

    def test_empty_vid_pid(self):
        assert identify_adapter("", "") == ""
