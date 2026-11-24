"""Tests for conwrt.mtd_readback — the classified readback gate (#776).

Pins the three verdicts as DISTINCT classes (erased-noop vs mismatch vs
match), the re-read-before-condemn contract, and the busybox-safe
on-device script shape (name-resolution via /proc/mtd, span-bounded
read, 0xFF probe). Also pins the flash.sh wiring by contract.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from conwrt.mtd_readback import (
    MtdReadbackVerdict,
    classify,
    parse_rb_line,
    should_condemn,
    verify_script_lines,
    verdict_message,
)

FLASH_SH = Path(__file__).resolve().parents[1] / "scripts" / "conwrt-lite" / "lib" / "flash.sh"

MATCH_SHA = "a" * 64
OTHER_SHA = "b" * 64


class TestClassify:
    def test_match(self):
        assert classify(MATCH_SHA, MATCH_SHA, 0) is MtdReadbackVerdict.MATCH

    def test_erased_noop_is_its_own_class(self):
        # The MF286D lockout class: not-the-image AND entirely 0xFF over the span.
        assert classify(MATCH_SHA, OTHER_SHA, 0) is MtdReadbackVerdict.ERASED_NOOP

    def test_mismatch(self):
        assert classify(MATCH_SHA, OTHER_SHA, 512) is MtdReadbackVerdict.MISMATCH

    def test_partial_write_span_semantics(self):
        # A partial-file write judges ONLY the image span — bytes past it
        # (legitimately 0xFF) never enter the verdict.
        assert classify(MATCH_SHA, MATCH_SHA, 0) is MtdReadbackVerdict.MATCH


class TestReReadContract:
    def test_match_never_condemns(self):
        assert should_condemn(MtdReadbackVerdict.MATCH, None) is False

    def test_erased_noop_condemns_immediately(self):
        # A clean erased span is deterministic evidence — waiting cannot improve it.
        assert should_condemn(MtdReadbackVerdict.ERASED_NOOP, None) is True

    def test_mismatch_requires_the_one_reread(self):
        assert should_condemn(MtdReadbackVerdict.MISMATCH, None) is False

    def test_mismatch_condemns_only_on_confirmed_reread(self):
        assert should_condemn(MtdReadbackVerdict.MISMATCH, MtdReadbackVerdict.MISMATCH) is True

    def test_mismatch_cleared_by_reread(self):
        # Transport corruption on the first read is not a flash defect.
        assert should_condemn(MtdReadbackVerdict.MISMATCH, MtdReadbackVerdict.MATCH) is False


class TestVerifyScript:
    def test_resolves_mtd_by_name_not_number(self):
        # AP3915i lesson: MTD numbering shifts between stock and OpenWrt.
        lines = verify_script_lines("CFG1", "/tmp/cfg1.bin")
        assert any('/proc/mtd' in ln and 'CFG1' in ln for ln in lines)
        assert not any(re.search(r"mtd\d", ln) for ln in lines)

    def test_busybox_only_and_span_bounded(self):
        lines = verify_script_lines("CFG1", "/tmp/cfg1.bin")
        joined = "\n".join(lines)
        assert 'head -c "$_span"' in joined          # span-bounded, not whole-partition
        assert 'tr -d "\\377"' in joined             # erased-pattern probe
        assert "sha256sum" in joined                 # BusyBox-baseline digest
        assert "md5sum" not in joined

    def test_emits_parseable_line(self):
        joined = "\n".join(verify_script_lines("CFG1", "/tmp/cfg1.bin"))
        assert "RB_SHA=" in joined and "RB_NONFF=" in joined


class TestParseRbLine:
    def test_roundtrip(self):
        sha, nonff = parse_rb_line(f"RB_SHA={MATCH_SHA} RB_NONFF=7 SPAN=1536 DEV=/dev/mtd4")
        assert sha == MATCH_SHA and nonff == 7

    def test_rejects_garbage(self):
        with pytest.raises(ValueError):
            parse_rb_line("WRITE_OK")


class TestMessages:
    def test_erased_noop_names_recovery_window(self):
        msg = verdict_message(MtdReadbackVerdict.ERASED_NOOP, "CFG1")
        assert "NO-OP" in msg and "Do NOT reboot" in msg

    def test_mismatch_names_reread(self):
        assert "re-read" in verdict_message(MtdReadbackVerdict.MISMATCH, "CFG1")


class TestFlashShWiring:
    """Contract test: the shell gate must carry the same classification."""

    def test_gate_present_with_all_three_classes(self):
        src = FLASH_SH.read_text()
        assert "grep -m1 CFG1 /proc/mtd" in src          # by NAME
        assert "tr -d '\\377'" in src                    # erased probe
        assert "NO-OP'D" in src                          # erased-noop class named
        assert "MISMATCH confirmed on re-read" in src    # re-read contract
        assert "transport corruption" in src

    def test_no_bare_mtd_write_write_ok_left(self):
        src = FLASH_SH.read_text()
        assert 'mtd write /tmp/$_cfg1_name CFG1 &&' not in src  # un-gated form gone
