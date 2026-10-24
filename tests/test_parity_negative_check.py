"""#497 post-merge sweep finding: Rust-side attribution must match the
PROBLEM TEXT, not output that happens to contain the fixture path
(the dir names baud-too-high / warnings-* carry the expected substrings
themselves, so path-contaminated matching passes on any rejection)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "parity_negative_check", Path(__file__).parent.parent / "scripts" / "parity_negative_check.py")
pnc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pnc)

FABRICATED = """invalid models in tests/fixtures/schema-negative/baud-too-high:
  tests/fixtures/schema-negative/baud-too-high/baud-too-high.json: flash_methods: must have at least one method
"""


def test_attribution_blob_strips_fixture_path_noise():
    blob = pnc.problem_text_only(FABRICATED)
    assert "baud" not in blob, "fixture path noise must not leak into attribution"
    assert "flash_methods: must have at least one method" in blob


def test_attribution_blob_keeps_real_problems():
    real = """invalid models in x:
  x/default-ip-empty.json: openwrt.default_ip: must not be empty
"""
    assert "openwrt.default_ip: must not be empty" in pnc.problem_text_only(real)
