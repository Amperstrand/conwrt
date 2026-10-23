"""Corpus pin for the 1.x probe sweep target universe (§7 item-2 audit).

`conwrt.py probe` (the multi-target LAN sweep) has no Rust twin —
parity-matrix §7 records the deprecation-gate audit. This pin guards the
sweep's corpus-driven core: the set of addresses it will ever probe,
derived from every model's ``openwrt.default_ip`` + per-method
``recovery_ip`` plus the hard-coded fallbacks. Adding a model whose
default/recovery address is NOT one of the four fallback addresses
changes the sweep surface — that must be a deliberate, reviewed golden
update, not a silent drift.

Finding at pin time (2026-10-23): all 24 models' default/recovery IPs
collapse into the four fallback addresses — the sweep universe is
exactly [192.168.0.1, 192.168.1.1, 192.168.1.20, 192.168.8.1]. The
corpus sanity assert keeps an accidentally-empty model read (which
would produce the identical fallback-only list) from false-passing.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from model_loader import list_models

from conwrt.cmd_probe import _collect_probe_targets

GOLDEN = Path(__file__).parent / "fixtures" / "probe_targets.txt"


def test_sweep_targets_match_corpus_golden():
    models = list_models()
    assert len(models) >= 20, "model corpus unexpectedly small — golden would false-pass"
    targets = _collect_probe_targets(models)
    assert targets == GOLDEN.read_text().splitlines(), (
        "probe sweep target universe drifted — if a model legitimately added "
        "a new default/recovery address, regenerate "
        "tests/fixtures/probe_targets.txt in review"
    )
