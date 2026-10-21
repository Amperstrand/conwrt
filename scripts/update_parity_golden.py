#!/usr/bin/env python3
"""Regenerate the parity goldens from the Python (1.x) implementation.

The Python use-case builders are authoritative for parity: the Rust plan
pipeline must reproduce their shell output. This renders every fixture in
tests/fixtures/parity/ through the registered Python use case and writes
tests/fixtures/parity/golden/<stem>.sh.

Run from the repo root after changing a fixture or a Python use case:

    PYTHONPATH=scripts python3 scripts/update_parity_golden.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from profile.ops import render_shell  # noqa: E402

import use_cases  # noqa: E402


def main() -> int:
    fixture_dir = REPO / "tests" / "fixtures" / "parity"
    golden_dir = fixture_dir / "golden"
    golden_dir.mkdir(parents=True, exist_ok=True)
    for fixture_path in sorted(fixture_dir.glob("*.json")):
        if fixture_path.name == "manifest.json":
            continue
        fixture = json.loads(fixture_path.read_text())
        uc = use_cases.get(fixture["use_case"])
        if uc is None or uc.build_configure_ops is None:
            print(f"skip {fixture_path.name}: no Python builder", file=sys.stderr)
            continue
        script = render_shell(uc.build_configure_ops(fixture["params"]))
        out = golden_dir / f"{fixture_path.stem}.sh"
        out.write_text(script)
        print(f"wrote {out.relative_to(REPO)} ({len(script.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
