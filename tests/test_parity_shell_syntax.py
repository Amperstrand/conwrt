"""Corpus-wide shell-syntax gate.

Render-parity proves Python 1.x and Rust 2.x emit the SAME bytes — it
cannot catch the case where both agree on a script a POSIX shell rejects.
This gate renders every parity fixture through the Rust pipeline and
checks each with `sh -n` (dash semantics; the VM apply-acceptance runner
then executes them under busybox ash on real OpenWrt).

Found its first defect class on day one (2026-11-14): none — the 61-fixture
corpus passes clean; the gate exists to keep it that way.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from test_parity_rust_plan import _fixtures, REPO


class TestCorpusShellSyntax:
    def test_every_fixture_renders_shell_clean(self):
        bin_path = Path(os.environ.get("CARGO_TARGET_DIR", str(REPO / "target"))) / "debug" / "conwrt-plan-render"
        if not bin_path.exists():
            build = subprocess.run(
                [shutil.which("cargo") or "cargo", "build", "-q",
                 "-p", "conwrt-cli", "--bin", "conwrt-plan-render"],
                cwd=str(REPO), capture_output=True, text=True,
            )
            assert build.returncode == 0, f"render bin build failed: {build.stderr[-300:]}"
        checked = 0
        failures: list[str] = []
        for fixture in _fixtures():
            name = fixture["stem"]
            path = Path(fixture["path"])
            proc = subprocess.run(
                [str(bin_path), str(path)],
                capture_output=True, text=True, timeout=120,
            )
            assert proc.returncode == 0, (
                f"{name}: render failed: {proc.stderr[:300]}"
            )
            syntax = subprocess.run(
                ["sh", "-n"], input=proc.stdout,
                capture_output=True, text=True, timeout=60,
            )
            if syntax.returncode != 0:
                failures.append(f"{name}: {syntax.stderr.strip()[:200]}")
            checked += 1
        assert checked > 0, "no parity fixtures found"
        assert not failures, (
            "fixtures whose render is not valid POSIX shell "
            f"({len(failures)} of {checked}):\n" + "\n".join(failures)
        )

    def test_manifest_json_parses_everywhere(self):
        # cheap but catches truncation-class corruption early
        manifest = json.loads(
            (Path(__file__).parent / "fixtures" / "parity" / "manifest.json").read_text()
        )
        assert manifest["fixtures"], "manifest has no fixtures"
