"""shellcheck gate on the RENDERED plans (the goldens are the exact
1.x-verified output the Rust render must byte-match — linting them
lints every plan we can emit).

Golden tests prove PARITY with the 1.x builders; they can never prove
the script itself is sound — the script-semantics defect class codex
kept finding (WG_PUB quoting, heredoc terminators, set -e aborts) is
what shellcheck catches mechanically. Gate = severity error (hard
runtime failures); warnings are informational (style on POSIX sh is
noisy and the bytes are 1.x-frozen — fixing them means fixing the
Python builders, tracked case-by-case).

Skipped when shellcheck is absent (local benches); CI installs it.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SHELLCHECK: str | None = shutil.which("shellcheck")


def _cmd(args: list[str]) -> list[str]:
    assert SHELLCHECK is not None, "guarded by pytestmark"
    return [SHELLCHECK, *args]
GOLDENS_DIR = Path(__file__).resolve().parents[1] / "crates" / "conwrt-core" / "tests" / "goldens"
GOLDENS = sorted(GOLDENS_DIR.glob("*.sh"))

pytestmark = pytest.mark.skipif(SHELLCHECK is None, reason="shellcheck not installed")


@pytest.mark.parametrize("golden", [g.name for g in GOLDENS])
def test_golden_plan_has_no_shellcheck_errors(golden: str) -> None:
    path = GOLDENS_DIR / golden
    result = subprocess.run(
        _cmd(["--shell=sh", "--severity=error", "--norc", "-f", "gcc", str(path)]),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"{golden}: shellcheck errors (these are REAL script "
        f"defects — the goldens are the exact bytes every conwrt apply "
        f"emits):\n{result.stdout}"
    )


def test_shellcheck_actually_runs() -> None:
    """Guard the gate itself: a deliberately broken script must fail."""
    bad = "if [ -n $x ]; then echo hi; fi\n"  # SC errors on missing fi? use a hard one
    result = subprocess.run(
        _cmd(["--shell=sh", "--severity=error", "-"]),
        input="for i in 1 2 3\necho $i\n",
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0, "shellcheck must flag a syntax error"
    _ = bad
