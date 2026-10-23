"""§7 item-1 parity pin: `conwrt.py list` ≡ `conwrt models`, byte-for-byte.

The §7 per-command retirement policy (docs/roadmap/parity-matrix.md)
retires a Python ``cmd_*`` only when its Rust twin is pinned against the
same evidence. For the model listing the two tables differed in two
ways (flash-method ordering: JSON insertion order vs the Rust BTreeMap's
sorted keys; and the Rust trailing ``N model(s) valid in <dir>`` footer).
Per the matrix the RUST output is the go-forward shape — sorted is
deterministic under JSON key rewrites — and the (deprecated) Python
twin was aligned to it rather than faking equality.

This harness pins BOTH implementations byte-for-byte against one
committed golden (tests/fixtures/parity/models_list.txt, generated from
the Rust binary): if either side drifts — a formatting change, a corpus
edit without a golden update, or a Python regression — the corresponding
test fails. Golden regenerates deliberately in review:

    cargo build -q -p conwrt-cli --bin conwrt
    ./target/debug/conwrt models --dir models \\
        > tests/fixtures/parity/models_list.txt
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
GOLDEN = REPO / "tests" / "fixtures" / "parity" / "models_list.txt"


@pytest.fixture(scope="session")
def conwrt_bin() -> Path:
    cargo = shutil.which("cargo")
    if cargo is None:
        pytest.skip("cargo toolchain not available for the Rust parity binary")
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target"))
    bin_path = target_dir / "debug" / "conwrt"
    if not bin_path.exists():
        build = subprocess.run(
            [cargo, "build", "-q", "-p", "conwrt-cli", "--bin", "conwrt"],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            pytest.fail(
                f"conwrt build failed (exit {build.returncode}):\n"
                f"{build.stderr.strip()}"
            )
    assert bin_path.exists(), f"{bin_path} missing after cargo build"
    return bin_path


def _python_list() -> str:
    env = dict(os.environ, CONWRT_RUST_MIGRATION_DELAY="0")
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "conwrt.py"), "list"],
        capture_output=True,
        text=True,
        cwd=REPO,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _rust_models(bin_path: Path) -> str:
    proc = subprocess.run(
        [str(bin_path), "models", "--dir", "models"],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_rust_models_matches_golden(conwrt_bin):
    assert _rust_models(conwrt_bin) == GOLDEN.read_text(), (
        "`conwrt models` drifted from tests/fixtures/parity/models_list.txt "
        "— regenerate the golden in review (see module docstring)"
    )


def test_python_list_matches_golden():
    assert _python_list() == GOLDEN.read_text(), (
        "`conwrt.py list` drifted from tests/fixtures/parity/models_list.txt "
        "— the deprecated twin must stay byte-aligned with `conwrt models` "
        "(parity-matrix §7); fix the regression or regenerate the golden "
        "in review (see module docstring)"
    )
