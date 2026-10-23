"""Cross-implementation plan-renderer parity harness (Python half).

conwrt has two plan-op implementations:

  - Python 1.x: ``scripts/use_cases/*`` → ``profile.ops.render_shell``
    (complete, all ~30 presets)
  - Rust: ``crates/conwrt-core`` plan/profile pipeline → ``plan::render_shell``
    (the direction the project is going)

Nothing proved the two produce the same shell/uci semantics for the same
use case — this harness does. Each fixture in ``tests/fixtures/parity/`` is
rendered through BOTH implementations and the outputs are normalized and
diffed:

  - Python side: the registered use case's ``build_configure_ops(params)``
    → ``render_shell``.
  - Rust side: the ``conwrt-plan-render`` binary (built once per session)
    renders the same fixture file through the Rust planner.

Normalization (applied identically to both sides):
  1. drop shebang, ``set -e``, blank lines and comment lines
     (presentation-only; the Rust renderer adds a header and per-op
     annotation comments),
  2. tokenize each remaining line with ``shlex.split`` (recovers the exact
     argv the shell would see — quoting differences like
     ``uci set network.'wg0'='interface'`` vs ``uci set network.wg0=interface``
     normalize away),
  3. drop known-equivalent executor decorations: ``2>/dev/null`` words,
     the ``-q`` flag directly after ``uci``, and a trailing ``|| true``
     pair.

The expected status (EQUAL / GAP + reasons) is recorded in
``tests/fixtures/parity/manifest.json`` and asserted: if parity changes in
EITHER direction — a gap closes or a regression opens — the test fails
until the manifest is updated in review. The gap list must shrink, never
silently change. ``scripts/update_parity_golden.py`` regenerates the
Python goldens that pin the Rust side in ``cargo test``.
"""
from __future__ import annotations

import difflib
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from profile.ops import render_shell

import use_cases

REPO = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO / "tests" / "fixtures" / "parity"

# Words that are executor-side decorations with no semantic effect for
# parity: stderr silencing, uci quiet flag, and a trailing `|| true`
# guard (present in both renderers in various spots).
_DROP_WORDS = {"2>/dev/null"}

# 2.x-only package-install preamble (EnsurePackage apk/opkg blocks) — a
# deliberate Rust-side extension; 1.x Python bakes packages into the
# image, so its configure render carries no install lines. Same
# exclusion as crates/conwrt-core/src/parity.rs::command_lines and
# tests/use_case_goldens.rs.
_DROP_LINE_PREFIXES = ("opkg install ", "if command -v apk ", "&& apk add ")


def _normalize_line(line: str) -> list[str] | None:
    stripped = line.strip()
    # 2.x runs under a `set -e` preamble (itself dropped above) and so
    # guards best-effort substitutions with `|| true` — the 1.x render
    # is bare. Strip the shim inside `$( ... )` before tokenizing (the
    # token-level `|| true` drop below cannot see it: the closing paren
    # glues to the word).
    stripped = stripped.replace(" || true)", ")")
    if not stripped or stripped.startswith("#"):
        return None
    if stripped == "set -e" or stripped.startswith("#!"):
        return None
    if stripped.startswith(_DROP_LINE_PREFIXES):
        return None
    try:
        tokens = shlex.split(stripped)
    except ValueError as err:  # unbalanced quoting — a real problem
        raise AssertionError(f"cannot tokenize {stripped!r}: {err}") from err
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _DROP_WORDS:
            i += 1
            continue
        # `uci -q …` → `uci …` (quiet flag only, directly after `uci`)
        if tok == "-q" and out and out[-1] == "uci":
            i += 1
            continue
        # trailing `|| true` guard
        if tok == "||" and i + 1 < len(tokens) and tokens[i + 1] == "true":
            i += 2
            continue
        out.append(tok)
        i += 1
    return out


def normalize(script: str) -> list[list[str]]:
    """Normalize a rendered script to its semantic command stream."""
    return [t for t in (_normalize_line(l) for l in script.splitlines()) if t is not None]


def _render_tokens(lines: list[list[str]]) -> list[str]:
    return [" ".join(t) for t in lines]


@pytest.fixture(scope="session")
def plan_render_bin() -> Path:
    cargo = shutil.which("cargo")
    if cargo is None:
        pytest.skip("cargo toolchain not available for the Rust parity renderer")
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target"))
    bin_path = target_dir / "debug" / "conwrt-plan-render"
    if not bin_path.exists():
        build = subprocess.run(
            [cargo, "build", "-q", "-p", "conwrt-cli", "--bin", "conwrt-plan-render"],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            # check=True used to raise CalledProcessError with the reason
            # swallowed — the 2026-10-22 runner rustup failures (#439/#443)
            # cost a debug round purely to recover this stderr.
            pytest.fail(
                f"conwrt-plan-render build failed (exit {build.returncode}):\n"
                f"{build.stderr.strip()}"
            )
    assert bin_path.exists(), f"{bin_path} missing after cargo build"
    return bin_path


def _load_manifest() -> dict:
    return json.loads((FIXTURE_DIR / "manifest.json").read_text())


def _fixtures() -> list[dict]:
    manifest = _load_manifest()
    out = []
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        if path.name == "manifest.json":
            continue
        entry = manifest["fixtures"].get(path.stem)
        out.append(
            {
                "stem": path.stem,
                "path": path,
                "fixture": json.loads(path.read_text()),
                "expect": entry["expect"] if entry else None,
                "entry": entry,
            }
        )
    return out


def _python_render(fixture: dict) -> str:
    uc = use_cases.get(fixture["use_case"])
    assert uc is not None, f"use case {fixture['use_case']} not registered"
    assert uc.build_configure_ops is not None, (
        f"use case {fixture['use_case']} has no ops builder"
    )
    return render_shell(uc.build_configure_ops(fixture["params"]))


def _rust_render(bin_path: Path, fixture_path: Path) -> str:
    proc = subprocess.run(
        [str(bin_path), str(fixture_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, (
        f"Rust renderer failed for {fixture_path.name}: {proc.stderr}"
    )
    return proc.stdout


class TestParityManifest:
    def test_every_fixture_is_recorded(self):
        manifest = _load_manifest()
        files = {p.stem for p in FIXTURE_DIR.glob("*.json")} - {"manifest"}
        recorded = set(manifest["fixtures"])
        assert files == recorded, (
            f"parity manifest out of sync — files: {sorted(files)}, "
            f"recorded: {sorted(recorded)}"
        )

    def test_every_entry_has_valid_expectation(self):
        manifest = _load_manifest()
        for stem, entry in manifest["fixtures"].items():
            assert entry.get("expect") in {"EQUAL", "GAP"}, stem
            if entry["expect"] == "GAP":
                assert entry.get("gap_reasons"), f"{stem}: GAP needs reasons"
                fixture = json.loads((FIXTURE_DIR / f"{stem}.json").read_text())
                assert fixture["use_case"] == entry["use_case"]


class TestPlanRendererParity:
    @pytest.mark.parametrize("fx", _fixtures(), ids=lambda fx: fx["stem"])
    def test_matches_recorded_parity_status(self, plan_render_bin, fx):
        assert fx["expect"] is not None, (
            f"{fx['stem']} missing from manifest.json — record EQUAL or GAP"
        )
        py = normalize(_python_render(fx["fixture"]))
        rs = normalize(_rust_render(plan_render_bin, fx["path"]))
        actual = "EQUAL" if py == rs else "GAP"
        detail = ""
        if actual == "GAP":
            detail = "\n".join(
                difflib.unified_diff(
                    _render_tokens(py),
                    _render_tokens(rs),
                    fromfile=f"python/{fx['stem']}",
                    tofile=f"rust/{fx['stem']}",
                    lineterm="",
                )
            )
        assert actual == fx["expect"], (
            f"{fx['stem']}: parity status changed from "
            f"{fx['expect']} to {actual} — update "
            f"tests/fixtures/parity/manifest.json (gaps close loudly, "
            f"never silently).\n{detail}"
        )

    @pytest.mark.parametrize("fx", _fixtures(), ids=lambda fx: fx["stem"])
    def test_golden_matches_python_render(self, fx):
        golden = FIXTURE_DIR / "golden" / f"{fx['stem']}.sh"
        assert golden.exists(), (
            f"{golden.name} missing — run scripts/update_parity_golden.py"
        )
        assert golden.read_text() == _python_render(fx["fixture"]), (
            f"{fx['stem']}: golden out of date — run scripts/update_parity_golden.py"
        )
