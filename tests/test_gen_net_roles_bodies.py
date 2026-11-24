"""Tests for gen_net_roles_bodies (#763 P2 — the generator that keeps the
Rust plan constants byte-exact with scripts/use_cases/net_roles.py).

The generator is a top-level script (logic runs at import), so every test
loads a FRESH module instance via importlib with SRC/OUT injected before
exec_module — no monkeypatch-after-import races.

Two layers:
- sandbox behavior: generated .rs shape, the missing-constant guard,
  the raw-string '\"#' guard
- THE DRIFT DETECTOR: the generator against the REAL
  scripts/use_cases/net_roles.py must reproduce the checked-in
  crates/conwrt-core/src/plan/net_roles_bodies.rs byte-exactly —
  closing the #763 "guards drift while being able to drift" gap.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

REPO = Path(__file__).resolve().parents[1]
GEN_PATH = REPO / "scripts" / "gen_net_roles_bodies.py"

NAMES = ("_MODE_DAEMON", "_MODE_INIT", "_MODE_HOTPLUG", "_MODE_BUTTON",
         "_CONN_NOOP", "_CONN_ADAPTER", "_CONN_INIT",
         "_GUARD_DAEMON", "_GUARD_INIT")

REAL_OUT_REL = Path("crates/conwrt-core/src/plan/net_roles_bodies.rs")


def load_gen(monkeypatch, tmp_path: Path, net_roles_src: str):
    """Run the generator script EXACTLY as shipped, inside a sandbox repo.

    The script binds SRC/OUT to repo-RELATIVE paths at import and runs its
    whole body top-level — so the faithful harness is a fake repo layout
    (scripts/use_cases/net_roles.py) + chdir, not attribute injection
    (which the import-time assignments simply overwrite). Returns the OUT
    path inside the sandbox.
    """
    (tmp_path / "scripts/use_cases").mkdir(parents=True)
    (tmp_path / REAL_OUT_REL).parent.mkdir(parents=True)
    (tmp_path / "scripts/use_cases/net_roles.py").write_text(net_roles_src)
    out = tmp_path / REAL_OUT_REL
    monkeypatch.chdir(tmp_path)
    spec = importlib.util.spec_from_file_location(f"gen_{id(tmp_path)}", GEN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # runs the script body now, inside the sandbox
    return out


def fake_consts(names=NAMES, poison: str | None = None) -> str:
    lines = []
    for n in names:
        body = f"#!/bin/sh\n# body for {n}\nexit 0\n"
        if poison and n == "_CONN_NOOP":
            body = f'pre"#post\n{body}'
        lines.append(f'{n} = r"""{body}"""')
    return "\n".join(lines)


class TestSandbox:
    def test_generated_shape(self, tmp_path, monkeypatch):
        out = load_gen(monkeypatch, tmp_path, fake_consts())
        text = out.read_text()
        assert "GENERATED from scripts/use_cases/net_roles.py" in text
        assert "DO NOT EDIT BY HAND" in text
        for rs in ("MODE_DAEMON_SH", "MODE_INIT_SH", "MODE_HOTPLUG_SH",
                   "MODE_BUTTON_SH", "CONN_NOOP_SH", "CONN_ADAPTER_SH",
                   "CONN_INIT_SH", "GUARD_DAEMON_SH", "GUARD_INIT_SH"):
            assert f"pub(super) const {rs}: &str" in text
        assert 'r#"#!/bin/sh' in text, "raw-string form preserved"
        assert "body for _GUARD_INIT" in text, "body content carried byte-exact"

    def test_missing_constant_aborts(self, tmp_path, monkeypatch):
        with pytest.raises(AssertionError, match="missing constants"):
            load_gen(monkeypatch, tmp_path, fake_consts(names=NAMES[:2]))  # 2 of 9
        assert not (tmp_path / REAL_OUT_REL).exists(), \
            "aborted generation must not leave an OUT file"

    def test_raw_string_hash_guard(self, tmp_path, monkeypatch):
        # the assertion fires during exec; wrap load to observe it
        with pytest.raises(AssertionError, match='"#'):
            load_gen(monkeypatch, tmp_path, fake_consts(poison='"#'))


class TestRepoParity:
    def test_generator_reproduces_checked_in_artifact(self, tmp_path, monkeypatch):
        """THE drift detector: real net_roles.py -> byte-exact .rs."""
        real_src = (REPO / "scripts/use_cases/net_roles.py").read_text()
        out = load_gen(monkeypatch, tmp_path, real_src)
        checked_in = (REPO / REAL_OUT_REL).read_text()
        assert out.read_text() == checked_in, (
            "gen_net_roles_bodies output DRIFTED from the checked-in "
            "net_roles_bodies.rs — regenerate (run the script from repo "
            "root) or fix the generator"
        )

    def test_idempotent(self, tmp_path, monkeypatch):
        real_src = (REPO / "scripts/use_cases/net_roles.py").read_text()
        out1 = load_gen(monkeypatch, tmp_path / "a", real_src)
        out2 = load_gen(monkeypatch, tmp_path / "b", real_src)
        assert out1.read_text() == out2.read_text()
