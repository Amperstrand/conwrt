"""Tests for the soft-deprecation gate (scripts/rust_migration.py)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import pytest

import rust_migration
from rust_migration import ENV_VAR, _delay_from_env, soft_deprecated


def test_default_delay_is_15_seconds(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert _delay_from_env() == 15.0


def test_delay_is_configurable(monkeypatch):
    for value in ("0", "3.5", "60"):
        monkeypatch.setenv(ENV_VAR, value)
        assert _delay_from_env() == float(value)


def test_invalid_delay_fails_loudly(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "soon")
    with pytest.raises(SystemExit, match="must be a number"):
        _delay_from_env()
    monkeypatch.setenv(ENV_VAR, "-1")
    with pytest.raises(SystemExit, match="must be >= 0"):
        _delay_from_env()


def test_notice_names_the_rust_replacement(capsys, monkeypatch):
    monkeypatch.setenv(ENV_VAR, "0")
    soft_deprecated("conwrt models", "model listing/validation")
    err = capsys.readouterr().err
    assert "`conwrt models`" in err
    assert "model listing/validation" in err
    assert ENV_VAR in err


def test_delay_actually_sleeps(monkeypatch):
    slept: list[float] = []
    monkeypatch.setenv(ENV_VAR, "12")
    monkeypatch.setattr(rust_migration.time, "sleep", slept.append)
    soft_deprecated("conwrt diagnose --ip 192.168.1.1", "boot-state probing")
    assert slept == [12.0]


def test_zero_delay_does_not_sleep(monkeypatch):
    slept: list[float] = []
    monkeypatch.setenv(ENV_VAR, "0")
    monkeypatch.setattr(rust_migration.time, "sleep", slept.append)
    soft_deprecated("conwrt models", "model listing/validation")
    assert slept == []


def test_migrated_command_runs_end_to_end_fast():
    # `conwrt list` is gated; with the delay at 0 the command must behave
    # exactly as before (same stdout shape, notice on stderr).
    env = {"CONWRT_RUST_MIGRATION_DELAY": "0", "PATH": "/usr/bin:/bin"}
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent.parent / "scripts" / "conwrt.py"), "list"],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert result.returncode == 0
    assert "Model ID" in result.stdout
    assert "conwrt models" in result.stderr
