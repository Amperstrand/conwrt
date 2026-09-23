"""Hardware-safe checks for the opt-in labgrid power and serial smoke tests."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType

import pytest


def _load_smoke_test() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "labgrid" / "test_bench_power.py"
    spec = importlib.util.spec_from_file_location("test_bench_power", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_serial_test() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "labgrid" / "test_bench_serial.py"
    spec = importlib.util.spec_from_file_location("test_bench_serial", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _skipif_decisions(module: ModuleType) -> list[tuple[bool, str]]:
    """Evaluate a loaded module's skipif marks the way pytest does at collection."""
    decisions = []
    for mark in module.pytestmark:
        if mark.name != "skipif":
            continue
        condition = mark.args[0]
        outcome = condition() if callable(condition) else bool(condition)
        decisions.append((outcome, mark.kwargs.get("reason", "")))
    return decisions


def test_port_state_queries_status_by_json_path(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_smoke_test()
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: str | int | bool) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "Delivering power\n", "")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    assert module._port_state() == "Delivering power"
    assert commands[0][-1] == "ubus call poe info | jsonfilter -e '@.ports.lan4.status'"


def test_serial_test_skips_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without BENCH_SERIAL_TEST/LG_COORDINATOR the serial test must SKIP, not run.

    Asserts the skip decision itself (not just rc=0) so a broken gate that
    collected the hardware test would fail here, hardware-free.
    """
    for var in ("BENCH_SERIAL_TEST", "LG_COORDINATOR", "BENCH_PLACE"):
        monkeypatch.delenv(var, raising=False)
    module = _load_serial_test()

    decisions = _skipif_decisions(module)
    assert decisions, "test_bench_serial.py must carry env-gate skipif marks"
    assert all(skipped for skipped, _ in decisions), (
        f"without env every gate must skip, got {decisions}"
    )
    assert module.PLACE == "ap-lan2"


def test_serial_test_gate_opens_with_opt_in_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate is keyed on the env vars — an always-true skipif would fake the skip test."""
    monkeypatch.setenv("BENCH_SERIAL_TEST", "1")
    monkeypatch.setenv("LG_COORDINATOR", "127.0.0.1:20408")
    monkeypatch.delenv("BENCH_PLACE", raising=False)
    module = _load_serial_test()

    decisions = _skipif_decisions(module)
    assert decisions and not any(skipped for skipped, _ in decisions), (
        f"opt-in env must clear every gate, got {decisions}"
    )


def test_serial_reset_allowed_gate_reads_places_registry(tmp_path: Path) -> None:
    """The power-cycle safety gate: only registered reset_allowed=true places pass."""
    module = _load_serial_test()
    registry = tmp_path / "places.json"
    registry.write_text(json.dumps({"places": [
        {"name": "ap-lan2", "reset_allowed": True},
        {"name": "ap-lan5", "reset_allowed": False},
    ]}), encoding="utf-8")

    assert module._reset_allowed("ap-lan2", registry) is True
    assert module._reset_allowed("ap-lan5", registry) is False
    assert module._reset_allowed("ap-lan9", registry) is False  # unregistered = refuse


def test_serial_boot_markers_are_the_ap3915i_boot_contract() -> None:
    """The three markers the stream is searched for (machine-consumed substrings).

    Reference capture proving each appears in a normal AP3915i boot:
    data/bench/ap-lan2/20260923-serial-via-lan4/lan2-boot.log
    """
    module = _load_serial_test()

    assert set(module.BOOT_MARKERS) == {
        "U-Boot 2012",
        "Starting kernel",
        "jffs2_build_xattr_subsystem",
    }

