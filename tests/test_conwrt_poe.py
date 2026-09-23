"""conwrt_poe verified-manage semantics: a wedged realtek-poe daemon answers
`poe info` with a frozen per-port snapshot while silently dropping manage
calls (observed live 2026-09-22 and 2026-09-23). power_set must verify the
port actually changed and fail loudly on a frozen snapshot — but a frozen
snapshot inside the settling window is a HEALTHY readback lag (T23: MCU
status readback lags up to ~30s) and must not fail."""
import json
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "labgrid"))
import conwrt_poe  # noqa: E402


def _info(status: str, watts: float = 0.0) -> str:
    return json.dumps({"ports": {"lan4": {"status": status, "consumption": watts}}})


def _patch_ssh(script: list[str]):
    seq = list(script)

    def fake_ssh(_host: str, command: str) -> str:
        if "manage" in command:
            return ""  # the fork's silent success — the whole problem
        return seq.pop(0)

    return mock.patch.object(conwrt_poe, "_ssh", side_effect=fake_ssh)


def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []

    def fast(s: float) -> None:
        sleeps.append(s)
        if len(sleeps) > 200:
            raise AssertionError("poll loop did not converge")

    monkeypatch.setattr(time, "sleep", fast)
    monkeypatch.setattr(time, "monotonic", lambda: len(sleeps) * 0.5)


def test_disable_verifies_on_state_change(monkeypatch):
    _no_sleep(monkeypatch)
    with _patch_ssh([_info("Delivering power", 5.6), _info("Disabled")]):
        conwrt_poe.power_set("switch", None, 4, 0)


def test_enable_verifies_on_searching(monkeypatch):
    _no_sleep(monkeypatch)
    with _patch_ssh([_info("Disabled"), _info("Searching")]):
        conwrt_poe.power_set("switch", None, 4, 1)


def test_frozen_snapshot_raises_wedge(monkeypatch):
    _no_sleep(monkeypatch)
    # Frozen far past the settling window: wedge. (Fake clock advances
    # 0.5s/iteration, so the DROPPED raise lands ~84 snapshots in.)
    frozen = [_info("Delivering power", 5.6)] * 90
    with _patch_ssh(frozen), pytest.raises(RuntimeError, match="DROPPED.*frozen"):
        conwrt_poe.power_set("switch", None, 4, 0)


def test_timeout_raises_unverified(monkeypatch):
    _no_sleep(monkeypatch)
    jitter = [_info("Disabled", 5.0), _info("Disabled", 4.9)] * 62
    with _patch_ssh(jitter), pytest.raises(RuntimeError, match="UNVERIFIED"):
        conwrt_poe.power_set("switch", None, 4, 1)


def test_readback_lag_inside_settling_window_is_tolerated(monkeypatch):
    _no_sleep(monkeypatch)
    # T23: a healthy manage's status readback lags up to ~30s — the digest
    # stays frozen at the OLD state well beyond the 6s wedge grace before
    # flipping. This must verify, not raise DROPPED.
    lagging = [_info("Disabled", 0.0)] * 65 + [_info("Searching")]
    with _patch_ssh(lagging):
        conwrt_poe.power_set("switch", None, 4, 1)


def test_initializing_is_not_yet_success(monkeypatch):
    _no_sleep(monkeypatch)
    with _patch_ssh([_info("initializing"), _info("Delivering power", 4.2)]):
        conwrt_poe.power_set("switch", None, 4, 1)


def test_power_get_unchanged_semantics(monkeypatch):
    with _patch_ssh([_info("Delivering power", 5.0)]):
        assert conwrt_poe.power_get("switch", None, 4) is True
    with _patch_ssh([_info("Disabled")]):
        assert conwrt_poe.power_get("switch", None, 4) is False
