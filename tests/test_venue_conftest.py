"""Offline regression tests for the integration conftest venue fixture
(review debt: conwrt PR #184 threads r4274274165/r4274274171/r4274274201/
r4274274211). The conftest module is loaded via spec_from_file_location —
the same pattern tests/test_integration_image_gate.py uses.
"""

import importlib.util
import sys
import os
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "tests"))

_spec = importlib.util.spec_from_file_location(
    "integration_conftest_under_test", REPO / "tests" / "integration" / "conftest.py"
)
conftest = importlib.util.module_from_spec(_spec)
sys.modules["integration_conftest_under_test"] = conftest
_spec.loader.exec_module(conftest)


def test_venue_fixture_is_session_scoped():
    """r4274274201: function scope released the labgrid place after every
    test — a sibling session could take the device in the gap."""
    assert conftest.venue._pytestfixturefunction.scope == "session"


def test_darkness_marker_ignores_remote_tracebacks():
    """r4274274211: labgrid-client transports the REMOTE command's stderr;
    a deliberate remote Python failure must surface as a failure, not a
    darkness skip."""
    assert not conftest._venue_unreachable("Traceback (most recent call last):\nValueError: boom\n")


def test_darkness_markers_still_catch_labgrid_diagnostics():
    assert conftest._venue_unreachable("Timeout while waiting for ssh connection")
    assert conftest._venue_unreachable("no NetworkService resource found")


def test_labgrid_honors_native_coordinator(monkeypatch):
    """r4274274171: when LG_COORDINATOR is set, labgrid-client resolves it
    natively — no -x override."""
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(conftest.subprocess, "run", fake_run)
    monkeypatch.setenv("LG_COORDINATOR", "other-host:20407")
    monkeypatch.delenv("CONWRT_LABGRID_COORDINATOR", raising=False)
    conftest._labgrid(["acquire"], "p1")
    assert "-x" not in calls[0][0]


def test_labgrid_keeps_default_coordinator_without_native(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(conftest.subprocess, "run", fake_run)
    monkeypatch.delenv("LG_COORDINATOR", raising=False)
    monkeypatch.setenv("CONWRT_LABGRID_COORDINATOR", "ai-legion:20408")
    conftest._labgrid(["acquire"], "p1")
    argv = calls[0]
    assert argv[argv.index("-x") + 1] == "ai-legion:20408"


def test_acquire_place_queues_on_contention(monkeypatch):
    """r4274274165: contention queues via ONE blocking reserve --wait
    (never a poll loop), then acquires the allocated place."""
    calls = []
    acquisitions = {"n": 0}

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        if "acquire" in argv:
            acquisitions["n"] += 1
            rc = 1 if acquisitions["n"] == 1 else 0
            return types.SimpleNamespace(returncode=rc, stdout="", stderr="held" if rc else "")
        if "reserve" in argv:
            return types.SimpleNamespace(
                returncode=0,
                stdout="reserved cafebabe-1234-5678-9abc-def012345678\n",
                stderr="",
            )
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(conftest, "subprocess", types.SimpleNamespace(run=fake_run))
    monkeypatch.setenv("CONWRT_VENUE_QUEUE_WAIT_S", "5")
    ok, token = conftest._acquire_place("ap-lan4")
    assert ok is True
    assert token == "cafebabe-1234-5678-9abc-def012345678"
    reserve_call = next(c for c in calls if "reserve" in c[0])
    assert reserve_call[0][-2:] == ["--wait", "name=ap-lan4"]
    assert reserve_call[1].get("timeout") == 5
    assert "cancel-reservation" not in [a for c in calls for a in c]


def test_acquire_place_cancels_reservation_when_acquire_refuses(monkeypatch):
    calls = []
    acquisitions = {"n": 0}

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        if "acquire" in argv:
            acquisitions["n"] += 1
            return types.SimpleNamespace(returncode=1, stdout="", stderr="held")
        if "reserve" in argv:
            return types.SimpleNamespace(
                returncode=0,
                stdout="reserved cafebabe-1234-5678-9abc-def012345678\n",
                stderr="",
            )
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(conftest, "subprocess", types.SimpleNamespace(run=fake_run))
    ok, detail = conftest._acquire_place("ap-lan4")
    assert ok is False
    assert "acquire refused" in detail
    assert any("cancel-reservation" in c[0] for c in calls)


def test_acquire_place_returns_reason_when_queue_exhausted(monkeypatch):
    def fake_run(argv, **kwargs):
        if "reserve" in argv:
            return types.SimpleNamespace(returncode=124, stdout="", stderr="timeout waiting")
        return types.SimpleNamespace(returncode=1, stdout="", stderr="held")

    monkeypatch.setattr(conftest, "subprocess", types.SimpleNamespace(run=fake_run))
    ok, detail = conftest._acquire_place("ap-lan4")
    assert ok is False
    assert "reservation queue exhausted" in detail
