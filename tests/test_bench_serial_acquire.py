"""Offline tests for the bench-serial acquire queue (#638/#184) — the wire
is stubbed at _client_raw; nothing here talks to a coordinator."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "bench_serial_under_test", REPO / "labgrid" / "test_bench_serial.py"
)
mod = importlib.util.module_from_spec(spec)
sys.modules["bench_serial_under_test"] = mod
spec.loader.exec_module(mod)

TOKEN = "cafebabe-1234-5678-9abc-def012345678"


def _stub(monkeypatch, script: list[tuple[tuple, tuple]]):
    """script: ordered ((args...), (rc, out, err)) replies."""
    calls: list[tuple] = []
    replies = iter(reply for _, reply in script)

    def fake(*args, timeout=60):
        calls.append(args)
        return next(replies, (1, "", "exhausted"))

    monkeypatch.setattr(mod, "_client_raw", fake)
    return calls


class TestAcquireQueue:
    def test_outright_acquire_returns_empty_token(self, monkeypatch):
        calls = _stub(monkeypatch, [(("acquire",), (0, "", ""))])
        assert mod._acquire_place() == ""
        assert calls == [("acquire",)]

    def test_contention_queues_via_reserve_wait(self, monkeypatch):
        calls = _stub(monkeypatch, [
            (("acquire",), (1, "", "Place is acquired")),
            (("reserve", "--wait", "name=ap-lan2"), (0, f"reserved {TOKEN}\n", "")),
            (("acquire",), (0, "", "")),
        ])
        assert mod._acquire_place() == TOKEN
        assert calls[1] == ("reserve", "--wait", "name=ap-lan2")

    def test_exhausted_queue_names_the_stderr(self, monkeypatch):
        _stub(monkeypatch, [
            (("acquire",), (1, "", "Place is acquired")),
            (("reserve", "--wait", "name=ap-lan2"), (1, "", "reservation timeout")),
        ])
        try:
            mod._acquire_place()
            raise SystemExit("should have raised")
        except AssertionError as e:
            assert "queue exhausted" in str(e) and "reservation timeout" in str(e)

    def test_acquire_refused_after_reserve_cancels_token(self, monkeypatch):
        calls = _stub(monkeypatch, [
            (("acquire",), (1, "", "Place is acquired")),
            (("reserve", "--wait", "name=ap-lan2"), (0, f"{TOKEN}\n", "")),
            (("acquire",), (1, "", "still held")),
            (("cancel-reservation", TOKEN), (0, "", "")),
        ])
        try:
            mod._acquire_place()
            raise SystemExit("should have raised")
        except AssertionError as e:
            assert "acquire refused" in str(e)
        assert ("cancel-reservation", TOKEN) in calls

    def test_release_cancels_the_token(self, monkeypatch):
        calls = _stub(monkeypatch, [
            (("release",), (0, "", "")),
            (("cancel-reservation", TOKEN), (0, "", "")),
        ])
        mod._release_place(TOKEN)
        assert calls == [("release",), ("cancel-reservation", TOKEN)]

    def test_token_extraction(self):
        assert mod._reservation_token(f"noise {TOKEN} noise") == TOKEN
        assert mod._reservation_token("no uuid here") == ""
