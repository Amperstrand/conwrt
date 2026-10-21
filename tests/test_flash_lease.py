"""Unit tests for flash_lease (§4.3) and the protected-place registry.

All coordinator interaction goes through a fake Runner — no labgrid client,
no coordinator, no hardware. Dry-mode and protected-refusal tests assert
ZERO subprocess calls: the whole point of the safety order is that the
coordinator is never contacted when the answer is "no" or "dry".
"""
from __future__ import annotations

import subprocess
import textwrap

import pytest

import venues
from venues import FlashLease, ProtectedPlaceError, flash_lease


class FakeRunner:
    def __init__(self, failures: dict[str, str] | None = None):
        self.calls: list[list[str]] = []
        self.failures = failures or {}

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess:
        self.calls.append(list(args))
        key = " ".join(args)
        for marker, stderr in self.failures.items():
            if marker in key:
                return subprocess.CompletedProcess(
                    args, 1, stdout="", stderr=stderr
                )
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")


def _cp(args, rc=0, stderr=""):
    return subprocess.CompletedProcess(args, rc, stdout="", stderr=stderr)


class TestProtectedPlaces:
    def test_devices_mapping_protects_labgrid_place(self, tmp_path, monkeypatch):
        lab = tmp_path / "lab.yaml"
        lab.write_text(textwrap.dedent("""
            devices:
              nr7101-house:
                mgmt: 192.0.2.10
                labgrid_place: nr7101-router
                protected: true
              x1860-1:
                mgmt: 192.0.2.52
        """))
        monkeypatch.setattr(venues, "LAB_YAML", lab)
        assert venues.default_protected_places() == {"nr7101-router"}

    def test_devices_mapping_protects_own_id_without_place(self, tmp_path, monkeypatch):
        lab = tmp_path / "lab.yaml"
        lab.write_text(textwrap.dedent("""
            devices:
              solo-dut:
                mgmt: 192.0.2.9
                protected: true
        """))
        monkeypatch.setattr(venues, "LAB_YAML", lab)
        assert venues.default_protected_places() == {"solo-dut"}

    def test_legacy_places_list_still_counts(self, tmp_path, monkeypatch):
        lab = tmp_path / "lab.yaml"
        lab.write_text(textwrap.dedent("""
            places:
              - name: ap-lan4
                protected: true
        """))
        monkeypatch.setattr(venues, "LAB_YAML", lab)
        assert venues.default_protected_places() == {"ap-lan4"}

    def test_absent_registry_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CONWRT_LAB", raising=False)
        monkeypatch.setattr(venues, "LAB_YAML", tmp_path / "nope.yaml")
        with pytest.raises(RuntimeError, match="no lab registry"):
            venues.default_protected_places()


@pytest.fixture
def empty_registry(tmp_path, monkeypatch):
    """A readable registry protecting nothing (fail-closed needs one)."""
    monkeypatch.delenv("CONWRT_LAB", raising=False)
    lab = tmp_path / "lab.yaml"
    lab.write_text("places: []\n")
    monkeypatch.setattr(venues, "LAB_YAML", lab)


class TestFlashLease:
    def test_reserve_acquire_release_sequence(self, empty_registry):
        runner = FakeRunner()
        with flash_lease(
            "x1860-1", session="ses1", story="sysupgrade", runner=runner
        ) as lease:
            assert isinstance(lease, FlashLease)
            assert lease.place == "x1860-1"
            assert not lease.dry
            assert lease.reservation == "conwrt-ses1-sysupgrade"
            assert runner.calls == [
                ["reserve", "name=x1860-1", "--name",
                 "conwrt-ses1-sysupgrade", "--wait"],
                ["-p", "x1860-1", "acquire"],
            ]
        assert runner.calls[-1] == ["-p", "x1860-1", "release"]

    def test_release_runs_on_body_exception(self, empty_registry):
        runner = FakeRunner()
        with pytest.raises(RuntimeError, match="boom"), \
                flash_lease("ap-lan4", session="s", story="t", runner=runner):
            raise RuntimeError("boom")
        assert runner.calls[-1] == ["-p", "ap-lan4", "release"]

    def test_protected_place_refused_before_any_call(self):
        runner = FakeRunner()
        with pytest.raises(ProtectedPlaceError, match="protected"), \
                flash_lease(
                    "nr7101-router", session="s", story="t", runner=runner,
                    protected_places=lambda: {"nr7101-router"},
                ):
            pass
        assert runner.calls == []

    def test_dry_mode_never_contacts_coordinator(self, empty_registry):
        runner = FakeRunner()
        with flash_lease(
            "x1860-1", session="s", story="t", runner=runner,
            env={"CONWRT_FLASH_LEASE_DRY": "1"},
        ) as lease:
            assert lease.dry
            assert lease.reservation == "conwrt-s-t"
        assert runner.calls == []

    def test_reserve_failure_never_yields(self, empty_registry):
        runner = FakeRunner(failures={"reserve": "place is already reserved"})
        with pytest.raises(RuntimeError, match="cancel-reservation"), \
                flash_lease("x1860-1", session="s", story="t", runner=runner):
            pass
        assert len(runner.calls) == 1  # no acquire, no release after failed reserve

    def test_acquire_failure_cancels_reservation(self, empty_registry):
        runner = FakeRunner(failures={"acquire": "place acquired by sibling"})
        with pytest.raises(RuntimeError, match="canceled"), \
                flash_lease("x1860-1", session="s", story="t", runner=runner):
            pass
        assert runner.calls[-1] == ["cancel-reservation", "conwrt-s-t"]
        assert ["-p", "x1860-1", "release"] not in runner.calls

    def test_unsafe_tokens_sanitized_in_reservation_name(self, empty_registry):
        runner = FakeRunner()
        with flash_lease(
            "x1860-1", session="my session/2026", story="flash: [keep]",
            runner=runner,
        ) as lease:
            assert lease.reservation == "conwrt-my-session-2026-flash---keep-"
        assert runner.calls[0][3] == lease.reservation
