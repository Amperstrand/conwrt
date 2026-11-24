"""Tests for overnight.py's classification ladder + cycle machine
(#794 second tier, lane 1). Seams patched at module level; the adopt
sequence itself is already covered by test_overnight_adopt.py.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import overnight  # noqa: E402


@pytest.fixture()
def rows(monkeypatch):
    captured: list[dict] = []
    monkeypatch.setattr(overnight, "log", captured.append)
    return captured


def _patch_seams(monkeypatch, *, switch=None, dut=None, v6=None):
    switch_calls: list[str] = []
    dut_calls: list[str] = []
    v6_calls: list[str] = []

    def switch_ssh(cmd, timeout=60):
        switch_calls.append(cmd)
        if callable(switch):
            return switch(cmd)
        return (0, "")

    def dut_ssh(ip, cmd, timeout=30):
        dut_calls.append(cmd)
        if callable(dut):
            return dut(cmd)
        return (0, "")

    def dut_v6_shell(mac, vlan, cmd, timeout=30):
        v6_calls.append(cmd)
        if callable(v6):
            return v6(cmd)
        return (0, "")

    monkeypatch.setattr(overnight, "switch_ssh", switch_ssh)
    monkeypatch.setattr(overnight, "dut_ssh", dut_ssh)
    monkeypatch.setattr(overnight, "dut_v6_shell", dut_v6_shell)
    return switch_calls, dut_calls, v6_calls


class TestEui64:
    @pytest.mark.parametrize("mac,ll", [
        ("00:11:22:33:44:55", "fe80::0211:22ff:fe33:4455"),
        ("52:54:00:12:34:56", "fe80::5054:00ff:fe12:3456"),
        ("b4:2d:56:25:47:a2", "fe80::b62d:56ff:fe25:47a2")  # U/L bit already set,
    ])
    def test_vectors(self, mac, ll):
        assert overnight.eui64(mac) == ll


class TestClassifyHardware:
    def test_network_dead_when_v6_ping_fails(self, monkeypatch):
        _patch_seams(monkeypatch, switch=lambda cmd: (0, "V6-FAIL"))
        r = overnight.classify_hardware("192.168.104.51", "b4:2d:56:25:47:a2", 1004)
        assert r["outcome"] == "network-dead"

    def test_managed_with_all_files(self, monkeypatch):
        def dut(cmd):
            if "AUTH-OK" in cmd:
                return (0, "AUTH-OK\nup 1 min")
            return (0, "OK:/etc/shadow\nOK:/etc/config/network\nOK:/etc/dropbear/authorized_keys")
        _patch_seams(monkeypatch, switch=lambda cmd: (0, "V6-OK"), dut=dut)
        r = overnight.classify_hardware("192.168.104.51", "b4:2d:56:25:47:a2", 1004)
        assert r["outcome"] == "managed" and r["auth"] == "key"
        assert r.get("missing_files") == []

    def test_partial_when_files_missing(self, monkeypatch):
        def dut(cmd):
            if "AUTH-OK" in cmd:
                return (0, "AUTH-OK\nup 1 min")
            return (0, "OK:/etc/shadow\nMISS:/etc/dropbear/authorized_keys")
        _patch_seams(monkeypatch, switch=lambda cmd: (0, "V6-OK"), dut=dut)
        r = overnight.classify_hardware("192.168.104.51", "b4:2d:56:25:47:a2", 1004)
        assert r["outcome"] == "partial"
        assert "/etc/dropbear/authorized_keys" in r["missing_files"]

    def test_factory_when_v6_shell_answers(self, monkeypatch):
        _patch_seams(monkeypatch,
                     switch=lambda cmd: (0, "V6-OK" if "ping6" in cmd else ""),
                     dut=lambda cmd: (0, ""),
                     v6=lambda cmd: (0, "FACTORY-OK"))
        r = overnight.classify_hardware("192.168.104.51", "b4:2d:56:25:47:a2", 1004)
        assert r["outcome"] == "factory" and r["auth"] == "empty-password"

    def test_auth_dead_when_banner_only(self, monkeypatch):
        _patch_seams(monkeypatch,
                     switch=lambda cmd: (0, "SSH-2.0-dropbear2020.81") if "nc " in cmd else (0, "V6-OK" if "ping6" in cmd else ""),
                     dut=lambda cmd: (0, ""),
                     v6=lambda cmd: (0, ""))
        r = overnight.classify_hardware("192.168.104.51", "b4:2d:56:25:47:a2", 1004)
        assert r["outcome"] == "auth-dead"
        assert "banner present" in r["detail"]

    def test_no_dropbear_when_no_banner(self, monkeypatch):
        _patch_seams(monkeypatch,
                     switch=lambda cmd: (0, "V6-OK" if "ping6" in cmd else ""),
                     dut=lambda cmd: (0, ""),
                     v6=lambda cmd: (0, ""))
        r = overnight.classify_hardware("192.168.104.51", "b4:2d:56:25:47:a2", 1004)
        assert r["outcome"] == "no-dropbear"


class TestTrackHardware:
    def test_pass_cycle_with_adopt(self, monkeypatch, rows):
        calls = {"classify": 0, "adopt": 0}
        def classify(*a):
            calls["classify"] += 1
            # first call classifies pre-adopt (factory); the post-adopt
            # verification call sees the adopted state
            return {"outcome": "factory"} if calls["classify"] == 1 else {"outcome": "managed"}

        monkeypatch.setattr(overnight, "classify_hardware", classify)
        monkeypatch.setattr(overnight, "adopt_unit",
                            lambda *a: calls.__setitem__("adopt", calls["adopt"] + 1) or True)
        monkeypatch.setattr(overnight, "dut_ssh",
                            lambda ip, cmd, timeout=30: (0, "FB-RC=0"))
        monkeypatch.setattr(overnight.time, "sleep", lambda s: None)
        overnight.track_hardware(1, "192.168.104.51", "b4:2d:56:25:47:a2", 1004)
        cycle_rows = [r for r in rows if r.get("track") == "hardware"]
        assert cycle_rows and cycle_rows[-1]["outcome"] == "PASS"
        assert rows[-1]["track"] == "hardware-summary"  # summary trails the cycles
        assert calls["adopt"] == 1

    def test_auth_dead_stops_the_run(self, monkeypatch, rows, capsys):
        cycles_ran = []

        def classify(*a):
            cycles_ran.append(1)
            return {"outcome": "auth-dead", "detail": "banner present, all auth methods fail"}

        monkeypatch.setattr(overnight, "classify_hardware", classify)
        monkeypatch.setattr(overnight, "dut_ssh",
                            lambda ip, cmd, timeout=30: (0, "FB-RC=0"))
        monkeypatch.setattr(overnight.time, "sleep", lambda s: None)
        overnight.track_hardware(5, "192.168.104.51", "b4:2d:56:25:47:a2", 1004)
        # THE ROULETTE stops the campaign — not 5 cycles
        assert len(cycles_ran) == 1
        cycle_rows = [r for r in rows if r.get("track") == "hardware"]
        assert "AUTH-DEAD" in cycle_rows[-1]["outcome"]
        assert "AUTH-DEAD DETECTED" in capsys.readouterr().out

    def test_firstboot_unreachable_is_failure_not_stop(self, monkeypatch, rows):
        monkeypatch.setattr(overnight, "dut_ssh", lambda ip, cmd, timeout=30: (1, "no route"))
        monkeypatch.setattr(overnight, "dut_v6_shell", lambda m, v, cmd, timeout=30: (1, "no route"))
        monkeypatch.setattr(overnight, "classify_hardware", lambda *a: pytest.fail("must not classify"))
        monkeypatch.setattr(overnight.time, "sleep", lambda s: None)
        overnight.track_hardware(2, "192.168.104.51", "b4:2d:56:25:47:a2", 1004)
        outcomes = [r.get("outcome") for r in rows if r.get("track") == "hardware"]
        assert outcomes.count("firstboot-unreachable") == 2

    def test_managed_without_reset_counts_as_pass(self, monkeypatch, rows):
        monkeypatch.setattr(overnight, "classify_hardware",
                            lambda *a: {"outcome": "managed"})
        monkeypatch.setattr(overnight, "dut_ssh",
                            lambda ip, cmd, timeout=30: (0, "FB-RC=0"))
        monkeypatch.setattr(overnight.time, "sleep", lambda s: None)
        overnight.track_hardware(1, "192.168.104.51", "b4:2d:56:25:47:a2", 1004)
        cycle_rows = [r for r in rows if r.get("track") == "hardware"]
        assert cycle_rows[-1]["outcome"].startswith("PASS")


class TestMain:
    def test_hardware_track_requires_dut_args(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["overnight.py", "--track", "hardware"])
        monkeypatch.delenv("CONWRT_DUT_IP", raising=False)
        with pytest.raises(SystemExit):
            overnight.main()
        assert "--dut-ip" in capsys.readouterr().err

    def test_qemu_track_runs_without_dut_args(self, monkeypatch, rows, capsys):
        monkeypatch.setattr("sys.argv", ["overnight.py", "--track", "qemu"])
        monkeypatch.setattr(overnight, "track_qemu", lambda cuts, runs_per_timing=3: rows.append({"track": "qemu"}))
        monkeypatch.setattr(overnight, "track_hardware",
                            lambda *a: pytest.fail("qemu track must not run hardware"))
        rc = overnight.main()
        assert rc == 0
        assert any(r["track"] == "qemu" for r in rows)

    def test_hardware_track_runs_with_env_args(self, monkeypatch, rows, capsys):
        monkeypatch.setattr("sys.argv", ["overnight.py", "--cycles", "1"])
        monkeypatch.setenv("CONWRT_DUT_IP", "192.168.104.51")
        monkeypatch.setenv("CONWRT_DUT_MAC", "b4:2d:56:25:47:a2")
        monkeypatch.setenv("CONWRT_DUT_VLAN", "1004")
        monkeypatch.setattr(overnight, "track_hardware",
                            lambda cycles, ip, mac, vlan: rows.append({"cycles": cycles}))
        monkeypatch.setattr(overnight, "track_qemu",
                            lambda cuts, runs: pytest.fail("hardware track must not run qemu"))
        assert overnight.main() == 0
        assert rows[0]["cycles"] == 1
