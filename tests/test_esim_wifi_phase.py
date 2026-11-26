"""Tests for conwrt esim's raw ssh seams + WiFi-backup phase (#794).

The command/orchestration layers are covered by test_esim_commands.py;
the remaining 14% was the raw _ssh/_ssh_ok/_at_run subprocess seams and
provision's Phase-2 WiFi-STA backup branch. Seams faked at subprocess —
no router, no wire.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from conwrt import esim  # noqa: E402


def _cp(rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], rc, stdout=stdout, stderr=stderr)


@pytest.fixture()
def fake_run(monkeypatch):
    calls: list[list[str]] = []
    outputs: list = []

    def _run(argv, **kw):
        calls.append(argv)
        return outputs.pop(0) if outputs else _cp()

    monkeypatch.setattr(esim.subprocess, "run", _run)
    return calls


class TestRawSshSeams:
    def test_ssh_argv_and_output_concat(self, fake_run, monkeypatch):
        outputs = [_cp(0, "out", "err")]
        monkeypatch.setattr(esim.subprocess, "run",
                            lambda argv, **kw: outputs.pop(0))
        out = esim._ssh("1.2.3.4", "uptime", key="/k/id")
        assert out == "outerr"  # stdout + stderr concatenated
        # (argv shape asserted via fake_run in the sibling test below)

    def test_ssh_argv_with_and_without_key(self, fake_run):
        esim._ssh("1.2.3.4", "uptime")
        argv = fake_run[-1]
        assert argv[0] == "ssh" and argv[-1] == "uptime"
        assert "root@1.2.3.4" in argv
        assert "-i" not in argv
        assert "StrictHostKeyChecking=accept-new" in argv
        esim._ssh("1.2.3.4", "uptime", key="/k/id")
        assert "/k/id" in fake_run[-1]

    def test_ssh_ok_true_on_rc0(self, fake_run):
        fake_run.append(_cp(0))
        assert esim._ssh_ok("1.2.3.4") is True
        argv = fake_run[-1]
        assert "BatchMode=yes" in argv and argv[-1] == "true"

    def test_ssh_ok_false_on_timeout(self, monkeypatch):
        def boom(argv, **kw):
            raise subprocess.TimeoutExpired(cmd="ssh", timeout=10)
        monkeypatch.setattr(esim.subprocess, "run", boom)
        assert esim._ssh_ok("1.2.3.4") is False

    def test_at_run_wraps_modem_at(self, fake_run):
        esim._at_run("1.2.3.4", "AT+QCCID", key="/k/id")
        cmd = fake_run[-1][-1]
        assert "modem-at probe" in cmd
        assert "modem-at run $P 'AT+QCCID'" in cmd
        assert "2>/dev/null" in cmd


class TestProvisionWifiBackupPhase:
    def _seams(self, monkeypatch, ssh_replies):
        """Reply formats mirror the sibling suite (test_esim_commands.py):
        the MBIM gates, the eidValue payload shape, and the one-shot
        download's JSON iccid extraction."""
        calls: dict[str, list] = {"ssh": [], "at": [], "lpac": []}
        from types import SimpleNamespace
        base = {
            "ls /dev/cdc-wdm0 2>/dev/null && echo MBIM": "/dev/cdc-wdm0\nMBIM",
            "ping -I usb0 -c 2 -W 5 8.8.8.8 2>&1 | tail -1":
                "rtt min/avg/max = 40/42/45 ms",
        }
        base.update(ssh_replies)

        def _ssh(ip, cmd, key=None):
            calls["ssh"].append(cmd)
            return base.get(cmd, "")

        def _at(ip, cmd, key=None):
            calls["at"].append(cmd)
            return "+QCCID: 8986001234567890123\nOK"

        def _lpac(ip, args, key=None):
            calls["lpac"].append(args)
            if args == "chip info":
                return ('{"payload":{"data":{"eidValue":'
                        '"89049032000001000000000000000000"}}}')
            if args.startswith("profile download"):
                return '{"code":0,"data":{"iccid":"8986001234567890123"}}'
            if args.startswith("profile enable"):
                return '{"code":0}'
            if args.startswith("notification process"):
                return '{"code":0}'
            return "OK"

        monkeypatch.setattr(esim, "_ssh", _ssh)
        monkeypatch.setattr(esim, "_at_run", _at)
        monkeypatch.setattr(esim, "_lpac_run", _lpac)
        monkeypatch.setattr(esim, "_ssh_ok", lambda ip, key=None: True)
        monkeypatch.setattr(esim, "wait_for_power_cycle", lambda ip, key=None: True)
        monkeypatch.setattr(esim.time, "sleep", lambda s: None)
        return SimpleNamespace(calls=calls)

    def test_wifi_block_embedded_when_ssid_given(self, monkeypatch, capsys):
        s = self._seams(monkeypatch, {})
        rc = esim.cmd_esim_provision("1.2.3.4", None, "smdp.example", "MID1",
                                     "data.apn", wifi_ssid="Bench5G",
                                     wifi_key="secret123")
        assert rc == 0, capsys.readouterr().out[-400:]
        wifi_cmds = [c for c in s.calls["ssh"]
                     if "wireless.wwansta" in c]
        assert wifi_cmds, "phase-2 WiFi uci block must fire"
        cmd = wifi_cmds[0]
        assert "ssid='Bench5G'" in cmd and "key='secret123'" in cmd
        assert "mode='sta'" in cmd and "encryption='sae-mixed'" in cmd
        assert "uci revert wireless" in cmd
        assert "wifi reload" in cmd

    def test_wifi_test_success_message(self, monkeypatch, capsys):
        replies = {"ping -I phy0-sta0 -c 2 -W 5 8.8.8.8 2>&1 | tail -1":
                   "round-trip min/avg/max = 20/25/30 ms"}
        self._seams(monkeypatch, replies)
        rc = esim.cmd_esim_provision("1.2.3.4", None, "s", "m", "a",
                                     wifi_ssid="Bench5G", wifi_key="k")
        assert rc == 0
        assert "WiFi internet backup working" in capsys.readouterr().out

    def test_wifi_test_failure_warns_but_continues(self, monkeypatch, capsys):
        replies = {"ping -I phy0-sta0 -c 2 -W 5 8.8.8.8 2>&1 | tail -1":
                   "2 packets received, 0% loss"}  # no time=/round-trip
        self._seams(monkeypatch, replies)
        rc = esim.cmd_esim_provision("1.2.3.4", None, "s", "m", "a",
                                     wifi_ssid="Bench5G", wifi_key="k")
        out = capsys.readouterr().out
        assert rc == 0, "wifi failure is a warning, not a pipeline failure"
        assert "WiFi test:" in out

    def test_no_ssid_skips_phase(self, monkeypatch, capsys):
        s = self._seams(monkeypatch, {})
        rc = esim.cmd_esim_provision("1.2.3.4", None, "s", "m", "a")
        assert rc == 0
        out = capsys.readouterr().out
        assert "Skipping WiFi backup" in out
        assert not any("wireless.wwansta" in c for c in s.calls["ssh"])
