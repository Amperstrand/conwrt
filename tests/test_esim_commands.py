"""Tests for conwrt esim transport-level commands (#794 tier 2, lane 3).

The pure AT/lpac parsers already have 16 tests (test_esim_parsing.py);
this lane pins the COMMAND layer: status/profiles/switch flows, the
power-cycle poll, and the ssh seam composition. Transport stubbed at
module level — no router, no wire.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from conwrt import esim  # noqa: E402


@pytest.fixture()
def at(monkeypatch):
    """Script the AT-command layer; capture every modem command."""
    at_calls: list[str] = []
    replies: dict[str, str] = {}

    def at_run(ip, cmd, key=None):
        at_calls.append(cmd)
        return replies.get(cmd, "")

    monkeypatch.setattr(esim, "_at_run", at_run)
    return SimpleNamespace(calls=at_calls, replies=replies)


@pytest.fixture()
def lpac(monkeypatch):
    lpac_calls: list[str] = []
    replies: dict[str, str] = {}

    def lpac_run(ip, args, key=None):
        lpac_calls.append(args)
        return replies.get(args, "")

    monkeypatch.setattr(esim, "_lpac_run", lpac_run)
    return SimpleNamespace(calls=lpac_calls, replies=replies)


@pytest.fixture()
def ssh(monkeypatch):
    ssh_calls: list[str] = []
    replies: dict[str, str] = {}

    def _ssh(ip, cmd, key=None):
        ssh_calls.append(cmd)
        return replies.get(cmd, "")

    monkeypatch.setattr(esim, "_ssh", _ssh)
    return SimpleNamespace(calls=ssh_calls, replies=replies)


class TestSeamComposition:
    def test_at_run_wraps_modem_at(self, monkeypatch):
        sent = []

        def fake_ssh(ip, cmd, key=None):
            sent.append(cmd)
            return "OK"

        monkeypatch.setattr(esim, "_ssh", fake_ssh)
        out = esim._at_run("1.2.3.4", "AT+QCCID", key="k")
        assert out == "OK"
        assert sent[0].startswith("P=$(modem-at probe")
        assert "AT+QCCID" in sent[0]

    def test_lpac_run_sets_env(self, monkeypatch):
        sent = []

        def fake_ssh(ip, cmd, key=None):
            sent.append(cmd)
            return ""

        monkeypatch.setattr(esim, "_ssh", fake_ssh)
        esim._lpac_run("1.2.3.4", "profile list")
        assert "LPAC_APDU=mbim" in sent[0] and "/usr/bin/lpac profile list" in sent[0]


class TestWaitForPowerCycle:
    def test_full_cycle_detected(self, monkeypatch, capsys):
        # up -> down -> up: the poll sequence scripted via _ssh_ok
        states = iter([True, True, False, False, True])

        def ssh_ok(ip, key=None):
            return next(states)

        monkeypatch.setattr(esim, "_ssh_ok", ssh_ok)
        monkeypatch.setattr(esim.time, "sleep", lambda s: None)
        monkeypatch.setattr(esim.time, "time", lambda: 0)  # never times out
        assert esim.wait_for_power_cycle("1.2.3.4") is True
        out = capsys.readouterr().out
        assert "went down" in out and "device is back" in out

    def test_never_goes_down_times_out(self, monkeypatch, capsys):
        monkeypatch.setattr(esim, "_ssh_ok", lambda ip, key=None: True)
        monkeypatch.setattr(esim.time, "sleep", lambda s: None)
        # a clock that advances past the timeout on the second read
        t = iter([0, 10_000])
        monkeypatch.setattr(esim.time, "time", lambda: next(t))
        assert esim.wait_for_power_cycle("1.2.3.4") is False
        assert "TIMEOUT" in capsys.readouterr().out

    def test_goes_down_never_returns_times_out(self, monkeypatch, capsys):
        monkeypatch.setattr(esim, "_ssh_ok", lambda ip, key=None: False)
        monkeypatch.setattr(esim.time, "sleep", lambda s: None)
        t = iter([0, 0, 0, 0, 0, 10_000])
        monkeypatch.setattr(esim.time, "time", lambda: next(t))
        assert esim.wait_for_power_cycle("1.2.3.4") is False


class TestStatus:
    def test_prints_full_picture(self, at, capsys):
        # sample shapes copied from the canonical parser fixtures
        # (tests/test_esim_parsing.py QENG_LTE_SAMPLE / PROFILE_LIST_SAMPLE)
        at.replies.update({
            'AT+QENG="servingcell"':
                '+QENG: "servingcell","NOCONN","LTE","FDD",222,10,1D9DD1F,129,'
                '1650,3,5,5,AF7,-99,-10,-69,13,0,-,28',
            "AT+COPS?": '+COPS: 0,0,"TestTel",7',
            "AT+QCCID": "+QCCID: 8986001234567890123",
            "AT+CEREG?": '+CEREG: 2,1,"1A2345","01234567",7',
        })
        rc = esim.cmd_esim_status("1.2.3.4", key=None)
        out = capsys.readouterr().out
        assert rc == 0
        assert "8986001234567890123" in out
        assert "Operator:" in out and "Registration:" in out
        # the four probes fired in the documented order
        assert at.calls[0].startswith("AT+QENG")

    def test_empty_replies_still_succeed(self, at, capsys):
        rc = esim.cmd_esim_status("1.2.3.4", key=None)
        assert rc == 0
        assert "Registration:" in capsys.readouterr().out  # cereg dict always prints

    def test_legacy_warning_printed(self, at, capsys):
        esim.cmd_esim_status("1.2.3.4", key=None)
        assert "DEPRECATED" in capsys.readouterr().err


class TestProfiles:
    def test_not_mbim_mode_fails_with_fix_hint(self, ssh, lpac, capsys):
        ssh.replies["ls /dev/cdc-wdm0 2>/dev/null && echo MBIM || echo NOT-MBIM"] = "NOT-MBIM"
        rc = esim.cmd_esim_profiles("1.2.3.4", key=None)
        assert rc == 1
        err = capsys.readouterr().out
        assert "not in MBIM mode" in err and "usbnet" in err

    def test_lists_profiles(self, ssh, lpac, capsys):
        ssh.replies["ls /dev/cdc-wdm0 2>/dev/null && echo MBIM || echo NOT-MBIM"] = "/dev/cdc-wdm0\nMBIM"
        lpac.replies["profile list"] = (
            '{"type":"lpa","payload":{"code":0,"message":"success","data":['
            '{"iccid":"898600111","profileState":"enabled",'
            '"serviceProviderName":"silent.link","profileNickname":"data"}]}}')
        rc = esim.cmd_esim_profiles("1.2.3.4", key=None)
        out = capsys.readouterr().out
        assert rc == 0
        assert "898600111" in out and "silent.link" in out and "data" in out

    def test_no_profiles_fails(self, ssh, lpac, capsys):
        ssh.replies["ls /dev/cdc-wdm0 2>/dev/null && echo MBIM || echo NOT-MBIM"] = "MBIM"
        rc = esim.cmd_esim_profiles("1.2.3.4", key=None)
        assert rc == 1
        assert "could not list profiles" in capsys.readouterr().out


class TestSwitch:
    def test_success_code_zero(self, lpac, capsys):
        lpac.replies["profile enable 898600111"] = '{"code":0}'
        rc = esim.cmd_esim_switch("1.2.3.4", key=None, iccid="898600111")
        out = capsys.readouterr().out
        assert rc == 0
        assert "Power-cycle the router" in out  # does NOT reset the modem itself
        assert lpac.calls == ["profile enable 898600111"]

    def test_lpac_error_fails(self, lpac, capsys):
        lpac.replies["profile enable 898600111"] = '{"code":2,"message":"not found"}'
        rc = esim.cmd_esim_switch("1.2.3.4", key=None, iccid="898600111")
        assert rc == 1
        assert "not found" in capsys.readouterr().out


class TestProvision:
    """The 7-step pipeline, seams scripted end-to-end."""

    def _seams(self, monkeypatch):
        calls = {"ssh": [], "at": [], "lpac": []}
        ssh_replies: dict[str, str] = {
            "ls /dev/cdc-wdm0 2>/dev/null && echo MBIM || echo NOT-MBIM": "/dev/cdc-wdm0\nMBIM",
            # provision's post-cycle gate uses a SHORTER command string
            "ls /dev/cdc-wdm0 2>/dev/null && echo MBIM": "/dev/cdc-wdm0\nMBIM",
            "ping -I usb0 -c 2 -W 5 8.8.8.8 2>&1 | tail -1":
                "rtt min/avg/max = 40/42/45 ms",
        }
        lpac_replies = {
            "chip info": '{"payload":{"data":{"eidValue":"89049032000001000000000000000000"}}}',
            "profile list": '{"payload":{"data":[]}}',
            "profile download -s smdp.example -m MID1":
                '{"code":0,"data":{"iccid":"8986001234567890123"}}',
            "profile enable 8986001234567890123": '{"code":0}',
            "notification process -a -r": '{"code":0}',
        }
        at_replies = {"AT+QCCID": "+QCCID: 8986001234567890123"}
        # the pipeline has a literal 60s modem-settle sleep — never wait it
        monkeypatch.setattr(esim.time, "sleep", lambda s: None)

        def _ssh(ip, cmd, key=None):
            calls["ssh"].append(cmd)
            return ssh_replies.get(cmd, "")

        def _at(ip, cmd, key=None):
            calls["at"].append(cmd)
            return at_replies.get(cmd, "")

        def _lpac(ip, args, key=None):
            calls["lpac"].append(args)
            return lpac_replies.get(args, "")

        monkeypatch.setattr(esim, "_ssh", _ssh)
        monkeypatch.setattr(esim, "_at_run", _at)
        monkeypatch.setattr(esim, "_lpac_run", _lpac)
        monkeypatch.setattr(esim, "_ssh_ok", lambda ip, key=None: True)
        monkeypatch.setattr(esim, "wait_for_power_cycle", lambda ip, key=None: True)
        return SimpleNamespace(calls=calls, ssh_replies=ssh_replies,
                               lpac_replies=lpac_replies, at_replies=at_replies)

    def test_happy_path_runs_all_seven_steps(self, monkeypatch, capsys):
        s = self._seams(monkeypatch)
        rc = esim.cmd_esim_provision("1.2.3.4", None, "smdp.example", "MID1", "data.apn")
        out = capsys.readouterr().out
        assert rc == 0, out[-400:]
        # the pipeline's ordered legs all fired
        assert any("kmod-usb-net-cdc-mbim" in c for c in s.calls["ssh"])
        assert 'AT+QCFG="usbnet",2' in s.calls["at"]
        assert s.calls["lpac"][0] == "chip info"
        assert any(a.startswith("profile download -s smdp.example -m MID1")
                   for a in s.calls["lpac"])
        assert "profile enable 8986001234567890123" in s.calls["lpac"]
        # final modem re-config back to ECM mode
        assert 'AT+QCFG="usbnet",1' in s.calls["at"]

    def test_unreachable_router_fails_step_one(self, monkeypatch, capsys):
        s = self._seams(monkeypatch)
        monkeypatch.setattr(esim, "_ssh_ok", lambda ip, key=None: False)
        rc = esim.cmd_esim_provision("1.2.3.4", None, "smdp.example", "MID1", "data.apn")
        assert rc == 1
        assert "cannot reach router" in capsys.readouterr().out

    def test_power_cycle_timeout_fails(self, monkeypatch, capsys):
        s = self._seams(monkeypatch)
        monkeypatch.setattr(esim, "wait_for_power_cycle", lambda ip, key=None: False)
        rc = esim.cmd_esim_provision("1.2.3.4", None, "smdp.example", "MID1", "data.apn")
        assert rc == 1

    def test_download_failure_fails(self, monkeypatch, capsys):
        s = self._seams(monkeypatch)
        s.lpac_replies["profile download -s smdp.example -m MID1"] = \
            '{"code":1,"message":"matching ID not found"}'
        rc = esim.cmd_esim_provision("1.2.3.4", None, "smdp.example", "MID1", "data.apn")
        assert rc == 1
