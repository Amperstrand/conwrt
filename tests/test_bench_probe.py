"""bench_probe — positive-control tests (hardware-safe; canned switch only).

#286: a net-dead/silent verdict may only be recorded when the same-path
controls (switch shell, dbclient applet, VLAN interface) prove the bench
network itself is alive. Switch-side failures must read `unprobed`.
"""

from __future__ import annotations

import json

import pytest

import bench_probe as bp

PLACE = {"name": "ap-lan5", "mac": "b4:2d:56:24:ad:97", "vlan": 1005}
ZONE = f"switch.{PLACE['vlan']}"

NEIGH_PRESENT = ("192.168.105.51 dev switch.1005 lladdr b4:2d:56:24:ad:97 "
                 "ref 1 used 0/0/0 probes 1 REACHABLE")

# Needles are matched against the exact switch-side scripts probe() issues:
#   key probe  -> "dbclient -y -y"      control2 -> "command -v dbclient"
#   neighbors  -> "ip neigh show"       control3 -> "ip link show"
CONTROLS_OK = {
    "echo BENCH-CTRL-OK": "BENCH-CTRL-OK",
    "command -v dbclient": "/usr/bin/dbclient",
    "ip link show": "LINK-CTRL:0",
}


def fake_switch(monkeypatch: pytest.MonkeyPatch,
                responses: dict[str, str],
                default: str = "") -> list[str]:
    """Patch on_switch to answer scripted probes; record every script."""
    calls: list[str] = []

    def on_switch(script: str, timeout_s: int = bp.PROBE_TIMEOUT) -> str:
        calls.append(script)
        for needle, out in responses.items():
            if needle in script:
                return out
        return default

    monkeypatch.setattr(bp, "on_switch", on_switch)
    return calls


class TestNegativeVerdictsRequireControls:
    def test_net_dead_recorded_when_controls_pass(self, monkeypatch) -> None:
        # neigh present + dbclient timed out + healthy bench path -> net-dead
        fake_switch(monkeypatch, {
            "ip neigh show": NEIGH_PRESENT,
            "dbclient -y -y": "dbclient: Connection timed out",
            **CONTROLS_OK,
        })
        assert bp.probe(PLACE).verdict == "net-dead"

    def test_silent_recorded_when_controls_pass(self, monkeypatch) -> None:
        fake_switch(monkeypatch, {
            "ip neigh show": "",  # no neighbor entry
            "dbclient -y -y": "",
            **CONTROLS_OK,
        })
        assert bp.probe(PLACE).verdict == "silent"

    def test_switch_shell_dead_means_unprobed_not_net_dead(self, monkeypatch) -> None:
        # Switch SSH path broken: every control returns empty. Old code
        # recorded this as net-dead (a DUT failure) — #286.
        calls = fake_switch(monkeypatch, {"ip neigh show": NEIGH_PRESENT}, default="")
        result = bp.probe(PLACE)
        assert result.verdict == "unprobed"
        assert "switch SSH/shell control failed" in result.control
        assert any("echo BENCH-CTRL-OK" in c for c in calls), \
            "controls must run before a negative verdict is recorded"

    def test_missing_dbclient_applet_means_unprobed(self, monkeypatch) -> None:
        fake_switch(monkeypatch, {
            "ip neigh show": NEIGH_PRESENT,
            "dbclient -y -y": "sh: dbclient: not found",
            "echo BENCH-CTRL-OK": "BENCH-CTRL-OK",
            "command -v dbclient": "",  # applet absent on the switch
            "ip link show": "LINK-CTRL:0",
        })
        result = bp.probe(PLACE)
        assert result.verdict == "unprobed"
        assert "dbclient applet missing" in result.control

    def test_missing_vlan_means_unprobed_not_silent(self, monkeypatch) -> None:
        fake_switch(monkeypatch, {
            "ip neigh show": "",  # no neigh: would classify silent
            "dbclient -y -y": "",
            "echo BENCH-CTRL-OK": "BENCH-CTRL-OK",
            "command -v dbclient": "/usr/bin/dbclient",
            # real ip(8) error text names the interface — must NOT satisfy
            # the control (regression: substring check false-passed on it)
            "ip link show": f'Device "{ZONE}" does not exist.\nLINK-CTRL:1',
        })
        result = bp.probe(PLACE)
        assert result.verdict == "unprobed"
        assert "missing/down" in result.control

    def test_control_reason_carried_in_json_verdict(self, monkeypatch, tmp_path) -> None:
        fake_switch(monkeypatch, {"ip neigh show": NEIGH_PRESENT}, default="")
        result = bp.probe(PLACE, evidence_dir=tmp_path)
        assert result.verdict == "unprobed"
        evidence_file = next(p for p in tmp_path.iterdir() if p.name.endswith("-probe.txt"))
        evidence = json.loads(evidence_file.read_text().split("\n--- raw key probe ---")[0])
        assert evidence["verdict"] == "unprobed"
        assert "switch SSH/shell control failed" in evidence["control"]

    def test_text_output_names_the_control(self, monkeypatch) -> None:
        fake_switch(monkeypatch, {"ip neigh show": NEIGH_PRESENT}, default="")
        text = bp.probe(PLACE).text()
        assert "unprobed" in text
        assert "control" in text


class TestPositiveVerdictsUnaffected:
    def test_alive_skips_controls(self, monkeypatch) -> None:
        calls = fake_switch(monkeypatch, {
            "ip neigh show": NEIGH_PRESENT,
            "dbclient -y -y": "SSH-KEY-OK",
        }, default="")  # controls would fail; must not matter
        result = bp.probe(PLACE)
        assert result.verdict == "alive"
        assert result.control == ""
        assert not any("BENCH-CTRL-OK" in c for c in calls), \
            "positive verdicts already prove the path — controls gate negatives only"

    def test_auth_dead_skips_controls(self, monkeypatch) -> None:
        fake_switch(monkeypatch, {
            "ip neigh show": NEIGH_PRESENT,
            "dbclient -y -y": bp.AUTH_DEAD_MARKER,
        }, default="")
        assert bp.probe(PLACE).verdict == "auth-dead"


class TestControlsDirect:
    def test_all_controls_pass(self, monkeypatch) -> None:
        fake_switch(monkeypatch, CONTROLS_OK)
        assert bp.positive_controls(ZONE) == ""

    @pytest.mark.parametrize("broken,needle", [
        ({"echo BENCH-CTRL-OK": ""}, "switch SSH/shell"),
        ({"command -v dbclient": ""}, "dbclient applet"),
        ({"ip link show": ""}, "missing/down"),
    ])
    def test_each_control_failure_reasoned(self, monkeypatch, broken, needle) -> None:
        responses = dict(CONTROLS_OK)
        responses.update(broken)
        fake_switch(monkeypatch, responses)
        why = bp.positive_controls(ZONE)
        assert why != ""
        assert needle in why


class TestExitCode:
    def test_unprobed_is_not_success(self, monkeypatch, capsys) -> None:
        fake_switch(monkeypatch, {"ip neigh show": NEIGH_PRESENT}, default="")
        monkeypatch.setattr(bp, "load_place", lambda name: PLACE)
        monkeypatch.setattr(bp.sys, "argv",
                            ["bench_probe.py", "--place", PLACE["name"]])
        rc = bp.main()
        assert rc != 0
        assert "unprobed" in capsys.readouterr().out
