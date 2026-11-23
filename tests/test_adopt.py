"""Offline tests for `conwrt adopt` + `conwrt v6door` (#689) — a fake door
drives the gate ladder; nothing here dials a network."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from conwrt import adopt as A  # noqa: E402
from conwrt import v6door as V  # noqa: E402

PLAN = A.AdoptPlan(
    mac="b4:2d:56:25:79:b1",
    mgmt_ip="192.168.104.51/24",
    hostname="ap-lan4",
    ssh_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIConwrtKEY root@switch",
)


class FakeDoor(V.Door):
    """Canned per-command replies; records every command it was asked."""

    def __init__(self, replies: dict | None = None, defaults: bool = True):
        self.calls: list[str] = []
        self.replies = replies or {}
        self.defaults = defaults

    def run(self, cmd: str, timeout: int = 30) -> V.DoorResult:
        self.calls.append(cmd)
        for needle, reply in self.replies.items():
            if needle in cmd:
                return V.DoorResult(0, reply)
        if not self.defaults:
            return V.DoorResult(1, "connection refused")
        # sensible per-gate defaults
        if "uname -a" in cmd:
            return V.DoorResult(0, "Linux OpenWrt 6.6.74 #0 SMP")
        if "dhcp.lan.ignore" in cmd and "---READBACK---" in cmd:
            return V.DoorResult(0, "---READBACK---\n1\ndisabled\ndisabled")
        if "network.lan.ipaddr" in cmd and "---READBACK---" in cmd:
            return V.DoorResult(0, f"---READBACK---\nstatic\n{PLAN.mgmt_ip}")
        if "COMMITTED" in cmd:
            return V.DoorResult(0, "COMMITTED")
        if "authorized_keys" in cmd:
            return V.DoorResult(0, "---READBACK---\n1\n" + PLAN.hostname)
        return V.DoorResult(0, "")


class TestEui64:
    def test_known_vectors(self) -> None:
        assert V.derive_linklocal("00:11:22:33:44:55") == "fe80::211:22ff:fe33:4455"
        assert V.derive_linklocal("B4:2D:56:25:79:B1") == "fe80::b62d:56ff:fe25:79b1"

    def test_rejects_garbage(self) -> None:
        with pytest.raises(ValueError):
            V.derive_linklocal("not-a-mac")


class TestAdoptLadder:
    def test_happy_path_passes_all_gates(self) -> None:
        door = FakeDoor()
        report = A.run_adoption(PLAN, door, v4_timeout=0)
        names = [g.name for g in report.gates]
        assert names[:5] == ["alive", "shell", "rogue", "mgmt-ip", "key"]
        assert all(g.ok for g in report.gates[:5])
        # v4 is best-effort; with timeout 0 on an unreachable IP it may fail
        # without failing the adoption *report's* early gates.

    def test_lying_rogue_readback_stops_the_ladder(self) -> None:
        door = FakeDoor(replies={
            "dhcp.lan.dhcpv6='disabled'": "---READBACK---\n1\ndisabled\nserver",
        })
        report = A.run_adoption(PLAN, door)
        names = [g.name for g in report.gates]
        assert "rogue" in names[-1] and not report.gates[-1].ok
        # the mgmt-ip and key gates never ran
        assert not any("uci commit network" in c for c in door.calls)

    def test_lying_ip_readback_never_commits(self) -> None:
        door = FakeDoor(replies={
            "uci add_list network.lan.ipaddr": "---READBACK---\nstatic\n",
        })
        report = A.run_adoption(PLAN, door)
        assert any(not g.ok for g in report.gates)
        assert not any("uci commit network" in c for c in door.calls)

    def test_cidr_form_is_staged_never_bare_netmask(self) -> None:
        door = FakeDoor()
        A.run_adoption(PLAN, door, v4_timeout=0)
        staging = next(c for c in door.calls if "add_list network.lan.ipaddr" in c)
        assert f"'{PLAN.mgmt_ip}'" in staging
        assert "netmask" not in staging
        # clean baseline precedes staging (aborted-run /tmp/.uci discipline)
        assert "uci revert network" in staging

    def test_key_install_is_idempotent_and_readback(self) -> None:
        door = FakeDoor()
        A.run_adoption(PLAN, door, v4_timeout=0)
        keycmd = next(c for c in door.calls if "authorized_keys" in c)
        assert "grep -qF" in keycmd and "||" in keycmd
        assert "chmod 600" in keycmd

    def test_json_report_shape(self) -> None:
        door = FakeDoor()
        report = A.run_adoption(PLAN, door, v4_timeout=0)
        doc = json.loads(report.to_json())
        assert doc["mac"] == PLAN.mac
        assert isinstance(doc["adopted"], bool)
        assert {g["gate"] for g in doc["gates"]} >= {"alive", "shell", "rogue", "mgmt-ip", "key"}

    def test_door_failure_names_the_gate(self) -> None:
        report = A.run_adoption(PLAN, FakeDoor(defaults=False))
        assert not all(g.ok for g in report.gates)
        # the failing rung is named as a gate, not as transport boilerplate
        assert report.gates[-1].name == "shell"
        assert "uname -a" in report.gates[-1].detail


class TestDryRun:
    def test_prints_ladder_without_any_door(self, capsys) -> None:
        for line in A._dry_run_ladder(PLAN):
            assert isinstance(line, str)
        ladder = A._dry_run_ladder(PLAN)
        assert any("ping fe80::" in l for l in ladder)
        assert any(PLAN.mgmt_ip in l for l in ladder)
