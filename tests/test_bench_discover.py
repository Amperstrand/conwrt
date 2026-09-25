"""bench-discover — unit tests for the pure hypothesis-engine logic.

Hardware-safe: nothing here touches a network. Execution paths
(run_ladder/ssh_probe_host) are intentionally NOT exercised.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
spec = importlib.util.spec_from_file_location("bench_discover", _SCRIPTS / "bench_discover.py")
assert spec and spec.loader
bd = importlib.util.module_from_spec(spec)
sys.modules.setdefault("bench_discover", bd)
spec.loader.exec_module(bd)


# ---------------------------------------------------------------- EUI-64

class TestEui64LinkLocal:
    def test_known_vectors(self) -> None:
        # b4:2d:56:25:47:a2 -> b4^02 = b6 -> fe80::b62d:56ff:fe25:47a2
        assert bd.mac_to_eui64_linklocal("b4:2d:56:25:47:a2") == "fe80::b62d:56ff:fe25:47a2"
        assert bd.mac_to_eui64_linklocal("b4:2d:56:25:86:bd") == "fe80::b62d:56ff:fe25:86bd"
        # 00:11:22:33:44:55 -> 02:11:22:ff:fe:33:44:55 (RFC-documented example)
        assert bd.mac_to_eui64_linklocal("00:11:22:33:44:55") == "fe80::0211:22ff:fe33:4455"
        # RFC 4291: U/L bit XOR -> fa becomes f8; pair form keeps leading zeros
        assert bd.mac_to_eui64_linklocal("fa:16:3e:60:02:17") == "fe80::f816:3eff:fe60:0217"

    def test_format_tolerant(self) -> None:
        assert bd.mac_to_eui64_linklocal("B42D.5625.47A2".lower()) == "fe80::b62d:56ff:fe25:47a2"
        assert bd.mac_to_eui64_linklocal("b4-2d-56-25-47-a2") == "fe80::b62d:56ff:fe25:47a2"

    def test_rejects_garbage(self) -> None:
        with pytest.raises(ValueError):
            bd.mac_to_eui64_linklocal("not-a-mac")


# ---------------------------------------------------------------- helpers

def test_initial_ttl_guess() -> None:
    assert bd.initial_ttl_guess(64) == 64
    assert bd.initial_ttl_guess(63) == 64
    assert bd.initial_ttl_guess(33) == 64
    assert bd.initial_ttl_guess(32) == 32
    assert bd.initial_ttl_guess(128) == 128
    assert bd.initial_ttl_guess(254) == 255


def test_dhcp55_fingerprint() -> None:
    assert bd.dhcp55_fingerprint([1, 3, 6, 15]) == "1,3,6,15"


# ---------------------------------------------------------------- archaeology

def test_inventory_ip_history(tmp_path: Path) -> None:
    inv = tmp_path / "inventory.jsonl"
    inv.write_text(json.dumps({
        "mac_addresses": ["b4:2d:56:25:47:a2"],
        "notes": "was at 192.168.13.253 then moved; see 10.0.0.5 also 192.168.13.253",
    }) + "\n" + json.dumps({
        "mac_addresses": ["aa:bb:cc:dd:ee:ff"], "notes": "other device 1.2.3.4",
    }) + "\n")
    assert bd.inventory_ip_history("b4:2d:56:25:47:a2", inv) == ["192.168.13.253", "10.0.0.5"]


def test_subnet_candidates_priority_and_dedup() -> None:
    result = bd.subnet_candidates(
        ["192.168.13.2"],                      # probe host's own subnet (host IP form)
        inventory_history=["192.168.13.253"],  # dedups against the same /24
        extra=["10.9.9.0/24"],
    )
    assert result[0] == "192.168.13.0/24"      # archaeology == probe-host subnet merged
    assert "10.9.9.0/24" in result
    assert len(result) == len(set(result))
    assert result[-1] in bd.RFC1918_COMMON     # defaults are last resort


# ---------------------------------------------------------------- ladder

def _ctx():
    return bd.DiscoverContext(
        mac="b4:2d:56:25:47:a2", iface="switch.1007",
        probe_host="switch", control_ip="192.168.13.1",
        subnets=["192.168.13.0/24", "10.0.0.0/24"],
    )


def test_ladder_control_first() -> None:
    steps = bd.build_ladder(_ctx())
    assert steps[0].layer == "0-control"
    assert "ABORT" in steps[0].negative_next


def test_ladder_v6_before_v4() -> None:
    steps = bd.build_ladder(_ctx())
    layers = [s.layer for s in steps]
    assert layers.index("1-v6") < layers.index("2-v4")
    v6 = [s for s in steps if s.layer == "1-v6"]
    assert any("fe80::b62d:56ff:fe25:47a2" in s.command for s in v6)
    v4 = [s for s in steps if s.layer == "2-v4"]
    assert len(v4) == 2
    assert any("192.168.13.0" in s.statement or "192.168.13" in s.command for s in v4)


def test_ladder_creds_are_printed_not_commands() -> None:
    steps = bd.build_ladder(_ctx())
    cred = [s for s in steps if s.layer == "4-creds"][0]
    assert "never auto-executed" in cred.statement.lower()


def test_credential_ladder_order() -> None:
    ladder = bd.credential_ladder(fleet_passwords=["site-secret"])
    assert ladder[0] == {"user": "root", "password": "site-secret", "rationale": "fleet-history"}
    pws = [c["password"] for c in ladder]
    assert pws.index("site-secret") < pws.index("") < pws.index("password")
    assert ("root", "conwrt") in [(c["user"], c["password"]) for c in ladder]


def test_plan_mode_cli_no_network(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "ladder.json"
    rc = bd.main([
        "plan", "--mac", "b4:2d:56:25:47:a2", "--iface", "switch.1007",
        "--control-ip", "192.168.13.1", "--probe-subnets", "192.168.13.2",
        "--json", str(out),
    ])
    assert rc == 0
    text = capsys.readouterr().out
    assert "fe80::b62d:56ff:fe25:47a2" in text
    payload = json.loads(out.read_text())
    assert payload["linklocal"] == "fe80::b62d:56ff:fe25:47a2"
    assert payload["steps"][0]["layer"] == "0-control"
