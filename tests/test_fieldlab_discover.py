"""Coverage for fieldlab discover_cmd host-side legs (#794 continuation).

The neighbor-table parser, ping reachability verdict, port-scan
dispatch (python3 vs busybox nc), and HTTP probe — all against a
stubbed transport. The parsers are the real logic under test.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

import fieldlab.discover_cmd as discover_mod
from fieldlab.transport import Host


@pytest.fixture()
def stub_remote(monkeypatch):
    outputs: list[str] = []
    rcs: list[int] = []
    cmds: list[str] = []

    def fake_run_remote(host, cmd, timeout=10):
        cmds.append(cmd)
        out = outputs.pop(0) if outputs else ""
        rc = rcs.pop(0) if rcs else 0
        return SimpleNamespace(stdout=out, returncode=rc)

    tools: dict[str, bool] = {}

    def fake_check_tool(host, tool, timeout=10):
        return tools.get(tool, True)

    import fieldlab.transport as transport_mod
    monkeypatch.setattr(transport_mod, "run_remote", fake_run_remote)
    monkeypatch.setattr(discover_mod, "run_remote", fake_run_remote)
    monkeypatch.setattr(discover_mod, "check_tool", fake_check_tool)
    return SimpleNamespace(outputs=outputs, rcs=rcs, cmds=cmds, tools=tools)


class TestReadNeighbors:
    def test_parses_entries_and_state(self, stub_remote):
        stub_remote.outputs.append(
            "192.168.8.23 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
            "192.168.8.99 dev eth0 lladdr 11:22:33:44:55:66 STALE\n")
        ns = discover_mod._read_neighbors(Host(ip="r"), "eth0")
        assert ns[0]["ip"] == "192.168.8.23"
        assert ns[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert ns[0]["state"] == "reachable"
        assert ns[1]["state"] == "stale"

    def test_skips_garbage_lines(self, stub_remote):
        stub_remote.outputs.append("\nrandom text no ip\n")
        assert discover_mod._read_neighbors(Host(ip="r"), "eth0") == []

    def test_unknown_state_default(self, stub_remote):
        stub_remote.outputs.append("10.1.2.3 dev eth0 lladdr aa:bb:cc:dd:ee:01")
        ns = discover_mod._read_neighbors(Host(ip="r"), "eth0")
        assert ns[0]["state"] == "unknown"

    def test_interface_is_quoted_in_command(self, stub_remote):
        stub_remote.outputs.append("")
        discover_mod._read_neighbors(Host(ip="r"), "eth 0")
        assert "'eth 0'" in stub_remote.cmds[0]


class TestPingTarget:
    def test_reachable_when_zero_loss(self, stub_remote):
        stub_remote.outputs.append(
            "PING x: 2 packets.\n--- x ---\n2 received, 0% packet loss\n"
            "rtt min/avg/max = 1.2/2.3/4.5 ms\n")
        r = discover_mod._ping_target(Host(ip="r"), "10.0.0.5")
        assert r["reachable"] and "rtt" in r["rtt"]

    def test_unreachable_on_loss(self, stub_remote):
        stub_remote.rcs.append(1)
        stub_remote.outputs.append("2 packets, 100% packet loss")
        r = discover_mod._ping_target(Host(ip="r"), "10.0.0.5")
        assert not r["reachable"]

    def test_probe_interface_flag(self, stub_remote):
        stub_remote.outputs.append("")
        discover_mod._ping_target(Host(ip="r"), "10.0.0.5", probe_if="eth0")
        assert " -I eth0" in stub_remote.cmds[0]
        stub_remote.outputs.append("")
        discover_mod._ping_target(Host(ip="r"), "10.0.0.5")
        assert " -I " not in stub_remote.cmds[1]


class TestScanPorts:
    def test_python_path_probes_each_port(self, stub_remote):
        stub_remote.outputs.extend(["open\n", "closed\n"])
        rs = discover_mod._scan_ports(Host(ip="r"), "10.0.0.5", [80, 443])
        assert rs == [{"port": 80, "state": "open"},
                      {"port": 443, "state": "closed"}]
        assert "python3 -c" in stub_remote.cmds[0]

    def test_nc_fallback_shape(self, stub_remote):
        stub_remote.tools["python3"] = False
        stub_remote.outputs.extend(["open\n", "closed\n"])
        rs = discover_mod._scan_ports(Host(ip="r"), "10.0.0.5", [22])
        assert rs[0]["state"] == "open"
        assert stub_remote.cmds[0].startswith("nc ")

    def test_no_tool_error_row(self, stub_remote):
        stub_remote.tools["python3"] = False
        stub_remote.tools["nc"] = False
        rs = discover_mod._scan_ports(Host(ip="r"), "10.0.0.5", [22])
        assert rs == [{"error": "neither python3 nor nc available on field router"}]


class TestProbeHttp:
    def test_http_response_reachable(self, stub_remote):
        stub_remote.outputs.append("HTTP/1.1 200 OK\nServer: uhttpd")
        r = discover_mod._probe_http(Host(ip="r"), "10.0.0.5")
        assert r["available"] and r["reachable"]

    def test_non_http_is_not_reachable(self, stub_remote):
        stub_remote.outputs.append("ssh banner junk")
        r = discover_mod._probe_http(Host(ip="r"), "10.0.0.5")
        assert r["available"] and not r["reachable"]

    def test_curl_missing_note(self, stub_remote):
        stub_remote.tools["curl"] = False
        r = discover_mod._probe_http(Host(ip="r"), "10.0.0.5")
        assert not r["available"] and "curl" in r["note"]
