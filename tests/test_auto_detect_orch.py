"""Orchestration tests for auto_detect (#794 lane 2) — the phase pipeline
and main() wiring, with every network-touching phase patched at module
level (the pure helpers already have 93 tests in test_auto_detect.py).
No scapy, no tcpdump, no wire.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import auto_detect as ad
from auto_detect import DetectedRouter


def _router(ip="192.168.0.1", mac="AA:BB:CC:DD:EE:01") -> DetectedRouter:
    return DetectedRouter(ip=ip, mac=mac)


def _patched_phases(monkeypatch, *, passive=None, lldp=None, dhcp=None,
                    arp=None, link=True, identified=None):
    """Patch every phase function auto_detect() composes; returns spies.

    Seeds one passive ARP host by default so the pipeline reaches
    Phase 4/5 (an empty picture returns [] before identify_router).
    """
    passive = passive or {
        "macs": {},
        "dhcp_servers": [],
        "arp_hosts": [{"ip": "192.168.0.1", "mac": "AA:BB:CC:DD:EE:01"}],
        "icmpv6_routers": [],
    }
    lldp = lldp or {}
    dhcp = dhcp or {"gateway_ip": "", "server_mac": ""}
    routers = identified if identified is not None else [_router()]

    spies = {}
    for name, retval in [
        ("passive_listen", passive),
        ("lldp_probe", lldp),
        ("dhcp_client_probe", dhcp),
        ("get_link_state", link),
    ]:
        m = MagicMock(return_value=retval)
        monkeypatch.setattr(ad, name, m)
        spies[name] = m
    monkeypatch.setattr(ad, "arp_scan", MagicMock(return_value=arp or []))
    probed = []
    monkeypatch.setattr(ad, "active_probe", lambda ip: probed.append(ip) or {"ip": ip})
    def _identify(*a, **kw):
        # identify_router returns ONE DetectedRouter per call; pop from
        # the list so multi-router cases feed successive calls
        return routers.pop(0) if len(routers) > 1 else routers[0]

    monkeypatch.setattr(ad, "identify_router", _identify)
    spies["probed_ips"] = probed
    return spies, routers


class TestAutoDetectOrchestration:
    def test_returns_identified_routers(self, monkeypatch):
        routers = [_router(), _router("192.168.0.2")]
        _patched_phases(
            monkeypatch,
            passive={"macs": {}, "dhcp_servers": [],
                     "arp_hosts": [{"ip": "192.168.0.1", "mac": "AA:BB:CC:DD:EE:01"},
                                   {"ip": "192.168.0.2", "mac": "AA:BB:CC:DD:EE:02"}],
                     "icmpv6_routers": []},
            identified=routers)
        expected = list(routers)  # the stub pops; snapshot before
        out = ad.auto_detect("eth0")
        # one identify call per discovered host, in sorted order
        assert out == expected and len(out) == 2

    def test_dhcp_probe_only_runs_without_passive_servers(self, monkeypatch):
        spies, _ = _patched_phases(
            monkeypatch,
            passive={"macs": {}, "dhcp_servers": [{"ip": "192.168.0.1", "mac": "AA:BB:CC:DD:EE:01"}],
                     "arp_hosts": [], "icmpv6_routers": []})
        ad.auto_detect("eth0")
        spies["dhcp_client_probe"].assert_not_called()

    def test_dhcp_probe_runs_when_passive_found_none(self, monkeypatch):
        spies, _ = _patched_phases(
            monkeypatch,
            dhcp={"gateway_ip": "192.168.0.254", "server_mac": "AA:BB:CC:DD:EE:FE"})
        out = ad.auto_detect("eth0")
        spies["dhcp_client_probe"].assert_called_once()

    def test_passive_arp_hosts_seed_the_probe_targets(self, monkeypatch):
        spies, _ = _patched_phases(
            monkeypatch,
            passive={"macs": {}, "dhcp_servers": [],
                     "arp_hosts": [{"ip": "192.168.77.5", "mac": "AA:BB:CC:DD:EE:05"}],
                     "icmpv6_routers": []})
        ad.auto_detect("eth0")
        assert "192.168.77.5" in spies["probed_ips"]

    def test_lldp_management_ip_seeds_targets(self, monkeypatch):
        spies, _ = _patched_phases(monkeypatch, lldp={})
        info = ad.LLDPInfo(chassis_mac="AA:BB:CC:DD:EE:10", chassis_name="sw",
                           management_ip="10.1.2.3", vendor_specific={})
        # LLDP seeds discovered_ips BEFORE the passive picture is read:
        # patch lldp separately with the info while keeping the default
        # passive seed
        monkeypatch.setattr(ad, "lldp_probe", MagicMock(return_value={"10.1.2.3": info}))
        ad.auto_detect("eth0")
        assert "10.1.2.3" in spies["probed_ips"]

    def test_no_link_still_proceeds_with_warning(self, monkeypatch, capsys):
        _patched_phases(monkeypatch, link=False)
        out = ad.auto_detect("eth0")
        assert out == [_router()]
        assert "No link" in capsys.readouterr().out


class TestMain:
    def test_main_json_output_shape(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv",
                            ["auto_detect.py", "--interface", "eth9", "--json"])
        monkeypatch.setattr(ad, "auto_detect", lambda iface, **kw: [_router()])
        ad.main()
        out = capsys.readouterr().out
        import json as _json
        parsed = _json.loads(out)
        assert parsed[0]["ip"] == "192.168.0.1"
        assert parsed[0]["mac"] == "AA:BB:CC:DD:EE:01"

    def test_main_no_menu_prints_routers(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv",
                            ["auto_detect.py", "-i", "eth9", "--no-menu"])
        monkeypatch.setattr(ad, "auto_detect", lambda iface, **kw: [_router()])
        monkeypatch.setattr(ad, "_print_router", lambda r: print(f"ROUTER {r.ip}"))
        ad.main()
        assert "ROUTER 192.168.0.1" in capsys.readouterr().out

    def test_main_no_devices_json_is_empty_list(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv",
                            ["auto_detect.py", "--interface", "eth9", "--json"])
        monkeypatch.setattr(ad, "auto_detect", lambda iface, **kw: [])
        ad.main()
        assert capsys.readouterr().out.strip() == "[]"


class TestArpScanFallback:
    def test_fallback_uses_arp_lookup_per_ip(self, monkeypatch):
        lookups = {}

        def fake_lookup(ip):
            lookups[ip] = f"AA:BB:CC:00:00:{len(lookups):02X}"
            return lookups[ip]

        monkeypatch.setattr(ad, "_arp_lookup", fake_lookup)
        monkeypatch.setattr(ad, "_ping", lambda ip, timeout=2: True)
        monkeypatch.setattr(ad, "configure_interface_ip", lambda *a, **kw: True)
        monkeypatch.setattr(ad.time, "sleep", lambda s: None)
        found = ad._arp_scan_fallback("eth0", ["10.0.0.1", "10.0.0.2"])
        assert {e["ip"] for e in found} == {"10.0.0.1", "10.0.0.2"}
        assert all(e["mac"] in lookups.values() for e in found)

    def test_arp_lookup_parses_command_output(self, monkeypatch):
        from subprocess import CompletedProcess

        monkeypatch.setattr(
            ad.subprocess, "run",
            lambda *a, **kw: CompletedProcess(
                args=[], returncode=0,
                stdout="? (10.0.0.9) at aa:bb:cc:dd:ee:ff [ether] on eth0\n"))
        # raw match, no normalization (callers normalize via _normalize_mac)
        assert ad._arp_lookup("10.0.0.9") == "aa:bb:cc:dd:ee:ff"


class TestTcpdumpFallbackParser:
    def test_arp_replies_populate_result(self, monkeypatch):
        # the readline loop consumes tcpdump transcript lines; feed two
        # ARP replies and confirm the parsed shapes (normalized MACs)
        result = {"macs": {}, "dhcp_servers": [], "arp_hosts": [], "icmpv6_routers": []}
        lines = iter([
            "14:00:01.000001 ARP, Reply 192.168.0.1 is-at aa:bb:cc:dd:ee:01,\n",
            "14:00:02.000002 ARP, Reply 192.168.0.2 is-at aa:bb:cc:dd:ee:02,\n",
            "",
        ])

        from subprocess import CompletedProcess
        from types import SimpleNamespace

        class _FakeProc(SimpleNamespace):
            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

        proc = _FakeProc(stdout=SimpleNamespace(readline=lambda: next(lines)))
        monkeypatch.setattr(
            ad.subprocess, "run",
            lambda *a, **kw: CompletedProcess(args=[], returncode=0, stdout="", stderr=""))
        monkeypatch.setattr(ad.subprocess, "Popen", lambda *a, **kw: proc)
        monkeypatch.setattr(ad.time, "monotonic", lambda: [0, 0, 99].pop(0))
        ad._passive_listen_tcpdump("eth0", 5, result)
        assert {e["ip"] for e in result["arp_hosts"]} == {"192.168.0.1", "192.168.0.2"}
        assert result["macs"]["AA:BB:CC:DD:EE:01"]["ip"] == "192.168.0.1"
