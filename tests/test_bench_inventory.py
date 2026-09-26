"""Offline checks for bench_inventory — parsers, drift classification,
exporter emission and places.json rewriting. No hardware is touched."""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import bench_inventory as bi

POE_RAW = json.dumps({"ports": {
    "lan2": {"status": "Delivering power"},
    "lan3": {"status": "Delivering power"},
    "lan4": {"status": "Delivering power"},
    "lan5": {"status": "Delivering power"},
    "lan6": "disabled",
    "lan7": "disabled",
    "lan8": "fault",
}})

FDB_RAW = "\n".join([
    "a0:36:9c:11:22:33 dev lan1 vlan 1 master switch permanent",
    "a0:36:9c:11:22:33 dev lan2 vlan 1002 master switch static",
    "dc:b8:08:6c:ea:7f dev lan2 vlan 1002 master switch used 12 sec ago",
    "b4:2d:56:25:47:a2 dev lan3 vlan 1003 master switch used 4 sec ago",
    "b4:2d:56:25:79:b1 dev lan4 vlan 1004 master switch used 0 sec ago",
    "b4:2d:56:24:ad:97 dev lan5 vlan 1005 master switch used 30 sec ago",
    "aa:bb:cc:dd:ee:ff dev lan7 vlan 1007 offload used 2 sec ago",
    "b4:2d:56:25:47:a2 dev lan3 local offload",
])

NEIGH_RAW = "\n".join([
    "--vlan 1002",
    "192.168.102.51 dev switch.1002 lladdr dc:b8:08:6c:ea:7f  REACHABLE",
    "fe80::deb8:8ff:fe6c:ea7f dev switch.1002 lladdr dc:b8:08:6c:ea:7f router STALE",
    "--vlan 1004",
    "192.168.104.51 lladdr b4:2d:56:25:79:b1 ref 1 used 0/0/0 probes 1 REACHABLE",
    "192.168.104.99  used 0/0/0 probes 6 FAILED",
    "--vlan 1005",
    "fe80::b62d:56ff:fe24:ad:97 lladdr b4:2d:56:24:ad:97 router used 0/0/0 probes 1 STALE",
    "--vlan 1007",
    "192.168.107.51 dev switch.1007 lladdr aa:bb:cc:dd:ee:ff  REACHABLE",
])

PLACES = {
    "labgrid_host": "example-exporter",
    "places": [
        {"name": "ap-lan2", "mac": "DC:B8:08:6C:EA:7F", "dut_ip": "192.168.102.51",
         "reset_allowed": True, "password": "seekrit"},
        {"name": "ap-lan3", "mac": "b4:2d:56:25:47:a2", "dut_ip": "192.168.103.51",
         "reset_allowed": True},
        {"name": "ap-lan4", "mac": "b4:2d:56:25:79:b1", "dut_ip": "192.168.104.51",
         "reset_allowed": True},
        {"name": "ap-lan5", "mac": "b4:2d:56:24:ad:97", "dut_ip": "192.168.105.51",
         "reset_allowed": False, "power_export": False},
        {"name": "ap-lan6", "mac": "11:22:33:44:55:66", "dut_ip": "192.168.106.51",
         "reset_allowed": False},
    ],
}


def observations() -> dict[str, bi.PortObservation]:
    fdb = bi.parse_fdb(FDB_RAW)
    neigh = bi.parse_neigh(NEIGH_RAW)
    obs: dict[str, bi.PortObservation] = {}
    for port in ("lan2", "lan3", "lan4", "lan5", "lan6", "lan7", "lan8"):
        n = int(port.removeprefix("lan"))
        o = bi.PortObservation(port=port, vlan=1000 + n,
                               poe=bi.parse_poe_info(POE_RAW).get(port, ""))
        for mac in fdb.get(port, set()):
            o.macs.add(mac)
        for ip, mac in neigh.get(o.vlan, []):
            o.macs.add(mac)
            o.ips.setdefault(mac, []).append(ip)
        obs[port] = o
    return obs


def registry(tmp_path: Path) -> bi.Registry:
    path = tmp_path / "places.json"
    path.write_text(json.dumps(PLACES))
    return bi.Registry.load(path)


def test_parse_fdb_filters_static_and_keeps_dynamic() -> None:
    fdb = bi.parse_fdb(FDB_RAW)
    assert fdb["lan2"] == {"dc:b8:08:6c:ea:7f"}          # permanent/static self filtered
    assert fdb["lan3"] == {"b4:2d:56:25:47:a2"}
    assert "lan1" not in fdb
    assert fdb["lan7"] == {"aa:bb:cc:dd:ee:ff"}


def test_parse_neigh_skips_failed_and_maps_vlan() -> None:
    neigh = bi.parse_neigh(NEIGH_RAW)
    assert ("192.168.102.51", "dc:b8:08:6c:ea:7f") in neigh[1002]
    v6 = [ip for ip, _ in neigh[1002] if ip.startswith("fe80::")]
    assert v6, "link-locals must be captured for the identity probe"
    assert all(ip != "192.168.104.99" for ip, _ in neigh[1004])  # FAILED: no lladdr
    # BusyBox `ip neigh show dev X` omits the dev token (live switch shape,
    # observed 2026-09-23): the --vlan marker scopes the block, not the dev field
    assert ("192.168.104.51", "b4:2d:56:25:79:b1") in neigh[1004]
    assert ("fe80::b62d:56ff:fe24:ad:97", "b4:2d:56:24:ad:97") in neigh[1005]


def test_parse_poe_info_tolerates_string_entries() -> None:
    poe = bi.parse_poe_info(POE_RAW)
    assert poe["lan2"] == "Delivering power"
    assert poe["lan6"] == "disabled"
    assert poe["lan8"] == "fault"


def test_parse_identity_requires_four_lines() -> None:
    assert bi.parse_identity("board\nmodel\nhost") == {}
    ident = bi.parse_identity("extreme-networks,ws-ap3915i\nWS-AP3915i\nOpenWrt\n24.10.2")
    assert ident == {"board": "extreme-networks,ws-ap3915i", "model": "WS-AP3915i",
                     "hostname": "OpenWrt", "release": "24.10.2"}


PLACES_WITH_LAN7 = copy.deepcopy(PLACES)
PLACES_WITH_LAN7["places"].append(
    {"name": "ap-lan7", "mac": "77:88:99:aa:bb:cc", "dut_ip": "192.168.107.51",
     "reset_allowed": True})


def registry_in(tmp_path: Path | str, places: dict | None = None) -> bi.Registry:
    path = Path(tmp_path) / "places.json"
    path.write_text(json.dumps(places or PLACES))
    return bi.Registry.load(path)


def test_classify_full_matrix() -> None:
    with tempfile.TemporaryDirectory() as td:
        findings = {f.port: f for f in bi.classify(registry_in(td), observations())}
    assert findings["lan2"].status == "ok"
    assert findings["lan3"].status == "ok"
    assert findings["lan4"].status == "ok"
    # lan5: registered, unit present, power_export=False -> hazard marker
    assert findings["lan5"].status == "ok"
    assert "HAZARD" in findings["lan5"].detail
    # lan6: expected MAC nowhere, port dead -> empty
    assert findings["lan6"].status == "empty"
    # lan7: live MAC, no registry entry
    assert findings["lan7"].status == "unregistered"
    # lan8: fault, no evidence -> empty
    assert findings["lan8"].status == "empty"


def test_classify_detects_move() -> None:
    obs = observations()
    # lan4's unit re-homed to lan7; lan7's stranger removed
    obs["lan7"].macs = {"b4:2d:56:25:79:b1"}
    obs["lan4"].macs = set()
    obs["lan4"].poe = "disabled"
    with tempfile.TemporaryDirectory() as td:
        r = registry_in(td, PLACES_WITH_LAN7)
        findings = {f.port: f for f in bi.classify(r, obs)}
    assert findings["lan4"].status == "moved"
    assert "lan7" in findings["lan4"].detail
    assert findings["lan7"].status == "swapped"
    assert "ap-lan4" in findings["lan7"].detail  # cross-reference to old owner


def test_classify_dark_and_multi() -> None:
    obs = observations()
    obs["lan6"].poe = "Delivering power"           # powered, no L2/L3 -> dark
    obs["lan7"].macs = {"aa:bb:cc:dd:ee:ff", "11:11:11:11:11:11"}
    with tempfile.TemporaryDirectory() as td:
        r = registry_in(td)
        findings = {f.port: f for f in bi.classify(r, obs)}
    assert findings["lan6"].status == "dark"
    assert findings["lan7"].status == "multi_mac"


def test_classify_never_seen_port_is_dark_baseline() -> None:
    """Pre-fix baseline pin: a delivering port with no L2/L3 evidence and no
    probe results must classify dark — the liveness refresh may refine this
    (stale vs never-seen) but never flips never-seen to ok/alive."""
    obs = observations()
    obs["lan6"].poe = "Delivering power"
    obs["lan6"].macs = set()
    obs["lan6"].ips = {}
    with tempfile.TemporaryDirectory() as td:
        findings = {f.port: f for f in bi.classify(registry_in(td), obs)}
    f = findings["lan6"]
    assert f.status == "dark"
    assert f.seen_mac == ""


# ------------------------------------------------ liveness probe plumbing

def test_liveness_script_is_busybox_safe_and_bounded() -> None:
    s = bi.liveness_script("192.168.106.51", "11:22:33:44:55:66", 1006)
    assert "ping -c 1 -W 2 192.168.106.51" in s
    assert "nc -w 3 192.168.106.51 22" in s
    assert "nc -w 3 192.168.106.51 80" in s
    # 3 ICMPv6 attempts: one echo can be lost to NDP re-resolution of a
    # cold/STALE neighbor (live-observed lan2 transient dark)
    assert "ping6 -c 3 -W 2 fe80::1322:33ff:fe44:5566%switch.1006" in s
    assert "telnet" not in s and "ssh " not in s and " -z " not in s
    probes = [p for p in s.split("; ") if not p.startswith("echo")]
    for probe in probes:
        assert "-w 3" in probe or "-W 2" in probe, f"unbounded probe: {probe}"
    assert "ping6 -c 1 " not in s          # single-shot v6 is the flake class


def test_liveness_script_sends_real_http_request_on_80() -> None:
    s = bi.liveness_script("192.168.102.51", "", 1002)
    assert "GET / HTTP/1.0" in s          # idle-holding HTTP server must close
    assert "P6" not in s                  # no MAC -> no ping6 candidate


def test_liveness_script_skips_absent_or_malformed_candidates() -> None:
    assert bi.liveness_script("", "", 1006) == ""
    assert bi.liveness_script("192.168.1.1; reboot", "", 1002) == ""   # injection-shaped
    assert bi.liveness_script("not-an-ip", "", 1002) == ""
    assert "P4" not in bi.liveness_script("", "11:22:33:44:55:66", 1006)
    assert "P6" not in bi.liveness_script("192.168.1.1", "zz:zz", 1006)


CONTROLS_OK = "C4:0\nCT:0\nC6:0\n"


def test_parse_liveness_full_batch_yields_liveness_partial_yields_none() -> None:
    expected = ("C4", "CT", "C6", "P4", "T22", "T80", "P6")
    full = bi.parse_liveness(CONTROLS_OK + "P4:1\nT22:0\nT80:1\nP6:0\n", expected)
    assert full is not None
    assert (full.ping4, full.tcp22, full.tcp80, full.ping6) == (False, True, False, True)
    assert full.ok and full.channels == "tcp:22,ping6"
    assert full.controls_ok
    # partial batch (P6 line lost): missing expected marker => unprobed, never
    # an all-False "probed-dead" verdict fabricated from the gaps
    assert bi.parse_liveness(CONTROLS_OK + "P4:1\nT22:1\nT80:1\n", expected) is None
    assert bi.parse_liveness(CONTROLS_OK + "T22:0\n", expected) is None
    # a LOST control line is just as partial as a lost probe line
    assert bi.parse_liveness("C4:0\nCT:0\nP4:1\nT22:0\nT80:1\nP6:0\n", expected) is None
    # garbage output and empty expectation are equally unprobed
    assert bi.parse_liveness("ssh: connect timeout", expected) is None
    assert bi.parse_liveness(CONTROLS_OK + "P4:1\nT22:0\nT80:1\nP6:1\n", ()) is None
    dead = bi.parse_liveness(CONTROLS_OK + "P4:1\nT22:1\nT80:1\nP6:1\n", expected)
    assert dead is not None and not dead.ok and dead.channels == "none"
    # FAILED control: the negatives are untrusted — controls_ok=False, and
    # the verdict must classify unprobed, never dark
    broken = bi.parse_liveness("C4:1\nCT:0\nC6:1\nP4:1\nT22:1\nT80:1\nP6:1\n",
                               expected)
    assert broken is not None and not broken.controls_ok and not broken.ok


def test_probe_markers_match_script_emissions() -> None:
    """Drift lock: the markers parse_liveness demands are exactly the ones
    liveness_script emits, for every candidate combination."""
    cases = (("192.168.106.51", "11:22:33:44:55:66"),
             ("192.168.106.51", ""),
             ("", "11:22:33:44:55:66"),
             ("192.168.1.1; reboot", "zz:zz"),
             ("", ""))
    for dut_ip, mac in cases:
        script = bi.liveness_script(dut_ip, mac, 1006)
        markers = bi.probe_markers(dut_ip, mac)
        emitted = {tok for tok in ("C4", "CT", "C6", "P4", "T22", "T80", "P6")
                   if f"echo {tok}:$?" in script}
        assert emitted == set(markers), (dut_ip, mac)
        assert bool(script) == bool(markers)


# ------------------------------------------- classification with liveness

def test_classify_stale_entries_with_failing_probes_is_dark() -> None:
    """Cached fdb/neigh entries must not fake an ok when nothing answers."""
    obs = observations()
    obs["lan6"].poe = "Delivering power"
    obs["lan6"].macs = {"11:22:33:44:55:66"}
    obs["lan6"].ips = {"11:22:33:44:55:66": ["192.168.106.51"]}
    obs["lan6"].liveness = bi.Liveness()
    with tempfile.TemporaryDirectory() as td:
        findings = {f.port: f for f in bi.classify(registry_in(td), obs)}
    f = findings["lan6"]
    assert f.status == "dark"
    assert "stale L2/L3 entries" in f.detail and "11:22:33:44:55:66" in f.detail


def test_classify_stale_entries_with_tcp22_ok_is_ok() -> None:
    obs = observations()
    obs["lan6"].poe = "Delivering power"
    obs["lan6"].macs = {"11:22:33:44:55:66"}
    obs["lan6"].liveness = bi.Liveness(tcp22=True)
    with tempfile.TemporaryDirectory() as td:
        findings = {f.port: f for f in bi.classify(registry_in(td), obs)}
    f = findings["lan6"]
    assert f.status == "ok"
    assert f.seen_mac == "11:22:33:44:55:66"
    assert "liveness ok (tcp:22)" in f.detail


def test_classify_probes_ok_without_mac_is_alive() -> None:
    obs = observations()
    obs["lan6"].poe = "Delivering power"
    obs["lan6"].macs = set()
    obs["lan6"].ips = {}
    obs["lan6"].liveness = bi.Liveness(tcp22=True, ping6=True)
    with tempfile.TemporaryDirectory() as td:
        findings = {f.port: f for f in bi.classify(registry_in(td), obs)}
    f = findings["lan6"]
    assert f.status == "alive"
    assert "liveness ok (tcp:22,ping6)" in f.detail


def test_classify_never_seen_with_failed_probes_is_dark() -> None:
    obs = observations()
    obs["lan6"].poe = "Delivering power"
    obs["lan6"].macs = set()
    obs["lan6"].ips = {}
    obs["lan6"].liveness = bi.Liveness()
    with tempfile.TemporaryDirectory() as td:
        findings = {f.port: f for f in bi.classify(registry_in(td), obs)}
    f = findings["lan6"]
    assert f.status == "dark"
    assert "never seen" in f.detail and "stale" not in f.detail


def test_classify_moved_survives_probe_failure() -> None:
    """Unit confirmed on another port: registry bookkeeping wins over the
    stale-cache dark verdict on the vacated port."""
    obs = observations()
    obs["lan7"].macs = {"b4:2d:56:25:79:b1"}      # lan4's unit on lan7
    obs["lan4"].macs = set()
    obs["lan4"].ips = {}
    obs["lan4"].poe = "Delivering power"
    obs["lan4"].liveness = bi.Liveness()          # vacated port: probes fail
    with tempfile.TemporaryDirectory() as td:
        r = registry_in(td, PLACES_WITH_LAN7)
        findings = {f.port: f for f in bi.classify(r, obs)}
    assert findings["lan4"].status == "moved"
    assert findings["lan7"].status == "swapped"


# ---------------------------------------------- refresh_liveness (mocked SSH)

def _fake_ssh(probe_out: str, neigh_out: str | None = None):
    calls: list[str] = []

    def fake_run(cmd: list[str], **_: object) -> SimpleNamespace:
        script = cmd[-1]
        calls.append(script)
        if script.startswith("ip neigh"):
            vlan = script.rsplit("switch.", 1)[1]
            lines = [ln for ln in (neigh_out or "").splitlines()
                     if f" dev switch.{vlan} " in ln]
            return SimpleNamespace(returncode=0, stdout="\n".join(lines))
        return SimpleNamespace(returncode=0, stdout=probe_out)

    return fake_run, calls


def test_refresh_liveness_probes_only_delivering_registered_ports(
        monkeypatch: pytest.MonkeyPatch) -> None:
    probe_out = CONTROLS_OK + "P4:1\nT22:0\nT80:1\nP6:1\n"
    fake_run, calls = _fake_ssh(probe_out)
    monkeypatch.setattr(bi.subprocess, "run", fake_run)
    obs = observations()          # lan2-5 delivering+registered, lan6 disabled,
    with tempfile.TemporaryDirectory() as td:   # lan7 delivering+unregistered, lan8 fault
        r = registry_in(td)
        bi.refresh_liveness("switch", r, obs)
    probe_calls = [c for c in calls if "echo P4:" in c or "echo P6:" in c]
    assert len(probe_calls) == 4
    assert all("nc -w 3" in c for c in probe_calls)
    assert obs["lan2"].liveness is not None and obs["lan2"].liveness.ok
    assert obs["lan6"].liveness is None      # no PoE draw -> never probed
    assert obs["lan7"].liveness is None      # unregistered: no dut_ip/mac to probe
    assert obs["lan8"].liveness is None


def test_refresh_liveness_transport_failure_leaves_unprobed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    def raising_run(*_: object, **__: object) -> None:
        raise bi.subprocess.TimeoutExpired(cmd="ssh", timeout=40)

    monkeypatch.setattr(bi.subprocess, "run", raising_run)
    obs = observations()
    with tempfile.TemporaryDirectory() as td:
        r = registry_in(td)
        bi.refresh_liveness("switch", r, obs)
    assert obs["lan2"].liveness is None      # transport died: no fake verdict
    with tempfile.TemporaryDirectory() as td:
        findings = {f.port: f for f in bi.classify(registry_in(td), obs)}
    assert findings["lan2"].status == "ok"


def test_refresh_liveness_merges_neigh_so_live_unit_classifies_ok(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The 2026-09-23 lan4 incident, end to end: cache empty, unit answers
    TCP:22, the post-probe neigh read materializes the MAC -> ok, not dark."""
    probe_out = CONTROLS_OK + "P4:1\nT22:0\nT80:1\nP6:1\n"     # ICMP filtered, SSH answers
    neigh_out = ("192.168.106.51 dev switch.1006 lladdr 11:22:33:44:55:66  REACHABLE\n")
    fake_run, _ = _fake_ssh(probe_out, neigh_out)
    monkeypatch.setattr(bi.subprocess, "run", fake_run)
    obs = observations()
    obs["lan6"].poe = "Delivering power"
    obs["lan6"].macs = set()
    obs["lan6"].ips = {}
    with tempfile.TemporaryDirectory() as td:
        r = registry_in(td)
        bi.refresh_liveness("switch", r, obs)
        findings = {f.port: f for f in bi.classify(r, obs)}
    o = obs["lan6"]
    assert o.liveness is not None and o.liveness.ok
    assert o.macs == {"11:22:33:44:55:66"}
    assert "192.168.106.51" in o.ips["11:22:33:44:55:66"]
    f = findings["lan6"]
    assert f.status == "ok" and f.seen_mac == "11:22:33:44:55:66"
    assert "liveness ok" in f.detail


def test_refresh_liveness_arp_channel_counts_as_liveness(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """All probes fail but a NEW neighbor entry materialized from the probe
    traffic itself: L2-alive, must not be darked."""
    probe_out = CONTROLS_OK + "P4:1\nT22:1\nT80:1\nP6:1\n"
    neigh_out = ("192.168.106.51 dev switch.1006 lladdr de:ad:be:ef:00:01  REACHABLE\n")
    fake_run, _ = _fake_ssh(probe_out, neigh_out)
    monkeypatch.setattr(bi.subprocess, "run", fake_run)
    obs = observations()
    obs["lan6"].poe = "Delivering power"
    obs["lan6"].macs = set()
    obs["lan6"].ips = {}
    with tempfile.TemporaryDirectory() as td:
        r = registry_in(td)
        bi.refresh_liveness("switch", r, obs)
        findings = {f.port: f for f in bi.classify(r, obs)}
    assert obs["lan6"].liveness is not None and obs["lan6"].liveness.ok
    assert obs["lan6"].liveness.arp
    assert findings["lan6"].status == "swapped"    # answers ARP with a stranger MAC


def test_refresh_liveness_dead_unit_keeps_stale_macs_dark(
        monkeypatch: pytest.MonkeyPatch) -> None:
    probe_out = CONTROLS_OK + "P4:1\nT22:1\nT80:1\nP6:1\n"
    stale_neigh = ("192.168.106.51 dev switch.1006 lladdr 11:22:33:44:55:66  STALE\n")
    fake_run, _ = _fake_ssh(probe_out, stale_neigh)
    monkeypatch.setattr(bi.subprocess, "run", fake_run)
    obs = observations()
    obs["lan6"].poe = "Delivering power"
    obs["lan6"].macs = {"11:22:33:44:55:66"}
    obs["lan6"].ips = {"11:22:33:44:55:66": ["192.168.106.51"]}
    with tempfile.TemporaryDirectory() as td:
        r = registry_in(td)
        bi.refresh_liveness("switch", r, obs)
        findings = {f.port: f for f in bi.classify(r, obs)}
    assert obs["lan6"].liveness is not None and not obs["lan6"].liveness.ok
    f = findings["lan6"]
    assert f.status == "dark"
    assert "stale L2/L3 entries" in f.detail


def test_emit_exporter_skips_power_export_false_and_unregistered() -> None:
    with tempfile.TemporaryDirectory() as td:
        r = registry_in(td)
        findings = bi.classify(r, observations())
        out = bi.emit_exporter(findings, r, "SWITCH_IP")
    assert "index: 2" in out and "index: 4" in out
    assert "index: 5" not in out, "one-way-trip port must get no power stanza"
    assert "power_export=false" in out
    assert "UNREGISTERED" in out and "lan7" in out
    assert "address: 192.168.102.51" in out   # NetworkService from registry dut_ip
    assert out.count("NetworkPowerPort:") >= 3
    assert "\n# " not in out                  # only ## comments (Jinja rule)


def test_update_places_records_move_and_preserves_secrets(tmp_path: Path) -> None:
    path = tmp_path / "places.json"
    path.write_text(json.dumps(PLACES_WITH_LAN7))
    r = bi.Registry.load(path)
    obs = observations()
    obs["lan7"].macs = {"b4:2d:56:25:79:b1"}      # lan4 unit moved to lan7
    obs["lan4"].macs = set()
    obs["lan4"].poe = "disabled"
    findings = bi.classify(r, obs)
    changes = bi.update_places(r, findings, obs)
    assert any("cleared" in c and "lan4" in c for c in changes)
    assert any("lan7" in c and "b4:2d:56:25:79:b1" in c for c in changes)
    saved = json.loads(path.read_text())
    by_name = {e["name"]: e for e in saved["places"]}
    assert by_name["ap-lan2"]["password"] == "seekrit"      # unknown keys preserved
    assert by_name["ap-lan4"]["mac"] == ""                   # vacated
    assert "moved to lan7" in by_name["ap-lan4"]["note"]
    assert by_name["ap-lan7"]["mac"] == "b4:2d:56:25:79:b1"  # re-homed
    assert saved["labgrid_host"] == "example-exporter"       # top-level keys preserved


def test_update_places_noop_when_clean(tmp_path: Path) -> None:
    original = json.dumps(PLACES, sort_keys=True)
    path = tmp_path / "places.json"
    path.write_text(original)
    r = bi.Registry.load(path)
    assert bi.update_places(r, bi.classify(r, observations()), observations()) == []
    assert json.dumps(json.loads(path.read_text()), sort_keys=True) == original


def test_record_appends_events(tmp_path: Path) -> None:
    inv = tmp_path / "inventory.jsonl"
    inv.write_text(json.dumps({"timestamp": "t0", "mac_addresses": ["aa:bb:cc:dd:ee:ff"],
                               "model": "NR7101"}) + "\n")
    findings = bi.classify(registry_in(tmp_path), observations())
    n = bi.record(findings, observations(), str(inv))
    assert n >= 4
    lines = [json.loads(line) for line in inv.read_text().splitlines() if line.strip()]
    events = [e for e in lines if e.get("event") == "bench_scan"]
    assert {e["bench_place"] for e in events} >= {"ap-lan2", "ap-lan3", "ap-lan4", "ap-lan5"}
    assert all(e["mac_addresses"] for e in events)
    # existing specimen rows untouched
    assert lines[0]["model"] == "NR7101"


def test_collect_script_covers_all_dut_vlans() -> None:
    script = bi.collect_script(("lan2", "lan5", "lan8"))
    assert "1002" in script and "1005" in script and "1008" in script
    assert "1001" not in script  # lan1/uplink never scanned


# --------------------------------------------- session transport parity

COLLECT_OUT = ("===POE===\n" + json.dumps({"ports": {"lan2": "Delivering power"}})
               + "\n===FDB===\n===NEIGH===\n")


def test_collect_pins_ssh_argv_and_remote_script(monkeypatch: pytest.MonkeyPatch) -> None:
    """Direct-path parity after the BenchSession rewire: collect emits the
    same remote script (byte-for-byte) over the same ssh argv form."""
    import bench_session as bs
    calls: list = []

    def fake_run(cmd: list[str], **kwargs: object):
        calls.append((cmd, kwargs))
        return SimpleNamespace(returncode=0, stdout=COLLECT_OUT)

    monkeypatch.setattr(bi.subprocess, "run", fake_run)
    monkeypatch.setenv("CONWRT_BENCH", "direct")
    obs = bi.collect("192.168.13.2", ("lan2", "lan4"))
    argv, kwargs = calls[0]
    assert argv == ["ssh", *bs.SSH_OPTS, "root@192.168.13.2",
                    bi.collect_script(("lan2", "lan4"))]
    assert kwargs["capture_output"] is True and kwargs["text"] is True
    assert obs["lan2"].poe == "Delivering power"


def test_collect_labgrid_without_lib_fails_typed_before_hardware(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """CONWRT_BENCH=labgrid must fail with the typed error before any
    hardware call — never an ImportError traceback, never silent direct."""
    import sys as _sys

    monkeypatch.setenv("CONWRT_BENCH", "labgrid")
    monkeypatch.setitem(_sys.modules, "labgrid", None)

    def no_hardware(*_: object, **__: object) -> None:
        raise AssertionError("hardware call attempted before backend validation")

    monkeypatch.setattr(bi.subprocess, "run", no_hardware)
    with pytest.raises(bi.ScanError, match="pip install labgrid"):
        bi.collect("192.168.13.2", ("lan2",))


def test_no_committed_coordinates() -> None:
    """Policy: no real bench IPs in the scan tool (AGENTS privacy rule)."""
    source = Path(bi.__file__).read_text()
    assert "192.168.13." not in source
    assert "20408" not in source


def test_main_rejects_missing_host() -> None:
    with pytest.raises(SystemExit):
        bi.main(["scan"])


def test_control_script_probes_the_switches_own_svi_through_the_vlan() -> None:
    s = bi.control_script(1004)
    assert "ping -c 1 -W 2 -I switch.1004 192.168.104.1" in s
    assert "nc -w 3 192.168.104.1 22" in s
    assert "ping6 -c 2 -W 2 -I switch.1004 ff02::1" in s


def test_failed_controls_classify_unprobed_not_dark(tmp_path: Path) -> None:
    """A probe path with broken controls must never verdict a port dark."""
    obs = observations()
    obs["lan6"].poe = "Delivering power"
    obs["lan6"].macs = {"11:22:33:44:55:66"}
    obs["lan6"].ips = {"11:22:33:44:55:66": ["192.168.106.51"]}
    obs["lan6"].liveness = bi.Liveness(controls_ok=False)
    findings = {f.port: f for f in bi.classify(registry_in(str(tmp_path)), obs)}
    f = findings["lan6"]
    assert f.status == "unprobed"
    assert "controls FAILED" in f.detail
