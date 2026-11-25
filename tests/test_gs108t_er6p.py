"""gs108t_config + er6p_redeploy host-side tests (#763 P3).

gs108t_config: the S350 web-UI VLAN planner — desired-state derivation
from lab.yaml bays, config/secrets loading (default password, missing
device), and the login form sequence against a recorded fake page.

er6p_redeploy: the ER6P factory-catch redeploy — port detection from
factory-state output (bridge/uplink/bays, the "never assume port
names" rule) and the generated uci payload (mgmt VLAN 12, per-bay
400+i VLANs and 192.168.40+i subnets, the rogue-DHCP triple, the
PAYLOAD-APPLIED + __DONE__ handshake markers). run() stubbed at the
module seam; PUBKEY staged via a fake HOME before import.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import gs108t_config as gs  # noqa: E402

LAB_YAML = """
devices:
  gs108t:
    mgmt: 192.168.0.239
    bays:
      uplink: p1
      p2: {vlan: 82}
      p3: {vlan: 83}
      p4: {}
"""


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    labdir = tmp_path / "labdata"
    labdir.mkdir()
    (labdir / "lab.yaml").write_text(LAB_YAML)
    monkeypatch.setenv("CONWRT_LAB", str(labdir))
    return labdir


class TestLoadCfg:
    def test_loads_device_and_default_password(self, lab):
        cfg, dev, pw = gs.load_cfg()
        assert dev["mgmt"] == "192.168.0.239"
        assert pw == "password"  # no lab-secrets.yaml -> default

    def test_secrets_override_password(self, lab):
        (lab / "lab-secrets.yaml").write_text("gs108t_web: hunter2\n")
        _, _, pw = gs.load_cfg()
        assert pw == "hunter2"

    def test_missing_device_exits(self, tmp_path, monkeypatch, capsys):
        labdir = tmp_path / "labdata"
        labdir.mkdir()
        (labdir / "lab.yaml").write_text("devices: {}\n")
        monkeypatch.setenv("CONWRT_LAB", str(labdir))
        with pytest.raises(SystemExit, match="gs108t not in lab.yaml"):
            gs.load_cfg()


class TestDesired:
    def test_bays_to_vlan_rows(self):
        dev = {"bays": {"uplink": "p1", "p2": {"vlan": 82},
                        "p3": {"vlan": 83}, "p4": {}}}
        rows = gs.desired(dev)
        assert rows == [
            {"vlan": 82, "untagged": [2], "tagged": [1]},
            {"vlan": 83, "untagged": [3], "tagged": [1]},
        ]

    def test_no_vlan_entry_skipped(self):
        assert gs.desired({"bays": {"p4": {}}}) == []
        assert gs.desired({}) == []


class TestLogin:
    def test_form_sequence(self, lab):
        calls = []

        class FakePage:
            def goto(self, url, timeout=None):
                calls.append(("goto", url))
            def fill(self, sel, val):
                calls.append(("fill", sel, val))
            def click(self, sel):
                calls.append(("click", sel))

        base = gs.login(None, FakePage(), "pw123")
        assert base == f"http://127.0.0.1:{gs.BASE_LOCAL}"
        assert calls[0] == ("goto", base + "/")
        assert calls[1] == ("fill", 'input[name="pwd"]', "pw123")
        assert calls[2] == ("click", 'input[name="login"]')


# --- er6p_redeploy ----------------------------------------------------------

@pytest.fixture(scope="module")
def er6p(tmp_path_factory):
    """Import with a fake HOME carrying a pubkey — the module reads
    ~/.ssh/id_ed25519.pub at import time."""
    home = tmp_path_factory.mktemp("er6p-home")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519.pub").write_text(
        "ssh-ed25519 AAAAFakeKeyForTests\n")
    old_home = Path.home
    import os
    old_env_home = os.environ.get("HOME")
    os.environ["HOME"] = str(home)
    try:
        spec = importlib.util.spec_from_file_location(
            "er6p_redeploy", REPO / "scripts" / "er6p_redeploy.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        if old_env_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_env_home


FACTORY_OUT = """lan1 lan2 lan3 lan4 lan5 wan
network.@device[0].name='br-lan'
network.@device[0].ports='lan1 lan2 lan3 lan4'
__DONE__"""


class TestDetectPorts:
    def test_bridge_uplink_bays_from_factory_state(self, er6p, monkeypatch):
        # KNOWN parsing DEFECT (filed; pinned as current behavior per the
        # tests-only rule): the standard single-string `uci show` ports
        # value ('lan1 lan2 lan3 lan4') is split on "' '" which never
        # occurs inside the capture — bridge_ports becomes ONE space-
        # joined blob, and the uplink falls back to all_ports[0] ('lan1'),
        # NOT the actual wan port. The blob still lands in the payload as
        # one bay whose ports value uci accepts (spaces are legal in the
        # list value), which is how the rig session worked.
        monkeypatch.setattr(
            er6p, "run",
            lambda cmd, timeout=30: (0, FACTORY_OUT))
        info = er6p.detect_ports(18096)
        assert info["bridge"] == "br-lan"
        assert info["bays"] == ["lan1 lan2 lan3 lan4"]  # the blob
        assert info["uplink"] == "lan1"  # all_ports[0] fallback, not wan
        assert "wan" in info["all"]

    def test_failed_probe_dies(self, er6p, monkeypatch):
        monkeypatch.setattr(er6p, "run", lambda cmd, timeout=30: (1, "timeout"))
        with pytest.raises(SystemExit):
            er6p.detect_ports(18096)

    def test_no_bridge_config_falls_back(self, er6p, monkeypatch):
        # no uci ports line: bays fall back to netdev names (minus lo/
        # bridge/dsa), and the uplink falls back to all_ports[0] — a
        # deliberately conservative guess the operator confirms
        out = "lan1 lan2 wan\n__DONE__"
        monkeypatch.setattr(er6p, "run", lambda cmd, timeout=30: (0, out))
        info = er6p.detect_ports(18096)
        assert info["bridge"] == "br-lan"  # default
        assert info["bays"] == ["lan1", "lan2", "wan"]
        assert info["uplink"] == "lan1"  # all_ports[0] fallback


class TestBuildPayload:
    def test_payload_shape(self, er6p):
        payload = er6p.build_payload(
            {"bridge": "br-lan", "uplink": "wan",
             "bays": ["lan1", "lan2"]})
        # mgmt VLAN 12 on the uplink, static final IP
        assert "vlan='12'" in payload
        assert "ports='wan:t'" in payload
        assert "network.lan.ipaddr='192.168.12.4'" in payload
        # per-bay VLANs 400+i, subnets 192.168.40+i, ports u*
        assert "vlan='400'" in payload and "ports='lan1:u*'" in payload
        assert "vlan='401'" in payload and "ports='lan2:u*'" in payload
        assert "network.dut0.ipaddr='192.168.40.1'" in payload
        assert "network.dut1.ipaddr='192.168.41.1'" in payload
        # the rogue-DHCP triple (AGENTS.md discipline, baked in)
        assert "uci set dhcp.lan.ignore='1'" in payload
        assert "uci set dhcp.lan.ra='disabled'" in payload
        assert "uci set dhcp.lan.dhcpv6='disabled'" in payload
        # commits + the handshake markers the driver waits on
        assert "uci commit network" in payload
        assert "echo PAYLOAD-APPLIED; echo __DONE__" in payload

    def test_payload_uses_detected_bridge(self, er6p):
        payload = er6p.build_payload(
            {"bridge": "br0", "uplink": "eth1", "bays": ["lan9"]})
        assert "device='br0'" in payload
        assert "ports='eth1:t'" in payload


class TestEvidenceHelpers:
    def test_ok_fail_die(self, er6p):
        er6p.ok("a-good-thing")
        er6p.fail("a-bad-thing")
        assert "OK   a-good-thing" in er6p.EVID
        assert "FAIL a-bad-thing" in er6p.EVID
        with pytest.raises(SystemExit):
            er6p.die("fatal")
        assert any("fatal" in e for e in er6p.EVID)
