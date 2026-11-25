"""identify_router tests — the detection engine's decision core (#794).

`identify_router` is the confidence ladder behind watch/auto: MAC
resolution precedence, LLDP evidence extraction, and the
board > lldp > http > oui match ordering with corroboration-based
confidence. Everything here is pure decision logic driven with canned
probe/passive dicts and monkeypatched matchers — no sockets, no sniff.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

spec = importlib.util.spec_from_file_location("auto_detect", Path(__file__).resolve().parents[1] / "scripts" / "auto_detect.py")
ad = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ad)
from lldp import LLDPInfo  # noqa: E402

IP = "192.168.0.1"
MODEL = {"id": "dlink-covr-x1860-a1", "description": "D-Link COVR-X1860 A1",
         "vendor": "D-Link",
         "flash_methods": {"dlink-hnap": {"default_password": "admin"},
                           "recovery-http": {}}}


def probe(**kw) -> dict:
    base = {"ip": IP, "http_get": {"body": "", "headers": ""},
            "http_head": {"headers": ""}, "ssh": {}, "hnap": {}, "ping": True}
    base.update(kw)
    return base


def passive(arp_hosts=(), dhcp_servers=(), macs=None) -> dict:
    return {"macs": macs or {}, "dhcp_servers": list(dhcp_servers),
            "arp_hosts": list(arp_hosts), "icmpv6_routers": []}


@pytest.fixture(autouse=True)
def quiet_matchers(monkeypatch):
    """No matcher fires unless a test explicitly arms one — tests then
    override only the rung under assertion."""
    monkeypatch.setattr(ad, "match_models_by_oui", lambda mac: [])
    monkeypatch.setattr(ad, "match_model_by_board", lambda bj: None)
    monkeypatch.setattr(ad, "match_model_by_http", lambda b, h: [])
    monkeypatch.setattr(ad, "match_model_by_lldp", lambda info: [])
    monkeypatch.setattr(ad, "lookup_mac_vendor", lambda mac: "")
    monkeypatch.setattr(ad, "classify_http_response", lambda b, h: "unknown")
    monkeypatch.setattr(ad, "classify_web_ui", lambda pd: "unknown")
    monkeypatch.setattr(ad, "assess_readiness", lambda r: "unknown")


class TestMacResolutionPrecedence:
    def test_arp_hosts_win(self):
        r = ad.identify_router(probe(), passive(
            arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}],
            dhcp_servers=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:02"}]))
        assert r.mac == "AA:BB:CC:DD:EE:01"

    def test_dhcp_servers_second(self):
        r = ad.identify_router(probe(), passive(
            dhcp_servers=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:02"}]))
        assert r.mac == "AA:BB:CC:DD:EE:02"

    def test_arp_lookup_third(self, monkeypatch):
        monkeypatch.setattr(ad, "_arp_lookup", lambda ip: "aa:bb:cc:dd:ee:03")
        r = ad.identify_router(probe(), passive())
        assert r.mac == "AA:BB:CC:DD:EE:03"

    def test_lldp_management_ip_match(self):
        lldp = {"n1": LLDPInfo(chassis_mac="AA:BB:CC:DD:EE:04", management_ip=IP)}
        r = ad.identify_router(probe(), passive(), lldp)
        assert r.mac == "AA:BB:CC:DD:EE:04"
        assert r.lldp_info is lldp["n1"]

    def test_lldp_first_info_fallback(self):
        lldp = {"n9": LLDPInfo(chassis_mac="AA:BB:CC:DD:EE:05", management_ip="10.0.0.9")}
        r = ad.identify_router(probe(), passive(), lldp)
        assert r.mac == "AA:BB:CC:DD:EE:05"

    def test_unknown_when_nothing(self, monkeypatch):
        monkeypatch.setattr(ad, "_arp_lookup", lambda ip: "")
        assert ad.identify_router(probe(), passive()).mac == "unknown"


class TestLldpEvidence:
    def test_zyxel_fields_extracted(self):
        info = LLDPInfo(chassis_name="NR7101", management_ip=IP,
                        chassis_mac="AA:BB:CC:DD:EE:06",
                        management_url="http://192.168.0.1/",
                        vendor_specific={"zyxel_firmware": "V1.00",
                                         "zyxel_device": "NR7101"})
        r = ad.identify_router(probe(), passive(), {"n": info})
        assert r.stock_firmware_version == "V1.00"
        # evidence entries are formatted "[phase] message" strings
        assert any("LLDP chassis: NR7101" in e for e in r.evidence)
        assert any("ZyXEL firmware: V1.00" in e for e in r.evidence)


class TestConfidenceLadder:
    def test_board_match_is_certain(self, monkeypatch):
        monkeypatch.setattr(ad, "match_model_by_board", lambda bj: MODEL)
        r = ad.identify_router(probe(ssh={"available": True,
                                          "board_json": {"model": "x"}}),
                               passive(arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}]))
        assert r.model_id == MODEL["id"] and r.confidence == "certain"

    def test_lldp_corroborated_by_oui_is_certain(self, monkeypatch):
        monkeypatch.setattr(ad, "match_model_by_lldp", lambda i: [MODEL])
        monkeypatch.setattr(ad, "match_models_by_oui", lambda m: [MODEL])
        r = ad.identify_router(probe(), passive(
            arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}]),
            {"n": LLDPInfo(management_ip=IP)})
        assert r.model_id == MODEL["id"] and r.confidence == "certain"

    def test_lldp_alone_is_likely(self, monkeypatch):
        monkeypatch.setattr(ad, "match_model_by_lldp", lambda i: [MODEL])
        r = ad.identify_router(probe(), passive(
            arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}]),
            {"n": LLDPInfo(management_ip=IP)})
        assert r.confidence == "likely"

    def test_http_corroborated_vs_alone(self, monkeypatch):
        monkeypatch.setattr(ad, "match_model_by_http", lambda b, h: [MODEL])
        base = probe(http_get={"body": "sign", "headers": ""})
        arp = passive(arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}])
        assert ad.identify_router(base, arp).confidence == "likely"
        monkeypatch.setattr(ad, "match_models_by_oui", lambda m: [MODEL])
        assert ad.identify_router(base, arp).confidence == "certain"

    def test_oui_only_is_possible(self, monkeypatch):
        monkeypatch.setattr(ad, "match_models_by_oui", lambda m: [MODEL])
        r = ad.identify_router(probe(), passive(
            arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}]))
        assert r.confidence == "possible" and r.model_id == MODEL["id"]

    def test_no_match_leaves_model_empty(self):
        r = ad.identify_router(probe(), passive(
            arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}]))
        assert r.model_id == "" and r.confidence == "possible"

    def test_flash_methods_and_default_password(self, monkeypatch):
        monkeypatch.setattr(ad, "match_models_by_oui", lambda m: [MODEL])
        r = ad.identify_router(probe(), passive(
            arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}]))
        assert sorted(r.flash_methods) == ["dlink-hnap", "recovery-http"]
        assert r.default_password == "admin"

    def test_board_beats_lldp_and_http(self, monkeypatch):
        monkeypatch.setattr(ad, "match_model_by_board", lambda bj: MODEL)
        other = dict(MODEL, id="other-model")
        monkeypatch.setattr(ad, "match_model_by_lldp", lambda i: [other])
        monkeypatch.setattr(ad, "match_model_by_http", lambda b, h: [other])
        r = ad.identify_router(probe(ssh={"available": True,
                                          "board_json": {"model": "covr"}}),
                               passive(arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}]),
                               {"n": LLDPInfo(management_ip=IP)})
        assert r.model_id == MODEL["id"] and r.confidence == "certain"


class TestRouterFields:
    def test_zyxel_stock_overrides_firmware_state(self, monkeypatch):
        monkeypatch.setattr(ad, "classify_web_ui", lambda pd: "zyxel_stock")
        monkeypatch.setattr(ad, "classify_http_response", lambda b, h: "stock")
        r = ad.identify_router(probe(), passive(
            arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}]))
        assert r.firmware_state == "zyxel_stock"

    def test_openwrt_not_overridden(self, monkeypatch):
        monkeypatch.setattr(ad, "classify_web_ui", lambda pd: "zyxel_stock")
        monkeypatch.setattr(ad, "classify_http_response", lambda b, h: "openwrt")
        r = ad.identify_router(probe(), passive(
            arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}]))
        assert r.firmware_state == "openwrt"

    def test_dhcp_server_flag(self):
        r = ad.identify_router(probe(), passive(
            dhcp_servers=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:02"}]))
        assert r.dhcp_server and r.dhcp_info["gateway"] == IP

    def test_vendor_falls_back_to_model(self, monkeypatch):
        monkeypatch.setattr(ad, "match_models_by_oui", lambda m: [MODEL])
        r = ad.identify_router(probe(), passive(
            arp_hosts=[{"ip": IP, "mac": "AA:BB:CC:DD:EE:01"}]))
        assert r.vendor == "D-Link"
