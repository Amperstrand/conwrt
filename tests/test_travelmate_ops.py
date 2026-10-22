"""Ops characterization tests for travelmate.py — incl. uplink seeding.

render_shell(_build_travelmate_ops(...)) is the authoritative output.
The no-uplinks render must stay byte-identical to the 1.x golden the
Rust port compares against (crates/conwrt-core/tests/goldens/
travelmate.sh); the seeded branches mirror the Rust WifiUplink render.
"""
from profile.ops import render_shell
from use_cases.travelmate import _build_travelmate_ops, _host_saved_wifis


DEFAULT_PARAMS: dict = {}
CUSTOM_PARAMS = {
    "radio": "radio1",
    "timeout": 120,
    "retry": 10,
    "captive": False,
}


class TestTravelmateOpsDefault:
    def test_render_shell(self):
        rendered = render_shell(_build_travelmate_ops(DEFAULT_PARAMS))
        assert "uci set travelmate.global.trm_enabled='1'" in rendered
        assert "uci set travelmate.global.trm_captive='1'" in rendered
        assert "uci set travelmate.global.trm_timeout='60'" in rendered
        assert "uci set travelmate.global.trm_radio='radio0'" in rendered
        assert "uci commit travelmate" in rendered
        assert "/etc/init.d/travelmate enable" in rendered

    def test_no_uplinks_keeps_1x_shape(self):
        rendered = render_shell(_build_travelmate_ops({}))
        assert "trm_iface" not in rendered
        assert "wifi-iface" not in rendered
        assert "trm_wwan" not in rendered
        assert 'echo "Travelmate configured: auto-connect on radio0"' in rendered


class TestTravelmateOpsCustom:
    def test_custom_params(self):
        rendered = render_shell(_build_travelmate_ops(CUSTOM_PARAMS))
        assert "uci set travelmate.global.trm_captive='0'" in rendered
        assert "uci set travelmate.global.trm_timeout='120'" in rendered
        assert "uci set travelmate.global.trm_retry='10'" in rendered
        assert "uci set travelmate.global.trm_radio='radio1'" in rendered

    def test_captive_disabled(self):
        rendered = render_shell(_build_travelmate_ops({"captive": False}))
        assert "trm_captive='0'" in rendered

    def test_custom_radio(self):
        rendered = render_shell(_build_travelmate_ops({"radio": "radio1"}))
        assert "trm_radio='radio1'" in rendered


class TestTravelmateSeeding:
    HARDCODED = [{
        "ssid": "home-net",
        "psk": "hunter2 son",
        "encryption": "psk2",
        "radio": "radio1",
    }, {
        "ssid": "cafe open",
        "encryption": "none",
        "radio": "radio0",
    }]

    def test_hardcoded_uplinks_render_travelmate_setup_shape(self):
        rendered = render_shell(_build_travelmate_ops({"uplinks": self.HARDCODED}))
        assert "uci set travelmate.global.trm_iface='trm_wwan'" in rendered
        assert "uci set network.trm_wwan=interface" in rendered
        assert "uci set network.trm_wwan.proto='dhcp'" in rendered
        assert "uci set network.trm_wwan.metric='100'" in rendered
        assert "uci set network.trm_wwan6=interface" in rendered
        assert "uci set network.trm_wwan6.device='@trm_wwan'" in rendered
        assert "uci set network.trm_wwan6.proto='dhcpv6'" in rendered
        # wan-zone membership by NAME (the shared helper)
        assert "uci add_list firewall.\"$_z\".network='trm_wwan'" in rendered
        assert "uci add_list firewall.\"$_z\".network='trm_wwan6'" in rendered
        # STA ifaces
        assert "uci set wireless.trm_uplink1=wifi-iface" in rendered
        assert "uci set wireless.trm_uplink1.device='radio1'" in rendered
        assert "uci set wireless.trm_uplink1.mode='sta'" in rendered
        assert "uci set wireless.trm_uplink1.network='trm_wwan'" in rendered
        assert "uci set wireless.trm_uplink1.ssid='home-net'" in rendered
        assert "uci set wireless.trm_uplink1.encryption='psk2'" in rendered
        assert "uci set wireless.trm_uplink1.key='hunter2 son'" in rendered
        assert "uci set wireless.trm_uplink2.ssid='cafe open'" in rendered
        assert "uci set wireless.trm_uplink2.encryption='none'" in rendered
        assert "trm_uplink2.key" not in rendered
        assert "uci commit wireless" in rendered
        assert "wifi reload; ubus call network.interface.trm_wwan up" in rendered
        assert "(2 uplinks)" in rendered

    def test_seed_from_host_merges_after_hardcoded(self, monkeypatch):
        host_wifis = [{"ssid": "somewhere", "psk": "pw", "encryption": "sae", "radio": "radio0"}]
        monkeypatch.setattr("use_cases.travelmate._host_saved_wifis", lambda: host_wifis)
        rendered = render_shell(_build_travelmate_ops(
            {"uplinks": self.HARDCODED[:1], "seed_from_host": True}))
        assert "uci set wireless.trm_uplink1.ssid='home-net'" in rendered
        assert "uci set wireless.trm_uplink2.ssid='somewhere'" in rendered
        assert "uci set wireless.trm_uplink2.encryption='sae'" in rendered

    def test_seed_from_host_off_by_default(self, monkeypatch):
        called = {"n": 0}

        def boom():
            called["n"] += 1
            return []

        monkeypatch.setattr("use_cases.travelmate._host_saved_wifis", boom)
        render_shell(_build_travelmate_ops({}))
        assert called["n"] == 0

    def test_host_extraction_parses_keyfiles_and_skips_eap(self, monkeypatch):
        fake = (
            "==F==\n[connection]\nid=cellA\n[wifi]\nssid=Home AP\n"
            "[wifi-security]\nkey-mgmt=wpa-psk\npsk=pw-one\n"
            "==F==\n[connection]\nid=cellB\n[wifi]\nssid=Office 5G\nband=a\n"
            "[wifi-security]\nkey-mgmt=sae\npsk=pw-two\n"
            "==F==\n[connection]\nid=work\n[wifi]\nssid=Corp\n"
            "[wifi-security]\nkey-mgmt=wpa-eap\n"
            "==F==\n[connection]\nid=cafe\n[wifi]\nssid=FreeCafe\n"
        )
        run = type("R", (), {"stdout": fake})()
        monkeypatch.setattr(
            "use_cases.travelmate.subprocess.run", lambda *a, **k: run)
        wifis = _host_saved_wifis()
        assert wifis == [
            {"ssid": "Home AP", "psk": "pw-one", "encryption": "psk2", "radio": "radio0"},
            {"ssid": "Office 5G", "psk": "pw-two", "encryption": "sae", "radio": "radio1"},
            {"ssid": "FreeCafe", "psk": "", "encryption": "none", "radio": "radio0"},
        ]

    def test_host_extraction_sudo_failure_raises_helpful(self, monkeypatch):
        import subprocess as sp

        def boom(*a, **k):
            raise sp.CalledProcessError(1, "sudo")

        monkeypatch.setattr("use_cases.travelmate.subprocess.run", boom)
        try:
            _host_saved_wifis()
            raise AssertionError("must raise")
        except RuntimeError as exc:
            assert "passwordless sudo" in str(exc)
