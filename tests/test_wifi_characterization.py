"""Characterization and roundtrip tests for wifi.py UCI generators.

Characterization tests lock the current output of wifi_sta_uci_lines and
wifi_ap_uci_lines so refactoring to ops can be verified byte-for-byte.

Roundtrip tests verify that render_shell(wifi_*_ops(...)) matches the
output of wifi_*_uci_lines(...) exactly.
"""
from profile.ops import render_shell
from profile.wifi import wifi_sta_ops, wifi_ap_ops, wifi_sta_uci_lines, wifi_ap_uci_lines


# -- Characterization fixtures (lock current string output) --

STA_LINES_NO_KEY = wifi_sta_uci_lines("radio0", "UpstreamNet", "psk2")
STA_LINES_WITH_KEY = wifi_sta_uci_lines("radio0", "UpstreamNet", "psk2", "mypass", "wan")
STA_LINES_CUSTOM_CC = wifi_sta_uci_lines("radio1", "TestNet", "sae", "key123", "wan", "NO")

AP_LINES_NO_KEY = wifi_ap_uci_lines("radio0", "MyLAN", "psk2")
AP_LINES_WITH_KEY = wifi_ap_uci_lines("radio0", "MyLAN", "psk2", "secretpass")
AP_LINES_CHANNEL = wifi_ap_uci_lines("radio1", "MyLAN", "none", channel="36")


class TestWifiStaUciLinesCharacterization:
    def test_basic_no_key(self):
        assert STA_LINES_NO_KEY == [
            "uci set wireless.radio0.disabled='0'",
            "uci set wireless.radio0.country='DE'",
            "uci del wireless.default_radio0.disabled 2>/dev/null",
            "uci set wireless.default_radio0=wifi-iface",
            "uci set wireless.default_radio0.device='radio0'",
            "uci set wireless.default_radio0.mode='sta'",
            "uci set wireless.default_radio0.ssid='UpstreamNet'",
            "uci set wireless.default_radio0.encryption='psk2'",
            "uci set wireless.default_radio0.network='wan'",
        ]

    def test_with_key(self):
        assert "uci set wireless.default_radio0.key='mypass'" in STA_LINES_WITH_KEY
        assert len(STA_LINES_WITH_KEY) == len(STA_LINES_NO_KEY) + 1

    def test_custom_country(self):
        assert "uci set wireless.radio1.country='NO'" in STA_LINES_CUSTOM_CC
        assert "uci set wireless.default_radio1.ssid='TestNet'" in STA_LINES_CUSTOM_CC


class TestWifiApUciLinesCharacterization:
    def test_basic_no_key(self):
        assert AP_LINES_NO_KEY == [
            "uci set wireless.radio0.disabled='0'",
            "uci set wireless.radio0.country='DE'",
            "uci del wireless.default_radio0.disabled 2>/dev/null",
            "uci set wireless.default_radio0=wifi-iface",
            "uci set wireless.default_radio0.device='radio0'",
            "uci set wireless.default_radio0.mode='ap'",
            "uci set wireless.default_radio0.ssid='MyLAN'",
            "uci set wireless.default_radio0.encryption='psk2'",
            "uci set wireless.default_radio0.network='lan'",
        ]

    def test_with_key(self):
        assert "uci set wireless.default_radio0.key='secretpass'" in AP_LINES_WITH_KEY

    def test_with_channel(self):
        assert "uci set wireless.radio1.channel='36'" in AP_LINES_CHANNEL


# -- Roundtrip tests: render_shell(ops) must match uci_lines exactly --


class TestWifiStaOpsRoundtrip:
    """render_shell(wifi_sta_ops(...)) must produce identical output to wifi_sta_uci_lines(...)."""

    def test_basic_no_key(self):
        ops = wifi_sta_ops("radio0", "UpstreamNet", "psk2")
        rendered = render_shell(ops)
        expected = "\n".join(STA_LINES_NO_KEY)
        assert rendered == expected

    def test_with_key(self):
        ops = wifi_sta_ops("radio0", "UpstreamNet", "psk2", "mypass", "wan")
        rendered = render_shell(ops)
        expected = "\n".join(STA_LINES_WITH_KEY)
        assert rendered == expected

    def test_custom_country(self):
        ops = wifi_sta_ops("radio1", "TestNet", "sae", "key123", "wan", "NO")
        rendered = render_shell(ops)
        expected = "\n".join(STA_LINES_CUSTOM_CC)
        assert rendered == expected

    def test_special_chars_in_ssid(self):
        ops = wifi_sta_ops("radio0", "Café's Net", "psk2")
        lines = wifi_sta_uci_lines("radio0", "Café's Net", "psk2")
        assert render_shell(ops) == "\n".join(lines)

    def test_special_chars_in_key(self):
        ops = wifi_sta_ops("radio0", "TestNet", "psk2", "it's a \"secret\"")
        lines = wifi_sta_uci_lines("radio0", "TestNet", "psk2", "it's a \"secret\"")
        assert render_shell(ops) == "\n".join(lines)


class TestWifiApOpsRoundtrip:
    """render_shell(wifi_ap_ops(...)) must produce identical output to wifi_ap_uci_lines(...)."""

    def test_basic_no_key(self):
        ops = wifi_ap_ops("radio0", "MyLAN", "psk2")
        rendered = render_shell(ops)
        expected = "\n".join(AP_LINES_NO_KEY)
        assert rendered == expected

    def test_with_key(self):
        ops = wifi_ap_ops("radio0", "MyLAN", "psk2", "secretpass")
        rendered = render_shell(ops)
        expected = "\n".join(AP_LINES_WITH_KEY)
        assert rendered == expected

    def test_with_channel(self):
        ops = wifi_ap_ops("radio1", "MyLAN", "none", channel="36")
        rendered = render_shell(ops)
        expected = "\n".join(AP_LINES_CHANNEL)
        assert rendered == expected

    def test_special_chars_in_ssid(self):
        ops = wifi_ap_ops("radio0", "Café's Net", "psk2")
        lines = wifi_ap_uci_lines("radio0", "Café's Net", "psk2")
        assert render_shell(ops) == "\n".join(lines)
