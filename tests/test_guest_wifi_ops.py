"""Ops characterization tests for guest_wifi.py."""
from profile.ops import render_shell
from use_cases.guest_wifi import _build_guest_wifi_ops


DEFAULT_PARAMS: dict = {}
SECURED_PARAMS: dict = {
    "ssid": "MyGuest",
    "key": "guestpass123",
    "encryption": "psk2",
    "isolation": True,
}
OPEN_PARAMS: dict = {
    "ssid": "FreeWiFi",
    "encryption": "none",
    "key": "",
    "isolation": False,
}


class TestGuestWifiOpsDefault:
    def test_creates_guest_interface(self):
        rendered = render_shell(_build_guest_wifi_ops(DEFAULT_PARAMS))
        assert "uci set network.guest=interface" in rendered
        assert "proto" in rendered
        assert "192.168.4.1" in rendered

    def test_creates_dhcp(self):
        rendered = render_shell(_build_guest_wifi_ops(DEFAULT_PARAMS))
        assert "uci set dhcp.guest=dhcp" in rendered
        assert "interface" in rendered

    def test_creates_firewall_zone(self):
        rendered = render_shell(_build_guest_wifi_ops(DEFAULT_PARAMS))
        assert "uci add firewall zone" in rendered
        assert "name" in rendered
        assert "REJECT" in rendered

    def test_allows_dns_dhcp_to_guest(self):
        rendered = render_shell(_build_guest_wifi_ops(DEFAULT_PARAMS))
        assert "Allow-DNS-" in rendered
        assert "Allow-DHCP-" in rendered
        assert "ACCEPT" in rendered

    def test_forwards_guest_to_wan(self):
        rendered = render_shell(_build_guest_wifi_ops(DEFAULT_PARAMS))
        assert "uci add firewall forwarding" in rendered
        assert "dest" in rendered
        assert "wan" in rendered


class TestGuestWifiOpsSecured:
    def test_custom_ssid(self):
        rendered = render_shell(_build_guest_wifi_ops(SECURED_PARAMS))
        assert "MyGuest" in rendered

    def test_psk2_encryption(self):
        rendered = render_shell(_build_guest_wifi_ops(SECURED_PARAMS))
        assert "encryption=psk2" in rendered
        assert "guestpass123" in rendered

    def test_isolation_enabled(self):
        rendered = render_shell(_build_guest_wifi_ops(SECURED_PARAMS))
        assert "isolate=1" in rendered


class TestGuestWifiOpsOpen:
    def test_open_network_no_key(self):
        rendered = render_shell(_build_guest_wifi_ops(OPEN_PARAMS))
        assert "FreeWiFi" in rendered
        assert "encryption=none" in rendered

    def test_isolation_disabled(self):
        rendered = render_shell(_build_guest_wifi_ops(OPEN_PARAMS))
        assert "isolate=0" in rendered

    def test_no_key_set_for_open(self):
        rendered = render_shell(_build_guest_wifi_ops(OPEN_PARAMS))
        # The key command should not appear for open networks
        lines = rendered.split("\n")
        key_lines = [l for l in lines if ".key=" in l]
        assert len(key_lines) == 0
