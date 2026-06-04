"""Characterization tests for adguard.py ops pipeline.

render_shell(_build_adguard_ops(...)) is the authoritative output.
If ops change, these tests must be updated to match.
"""
from profile.ops import render_shell
from use_cases.adguard import _build_adguard_ops


DEFAULT_PARAMS = {}
CUSTOM_PARAMS = {
    "listen_ip": "192.168.1.1",
    "web_port": 8080,
    "dns_port": 53,
}

EXPECTED_DEFAULT = (
    "# --- AdGuard Home ---\n"
    "uci set adguardhome.adguardhome=adguardhome\n"
    "uci set adguardhome.adguardhome.enabled='1'\n"
    "uci set adguardhome.adguardhome.http_address='0.0.0.0:3000'\n"
    "uci set adguardhome.adguardhome.dns_port='5353'\n"
    "uci commit adguardhome\n"
    "/etc/init.d/adguardhome enable\n"
    "/etc/init.d/adguardhome start\n"
    "\n"
    "uci set dhcp.@dnsmasq[0].noresolv='1'\n"
    "uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5353'\n"
    "uci commit dhcp\n"
    "/etc/init.d/dnsmasq restart\n"
    'echo "AdGuard Home configured: DNS on port 5353, web UI at 0.0.0.0:3000"'
)

EXPECTED_CUSTOM = (
    "# --- AdGuard Home ---\n"
    "uci set adguardhome.adguardhome=adguardhome\n"
    "uci set adguardhome.adguardhome.enabled='1'\n"
    "uci set adguardhome.adguardhome.http_address='192.168.1.1:8080'\n"
    "uci set adguardhome.adguardhome.dns_port='53'\n"
    "uci commit adguardhome\n"
    "/etc/init.d/adguardhome enable\n"
    "/etc/init.d/adguardhome start\n"
    "\n"
    "uci set dhcp.@dnsmasq[0].noresolv='1'\n"
    "uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#53'\n"
    "uci commit dhcp\n"
    "/etc/init.d/dnsmasq restart\n"
    'echo "AdGuard Home configured: DNS on port 53, web UI at 192.168.1.1:8080"'
)


class TestAdguardOpsDefault:
    def test_render_shell(self):
        assert render_shell(_build_adguard_ops(DEFAULT_PARAMS)) == EXPECTED_DEFAULT


class TestAdguardOpsCustom:
    def test_render_shell(self):
        assert render_shell(_build_adguard_ops(CUSTOM_PARAMS)) == EXPECTED_CUSTOM

    def test_custom_dns_port(self):
        rendered = render_shell(_build_adguard_ops({"dns_port": 42}))
        assert "dns_port='42'" in rendered
        assert "127.0.0.1#42" in rendered
        assert "port 42" in rendered

    def test_custom_listen_ip(self):
        rendered = render_shell(_build_adguard_ops({"listen_ip": "10.0.0.1", "web_port": 443}))
        assert "http_address='10.0.0.1:443'" in rendered
        assert "web UI at 10.0.0.1:443" in rendered
