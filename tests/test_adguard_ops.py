"""Characterization and roundtrip tests for adguard.py UCI generators.

Characterization tests lock the current output of _build_adguard so
refactoring to ops can be verified.

Roundtrip tests verify that render_shell(_build_adguard_ops(...)) matches
the configuration lines from _build_adguard(...) (excluding comments/echo).
"""
from helpers import config_lines as _config_lines
from profile.ops import render_shell
from use_cases.adguard import _build_adguard, _build_adguard_ops


DEFAULT_PARAMS = {}
CUSTOM_PARAMS = {
    "listen_ip": "192.168.1.1",
    "web_port": 8080,
    "dns_port": 53,
}


class TestAdguardCharacterization:
    def test_default_params_output(self):
        script = _build_adguard(DEFAULT_PARAMS)
        assert "uci set adguardhome.adguardhome=adguardhome" in script
        assert "uci set adguardhome.adguardhome.enabled='1'" in script
        assert "uci set adguardhome.adguardhome.http_address='0.0.0.0:3000'" in script
        assert "uci set adguardhome.adguardhome.dns_port='5353'" in script
        assert "uci commit adguardhome" in script
        assert "/etc/init.d/adguardhome enable" in script

    def test_custom_params_output(self):
        script = _build_adguard(CUSTOM_PARAMS)
        assert "uci set adguardhome.adguardhome.http_address='192.168.1.1:8080'" in script
        assert "uci set adguardhome.adguardhome.dns_port='53'" in script
        assert "uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#53'" in script


class TestAdguardOpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_adguard(params)
        ops = _build_adguard_ops(params)
        rendered = render_shell(ops)
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_default_params(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_custom_params(self):
        self._assert_config_match(CUSTOM_PARAMS)

    def test_custom_dns_port(self):
        self._assert_config_match({"dns_port": 42})

    def test_custom_listen_ip(self):
        self._assert_config_match({"listen_ip": "10.0.0.1", "web_port": 443})
