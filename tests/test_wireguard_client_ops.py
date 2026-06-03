"""Roundtrip tests for wireguard_client.py UCI generators.

Verify that render_shell(_build_wireguard_client_ops(...)) matches
the configuration lines from _build_wireguard_client(...) (excluding comments/echo/blanks).
"""
from helpers import config_lines as _config_lines
from profile.ops import render_shell
from use_cases.wireguard_client import _build_wireguard_client, _build_wireguard_client_ops


DEFAULT_PARAMS = {
    "peer_public_key": "SERVERKEY",
    "endpoint_host": "vpn.example.com",
}

CUSTOM_PARAMS = {
    "private_key": "PRIVKEY",
    "peer_public_key": "SERVERKEY",
    "endpoint_host": "vpn.example.com",
    "endpoint_port": 12345,
    "peer_psk": "PSKKEY",
    "address": "10.99.0.5/32",
    "dns": "1.1.1.1",
    "kill_switch": False,
    "allowed_ips": "10.0.0.0/8",
}

DNS_PARAMS = {
    "peer_public_key": "SERVERKEY",
    "endpoint_host": "vpn.example.com",
    "dns": "9.9.9.9",
}

NO_DNS_PARAMS = {
    "peer_public_key": "SERVERKEY",
    "endpoint_host": "vpn.example.com",
    "dns": "",
}

KILL_SWITCH_PARAMS = {
    "peer_public_key": "SERVERKEY",
    "endpoint_host": "vpn.example.com",
    "kill_switch": True,
}

NO_KILL_SWITCH_PARAMS = {
    "peer_public_key": "SERVERKEY",
    "endpoint_host": "vpn.example.com",
    "kill_switch": False,
}

PSK_PARAMS = {
    "peer_public_key": "SERVERKEY",
    "endpoint_host": "vpn.example.com",
    "peer_psk": "my-secret-psk",
}


class TestWireguardClientCharacterization:
    def test_default_params_output(self):
        script = _build_wireguard_client(DEFAULT_PARAMS)
        assert "uci set network.wg0=interface" in script
        assert "uci set network.wg0.proto='wireguard'" in script
        assert "uci set network.wg0.private_key='generate'" in script
        assert "uci set network.wg0.addresses='10.67.0.2/32'" in script
        assert "uci set network.wg0_peer=wireguard_wg0" in script
        assert "uci set network.wg0_peer.endpoint_host='vpn.example.com'" in script
        assert "uci set network.wg0_peer.endpoint_port='51820'" in script
        assert "uci add firewall zone" in script
        assert "uci commit network" in script
        assert "uci commit firewall" in script

    def test_kill_switch_present_by_default(self):
        script = _build_wireguard_client(DEFAULT_PARAMS)
        assert "uci set firewall.@rule[-1].name='KillSwitch-Reject-NonVPN'" in script

    def test_no_kill_switch(self):
        script = _build_wireguard_client(NO_KILL_SWITCH_PARAMS)
        assert "KillSwitch" not in script

    def test_dns_present(self):
        script = _build_wireguard_client(DNS_PARAMS)
        assert "uci add_list network.wg0.dns='9.9.9.9'" in script

    def test_no_dns(self):
        script = _build_wireguard_client(NO_DNS_PARAMS)
        assert "uci add_list" not in script

    def test_psk_present(self):
        script = _build_wireguard_client(PSK_PARAMS)
        assert "uci set network.wg0_peer.preshared_key='my-secret-psk'" in script


class TestWireguardClientOpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_wireguard_client(params)
        ops = _build_wireguard_client_ops(params)
        rendered = render_shell(ops)
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_default_params(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_custom_params(self):
        self._assert_config_match(CUSTOM_PARAMS)

    def test_with_dns(self):
        self._assert_config_match(DNS_PARAMS)

    def test_without_dns(self):
        self._assert_config_match(NO_DNS_PARAMS)

    def test_with_kill_switch(self):
        self._assert_config_match(KILL_SWITCH_PARAMS)

    def test_without_kill_switch(self):
        self._assert_config_match(NO_KILL_SWITCH_PARAMS)

    def test_with_psk(self):
        self._assert_config_match(PSK_PARAMS)
