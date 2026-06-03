"""Characterization and roundtrip tests for wireguard_server.py UCI generators.

Characterization tests lock the current output of _build_wireguard_server so
refactoring to ops can be verified.

Roundtrip tests verify that render_shell(_build_wireguard_server_ops(...)) matches
the configuration lines from _build_wireguard_server(...) (excluding comments/echo).
"""
from helpers import config_lines as _config_lines
from profile.ops import render_shell
from use_cases.wireguard_server import _build_wireguard_server, _build_wireguard_server_ops


DEFAULT_PARAMS = {"private_key": "test_key_12345"}
CUSTOM_PARAMS = {
    "private_key": "abc123",
    "listen_port": 12345,
    "subnet": "172.16.0.1/16",
}
WITH_PEER = {
    "private_key": "server_key",
    "peer1_public_key": "peer_pub_key",
    "peer1_allowed_ips": "10.1.99.2/32",
}
WITH_PSK = {
    "private_key": "server_key",
    "peer1_public_key": "peer_pub_key",
    "peer1_psk": "shared_secret_key",
}


class TestWireguardServerCharacterization:
    def test_default_params_output(self):
        script = _build_wireguard_server(DEFAULT_PARAMS)
        assert "uci set network.wg0=interface" in script
        assert "uci set network.wg0.proto='wireguard'" in script
        assert "uci add_list network.wg0.addresses='10.1.99.1/24'" in script
        assert "uci commit network" in script
        assert "uci commit firewall" in script

    def test_custom_params_output(self):
        script = _build_wireguard_server(CUSTOM_PARAMS)
        assert "uci set network.wg0.listen_port='12345'" in script
        assert "uci add_list network.wg0.addresses='172.16.0.1/16'" in script

    def test_with_peer(self):
        script = _build_wireguard_server(WITH_PEER)
        assert "uci set network.wg0_peer1=wireguard_wg0" in script
        assert "uci set network.wg0_peer1.public_key='peer_pub_key'" in script
        assert "uci set network.wg0_peer1.allowed_ips='10.1.99.2/32'" in script

    def test_without_peer(self):
        script = _build_wireguard_server(DEFAULT_PARAMS)
        assert "wg0_peer1" not in script

    def test_with_psk(self):
        script = _build_wireguard_server(WITH_PSK)
        assert "uci set network.wg0_peer1.preshared_key='shared_secret_key'" in script


class TestWireguardServerOpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_wireguard_server(params)
        ops = _build_wireguard_server_ops(params)
        rendered = render_shell(ops)
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_default_params(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_custom_params(self):
        self._assert_config_match(CUSTOM_PARAMS)

    def test_with_peer(self):
        self._assert_config_match(WITH_PEER)

    def test_without_peer(self):
        self._assert_config_match({"private_key": "key_only"})

    def test_with_psk(self):
        self._assert_config_match(WITH_PSK)
