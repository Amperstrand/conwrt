"""Ops characterization tests for wireguard_server.py.

render_shell(_build_wireguard_server_ops(...)) is the authoritative output.
"""
from profile.ops import render_shell
from use_cases.wireguard_server import _build_wireguard_server_ops


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


class TestWireguardServerOpsDefault:
    def test_render_shell(self):
        rendered = render_shell(_build_wireguard_server_ops(DEFAULT_PARAMS))
        assert "uci set network.wg0=interface" in rendered
        assert "uci set network.wg0.proto='wireguard'" in rendered
        assert "uci add_list network.wg0.addresses='10.1.99.1/24'" in rendered
        assert "uci commit network" in rendered
        assert "uci commit firewall" in rendered

    def test_without_peer(self):
        rendered = render_shell(_build_wireguard_server_ops(DEFAULT_PARAMS))
        assert "wg0_peer1" not in rendered


class TestWireguardServerOpsCustom:
    def test_custom_params(self):
        rendered = render_shell(_build_wireguard_server_ops(CUSTOM_PARAMS))
        assert "uci set network.wg0.listen_port='12345'" in rendered
        assert "uci add_list network.wg0.addresses='172.16.0.1/16'" in rendered

    def test_with_peer(self):
        rendered = render_shell(_build_wireguard_server_ops(WITH_PEER))
        assert "uci set network.wg0_peer1=wireguard_wg0" in rendered
        assert "uci set network.wg0_peer1.public_key='peer_pub_key'" in rendered
        assert "uci set network.wg0_peer1.allowed_ips='10.1.99.2/32'" in rendered

    def test_with_psk(self):
        rendered = render_shell(_build_wireguard_server_ops(WITH_PSK))
        assert "uci set network.wg0_peer1.preshared_key='shared_secret_key'" in rendered

    def test_without_peer(self):
        rendered = render_shell(_build_wireguard_server_ops({"private_key": "key_only"}))
        assert "wg0_peer1" not in rendered
