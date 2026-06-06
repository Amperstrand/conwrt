"""Ops characterization tests for wireguard_client.py.

render_shell(_build_wireguard_client_ops(...)) is the authoritative output.
"""
from profile.ops import render_shell
from use_cases.wireguard_client import _build_wireguard_client_ops


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


class TestWireguardClientOpsDefault:
    def test_render_shell(self):
        rendered = render_shell(_build_wireguard_client_ops(DEFAULT_PARAMS))
        assert "uci set network.wg0=interface" in rendered
        assert "uci set network.wg0.proto='wireguard'" in rendered
        assert "uci set network.wg0.private_key='generate'" in rendered
        assert "uci set network.wg0.addresses='10.67.0.2/32'" in rendered
        assert "uci set network.wg0_peer=wireguard_wg0" in rendered
        assert "uci set network.wg0_peer.endpoint_host='vpn.example.com'" in rendered
        assert "uci set network.wg0_peer.endpoint_port='51820'" in rendered
        assert "uci set firewall.wg_client_vpn=zone" in rendered
        assert "uci commit network" in rendered
        assert "uci commit firewall" in rendered

    def test_kill_switch_present_by_default(self):
        rendered = render_shell(_build_wireguard_client_ops(DEFAULT_PARAMS))
        assert "uci set firewall.wg_client_killswitch.name='KillSwitch-Reject-NonVPN'" in rendered

    def test_no_kill_switch(self):
        rendered = render_shell(_build_wireguard_client_ops(NO_KILL_SWITCH_PARAMS))
        assert "wg_client_killswitch" not in rendered

    def test_dns_present(self):
        rendered = render_shell(_build_wireguard_client_ops(DNS_PARAMS))
        assert "uci add_list network.wg0.dns='9.9.9.9'" in rendered

    def test_no_dns(self):
        rendered = render_shell(_build_wireguard_client_ops(NO_DNS_PARAMS))
        assert "uci add_list" not in rendered

    def test_psk_present(self):
        rendered = render_shell(_build_wireguard_client_ops(PSK_PARAMS))
        assert "uci set network.wg0_peer.preshared_key='my-secret-psk'" in rendered


class TestWireguardClientOpsCustom:
    def test_custom_params(self):
        rendered = render_shell(_build_wireguard_client_ops(CUSTOM_PARAMS))
        assert "private_key='PRIVKEY'" in rendered
        assert "endpoint_port='12345'" in rendered
        assert "preshared_key='PSKKEY'" in rendered
        assert "addresses='10.99.0.5/32'" in rendered
        assert "dns='1.1.1.1'" in rendered
        assert "allowed_ips='10.0.0.0/8'" in rendered

    def test_with_kill_switch(self):
        rendered = render_shell(_build_wireguard_client_ops(KILL_SWITCH_PARAMS))
        assert "KillSwitch" in rendered

    def test_without_kill_switch(self):
        rendered = render_shell(_build_wireguard_client_ops(NO_KILL_SWITCH_PARAMS))
        assert "wg_client_killswitch" not in rendered
