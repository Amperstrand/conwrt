"""Characterization and roundtrip tests for fips_bluetooth_rfcomm.py generators.

Characterization tests lock the current output of _build_fips_rfcomm so
refactoring to ops can be verified.

Roundtrip tests verify that render_shell(_build_fips_rfcomm_ops(...)) matches
the configuration lines from _build_fips_rfcomm(...) (excluding the final
informational echo).
"""
from profile.ops import render_shell
from use_cases.fips_bluetooth_rfcomm import _build_fips_rfcomm, _build_fips_rfcomm_ops


DEFAULT_PARAMS: dict = {}

SERVER_WITH_PEERS: dict = {
    "role": "server",
    "channel": 5,
    "peers": [
        {"npub": "abc123", "bt_mac": "AA:BB:CC:DD:EE:FF", "alias": "node1"},
    ],
}

CLIENT_NO_TUN: dict = {
    "tun_enabled": False,
    "tun_dns": False,
    "tun_gateway": False,
}

CLIENT_CUSTOM_PIN: dict = {
    "bt_pin": "1234",
    "channel": 10,
}


def _config_lines(script: str) -> list[str]:
    lines = script.strip().splitlines()
    return [
        ln.strip()
        for ln in lines
        if ln.strip() and not ln.strip().startswith("echo 'FIPS Bluetooth RFCOMM configured")
    ]


class TestFipsRfcommCharacterization:
    def test_client_default_output(self):
        script = _build_fips_rfcomm(DEFAULT_PARAMS)
        assert "mkdir -p /etc/fips" in script
        assert "echo '0000' > /etc/fips/bt-pin" in script
        assert "chmod +x /etc/init.d/bt-agent" in script
        assert "/etc/init.d/bt-agent enable" in script
        assert "chmod +x /etc/init.d/fips" in script
        assert "/etc/init.d/fips enable" in script

    def test_server_with_peers_output(self):
        script = _build_fips_rfcomm(SERVER_WITH_PEERS)
        assert 'mode: "server"' in script
        assert "accept_connections: true" in script
        assert "peers_allow: /etc/fips/peers.allow" in script
        assert "echo 'abc123' > /etc/fips/peers.allow" in script

    def test_client_no_tun_output(self):
        script = _build_fips_rfcomm(CLIENT_NO_TUN)
        assert "enabled: false" in script
        assert "gateway:" not in script
        assert "dns:" not in script

    def test_custom_pin_channel(self):
        script = _build_fips_rfcomm(CLIENT_CUSTOM_PIN)
        assert "echo '1234' > /etc/fips/bt-pin" in script
        assert "channel: 10" in script


class TestFipsRfcommOpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_fips_rfcomm(params)
        ops = _build_fips_rfcomm_ops(params)
        rendered = render_shell(ops)
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_client_default(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_server_with_peers(self):
        self._assert_config_match(SERVER_WITH_PEERS)

    def test_client_no_tun(self):
        self._assert_config_match(CLIENT_NO_TUN)

    def test_client_custom_pin_channel(self):
        self._assert_config_match(CLIENT_CUSTOM_PIN)

    def test_server_no_peers(self):
        self._assert_config_match({"role": "server"})

    def test_server_multiple_peers(self):
        self._assert_config_match({
            "role": "server",
            "peers": [
                {"npub": "key1", "bt_mac": "11:22:33:44:55:66", "alias": "a"},
                {"npub": "key2", "bt_mac": "AA:BB:CC:DD:EE:FF"},
            ],
        })

    def test_tun_enabled_no_dns_no_gateway(self):
        self._assert_config_match({
            "tun_enabled": True,
            "tun_dns": False,
            "tun_gateway": False,
        })
