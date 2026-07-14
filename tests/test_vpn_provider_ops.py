"""Ops characterization tests for vpn_providers.

Each provider's render_shell(_build_<provider>_ops(...)) is the authoritative
output. Tests verify that rendered scripts contain the expected API endpoints,
UCI commands, firewall rules, DNS config, and provider-specific markers.
"""
from profile.ops import render_shell
from use_cases import registry
from use_cases.vpn_providers.pia import _build_pia_ops
from use_cases.vpn_providers.mullvad import _build_mullvad_ops
from use_cases.vpn_providers.nordvpn import _build_nordvpn_ops
from use_cases.vpn_providers.ivpn import _build_ivpn_ops
from use_cases.vpn_providers.surfshark import _build_surfshark_ops
from use_cases.vpn_providers.openvpn import _build_openvpn_ops


# -- PIA -----------------------------------------------------------------------

PIA_PARAMS = {
    "username": "testuser",
    "password": "testpass",
    "region": "czech",
    "upstream_gateway": "192.168.1.1",
}

PIA_NO_KILL = {**PIA_PARAMS, "kill_switch": False}


class TestPiaOps:
    def test_api_endpoint_present(self):
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert "gtoken/generateToken" in r
        assert "czech.privacy.network" in r
        assert "addKey" in r

    def test_credentials_injected(self):
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert "testuser" in r
        assert "testpass" in r

    def test_wireguard_interface_configured(self):
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert "uci set network.wg0=interface" in r
        assert "uci set network.wg0.proto='wireguard'" in r
        assert "persistent_keepalive" in r

    def test_static_route_present(self):
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert "pia_server_route" in r
        assert "192.168.1.1" in r

    def test_kill_switch_present(self):
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert "vpn_killswitch" in r
        assert "KillSwitch-Reject-NonVPN" in r
        assert "wg show wg0" in r

    def test_no_kill_switch(self):
        r = render_shell(_build_pia_ops(PIA_NO_KILL))
        assert "vpn_killswitch" not in r

    def test_dns_configured(self):
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert "10.0.0.243" in r
        assert "10.0.0.242" in r
        assert "noresolv" in r

    def test_firewall_zone(self):
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert "vpn_zone" in r
        assert "vpn_fwd" in r

    def test_url_encoding_fragment(self):
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert "%2B" in r
        assert "%3D" in r

    def test_json_helper(self):
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert "json_get" in r
        assert "command -v jq" in r


# -- Mullvad -------------------------------------------------------------------

MULLVAD_PARAMS = {
    "account_token": "1234567890",
    "country": "se",
    "upstream_gateway": "192.168.1.1",
}


class TestMullvadOps:
    def test_api_endpoint_present(self):
        r = render_shell(_build_mullvad_ops(MULLVAD_PARAMS))
        assert "api.mullvad.net" in r
        assert "wg-peers" in r

    def test_account_token_injected(self):
        r = render_shell(_build_mullvad_ops(MULLVAD_PARAMS))
        assert "1234567890" in r

    def test_server_list_fetched(self):
        r = render_shell(_build_mullvad_ops(MULLVAD_PARAMS))
        assert "relays/wireguard" in r

    def test_country_filter(self):
        r = render_shell(_build_mullvad_ops(MULLVAD_PARAMS))
        assert '"se"' in r

    def test_wireguard_interface_configured(self):
        r = render_shell(_build_mullvad_ops(MULLVAD_PARAMS))
        assert "uci set network.wg0=interface" in r
        assert "uci set network.wg0.proto='wireguard'" in r

    def test_static_route_present(self):
        r = render_shell(_build_mullvad_ops(MULLVAD_PARAMS))
        assert "mullvad_server_route" in r

    def test_dns_configured(self):
        r = render_shell(_build_mullvad_ops(MULLVAD_PARAMS))
        assert "10.64.0.1" in r

    def test_kill_switch_present(self):
        r = render_shell(_build_mullvad_ops(MULLVAD_PARAMS))
        assert "KillSwitch-Reject-NonVPN" in r


# -- NordVPN -------------------------------------------------------------------

NORDVPN_PARAMS = {
    "service_username": "norduser",
    "service_password": "nordpass",
    "upstream_gateway": "192.168.1.1",
}


class TestNordvpnOps:
    def test_api_endpoint_present(self):
        r = render_shell(_build_nordvpn_ops(NORDVPN_PARAMS))
        assert "api.nordvpn.com" in r
        assert "users/tokens" in r

    def test_credentials_injected(self):
        r = render_shell(_build_nordvpn_ops(NORDVPN_PARAMS))
        assert "norduser" in r
        assert "nordpass" in r

    def test_server_recommendations(self):
        r = render_shell(_build_nordvpn_ops(NORDVPN_PARAMS))
        assert "recommendations" in r

    def test_wireguard_interface_configured(self):
        r = render_shell(_build_nordvpn_ops(NORDVPN_PARAMS))
        assert "uci set network.wg0=interface" in r
        assert "uci set network.wg0.proto='wireguard'" in r

    def test_dns_configured(self):
        r = render_shell(_build_nordvpn_ops(NORDVPN_PARAMS))
        assert "103.86.96.100" in r

    def test_kill_switch_present(self):
        r = render_shell(_build_nordvpn_ops(NORDVPN_PARAMS))
        assert "KillSwitch-Reject-NonVPN" in r


# -- IVPN ----------------------------------------------------------------------

IVPN_PARAMS = {
    "account_id": "ivpn-test123",
    "upstream_gateway": "192.168.1.1",
}


class TestIvpnOps:
    def test_api_endpoint_present(self):
        r = render_shell(_build_ivpn_ops(IVPN_PARAMS))
        assert "api.ivpn.net" in r
        assert "wireguard/key" in r

    def test_account_id_injected(self):
        r = render_shell(_build_ivpn_ops(IVPN_PARAMS))
        assert "ivpn-test123" in r

    def test_server_list_fetched(self):
        r = render_shell(_build_ivpn_ops(IVPN_PARAMS))
        assert "v4/servers" in r

    def test_wireguard_interface_configured(self):
        r = render_shell(_build_ivpn_ops(IVPN_PARAMS))
        assert "uci set network.wg0=interface" in r

    def test_dns_configured(self):
        r = render_shell(_build_ivpn_ops(IVPN_PARAMS))
        assert "10.0.0.53" in r


# -- Surfshark -----------------------------------------------------------------

SURFSHARK_PARAMS = {
    "username": "ssuser",
    "password": "sspass",
    "upstream_gateway": "192.168.1.1",
}


class TestSurfsharkOps:
    def test_api_endpoint_present(self):
        r = render_shell(_build_surfshark_ops(SURFSHARK_PARAMS))
        assert "api.surfshark.com" in r

    def test_credentials_injected(self):
        r = render_shell(_build_surfshark_ops(SURFSHARK_PARAMS))
        assert "ssuser" in r
        assert "sspass" in r

    def test_auth_login(self):
        r = render_shell(_build_surfshark_ops(SURFSHARK_PARAMS))
        assert "auth/login" in r

    def test_wireguard_interface_configured(self):
        r = render_shell(_build_surfshark_ops(SURFSHARK_PARAMS))
        assert "uci set network.wg0=interface" in r

    def test_dns_configured(self):
        r = render_shell(_build_surfshark_ops(SURFSHARK_PARAMS))
        assert "162.252.172.57" in r


# -- Generic OpenVPN -----------------------------------------------------------

OVPN_PARAMS = {
    "ovpn_config": "client\ndev tun\nremote vpn.example.com 1194 udp\nproto udp\n",
    "username": "ovpnuser",
    "password": "ovpnpass",
}

OVPN_NO_KILL = {**OVPN_PARAMS, "kill_switch": False}


class TestOpenvpnOps:
    def test_config_written(self):
        r = render_shell(_build_openvpn_ops(OVPN_PARAMS))
        assert "vpn-client.ovpn" in r
        assert "vpn.example.com" in r

    def test_credentials_file(self):
        r = render_shell(_build_openvpn_ops(OVPN_PARAMS))
        assert "vpn-auth.txt" in r
        assert "ovpnuser" in r

    def test_uci_openvpn_configured(self):
        r = render_shell(_build_openvpn_ops(OVPN_PARAMS))
        assert "uci set openvpn.vpn_client" in r
        assert "config-openvpn" in r

    def test_network_interface(self):
        r = render_shell(_build_openvpn_ops(OVPN_PARAMS))
        assert "proto='openvpn'" in r or "proto=openvpn" in r

    def test_kill_switch_present(self):
        r = render_shell(_build_openvpn_ops(OVPN_PARAMS))
        assert "KillSwitch-Reject-NonVPN" in r

    def test_no_kill_switch(self):
        r = render_shell(_build_openvpn_ops(OVPN_NO_KILL))
        assert "vpn_killswitch" not in r

    def test_openvpn_service_restart(self):
        r = render_shell(_build_openvpn_ops(OVPN_PARAMS))
        assert "/etc/init.d/openvpn restart" in r


# -- Registry ------------------------------------------------------------------

class TestVpnProviderRegistry:
    def test_all_providers_registered(self):
        r = registry()
        expected = {
            "vpn-pia", "vpn-mullvad", "vpn-nordvpn",
            "vpn-ivpn", "vpn-surfshark", "vpn-openvpn",
        }
        for name in expected:
            assert name in r, f"Missing provider: {name}"

    def test_provider_descriptions(self):
        r = registry()
        for name in r:
            if name.startswith("vpn-"):
                uc = r[name]
                assert uc.description, f"{name} has empty description"
                assert uc.packages, f"{name} has no packages"

    def test_pia_params(self):
        r = registry()
        uc = r["vpn-pia"]
        assert "username" in uc.params
        assert uc.params["username"].required
        assert "upstream_gateway" in uc.params
        assert uc.params["upstream_gateway"].required
        assert uc.params["region"].default == "netherlands"

    def test_mullvad_params(self):
        r = registry()
        uc = r["vpn-mullvad"]
        assert "account_token" in uc.params
        assert uc.params["account_token"].required

    def test_openvpn_params(self):
        r = registry()
        uc = r["vpn-openvpn"]
        assert "ovpn_config" in uc.params
        assert uc.params["ovpn_config"].required
        assert "wireguard-tools" not in uc.packages
        assert "openvpn-openssl" in uc.packages
