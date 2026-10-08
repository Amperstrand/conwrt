"""Ops characterization tests for vpn_providers.

Each provider's render_shell(_build_<provider>_ops(...)) is the authoritative
output. Tests verify that rendered scripts contain the expected API endpoints,
UCI commands, firewall rules, DNS config, and provider-specific markers.
"""
from unittest.mock import patch

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

    def test_jq_install_supports_apk_and_opkg(self):
        # apk (OpenWrt >=25.x) first, opkg (<=24.x) fallback — #40 revival
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert "apk add jq" in r
        assert "opkg install jq" in r


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

def _nordvpn_test_conf_path():
    import tempfile
    from pathlib import Path

    conf = Path(tempfile.gettempdir()) / "conwrt-nordvpn-test.conf"
    conf.write_text(
        "[Interface]\n"
        "PrivateKey = cz0RJohr4gsPsIREjDaKW3jI1MwTcRYCXx5LhJI7mQs=\n"
        "Address = 10.5.0.2/16\n"
        "DNS = 103.86.96.100\n"
        "[Peer]\n"
        "PublicKey = qJb7+jCxGN8MAcSTKcDvDE81XobRBv1mu+phcB3zOGw=\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "Endpoint = hamburg.de.wg.nordhold.net:51820\n"
        "PersistentKeepalive = 25\n"
    )
    return str(conf)


NORDVPN_PARAMS = {
    "config_file": _nordvpn_test_conf_path(),
    "upstream_iface": "wwan",
}

def _write_nordvpn_conf(tmp_path):
    conf = tmp_path / "nordvpn.conf"
    conf.write_text(
        "[Interface]\n"
        "PrivateKey = cz0RJohr4gsPsIREjDaKW3jI1MwTcRYCXx5LhJI7mQs=\n"
        "Address = 10.5.0.2/16\n"
        "DNS = 103.86.96.100\n"
        "[Peer]\n"
        "PublicKey = qJb7+jCxGN8MAcSTKcDvDE81XobRBv1mu+phcB3zOGw=\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "Endpoint = hamburg.de.wg.nordhold.net:51820\n"
        "PersistentKeepalive = 25\n"
    )
    return str(conf)


import use_cases.vpn_providers.nordvpn as watch_nordvpn


class TestNordvpnOps:
    def test_static_config_mode_bakes_wg(self, tmp_path):
        params = dict(NORDVPN_PARAMS, config_file=_write_nordvpn_conf(tmp_path))
        r = render_shell(_build_nordvpn_ops(params))
        assert "wireguard" in r
        assert "cz0RJohr4gsPsIREjDaKW3jI1MwTcRYCXx5LhJI7mQs=" in r
        assert "qJb7+jCxGN8MAcSTKcDvDE81XobRBv1mu+phcB3zOGw=" in r
        assert "10.5.0.2/16" in r

    def test_token_mode_resolves_at_build_time(self):
        """Token mode bakes a static config — no API calls from the device."""
        with patch.object(watch_nordvpn, "_fetch_credentials", return_value={"nordlynx_private_key": "PRIVKEY=", "username": "u", "password": "p"}), \
             patch.object(watch_nordvpn, "_resolve_endpoint",
                          return_value=("185.1.2.3", "51820", "SRVKEY=")):
            r = render_shell(_build_nordvpn_ops({"access_token": "a" * 64}))
        assert 'WG_PRIV="PRIVKEY="' in r
        assert 'SERVER_IP="185.1.2.3"' in r
        assert 'SERVER_KEY="SRVKEY="' in r
        assert "api.nordvpn.com" not in r, "token mode must resolve at build time"
        assert "curl" not in r, "no curl dependency on the device"

    def test_server_defaults_to_de(self):
        with patch.object(watch_nordvpn, "_fetch_credentials", return_value={"nordlynx_private_key": "P=", "username": "u", "password": "p"}), \
             patch.object(watch_nordvpn, "_resolve_endpoint", wraps=watch_nordvpn._resolve_endpoint) as mock:
            mock.side_effect = lambda server, token: ("1.2.3.4", "51820", "K=")
            _build_nordvpn_ops({"access_token": "a" * 64})
        assert mock.call_args[0][0] == "DE"

    def test_wireguard_interface_configured(self, tmp_path):
        params = dict(NORDVPN_PARAMS, config_file=_write_nordvpn_conf(tmp_path))
        r = render_shell(_build_nordvpn_ops(params))
        assert "uci set network.wg0=interface" in r
        assert "uci set network.wg0.proto='wireguard'" in r

    def test_management_rule_on_by_default(self, tmp_path):
        params = dict(NORDVPN_PARAMS, config_file=_write_nordvpn_conf(tmp_path))
        r = render_shell(_build_nordvpn_ops(params))
        assert "Allow-VPN-Management" in r
        assert "dest_port='22 80 443'" in r

    def test_management_rule_can_be_disabled(self, tmp_path):
        params = dict(NORDVPN_PARAMS, config_file=_write_nordvpn_conf(tmp_path),
                      allow_management=False)
        r = render_shell(_build_nordvpn_ops(params))
        assert "firewall.vpn_mgmt=rule" not in r, \
            "only the stale-section cleanup may mention the rule"

    def test_vpn_ap_baked_when_configured(self, tmp_path):
        params = dict(NORDVPN_PARAMS, config_file=_write_nordvpn_conf(tmp_path),
                      ap_ssid="nord", ap_key="nordnord")
        r = render_shell(_build_nordvpn_ops(params))
        assert "wifinet_vpn_ap" in r
        assert "ssid='nord'" in r
        assert "key='nordnord'" in r
        assert "network.vpnlan_dev.name='br-vpnlan'" in r, "AP must be bridged (standalone ifaces never deliver DHCP)"
        assert "network.vpnlan.device='br-vpnlan'" in r
        assert "dhcp.vpnlan=dhcp" in r
        # Dedicated zone with its own input rules — vpnlan must NOT join the vpn
        # zone (its input/forward policies would drop DHCP and vpnlan→wg0).
        assert "firewall.vpn_ap_zone.name='vpnap'" in r
        assert "firewall.vpn_ap_fwd.src='vpnap'" in r
        assert "firewall.vpn_ap_fwd.dest='vpn'" in r
        assert "Allow-VPNAP-DHCP" in r and "dest_port='67 68'" in r
        assert "Allow-VPNAP-DNS" in r and "172.16.31.0/24" in r
        assert "Allow-VPNAP-Management" in r
        assert "del_list firewall.vpn_zone.network='vpnlan'" in r
        # dnsmasq re-arm after the AP bridge is up
        assert "br-vpnlan" in r and "dnsmasq restart" in r

    def test_vpn_ap_absent_without_params(self, tmp_path):
        params = dict(NORDVPN_PARAMS, config_file=_write_nordvpn_conf(tmp_path))
        r = render_shell(_build_nordvpn_ops(params))
        assert "wifinet_vpn_ap" not in r
        assert "vpnlan" not in r

    def test_ap_password_quoting(self, tmp_path):
        params = dict(NORDVPN_PARAMS, config_file=_write_nordvpn_conf(tmp_path),
                      ap_ssid="it's", ap_key="pass'word")
        r = render_shell(_build_nordvpn_ops(params))
        assert "ssid='it'\\''s'" in r
        assert "key='pass'\\''word'" in r

    def test_unconfigured_returns_skip_comment(self):
        ops = _build_nordvpn_ops({})
        assert any("NOT CONFIGURED" in str(getattr(op, "text", "")) for op in ops)

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

    def test_firewall_zone_attaches_to_logical_interface(self):
        # Codex #81 4107888569: zone.network references a UCI network section
        # (vpn_if), not the raw tun0 device.
        from profile.ops import UciSet

        zone_sets = [o for o in _build_openvpn_ops(OVPN_PARAMS)
                     if isinstance(o, UciSet) and o.section == "vpn_zone"]
        assert zone_sets, "openvpn ops must configure firewall.vpn_zone"
        assert zone_sets[0].values["network"] == "vpn_if"


# -- Static route (shared) -----------------------------------------------------

class TestStaticRouteExpansion:
    """Route target is a runtime shell variable — single quotes stored the
    literal '${SERVER_IP}' text (Codex #81 4107888562; AGENTS.md double-quote
    rule for shell variables in uci commands)."""

    def test_route_target_expands_the_server_variable(self):
        from use_cases.vpn_providers.base import static_route_sh

        frag = static_route_sh("SERVER_IP", "192.168.1.1")
        assert 'target="${SERVER_IP}"' in frag
        assert "target='${SERVER_IP}'" not in frag

    def test_pia_render_uses_double_quoted_target(self):
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert 'target="${SERVER_IP}"' in r

    def test_literal_values_keep_single_quotes(self):
        from use_cases.vpn_providers.base import static_route_sh

        frag = static_route_sh("SERVER_IP", "192.168.1.1")
        assert "interface='wwan'" in frag
        assert "gateway='192.168.1.1'" in frag
        assert "netmask='255.255.255.255'" in frag


# -- Shared verify/finalization ops --------------------------------------------

class TestDnsCommitAndReload:
    """Codex #81 4107888589: build_dns_ops mutates dhcp.@dnsmasq[0], so the
    shared finalization must commit dhcp and restart dnsmasq — otherwise the
    provider DNS + noresolv never reach the running resolver and vanish on
    reboot."""

    def test_verify_ops_commit_dhcp_and_restart_dnsmasq(self):
        from profile.ops import ServiceAction, UciCommit
        from use_cases.vpn_providers.base import build_verify_ops

        ops = build_verify_ops()
        assert UciCommit(config="dhcp") in ops
        assert ServiceAction(name="dnsmasq", action="restart") in ops

    def test_pia_render_commits_dhcp_and_reloads_dnsmasq(self):
        r = render_shell(_build_pia_ops(PIA_PARAMS))
        assert "uci commit dhcp" in r
        assert r.index("uci commit dhcp") > r.index("uci commit firewall")
        assert "/etc/init.d/dnsmasq restart" in r
        assert r.index("/etc/init.d/dnsmasq restart") > r.index("/etc/init.d/network restart")


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


class TestHeredocTransportVerbatim:
    def test_run_step_script_preserves_hash_lines_in_heredocs(self):
        """Heredoc payloads carry key/cert data where '#' lines are DATA.

        Regression: _run_step_script stripped comment-looking lines from the
        whole payload, silently truncating OpenVPN tls-auth keys (TLS
        handshake failures, 2026-10-08).
        """
        import sys as _sys
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "scripts"))
        from profile.apply import _run_step_script

        captured = {}

        def fake_run(cmd, input=None, **kwargs):
            captured["payload"] = input
            return type("R", (), {"returncode": 0, "stderr": ""})()

        import profile.apply as apply_mod
        with patch.object(apply_mod.subprocess, "run", side_effect=fake_run):
            ok = _run_step_script(
                "192.168.0.1",
                "cat > /etc/k << 'EOF'\n"
                "-----BEGIN KEY-----\n"
                "#\n"
                "# 2048 bit key\n"
                "#\n"
                "deadbeef\n"
                "EOF\n",
                "", lambda m: None,
            )
        assert ok
        assert "# 2048 bit key" in captured["payload"], "heredoc data line stripped"
        assert "deadbeef" in captured["payload"]
