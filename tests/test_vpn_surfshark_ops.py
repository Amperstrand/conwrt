"""Characterization + injection-gate tests for vpn_providers/surfshark.py.

The credential/country/gateway charset gates are the fix landed with
the Rust port (plan.rs VpnSurfsharkProfile::validate).
"""
import pytest
from profile.ops import render_shell
from use_cases.vpn_providers.surfshark import _build_surfshark_ops


PARAMS: dict = {
    "username": "svcuser",
    "password": "svcpass",
    "country": "Germany",
    "upstream_gateway": "192.168.8.1",
}


class TestSurfsharkOps:
    def test_transport_script_shape(self):
        rendered = render_shell(_build_surfshark_ops(PARAMS))
        assert "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'" in rendered
        assert "-d '{\"username\":\"svcuser\",\"password\":\"svcpass\"}')" in rendered
        assert 'test("Germany";"i")' in rendered
        assert 'uci set network.surfshark_server_route.gateway=\'192.168.8.1\'' in rendered
        assert "wg genkey > /tmp/vpn_private.key" in rendered
        assert "uci set network.wg0.proto='wireguard'" in rendered
        assert "sh /tmp/vpn_setup.sh" in rendered
        # shared composition
        assert "uci set firewall.vpn_zone.name='vpn'" in rendered
        assert "uci add_list dhcp.@dnsmasq[0].server='162.252.172.57'" in rendered
        assert "wg show wg0" in rendered  # verify tail

    def test_no_country_picks_first_server(self):
        rendered = render_shell(_build_surfshark_ops({
            k: v for k, v in PARAMS.items() if k != "country"
        }))
        assert "country/" not in rendered
        assert "jq -r '.[0]'" in rendered


class TestSurfsharkGates:
    @pytest.mark.parametrize("field", ["username", "password"])
    def test_quote_in_credentials_rejected(self, field):
        with pytest.raises(ValueError, match="quotes"):
            _build_surfshark_ops({**PARAMS, field: "x'; rm -rf /; '"})

    @pytest.mark.parametrize("field", ["username", "password"])
    def test_backslash_in_credentials_rejected(self, field):
        with pytest.raises(ValueError, match="backslash"):
            _build_surfshark_ops({**PARAMS, field: "x\\y"})

    def test_hostile_country_rejected(self):
        for evil in ('Ger"; rm', "a;b", "x'y", "Ger\\many"):
            with pytest.raises(ValueError, match="country"):
                _build_surfshark_ops({**PARAMS, "country": evil})

    def test_non_ip_gateway_rejected(self):
        for evil in ("192.168.8.1; rm", "$(reboot)", "hostname.example"):
            with pytest.raises(ValueError, match="upstream_gateway"):
                _build_surfshark_ops({**PARAMS, "upstream_gateway": evil})

    def test_hostile_iface_rejected(self):
        with pytest.raises(Exception, match="unsafe characters"):
            _build_surfshark_ops({**PARAMS, "upstream_iface": "wwan; rm"})
