"""Characterization + defect-regression tests for vpn_providers/mullvad.py.

Fixes landed with the Rust port (plan.rs VpnMullvadProfile) — the
surfshark #604 review-class applied proactively.
"""
import pytest
from profile.ops import render_shell
from use_cases.vpn_providers.mullvad import _build_mullvad_ops


PARAMS: dict = {
    "account_token": "a1b2c3d4e5f6",
    "upstream_gateway": "192.168.8.1",
}


class TestMullvadOps:
    def test_transport_shape(self):
        rendered = render_shell(_build_mullvad_ops(PARAMS))
        assert "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'" in rendered
        assert "Authorization: Token a1b2c3d4e5f6" in rendered
        assert "uci set network.mullvad_server_route.gateway='192.168.8.1'" in rendered
        assert "uci set network.wg0.proto='wireguard'" in rendered

    def test_wg_pub_expands(self):
        rendered = render_shell(_build_mullvad_ops(PARAMS))
        assert "-d '{\"public_key\":\"'\"${WG_PUB}\"'\"}')" in rendered

    def test_country_select(self):
        rendered = render_shell(_build_mullvad_ops({**PARAMS, "country": "se"}))
        assert 'select(.country_code=="se")' in rendered

    def test_abort_guards(self):
        rendered = render_shell(_build_mullvad_ops(PARAMS))
        assert "server list incomplete — aborting before wg0 cleanup" in rendered
        assert "key registration failed (no peer IP)" in rendered

    def test_readback_and_revert_baseline(self):
        rendered = render_shell(_build_mullvad_ops(PARAMS))
        assert "WG_ADDR=$(uci -q get network.wg0.addresses)" in rendered
        assert "uci -q revert dhcp 2>/dev/null || true" in rendered


class TestMullvadGates:
    def test_hostile_token_rejected(self):
        for evil in ("x' rm", "a b", "$(id)", "a\\b"):
            with pytest.raises(ValueError, match="account_token"):
                _build_mullvad_ops({**PARAMS, "account_token": evil})

    def test_hostile_country_rejected(self):
        for evil in ('s"; rm', "swe", "s-e"):
            with pytest.raises(ValueError, match="country"):
                _build_mullvad_ops({**PARAMS, "country": evil})

    def test_non_ip_gateway_rejected(self):
        with pytest.raises(ValueError, match="upstream_gateway"):
            _build_mullvad_ops({**PARAMS, "upstream_gateway": "$(reboot)"})

    def test_hostile_iface_rejected(self):
        with pytest.raises(Exception, match="unsafe characters"):
            _build_mullvad_ops({**PARAMS, "upstream_iface": "wwan; rm"})
