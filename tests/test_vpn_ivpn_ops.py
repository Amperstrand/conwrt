"""Characterization + defect-regression tests for vpn_providers/ivpn.py.

The WG_PUB splice, charset gates, abort guards, readback, and revert
baseline are the fixes landed with the Rust port (plan.rs
VpnIvpnProfile) — the surfshark #604 review-class applied proactively.
"""
import pytest
from profile.ops import render_shell
from use_cases.vpn_providers.ivpn import _build_ivpn_ops


PARAMS: dict = {
    "account_id": "ivpn-abc123",
    "upstream_gateway": "192.168.8.1",
}


class TestIvpnOps:
    def test_transport_shape(self):
        rendered = render_shell(_build_ivpn_ops(PARAMS))
        assert "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'" in rendered
        assert "account_id=ivpn-abc123" in rendered
        assert "uci set network.ivpn_server_route.gateway='192.168.8.1'" in rendered
        assert "wg genkey > /tmp/vpn_private.key" in rendered
        assert "uci set network.wg0.proto='wireguard'" in rendered
        assert "sh /tmp/vpn_setup.sh" in rendered

    def test_wg_pub_expands(self):
        # regression (the surfshark #604-P1 class): single-quoted JSON
        # sent the LITERAL string ${WG_PUB} — registration never worked
        rendered = render_shell(_build_ivpn_ops(PARAMS))
        assert "-d '{\"public_key\":\"'\"${WG_PUB}\"'\"}')" in rendered
        assert "public_key\":\"${WG_PUB}\"" not in rendered

    def test_abort_guards_before_destructive_cleanup(self):
        rendered = render_shell(_build_ivpn_ops(PARAMS))
        assert "server list incomplete — aborting before wg0 cleanup" in rendered
        assert "key registration failed (no peer IP)" in rendered

    def test_pre_commit_address_readback(self):
        rendered = render_shell(_build_ivpn_ops(PARAMS))
        assert "WG_ADDR=$(uci -q get network.wg0.addresses)" in rendered
        assert "not a sane /32 — aborting before commit" in rendered

    def test_revert_baseline(self):
        rendered = render_shell(_build_ivpn_ops(PARAMS))
        assert "uci -q revert network 2>/dev/null || true" in rendered
        assert "uci -q revert dhcp 2>/dev/null || true" in rendered


class TestIvpnGates:
    def test_hostile_account_id_rejected(self):
        for evil in ("x'; rm -rf /; '", "a&b", "$(reboot)", "a b"):
            with pytest.raises(ValueError, match="account_id"):
                _build_ivpn_ops({**PARAMS, "account_id": evil})

    def test_non_ip_gateway_rejected(self):
        for evil in ("192.168.8.1; rm", "$(reboot)", "gw.example"):
            with pytest.raises(ValueError, match="upstream_gateway"):
                _build_ivpn_ops({**PARAMS, "upstream_gateway": evil})

    def test_hostile_iface_rejected(self):
        with pytest.raises(Exception, match="unsafe characters"):
            _build_ivpn_ops({**PARAMS, "upstream_iface": "wwan; rm"})
