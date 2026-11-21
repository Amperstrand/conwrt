"""#308: the VPN-AP management rule honors allow_management."""
from profile.ops import render_shell
from use_cases.vpn_providers.nordvpn import _build_vpn_ap_ops


class TestVpnApMgmtGate:
    def test_allow_true_sets_the_rule(self):
        rendered = render_shell(_build_vpn_ap_ops("TestAP", "pw123456", True))
        assert "firewall.vpn_ap_mgmt=rule" in rendered
        assert "Allow-VPNAP-Management" in rendered

    def test_allow_false_omits_and_removes(self):
        rendered = render_shell(_build_vpn_ap_ops("TestAP", "pw123456", False))
        assert "firewall.vpn_ap_mgmt=rule" not in rendered, (
            "allow_management=false must not accept 22/80/443 from VPN-AP clients")
        assert "uci -q delete firewall.vpn_ap_mgmt" in rendered, (
            "a leftover rule from a previous config must be removed")

    def test_flag_reaches_the_helper_from_the_caller(self):
        import inspect
        import use_cases.vpn_providers.nordvpn as nv
        src = inspect.getsource(nv)
        assert "_build_vpn_ap_ops(ap_ssid, ap_key, allow_management)" in src
