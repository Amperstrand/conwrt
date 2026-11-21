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


class TestVpnApTeardown311:
    def test_wg_transition_commits_openvpn_deletion(self):
        """#310: the WireGuard path commits openvpn after deleting
        openvpn.nordvpn — an uncommitted delete returns at reboot."""
        import inspect
        import use_cases.vpn_providers.nordvpn as nv
        src = inspect.getsource(nv)
        wg = re.search(r"def build_wireguard_ops.*?return ops", src, re.S)
        assert wg, "wireguard builder found"
        import re as _re
        block = wg.group(0)
        assert "uci -q delete openvpn.nordvpn" in block
        assert "uci commit openvpn" in block, (
            "the delete must be committed or the section returns at reboot")

    def test_teardown_ops_generated_when_ap_ssid_cleared(self):
        """#311: no ap_ssid ⇒ teardown ops (deletes + commits)."""
        from profile.ops import render_shell
        from use_cases.vpn_providers.nordvpn import _vpn_ap_teardown_ops
        rendered = render_shell(_vpn_ap_teardown_ops())
        for frag in ("delete wireless.wifinet_vpn_ap", "delete network.vpnlan",
                     "delete firewall.vpn_ap_mgmt", "uci commit wireless",
                     "wifi reload"):
            assert frag in rendered, frag


import re  # noqa: E402  (used above)
