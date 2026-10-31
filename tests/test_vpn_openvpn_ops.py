"""Characterization + defect-regression tests for vpn_providers/openvpn.py.

The heredoc-terminator gates and the fail-open verify loop are the
fixes landed with the Rust port (plan.rs VpnOpenvpnProfile).
"""
import pytest
from profile.ops import render_shell
from use_cases.vpn_providers.openvpn import _build_openvpn_ops


OVPN = (
    "client\n"
    "remote vpn.example.com 1194\n"
    "proto udp\n"
    "auth-user-pass"
)
FULL_PARAMS: dict = {
    "ovpn_config": OVPN,
    "username": "svcuser",
    "password": "svcpass",
    "proto": "udp",
    "kill_switch": True,
}


class TestVpnOpenvpnOps:
    def test_full_render_shape(self):
        rendered = render_shell(_build_openvpn_ops(FULL_PARAMS))
        assert "mkdir -p /etc/openvpn" in rendered
        assert "cat > /etc/openvpn/vpn-client.ovpn << 'OVPNEOF'" in rendered
        assert "remote vpn.example.com 1194" in rendered
        # credentials ride UCI overrides (init-script contract), no file
        assert "vpn-auth.txt" not in rendered
        assert "uci set openvpn.vpn_client=openvpn" in rendered
        assert "uci set openvpn.vpn_client.config='/etc/openvpn/vpn-client.ovpn'" in rendered
        assert "uci set openvpn.vpn_client.username='svcuser'" in rendered
        assert "uci set openvpn.vpn_client.password='svcpass'" in rendered
        assert "uci set network.vpn_if=interface" in rendered
        # unmanaged interface on the real tunnel device — proto='openvpn'
        # is not a netifd protocol (Codex #603 P1 finding 3)
        assert "uci set network.vpn_if.proto='none'" in rendered
        assert "uci set network.vpn_if.device='tun0'" in rendered
        # proto='openvpn' survives ONLY inside the legacy-debris cleanup
        assert "uci set network.vpn_if.proto='openvpn'" not in rendered
        assert "uci set firewall.vpn_zone.network='vpn_if'" in rendered
        assert "uci set firewall.vpn_killswitch.name='KillSwitch-Reject-NonVPN'" in rendered

    def test_no_credentials_no_auth_file(self):
        rendered = render_shell(_build_openvpn_ops({
            "ovpn_config": OVPN, "kill_switch": False,
        }))
        assert "vpn_client.username" not in rendered
        # the cleanup loop may NAME the rule; the section must not be SET
        assert "uci set firewall.vpn_killswitch=rule" not in rendered

    def test_fail_open_verify_loop_paired_with_kill_switch(self):
        # regression (fixed with this port): the kill switch had NO
        # auto-remove loop — a bad config bricked WAN
        rendered = render_shell(_build_openvpn_ops(FULL_PARAMS))
        assert "ip -4 addr show dev tun0" in rendered
        assert "VPN: tun interface failed — removing kill switch to restore WAN" in rendered
        assert "uci delete firewall.vpn_killswitch" in rendered


class TestVpnOpenvpnGates:
    def test_ovpn_config_required(self):
        with pytest.raises(ValueError):
            _build_openvpn_ops({"ovpn_config": ""})

    def test_heredoc_terminator_injection_rejected(self):
        with pytest.raises(ValueError, match="OVPNEOF"):
            _build_openvpn_ops({
                "ovpn_config": "client\nOVPNEOF\nreboot",
            })

    def test_newline_in_credentials_rejected(self):
        with pytest.raises(ValueError, match="single line"):
            _build_openvpn_ops({
                "ovpn_config": OVPN,
                "username": "u\nrm -rf /",
                "password": "x",
            })

    def test_proto_choice_enforced(self):
        with pytest.raises(ValueError, match="proto"):
            _build_openvpn_ops({"ovpn_config": OVPN, "proto": "udp; reboot"})
        assert "tcp" in render_shell(_build_openvpn_ops({
            "ovpn_config": OVPN, "proto": "tcp",
        }))
