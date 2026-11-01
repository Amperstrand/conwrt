"""Characterization + defect-regression tests for the ikev2 builder
(nordvpn.py _build_ikev2_ops). The statics-direct mode, charset gates,
and the purity split landed with the Rust port (plan.rs
VpnNordvpnIke2Profile) — the golden path and the I/O-free planner
both ride statics; the access_token path stays for the 1.x host flow.
"""
import pytest
from profile.ops import render_shell
from use_cases.vpn_providers.nordvpn import _build_ikev2_ops


STATICS: dict = {
    "username": "svcuser",
    "password": "svcpass",
    "station": "193.29.107.10",
    "hostname": "de500.nordvpn.com",
}


class TestIkev2StaticsMode:
    def test_transport_shape(self):
        rendered = render_shell(_build_ikev2_ops(STATICS))
        assert "cat > /tmp/nordvpn_ikev2_setup.sh << 'VPN_SETUP_EOF'" in rendered
        assert "sh /tmp/nordvpn_ikev2_setup.sh" in rendered

    def test_swanctl_config_carries_statics(self):
        rendered = render_shell(_build_ikev2_ops(STATICS))
        assert "remote_addrs = 193.29.107.10" in rendered
        assert 'eap_id = "svcuser"' in rendered
        assert 'secret = "svcpass"' in rendered

    def test_ca_cert_heredoc(self):
        rendered = render_shell(_build_ikev2_ops(STATICS))
        assert "cat > /etc/swanctl/x509ca/nordvpn.pem << 'NORD_CA_EOF'" in rendered
        assert "-----BEGIN CERTIFICATE-----" in rendered
        assert "NORD_CA_EOF" in rendered

    def test_charon_startup_and_nft_rules(self):
        rendered = render_shell(_build_ikev2_ops(STATICS))
        assert "/usr/lib/ipsec/charon" in rendered
        assert "swanctl --load-all" in rendered
        assert "swanctl --initiate --child nord" in rendered
        assert "udp dport { 500, 4500 } accept" in rendered
        assert "meta l4proto esp accept" in rendered

    def test_hw_accel_branches(self):
        on = render_shell(_build_ikev2_ops(STATICS))
        assert "modprobe crypto_hw_eip93" in on
        off = render_shell(_build_ikev2_ops({**STATICS, "hw_accel": False}))
        assert "rmmod crypto_hw_eip93" in off
        assert "blacklist crypto_hw_eip93" in off

    def test_hostname_defaults_to_station(self):
        no_hostname = {k: v for k, v in STATICS.items() if k != "hostname"}
        rendered = render_shell(_build_ikev2_ops(no_hostname))
        assert "193.29.107.10" in rendered  # station used for display too

    def test_tokenless_without_statics_is_not_configured(self):
        rendered = render_shell(_build_ikev2_ops({}))
        assert "NOT CONFIGURED" in rendered


class TestIkev2Gates:
    def test_partial_statics_rejected(self):
        with pytest.raises(ValueError, match="together"):
            _build_ikev2_ops({"username": "u", "password": "p"})  # no station

    @pytest.mark.parametrize("field", ["username", "password"])
    def test_double_quote_in_credentials_rejected(self, field):
        with pytest.raises(ValueError, match=field):
            _build_ikev2_ops({**STATICS, field: 'x"y'})

    def test_control_char_in_username_rejected(self):
        with pytest.raises(ValueError, match="username"):
            _build_ikev2_ops({**STATICS, "username": "a\nb"})

    def test_non_ip_station_rejected(self):
        for evil in ("de500.nordvpn.com", "$(reboot)", "1.2.3; rm"):
            with pytest.raises(ValueError, match="station"):
                _build_ikev2_ops({**STATICS, "station": evil})

    def test_bad_hostname_rejected(self):
        with pytest.raises(ValueError, match="hostname"):
            _build_ikev2_ops({**STATICS, "hostname": "a; rm -rf /"})
