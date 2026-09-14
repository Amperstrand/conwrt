"""Ops characterization tests for openvpn_pia.py (Private Internet Access)."""
from __future__ import annotations

import pytest

from profile.ops import render_shell
from use_cases import get
from use_cases.openvpn_pia import _build_openvpn_pia_ops

DEFAULT_PARAMS = {"username": "p1234567", "password": "s3cret"}

ENFORCED_PARAMS = {"username": "p1234567", "password": "s3cret", "phase": "enforced"}

CUSTOM_REMOTES = {
    "username": "p1234567",
    "password": "s3cret",
    "remote_hosts": "10.0.0.1:1198,10.0.0.2:1198",
    "dns_servers": "1.1.1.1,9.9.9.9",
}


def _render(params=None):
    return render_shell(_build_openvpn_pia_ops(params or DEFAULT_PARAMS))


class TestRegistration:
    def test_registered(self):
        uc = get("openvpn-pia")
        assert uc is not None
        assert uc.configure_via == "both"
        assert "openvpn-openssl" in uc.packages

    def test_requires_credentials(self):
        uc = get("openvpn-pia")
        assert uc is not None
        assert uc.params["username"].required
        assert uc.params["password"].required


class TestCredentials:
    def test_auth_file_written_600(self):
        rendered = _render()
        assert "cat > '/etc/openvpn/pia-auth.txt' <<'OPENWRT_EOF'" in rendered
        assert "p1234567" in rendered
        assert "s3cret" in rendered
        assert "chmod 600 /etc/openvpn/pia-auth.txt" in rendered

    def test_ca_downloaded(self):
        rendered = _render()
        assert "wget -q -O /etc/openvpn/ca.rsa.4096.crt" in rendered


class TestProfile:
    def test_has_remotes_and_random(self):
        rendered = _render()
        assert "remote 151.241.122.99 8080" in rendered
        assert "remote-random" in rendered

    def test_ipv6_push_is_ignored(self):
        rendered = _render()
        assert 'pull-filter ignore "route-ipv6"' in rendered
        assert 'pull-filter ignore "ifconfig-ipv6"' in rendered

    def test_uses_data_ciphers_without_persist_tun(self):
        rendered = _render()
        assert "data-ciphers AES-256-GCM" in rendered
        assert "persist-tun" not in rendered

    def test_custom_remotes(self):
        rendered = _render(CUSTOM_REMOTES)
        assert "remote 10.0.0.1 1198" in rendered
        assert "remote 10.0.0.2 1198" in rendered

    def test_profile_is_mode_600(self):
        rendered = _render()
        assert "chmod 600 /etc/openvpn/pia.ovpn" in rendered


class TestUci:
    def test_openvpn_instance(self):
        rendered = _render()
        assert "uci set openvpn.pia=openvpn" in rendered
        assert "uci set openvpn.pia.config='/etc/openvpn/pia.ovpn'" in rendered
        assert "uci set openvpn.pia.enabled='1'" in rendered
        assert "uci commit openvpn" in rendered

    def test_dns_lock(self):
        rendered = _render()
        assert "uci set dhcp.@dnsmasq[0].noresolv='1'" in rendered
        assert "uci add_list dhcp.@dnsmasq[0].server='10.0.0.241'" in rendered
        assert "uci add_list dhcp.@dnsmasq[0].server='10.0.0.243'" in rendered

    def test_custom_dns(self):
        rendered = _render(CUSTOM_REMOTES)
        assert "uci add_list dhcp.@dnsmasq[0].server='1.1.1.1'" in rendered
        assert "uci add_list dhcp.@dnsmasq[0].server='9.9.9.9'" in rendered

    def test_ipv6_disabled(self):
        rendered = _render()
        assert "uci set dhcp.lan.dhcpv6='disabled'" in rendered
        assert "uci set dhcp.lan.ra='disabled'" in rendered
        assert "net.ipv6.conf.all.disable_ipv6=1" in rendered

    def test_firewall_zone_and_forwarding(self):
        rendered = _render()
        assert "uci set firewall.pia_vpn=zone" in rendered
        assert "uci set firewall.pia_vpn.network='vpnclient'" in rendered
        assert "uci set firewall.pia_fwd=forwarding" in rendered
        assert "uci set firewall.pia_fwd.dest='vpn_zone'" in rendered


class TestPhase:
    def test_validation_keeps_wan_fallback(self):
        rendered = _render()
        assert "uci set firewall.wan_fallback=forwarding" in rendered

    def test_enforced_drops_wan_fallback(self):
        rendered = _render(ENFORCED_PARAMS)
        assert "uci set firewall.wan_fallback=forwarding" not in rendered
        assert "dest='wan'" in rendered  # cleanup still removes any stale WAN forwarding


class TestWatchdog:
    def test_scripts_shipped_and_executable(self):
        rendered = _render()
        for script in ("pia-health", "pia-watchdog", "pia-failopen", "pia-enforce"):
            assert f"/usr/bin/{script}" in rendered
        assert "chmod 755 /usr/bin/pia-watchdog" in rendered

    def test_policy_and_cron(self):
        rendered = _render()
        assert "cat > '/etc/config/pia' <<'OPENWRT_EOF'" in rendered
        assert "option phase 'validation'" in rendered
        assert "* * * * * /usr/bin/pia-watchdog" in rendered
        assert "/etc/init.d/cron enable" in rendered

    def test_fail_open_timeout_is_baked_into_scripts(self):
        rendered = _render({"username": "p", "password": "x", "fail_open_timeout": 300})
        assert "option fail_open_timeout '300'" in rendered


class TestValidation:
    def test_bad_phase(self):
        with pytest.raises(ValueError, match="phase"):
            _build_openvpn_pia_ops({"username": "p", "password": "x", "phase": "wat"})

    def test_bad_timeout(self):
        with pytest.raises(ValueError, match="fail_open_timeout"):
            _build_openvpn_pia_ops({"username": "p", "password": "x", "fail_open_timeout": 5})

    def test_bad_remote(self):
        with pytest.raises(Exception):
            _build_openvpn_pia_ops({"username": "p", "password": "x", "remote_hosts": "not a host"})
