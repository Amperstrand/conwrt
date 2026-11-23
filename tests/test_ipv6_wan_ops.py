"""Characterization tests for ipv6_wan.py ops pipeline (#3).

render_shell(_build_ipv6_wan_ops(...)) is the authoritative output. If
ops change, these tests must be updated to match.
"""
import pytest

from profile.ops import render_shell
from use_cases import get as get_use_case
from use_cases.ipv6_wan import _build_ipv6_wan_ops


DEFAULT_PARAMS = {}

EXPECTED_DEFAULT = (
    "# --- IPv6 WAN (NAT66/ULA stable LAN) ---\n"
    "uci set network.wan6=interface\n"
    "uci set network.wan6.proto='dhcpv6'\n"
    "uci set network.wan6.device='@wan'\n"
    "uci set network.wan6.reqprefix='auto'\n"
    "ula=$(uci -q get network.globals.ula_prefix) || ula=''; "
    "[ -n \"$ula\" ] || { mac=$(cat /sys/class/net/eth0/address); "
    "m1=$(echo $mac | cut -d: -f1); m2=$(echo $mac | cut -d: -f2); "
    "m3=$(echo $mac | cut -d: -f3); m4=$(echo $mac | cut -d: -f4); "
    "m5=$(echo $mac | cut -d: -f5); "
    "uci set network.globals.ula_prefix=\"fd$(printf %02x $((0x$m1 ^ 2))):"
    "${m2}ff:fe${m3}:${m4}${m5}::/64\"; }\n"
    "uci set network.lan.ip6assign='64'\n"
    "z=$(uci show firewall | grep \"=zone\" | grep \"name='wan'\" | "
    "cut -d. -f2 | cut -d= -f1); [ -z \"$z\" ] || uci set firewall.$z.masq6='1'\n"
    "uci commit network\n"
    "uci commit firewall\n"
    "/etc/init.d/network reload\n"
    "/etc/init.d/firewall reload"
)


class TestIpv6WanOps:
    def test_default_params(self):
        assert render_shell(_build_ipv6_wan_ops(DEFAULT_PARAMS)) == EXPECTED_DEFAULT

    def test_explicit_ula_and_no_masq6(self):
        rendered = render_shell(_build_ipv6_wan_ops({
            "ula_prefix": "fd12:3456:789a::/64", "masq6": False, "reqprefix": "56",
        }))
        assert "uci set network.globals.ula_prefix='fd12:3456:789a::/64'" in rendered
        assert "masq6" not in rendered          # opted out
        assert "generate" not in rendered       # param wins, no derive
        assert "uci set network.wan6.reqprefix='56'" in rendered

    def test_no_blanket_revert(self):
        # AGENTS.md: never a blanket uci revert on network/firewall
        rendered = render_shell(_build_ipv6_wan_ops(DEFAULT_PARAMS))
        assert "uci revert" not in rendered
        assert "uci -q delete" not in rendered

    def test_derive_guard_is_idempotent(self):
        rendered = render_shell(_build_ipv6_wan_ops(DEFAULT_PARAMS))
        # existing ULA wins; derive only fills the empty case
        assert "uci -q get network.globals.ula_prefix) || ula=''" in rendered
        assert "[ -n \"$ula\" ] ||" in rendered

    @pytest.mark.parametrize("params", [
        {"reqprefix": "x"},
        {"reqprefix": "33"},
        {"ula_prefix": "fd00::/48"},
        {"ula_prefix": "a b"},
        {"lan_ip6assign": "32"},
    ])
    def test_rejects_bad_params(self, params):
        with pytest.raises(ValueError):
            _build_ipv6_wan_ops(params)

    def test_registry_shape(self):
        uc = get_use_case("ipv6-wan")
        assert uc is not None
        assert uc.packages == []  # base-image only, nothing to install
        assert uc.params["masq6"].default is True
