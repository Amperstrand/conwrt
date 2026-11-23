"""Characterization tests for iot.py ops pipeline (#4).

render_shell(_build_iot_ops(...)) is the authoritative output. If ops
change, these tests must be updated to match.
"""
import pytest

from profile.ops import render_shell
from use_cases import get as get_use_case
from use_cases.iot import _build_iot_ops


P = {"key": "iotpass123"}


class TestIotOps:
    def test_default_shape(self):
        r = render_shell(_build_iot_ops(dict(P)))
        assert "uci set network.iot.proto='static'" in r
        assert "uci set network.iot.ipaddr='192.168.9.1'" in r
        assert "uci set network.iot.netmask='255.255.255.0'" in r
        assert "uci set dhcp.iot.leasetime='12h'" in r
        assert "uci set firewall.iot.input='REJECT'" in r
        assert "uci set firewall.iot_fwd.dest='wan'" in r
        assert "uci set wireless.iot_ap.isolate=1" in r
        assert "uci set wireless.iot_ap.key='iotpass123'" in r

    def test_radio_hard_gate_leads(self):
        r = render_shell(_build_iot_ops(dict(P)))
        assert r.index("for _r in radio0") < r.index("uci set network.iot=interface")
        assert "echo 'iot: no 2g radio found" in r

    def test_wan_cutoff_drops_forwarding_only(self):
        r = render_shell(_build_iot_ops(dict(P, wan_access=False)))
        assert "_fwd" not in r
        # DNS/DHCP reachability to the router survives the cutoff
        assert "Allow-DNS-iot" in r and "Allow-DHCP-iot" in r
        assert "wan_access=0" in r

    def test_custom_subnet_splits(self):
        r = render_shell(_build_iot_ops(dict(P, subnet="10.90.0.1/24")))
        assert "uci set network.iot.ipaddr='10.90.0.1'" in r

    @pytest.mark.parametrize("params", [
        {"key": ""},
        {"subnet": "10.0.0.0/8"},
        {"subnet": "nope"},
    ])
    def test_rejects_bad_params(self, params):
        with pytest.raises(ValueError):
            _build_iot_ops(params)

    def test_registry_shape(self):
        uc = get_use_case("iot")
        assert uc is not None
        assert uc.packages == []
        assert uc.params["key"].required
        assert uc.requires_capabilities == ["wifi"]
