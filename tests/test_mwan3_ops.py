"""Characterization and roundtrip tests for mwan3.py UCI generators.

Characterization tests lock the current output of _build_mwan3 so
refactoring to ops can be verified.

Roundtrip tests verify that render_shell(_build_mwan3_ops(...)) matches
the configuration lines from _build_mwan3(...) (excluding comments/echo).
"""
from helpers import config_lines as _config_lines
from profile.ops import render_shell
from use_cases.mwan3 import _build_mwan3, _build_mwan3_ops


DEFAULT_PARAMS: dict = {}
BALANCED_PARAMS: dict = {"policy": "balanced"}
CUSTOM_TRACK_PARAMS: dict = {
    "track_ips": ["9.9.9.9", "149.112.112.112"],
}


class TestMwan3Characterization:
    def test_default_failover_output(self):
        script = _build_mwan3(DEFAULT_PARAMS)
        assert "uci set mwan3.wan=interface" in script
        assert "uci set mwan3.wan.enabled='1'" in script
        assert "uci set mwan3.usbwan=interface" in script
        assert "uci set mwan3.wan_m1_w1=member" in script
        assert "uci set mwan3.usbwan_m2_w1=member" in script
        assert "uci set mwan3.wan_policy=policy" in script
        assert "uci commit mwan3" in script

    def test_balanced_policy_output(self):
        script = _build_mwan3(BALANCED_PARAMS)
        assert "uci set mwan3.wan_m1_w2=member" in script
        assert "uci set mwan3.usbwan_m1_w1=member" in script

    def test_custom_track_ips_output(self):
        script = _build_mwan3(CUSTOM_TRACK_PARAMS)
        assert "list track_ip '9.9.9.9'" in script
        assert "list track_ip '149.112.112.112'" in script
        assert "list track_ip '1.0.0.1'" not in script


class TestMwan3OpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_mwan3(params)
        ops = _build_mwan3_ops(params)
        rendered = render_shell(ops)
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_default_failover(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_balanced_policy(self):
        self._assert_config_match(BALANCED_PARAMS)

    def test_custom_track_ips(self):
        self._assert_config_match(CUSTOM_TRACK_PARAMS)

    def test_custom_interfaces(self):
        self._assert_config_match({
            "primary": "eth0",
            "secondary": "eth1",
        })

    def test_all_custom(self):
        self._assert_config_match({
            "primary": "wan2",
            "secondary": "wwan",
            "policy": "balanced",
            "track_ips": ["1.1.1.1"],
        })
