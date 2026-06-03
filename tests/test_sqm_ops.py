"""Characterization and roundtrip tests for sqm.py UCI generators.

Characterization tests lock the current output of _build_sqm so
refactoring to ops can be verified.

Roundtrip tests verify that render_shell(_build_sqm_ops(...)) matches
the configuration lines from _build_sqm(...) (excluding comments/echo).
"""
from helpers import config_lines as _config_lines
from profile.ops import render_shell
from use_cases.sqm import _build_sqm, _build_sqm_ops


DEFAULT_PARAMS = {"download_kbps": 340000, "upload_kbps": 19000}
CUSTOM_PARAMS = {
    "download_kbps": 100000,
    "upload_kbps": 50000,
    "interface": "eth1",
    "qdisc": "fq_codel",
    "script": "layer_cake.qos",
    "link_layer": "ethernet",
    "overhead": 44,
}


class TestSqmCharacterization:
    def test_default_params_output(self):
        script = _build_sqm(DEFAULT_PARAMS)
        assert "uci set sqm.wan=queue" in script
        assert "uci set sqm.wan.enabled='1'" in script
        assert "uci set sqm.wan.download='340000'" in script
        assert "uci set sqm.wan.upload='19000'" in script
        assert "uci commit sqm" in script
        assert "/etc/init.d/sqm enable" in script

    def test_custom_params_output(self):
        script = _build_sqm(CUSTOM_PARAMS)
        assert "uci set sqm.eth1=queue" in script
        assert "uci set sqm.eth1.qdisc='fq_codel'" in script
        assert "uci set sqm.eth1.script='layer_cake.qos'" in script
        assert "uci set sqm.eth1.linklayer='ethernet'" in script
        assert "uci set sqm.eth1.overhead='44'" in script


class TestSqmOpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_sqm(params)
        ops = _build_sqm_ops(params)
        rendered = render_shell(ops)
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_default_params(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_custom_params(self):
        self._assert_config_match(CUSTOM_PARAMS)

    def test_minimal_speeds(self):
        self._assert_config_match({"download_kbps": 1, "upload_kbps": 1})

    def test_max_overhead(self):
        self._assert_config_match({"download_kbps": 100, "upload_kbps": 100, "overhead": 512})
