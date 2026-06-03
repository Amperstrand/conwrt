"""Characterization and roundtrip tests for travelmate.py UCI generators.

Characterization tests lock the current output of _build_travelmate so
refactoring to ops can be verified.

Roundtrip tests verify that render_shell(_build_travelmate_ops(...)) matches
the configuration lines from _build_travelmate(...) (excluding comments/echo).
"""
from helpers import config_lines as _config_lines
from profile.ops import render_shell
from use_cases.travelmate import _build_travelmate, _build_travelmate_ops


DEFAULT_PARAMS: dict = {}
CUSTOM_PARAMS = {
    "radio": "radio1",
    "timeout": 120,
    "retry": 10,
    "captive": False,
}


class TestTravelmateCharacterization:
    def test_default_params_output(self):
        script = _build_travelmate(DEFAULT_PARAMS)
        assert "uci set travelmate.global.trm_enabled='1'" in script
        assert "uci set travelmate.global.trm_captive='1'" in script
        assert "uci set travelmate.global.trm_timeout='60'" in script
        assert "uci set travelmate.global.trm_radio='radio0'" in script
        assert "uci commit travelmate" in script
        assert "/etc/init.d/travelmate enable" in script

    def test_custom_params_output(self):
        script = _build_travelmate(CUSTOM_PARAMS)
        assert "uci set travelmate.global.trm_captive='0'" in script
        assert "uci set travelmate.global.trm_timeout='120'" in script
        assert "uci set travelmate.global.trm_retry='10'" in script
        assert "uci set travelmate.global.trm_radio='radio1'" in script


class TestTravelmateOpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_travelmate(params)
        ops = _build_travelmate_ops(params)
        rendered = render_shell(ops)
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_default_params(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_custom_params(self):
        self._assert_config_match(CUSTOM_PARAMS)

    def test_captive_disabled(self):
        self._assert_config_match({"captive": False})

    def test_custom_radio(self):
        self._assert_config_match({"radio": "radio1"})
