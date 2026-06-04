"""Ops characterization tests for travelmate.py.

render_shell(_build_travelmate_ops(...)) is the authoritative output.
"""
from profile.ops import render_shell
from use_cases.travelmate import _build_travelmate_ops


DEFAULT_PARAMS: dict = {}
CUSTOM_PARAMS = {
    "radio": "radio1",
    "timeout": 120,
    "retry": 10,
    "captive": False,
}


class TestTravelmateOpsDefault:
    def test_render_shell(self):
        rendered = render_shell(_build_travelmate_ops(DEFAULT_PARAMS))
        assert "uci set travelmate.global.trm_enabled='1'" in rendered
        assert "uci set travelmate.global.trm_captive='1'" in rendered
        assert "uci set travelmate.global.trm_timeout='60'" in rendered
        assert "uci set travelmate.global.trm_radio='radio0'" in rendered
        assert "uci commit travelmate" in rendered
        assert "/etc/init.d/travelmate enable" in rendered


class TestTravelmateOpsCustom:
    def test_custom_params(self):
        rendered = render_shell(_build_travelmate_ops(CUSTOM_PARAMS))
        assert "uci set travelmate.global.trm_captive='0'" in rendered
        assert "uci set travelmate.global.trm_timeout='120'" in rendered
        assert "uci set travelmate.global.trm_retry='10'" in rendered
        assert "uci set travelmate.global.trm_radio='radio1'" in rendered

    def test_captive_disabled(self):
        rendered = render_shell(_build_travelmate_ops({"captive": False}))
        assert "trm_captive='0'" in rendered

    def test_custom_radio(self):
        rendered = render_shell(_build_travelmate_ops({"radio": "radio1"}))
        assert "trm_radio='radio1'" in rendered
