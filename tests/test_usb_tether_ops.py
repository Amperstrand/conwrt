from helpers import config_lines
from profile.ops import render_shell
from use_cases import registry
from use_cases.usb_tether import (
    _build_tether_android_adb_ops,
    _build_tether_android_ops,
    _build_tether_ios_ops,
    _build_tether_ops,
)


def _config_lines(script: str) -> list[str]:
    return config_lines(script, comment_prefix="# ---", keep_echo_with_redirect=True, redirect_chars=(">", ">>", ">&"))



class TestUsbTetherOpsRoundtrip:
    def _assert_config_match(self, name: str, build_ops, params: dict) -> None:
        uc = registry()[name]
        script = uc.build_configure(params)
        ops = build_ops(params)
        rendered = "\n".join(_config_lines(render_shell(ops)))
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_tether_default(self):
        self._assert_config_match("tether", _build_tether_ops, {})

    def test_tether_android_default(self):
        self._assert_config_match("tether-android", _build_tether_android_ops, {})

    def test_tether_android_adb_default(self):
        self._assert_config_match("tether-android-adb", _build_tether_android_adb_ops, {})

    def test_tether_ios_default(self):
        self._assert_config_match("tether-ios", _build_tether_ios_ops, {})

    def test_tether_custom_interface(self):
        self._assert_config_match("tether", _build_tether_ops, {"interface": "wan2"})

    def test_tether_android_custom_interface(self):
        self._assert_config_match("tether-android", _build_tether_android_ops, {"interface": "eth2"})
