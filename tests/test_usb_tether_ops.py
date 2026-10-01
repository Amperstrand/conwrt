from helpers import config_lines
from profile.ops import render_shell
from use_cases import registry
from use_cases.usb_tether import (
    _ANDROID_PKGS,
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


class TestUsbTetherAndroidNcm:
    def test_android_packages_include_cdc_ncm(self):
        # Pixel 10 / modern Android tethers via CDC-NCM, not RNDIS
        # (conwrt-bench#46) — without this kmod the kernel cannot bind.
        assert "kmod-usb-net-cdc-ncm" in _ANDROID_PKGS

    def test_detection_script_matches_cdc_ncm_driver(self):
        from use_cases.usb_tether import _detect_usb_net_device

        script = _detect_usb_net_device(match_android=True, match_ios=False)
        assert "cdc_ncm" in script

    def test_adb_hotplug_has_ui_toggle_fallback(self):
        from use_cases.usb_tether import _adb_hotplug_script

        script = _adb_hotplug_script()
        for marker in (
            "svc usb setFunctions rndis",          # legacy path (Android <= 12)
            "android.settings.TETHER_SETTINGS",    # UI automation (Android 14+)
            "uiautomator dump",
            "input tap",                            # the toggle tap
            "ADB UI toggle enabled tethering",      # success log distinguishes methods
        ):
            assert marker in script, f"missing UI-toggle marker: {marker}"

    def test_adb_hotplug_ui_markers_reach_rendered_config(self):
        # The use case registration path must carry the new hotplug script
        # into the generated configure script, not just the builder.
        rendered = registry()["tether-android-adb"].build_configure({})
        assert "android.settings.TETHER_SETTINGS" in rendered
        assert "svc usb setFunctions rndis" in rendered
