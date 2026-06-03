from helpers import config_lines
from profile.ops import render_shell
from use_cases.auto_sqm import _build_auto_sqm, _build_auto_sqm_ops


DEFAULT_PARAMS = {}
STATIC_SPEED_PARAMS = {"mode": "static", "download_kbps": 50000, "upload_kbps": 10000}
DYNAMIC_PARAMS = {"mode": "dynamic", "dynamic_interval_hours": 6}


def _config_lines(script: str) -> list[str]:
    return config_lines(script, comment_prefix="# ---", keep_echo_with_redirect=True, redirect_chars=(">", ">>"))



class TestAutoSqmCharacterization:
    def test_default_produces_config_block(self):
        script = _build_auto_sqm(DEFAULT_PARAMS)
        assert "uci set auto_sqm.config.mode='static'" in script
        assert "uci commit auto_sqm" in script
        assert "cat <<'AUTO_SQM_EOF' > /usr/sbin/auto-sqm" in script
        assert "chmod +x /usr/sbin/auto-sqm" in script

    def test_static_with_speed_runs_auto_sqm(self):
        script = _build_auto_sqm(STATIC_SPEED_PARAMS)
        assert "/usr/sbin/auto-sqm" in script

    def test_dynamic_adds_cron(self):
        script = _build_auto_sqm(DYNAMIC_PARAMS)
        assert "/etc/crontabs/root" in script
        assert "/etc/init.d/cron enable" in script
        assert "/etc/init.d/cron restart" in script

    def test_custom_interface_in_hotplug(self):
        script = _build_auto_sqm({"interface": "wan2"})
        assert '[ "$INTERFACE" = "wan2" ]' in script


class TestAutoSqmOpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_auto_sqm(params)
        ops = _build_auto_sqm_ops(params)
        rendered = "\n".join(_config_lines(render_shell(ops)))
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_default_params(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_static_with_speed(self):
        self._assert_config_match(STATIC_SPEED_PARAMS)

    def test_dynamic_mode(self):
        self._assert_config_match(DYNAMIC_PARAMS)

    def test_custom_interface_and_device(self):
        self._assert_config_match({"interface": "wwan", "device": "eth1"})

    def test_custom_qdisc(self):
        self._assert_config_match({"qdisc": "fq_codel", "script": "simple.qos"})
