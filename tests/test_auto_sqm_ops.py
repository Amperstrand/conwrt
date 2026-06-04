"""Characterization tests for auto_sqm.py ops pipeline.

render_shell(_build_auto_sqm_ops(...)) is the authoritative output.
"""
from profile.ops import render_shell
from use_cases.auto_sqm import _build_auto_sqm_ops


DEFAULT_PARAMS = {}
STATIC_SPEED_PARAMS = {"mode": "static", "download_kbps": 50000, "upload_kbps": 10000}
DYNAMIC_PARAMS = {"mode": "dynamic", "dynamic_interval_hours": 6}


class TestAutoSqmOpsDefault:
    def test_render_shell_contains_config(self):
        rendered = render_shell(_build_auto_sqm_ops(DEFAULT_PARAMS))
        assert "uci set auto_sqm.config=auto_sqm" in rendered
        assert "uci set auto_sqm.config.mode='static'" in rendered
        assert "uci commit auto_sqm" in rendered

    def test_render_shell_contains_heredoc(self):
        rendered = render_shell(_build_auto_sqm_ops(DEFAULT_PARAMS))
        assert "cat <<'AUTO_SQM_EOF' > /usr/sbin/auto-sqm" in rendered
        assert "chmod +x /usr/sbin/auto-sqm" in rendered

    def test_default_does_not_run_auto_sqm(self):
        rendered = render_shell(_build_auto_sqm_ops(DEFAULT_PARAMS))
        assert "/usr/sbin/auto-sqm" not in rendered.split("cat <<'AUTO_SQM_EOF'")[0]

    def test_default_echoes_will_measure(self):
        rendered = render_shell(_build_auto_sqm_ops(DEFAULT_PARAMS))
        assert "echo 'auto-sqm: will measure and configure on WAN ifup'" in rendered


class TestAutoSqmOpsStaticSpeed:
    def test_runs_auto_sqm(self):
        rendered = render_shell(_build_auto_sqm_ops(STATIC_SPEED_PARAMS))
        assert "/usr/sbin/auto-sqm" in rendered

    def test_no_cron(self):
        rendered = render_shell(_build_auto_sqm_ops(STATIC_SPEED_PARAMS))
        assert "/etc/crontabs/root" not in rendered


class TestAutoSqmOpsDynamic:
    def test_adds_cron(self):
        rendered = render_shell(_build_auto_sqm_ops(DYNAMIC_PARAMS))
        assert "/etc/crontabs/root" in rendered
        assert "/etc/init.d/cron enable" in rendered
        assert "/etc/init.d/cron restart" in rendered

    def test_cron_interval(self):
        rendered = render_shell(_build_auto_sqm_ops(DYNAMIC_PARAMS))
        assert "0 */6 * * * /usr/sbin/auto-sqm" in rendered

    def test_dynamic_cron_no_defensive_wrappers(self):
        rendered = render_shell(_build_auto_sqm_ops(DYNAMIC_PARAMS))
        assert "/etc/init.d/cron restart 2>/dev/null || true" not in rendered
        assert "/etc/init.d/cron enable 2>/dev/null || true" not in rendered


class TestAutoSqmOpsCustomParams:
    def test_custom_interface_in_hotplug(self):
        rendered = render_shell(_build_auto_sqm_ops({"interface": "wan2"}))
        assert '[ "$INTERFACE" = "wan2" ]' in rendered

    def test_custom_device(self):
        rendered = render_shell(_build_auto_sqm_ops({"device": "eth1"}))
        assert "uci set auto_sqm.config.device='eth1'" in rendered

    def test_custom_qdisc(self):
        rendered = render_shell(_build_auto_sqm_ops({"qdisc": "fq_codel", "script": "simple.qos"}))
        assert "uci set auto_sqm.config.qdisc='fq_codel'" in rendered
        assert "uci set auto_sqm.config.script='simple.qos'" in rendered
