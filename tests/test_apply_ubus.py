from unittest.mock import MagicMock, patch

from config import ConwrtConfig, UseCaseConfig, WifiSTAConfig
from profile import apply_ubus, build_plan
from profile.plan import StepKind


def _make_plan_with_hostname():
    cfg = ConwrtConfig(hostname="test-router")
    return build_plan(cfg, mode="post_install")


def _make_plan_with_sqm():
    cfg = ConwrtConfig(
        use_cases=[UseCaseConfig(name="sqm", params={"download_kbps": 50000, "upload_kbps": 10000})],
    )
    return build_plan(cfg, mode="post_install")


class TestApplyUbus:
    @patch("ubus_utils.urllib.request.urlopen")
    def test_applies_hostname_via_ubus(self, mock_urlopen):
        import json

        def mock_response(data):
            cm = MagicMock()
            cm.__enter__ = MagicMock(return_value=cm)
            cm.__exit__ = MagicMock(return_value=False)
            cm.read.return_value = json.dumps(data).encode()
            return cm

        mock_urlopen.return_value = mock_response({
            "result": [0, {"ubus_rpc_session": "tok"}],
        })

        plan = _make_plan_with_hostname()
        log_msgs = []
        apply_ubus(
            plan, "192.168.1.1",
            username="root", password="",
            log=lambda m: log_msgs.append(m),
        )

        assert any("authenticated" in m for m in log_msgs)
        assert any("Hostname" in m for m in log_msgs)

    def test_dry_run_does_not_call_ubus(self):
        plan = _make_plan_with_hostname()
        log_msgs = []
        apply_ubus(
            plan, "192.168.1.1",
            dry_run=True,
            log=lambda m: log_msgs.append(m),
        )
        assert any("DRY RUN" in m for m in log_msgs)

    @patch("ubus_utils.urllib.request.urlopen")
    def test_applies_sqm_use_case(self, mock_urlopen):
        import json

        def mock_response(data):
            cm = MagicMock()
            cm.__enter__ = MagicMock(return_value=cm)
            cm.__exit__ = MagicMock(return_value=False)
            cm.read.return_value = json.dumps(data).encode()
            return cm

        mock_urlopen.return_value = mock_response({
            "result": [0, {"ubus_rpc_session": "tok"}],
        })

        plan = _make_plan_with_sqm()
        log_msgs = []
        apply_ubus(
            plan, "192.168.1.1",
            username="root", password="",
            log=lambda m: log_msgs.append(m),
        )

        sqm_msgs = [m for m in log_msgs if "sqm" in m.lower()]
        assert len(sqm_msgs) > 0

    @patch("ubus_utils.urllib.request.urlopen")
    def test_skips_wifi_steps_with_no_ops(self, mock_urlopen):
        import json

        def mock_response(data):
            cm = MagicMock()
            cm.__enter__ = MagicMock(return_value=cm)
            cm.__exit__ = MagicMock(return_value=False)
            cm.read.return_value = json.dumps(data).encode()
            return cm

        mock_urlopen.return_value = mock_response({
            "result": [0, {"ubus_rpc_session": "tok"}],
        })

        cfg = ConwrtConfig(
            hostname="r1",
            wifi_sta=WifiSTAConfig(band="5ghz", ssid="TestNet", encryption="psk2", key="passphrase"),
        )
        plan = build_plan(cfg, mode="post_install")
        wifi_steps = [s for s in plan.steps if s.kind == StepKind.WIFI_STA]
        assert len(wifi_steps) == 1
        assert len(wifi_steps[0].ops) == 0

        log_msgs = []
        apply_ubus(
            plan, "192.168.1.1",
            username="root", password="",
            log=lambda m: log_msgs.append(m),
        )

        host_msgs = [m for m in log_msgs if "Hostname" in m]
        assert len(host_msgs) > 0

    @patch("ubus_utils.urllib.request.urlopen")
    def test_skip_fallback_filters_shell_commands(self, mock_urlopen):
        import json

        def mock_response(data):
            cm = MagicMock()
            cm.__enter__ = MagicMock(return_value=cm)
            cm.__exit__ = MagicMock(return_value=False)
            cm.read.return_value = json.dumps(data).encode()
            return cm

        mock_urlopen.return_value = mock_response({
            "result": [0, {"ubus_rpc_session": "tok"}],
        })

        cfg = ConwrtConfig(hostname="r1")
        plan = build_plan(cfg, mode="post_install", password="secret")
        log_msgs = []
        apply_ubus(
            plan, "192.168.1.1",
            username="root", password="",
            skip_fallback=True,
            log=lambda m: log_msgs.append(m),
        )

        skipped_msgs = [m for m in log_msgs if "shell command(s) skipped" in m]
        assert len(skipped_msgs) > 0
