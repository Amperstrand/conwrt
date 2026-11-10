from __future__ import annotations

from unittest.mock import MagicMock, patch

from config import ConwrtConfig, UseCaseConfig, WifiSTAConfig
from profile.apply import apply_plan


def _mock_run(returncode: int, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def test_apply_plan_phase_order_wifi_before_opkg_before_usecase() -> None:
    cfg = ConwrtConfig(
        wifi_sta=WifiSTAConfig(band="5ghz", ssid="Upstream", encryption="psk2", key="pass"),
        use_cases=[
            UseCaseConfig(name="sqm", params={"download_kbps": 1000, "upload_kbps": 500}),
        ],
    )
    from profile import build_plan
    plan = build_plan(cfg, mode="post_install")

    calls: list[str] = []

    def track_run(*args, **kwargs):
        cmd = args[0] if args else kwargs.get("args", [])
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = str(cmd)
        # multi-line step scripts travel via stdin ("sh -s") — classify by payload
        stdin_payload = kwargs.get("input", "") or ""

        if "hostname" in cmd_str:
            calls.append("hostname")
        elif "wwan" in cmd_str.lower() or "wwan" in stdin_payload:
            calls.append("wwan_setup")
        elif "wireless" in cmd_str or "wifi" in cmd_str:
            calls.append("wifi")
        elif "opkg" in cmd_str:
            calls.append("opkg")
        elif "sqm" in cmd_str.lower() or "cake" in cmd_str.lower() or "sqm" in stdin_payload:
            calls.append("use_case_sqm")
        elif "ping" in cmd_str:
            calls.append("internet_check")
        else:
            calls.append(f"other:{cmd_str[:40]}")

        return _mock_run(0, stdout="radio1" if "wireless" in cmd_str else "")

    log = MagicMock()

    with patch("profile.apply.subprocess.run", side_effect=track_run), \
         patch("profile.apply._wait_for_internet", return_value=True), \
         patch("profile.apply.time.sleep"):
        apply_plan(plan, ip="1.2.3.4", ssh_key="", log=log)

    wwan_idx = next((i for i, c in enumerate(calls) if c == "wwan_setup"), None)
    wifi_idx = next((i for i, c in enumerate(calls) if c == "wifi"), None)
    opkg_idx = next((i for i, c in enumerate(calls) if c == "opkg"), None)
    sqm_idx = next((i for i, c in enumerate(calls) if c == "use_case_sqm"), None)

    assert wwan_idx is not None, f"wwan_setup not found in calls: {calls}"
    assert wifi_idx is not None, f"wifi not found in calls: {calls}"
    assert opkg_idx is not None, f"opkg not found in calls: {calls}"
    assert sqm_idx is not None, f"use_case_sqm not found in calls: {calls}"

    assert wwan_idx < wifi_idx, f"WWAN ({wwan_idx}) must run before WiFi ({wifi_idx}). Calls: {calls}"
    assert wifi_idx < opkg_idx, f"WiFi ({wifi_idx}) must run before opkg ({opkg_idx}). Calls: {calls}"
    assert opkg_idx < sqm_idx, f"opkg ({opkg_idx}) must run before SQM use case ({sqm_idx}). Calls: {calls}"


def test_apply_plan_triggers_scp_fallback_when_no_internet() -> None:
    cfg = ConwrtConfig(
        use_cases=[
            UseCaseConfig(name="sqm", params={"download_kbps": 1000, "upload_kbps": 500}),
        ],
    )
    from profile import build_plan
    plan = build_plan(cfg, mode="post_install")

    log = MagicMock()
    with patch("profile.apply.subprocess.run", return_value=_mock_run(0)), \
         patch("profile.apply._wait_for_internet", return_value=False), \
         patch("profile.apply._scp_install_packages", return_value=True) as mock_scp, \
         patch("profile.apply.time.sleep"):
        apply_plan(plan, ip="1.2.3.4", ssh_key="", log=log)

    mock_scp.assert_called_once()


def test_apply_plan_triggers_scp_fallback_on_opkg_failure() -> None:
    cfg = ConwrtConfig(
        use_cases=[
            UseCaseConfig(name="sqm", params={"download_kbps": 1000, "upload_kbps": 500}),
        ],
    )
    from profile import build_plan
    plan = build_plan(cfg, mode="post_install")

    run_count = 0

    def track_run(*args, **kwargs):
        nonlocal run_count
        run_count += 1
        cmd = args[0] if args else kwargs.get("args", [])
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        if "opkg" in cmd_str:
            return _mock_run(1, stderr="opkg failed")
        return _mock_run(0)

    log = MagicMock()
    with patch("profile.apply.subprocess.run", side_effect=track_run), \
         patch("profile.apply._wait_for_internet", return_value=True), \
         patch("profile.apply._scp_install_packages", return_value=False) as mock_scp:
        apply_plan(plan, ip="1.2.3.4", ssh_key="", log=log)

    mock_scp.assert_called_once()


def test_apply_plan_dry_run_returns_ip() -> None:
    cfg = ConwrtConfig()
    from profile import build_plan
    plan = build_plan(cfg, mode="post_install")

    result = apply_plan(plan, ip="192.168.1.1", dry_run=True)
    assert result == "192.168.1.1"


def test_apply_plan_no_packages_skips_phase2() -> None:
    cfg = ConwrtConfig()
    from profile import build_plan
    plan = build_plan(cfg, mode="post_install")

    has_packages = bool(plan.all_packages())
    assert not has_packages

    log = MagicMock()
    with patch("profile.apply.subprocess.run", return_value=_mock_run(0)), \
         patch("profile.apply._wait_for_internet") as mock_wait:
        apply_plan(plan, ip="1.2.3.4", ssh_key="", log=log)

    mock_wait.assert_not_called()


def test_wifi_sta_failure_aborts_apply() -> None:
    cfg = ConwrtConfig(
        wifi_sta=WifiSTAConfig(band="5ghz", ssid="Upstream", encryption="psk2", key="pass"),
        use_cases=[
            UseCaseConfig(name="sqm", params={"download_kbps": 1000, "upload_kbps": 500}),
        ],
    )
    from profile import build_plan
    plan = build_plan(cfg, mode="post_install")

    def track_run(*args, **kwargs):
        cmd = args[0] if args else kwargs.get("args", [])
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        if "wireless" in cmd_str or "wifi" in cmd_str:
            return _mock_run(1)
        return _mock_run(0)

    log = MagicMock()
    with patch("profile.apply.subprocess.run", side_effect=track_run), \
         patch("profile.apply._wait_for_internet") as mock_wait, \
         patch("profile.apply.time.sleep"):
        result = apply_plan(plan, ip="1.2.3.4", ssh_key="", log=log)

    assert result == "1.2.3.4"
    abort_msgs = [str(c) for c in log.call_args_list if "no WAN uplink" in str(c)]
    assert abort_msgs, "Expected abort log message about WAN uplink"
    mock_wait.assert_not_called()


def test_package_failure_logs_affected_use_cases() -> None:
    cfg = ConwrtConfig(
        use_cases=[
            UseCaseConfig(name="sqm", params={"download_kbps": 1000, "upload_kbps": 500}),
        ],
    )
    from profile import build_plan
    plan = build_plan(cfg, mode="post_install")

    run_count = 0

    def track_run(*args, **kwargs):
        nonlocal run_count
        run_count += 1
        cmd = args[0] if args else kwargs.get("args", [])
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        if "opkg" in cmd_str:
            return _mock_run(1)
        return _mock_run(0)

    log = MagicMock()
    with patch("profile.apply.subprocess.run", side_effect=track_run), \
         patch("profile.apply._wait_for_internet", return_value=True), \
         patch("profile.apply._scp_install_packages", return_value=False) as mock_scp, \
         patch("profile.apply.time.sleep"):
        apply_plan(plan, ip="1.2.3.4", ssh_key="", log=log)

    mock_scp.assert_called_once()
    affected_msgs = [str(c) for c in log.call_args_list if "may be broken" in str(c)]
    assert affected_msgs, "Expected warning about affected use cases"


class TestRunStepScript:
    """_run_step_script must send heredoc/multi-line scripts via stdin (sh -s)
    and only chain simple one-command-per-line scripts with && (joining a
    heredoc with && is an ash syntax error on the router)."""

    def _completed(self, returncode=0):
        m = MagicMock()
        m.returncode = returncode
        m.stderr = ""
        return m

    def test_plain_script_is_chained_with_and(self):
        from profile.apply import _run_step_script

        log = MagicMock()
        script = "# comment\nuci set x=1\nuci commit\n"
        with patch("profile.apply.subprocess.run", return_value=self._completed()) as mock_run:
            assert _run_step_script("1.2.3.4", script, "", log) is True
        cmd = " ".join(mock_run.call_args[0][0])
        assert "sh -s" not in cmd
        assert "uci set x=1 && uci commit" in cmd
        assert "input" not in mock_run.call_args.kwargs

    def test_heredoc_script_runs_via_stdin_sh_s(self):
        from profile.apply import _run_step_script

        log = MagicMock()
        script = (
            "cat > /etc/vpn-listing.sh << 'SCRIPT'\n"
            "#!/bin/sh\necho hi\n"
            "SCRIPT\n"
            "chmod +x /etc/vpn-listing.sh\n"
        )
        with patch("profile.apply.subprocess.run", return_value=self._completed()) as mock_run:
            assert _run_step_script("1.2.3.4", script, "", log) is True
        cmd = " ".join(mock_run.call_args[0][0])
        assert "sh -s" in cmd
        assert "&&" not in cmd
        payload = mock_run.call_args.kwargs.get("input", "")
        assert payload.startswith("set -e\n")
        assert "<< 'SCRIPT'" in payload

    def test_control_structure_script_runs_via_stdin(self):
        from profile.apply import _run_step_script

        log = MagicMock()
        script = "for i in 1 2 3; do\necho $i\ndone\n"
        with patch("profile.apply.subprocess.run", return_value=self._completed()) as mock_run:
            assert _run_step_script("1.2.3.4", script, "", log) is True
        assert "sh -s" in " ".join(mock_run.call_args[0][0])

    def test_line_contained_control_flow_is_and_joined_without_set_e(self):
        """sqm-style scripts: single-line `for` loops and assignments with
        `;`-separated fallbacks must keep chain-member semantics. Running them
        under `set -e` aborted the script when `uci get network.wan.device`
        failed, even though the trailing `; if...fi` was designed to absorb it."""
        from profile.apply import _run_step_script

        log = MagicMock()
        script = (
            "for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; true\n"
            '_sqm_dev=$(uci get network.wan.device 2>/dev/null); '
            'if [ -z "$_sqm_dev" ]; then _sqm_dev=$(ip route show default 0.0.0.0/0 2>/dev/null | awk \'{print $5}\' | head -1); fi; '
            'if [ -z "$_sqm_dev" ]; then _sqm_dev=wan; fi\n'
            "uci set sqm.wan=queue\n"
            'uci set sqm.wan.interface="$_sqm_dev"\n'
        )
        with patch("profile.apply.subprocess.run", return_value=self._completed()) as mock_run:
            assert _run_step_script("1.2.3.4", script, "", log) is True
        payload = mock_run.call_args.kwargs.get("input", "")
        assert "sh -s" in " ".join(mock_run.call_args[0][0])
        assert "set -e" not in payload
        assert "done; true && _sqm_dev=$(uci get network.wan.device" in payload
        assert "_sqm_dev=wan; fi && uci set sqm.wan=queue" in payload

    def test_heredoc_failure_returns_false_and_logs_stderr(self):
        from profile.apply import _run_step_script

        log = MagicMock()
        script = "cat > /x << 'EOF'\nbody\nEOF\n"
        with patch("profile.apply.subprocess.run", return_value=self._completed(1)):
            assert _run_step_script("1.2.3.4", script, "", log) is False
