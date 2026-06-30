"""Tests for conwrt.cmd_probe — active network probing command."""

import argparse
import json
from unittest.mock import patch

import pytest

from conwrt.cmd_probe import (
    FALLBACK_IPS,
    ProbeTarget,
    _classify_http_state,
    _classify_ssh_state,
    _cleanup_aliases,
    _collect_probe_targets,
    _configure_interface,
    _format_results_table,
    _host_ip_for_subnet,
    _match_models_by_ip,
    _probe_target,
    _subnet_for_ip,
    cmd_probe,
)


def _make_args(**overrides):
    defaults = {
        "interface": None,
        "timeout": 3.0,
        "json_output": False,
        "quiet": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


SAMPLE_MODELS = [
    {
        "id": "dlink-covr-x1860-a1",
        "openwrt": {"default_ip": "192.168.1.1"},
        "flash_methods": {
            "recovery-http": {"recovery_ip": "192.168.0.1"},
        },
    },
    {
        "id": "glinet-mt3000",
        "openwrt": {"default_ip": "192.168.1.1"},
        "flash_methods": {
            "uboot-http": {"recovery_ip": "192.168.1.1"},
        },
    },
    {
        "id": "ubnt-edgerouter-6p",
        "openwrt": {"default_ip": "192.168.1.1"},
        "flash_methods": {
            "tftp": {"recovery_ip": "192.168.1.20"},
        },
    },
    {
        "id": "glinet-gl-ar150",
        "openwrt": {"default_ip": "192.168.8.1"},
        "flash_methods": {},
    },
]


class TestCollectProbeTargets:
    def test_includes_model_default_ips(self):
        targets = _collect_probe_targets(SAMPLE_MODELS)
        assert "192.168.1.1" in targets
        assert "192.168.8.1" in targets

    def test_includes_recovery_ips(self):
        targets = _collect_probe_targets(SAMPLE_MODELS)
        assert "192.168.0.1" in targets
        assert "192.168.1.20" in targets

    def test_includes_fallback_ips(self):
        targets = _collect_probe_targets([])
        for ip in FALLBACK_IPS:
            assert ip in targets

    def test_deduplicates(self):
        targets = _collect_probe_targets(SAMPLE_MODELS)
        # Multiple models share 192.168.1.1 — should appear only once
        assert targets.count("192.168.1.1") == 1

    def test_models_with_no_flash_methods(self):
        models = [{"id": "bare", "openwrt": {"default_ip": "10.0.0.1"}, "flash_methods": {}}]
        targets = _collect_probe_targets(models)
        assert "10.0.0.1" in targets

    def test_empty_models_still_has_fallbacks(self):
        targets = _collect_probe_targets([])
        assert len(targets) >= len(FALLBACK_IPS)


class TestSubnetHelpers:
    def test_subnet_for_ip(self):
        assert _subnet_for_ip("192.168.0.1") == "192.168.0"
        assert _subnet_for_ip("10.0.0.5") == "10.0.0"

    def test_host_ip_for_subnet(self):
        assert _host_ip_for_subnet("192.168.0") == "192.168.0.10"
        assert _host_ip_for_subnet("10.0.0") == "10.0.0.10"


class TestConfigureInterface:
    @patch("conwrt.cmd_probe.subprocess.run")
    def test_assigns_new_alias(self, mock_run):
        added = []
        result = _configure_interface("en6", "192.168.0.1", "", added)
        assert result == "192.168.0"
        assert "192.168.0.10" in added
        # One call for assign (alias), no removal since no previous
        assert mock_run.call_count == 1
        call_args = mock_run.call_args[0][0]
        assert call_args == ["ifconfig", "en6", "inet", "192.168.0.10", "netmask", "255.255.255.0", "alias"]

    @patch("conwrt.cmd_probe.subprocess.run")
    def test_same_subnet_no_reconfiguration(self, mock_run):
        added = []
        result = _configure_interface("en6", "192.168.0.5", "192.168.0", added)
        assert result == "192.168.0"
        assert mock_run.call_count == 0

    @patch("conwrt.cmd_probe.subprocess.run")
    def test_different_subnet_reconfigures(self, mock_run):
        added = ["192.168.0.10"]
        result = _configure_interface("en6", "10.0.0.1", "192.168.0", added)
        assert result == "10.0.0"
        assert "10.0.0.10" in added
        assert "192.168.0.10" not in added
        # Two calls: remove old alias + assign new alias
        assert mock_run.call_count == 2
        remove_call = mock_run.call_args_list[0][0][0]
        assert remove_call == ["ifconfig", "en6", "inet", "192.168.0.10", "-alias"]
        assign_call = mock_run.call_args_list[1][0][0]
        assert assign_call == ["ifconfig", "en6", "inet", "10.0.0.10", "netmask", "255.255.255.0", "alias"]


class TestCleanupAliases:
    @patch("conwrt.cmd_probe.subprocess.run")
    def test_removes_all_aliases(self, mock_run):
        added = ["192.168.0.10", "10.0.0.10"]
        _cleanup_aliases("en6", added)
        assert len(added) == 0
        assert mock_run.call_count == 2

    @patch("conwrt.cmd_probe.subprocess.run")
    def test_empty_list_no_calls(self, mock_run):
        added = []
        _cleanup_aliases("en6", added)
        assert mock_run.call_count == 0


class TestClassifyHttpState:
    def test_uboot(self):
        assert _classify_http_state(("http_get", "uboot", "U-Boot page")) == "uboot"

    def test_openwrt_luci(self):
        assert _classify_http_state(("http_get", "openwrt_luci", "LuCI")) == "openwrt"

    def test_stock_glinet(self):
        assert _classify_http_state(("http_get", "glinet_stock", "GL.iNet")) == "stock"

    def test_stock_linksys(self):
        assert _classify_http_state(("http_get", "linksys_stock", "Linksys")) == "stock"

    def test_unknown_http(self):
        assert _classify_http_state(("http_get", "unknown_http", "500 bytes")) == "unknown"

    def test_no_response(self):
        assert _classify_http_state(("http_get", "no_response", "")) == "unknown"


class TestClassifySshState:
    def test_openwrt_ssh(self):
        assert _classify_ssh_state(("ssh", "openwrt_ssh", "release info")) == "openwrt"

    def test_ssh_ok(self):
        assert _classify_ssh_state(("ssh", "ssh_ok", "connected")) == "openwrt"

    def test_no_response(self):
        assert _classify_ssh_state(("ssh", "no_response", "")) == ""

    def test_ssh_timeout(self):
        assert _classify_ssh_state(("ssh", "ssh_timeout", "")) == ""


class TestProbeTarget:
    @patch("conwrt.cmd_probe.probe_ssh", return_value=("ssh", "no_response", ""))
    @patch("conwrt.cmd_probe.probe_http_get", return_value=("http_get", "no_response", ""))
    @patch("conwrt.cmd_probe.probe_ping", return_value=("ping", "unreachable", "no reply"))
    def test_unreachable_skips_further_probes(self, mock_ping, mock_http, mock_ssh):
        result = _probe_target("192.168.0.1")
        assert result.state == "unreachable"
        mock_ping.assert_called_once()
        mock_http.assert_not_called()
        mock_ssh.assert_not_called()

    @patch("conwrt.cmd_probe.probe_ssh", return_value=("ssh", "no_response", ""))
    @patch("conwrt.cmd_probe.probe_http_get", return_value=("http_get", "uboot", "U-Boot page"))
    @patch("conwrt.cmd_probe.probe_ping", return_value=("ping", "reachable", "reply in 1ms"))
    def test_uboot_signature(self, mock_ping, mock_http, mock_ssh):
        result = _probe_target("192.168.0.1")
        assert result.state == "uboot"
        assert len(result.evidence) == 3  # ping, http, ssh

    @patch("conwrt.cmd_probe.probe_ssh", return_value=("ssh", "openwrt_ssh", "OpenWrt release"))
    @patch("conwrt.cmd_probe.probe_http_get", return_value=("http_get", "no_response", ""))
    @patch("conwrt.cmd_probe.probe_ping", return_value=("ping", "reachable", "reply in 1ms"))
    def test_openwrt_ssh(self, mock_ping, mock_http, mock_ssh):
        result = _probe_target("192.168.1.1")
        assert result.state == "openwrt"

    @patch("conwrt.cmd_probe.probe_ssh", return_value=("ssh", "ssh_timeout", ""))
    @patch("conwrt.cmd_probe.probe_http_get", return_value=("http_get", "unknown_http", "500 bytes"))
    @patch("conwrt.cmd_probe.probe_ping", return_value=("ping", "reachable", "reply in 2ms"))
    def test_unknown_http_response(self, mock_ping, mock_http, mock_ssh):
        result = _probe_target("10.0.0.1")
        assert result.state == "unknown"

    @patch("conwrt.cmd_probe.probe_ssh", return_value=("ssh", "openwrt_ssh", "OpenWrt"))
    @patch("conwrt.cmd_probe.probe_http_get", return_value=("http_get", "uboot", "U-Boot"))
    @patch("conwrt.cmd_probe.probe_ping", return_value=("ping", "reachable", "1ms"))
    def test_uboot_takes_priority_over_ssh(self, mock_ping, mock_http, mock_ssh):
        result = _probe_target("192.168.0.1")
        assert result.state == "uboot"


class TestMatchModelsByIp:
    def test_matches_default_ip(self):
        result = _match_models_by_ip("192.168.1.1", SAMPLE_MODELS)
        assert "dlink-covr-x1860-a1" in result
        assert "glinet-mt3000" in result
        assert "ubnt-edgerouter-6p" in result

    def test_matches_recovery_ip(self):
        result = _match_models_by_ip("192.168.0.1", SAMPLE_MODELS)
        assert result == ["dlink-covr-x1860-a1"]

    def test_matches_multiple_models(self):
        result = _match_models_by_ip("192.168.1.20", SAMPLE_MODELS)
        assert result == ["ubnt-edgerouter-6p"]

    def test_no_match(self):
        result = _match_models_by_ip("10.10.10.10", SAMPLE_MODELS)
        assert result == []

    def test_matches_default_of_model_without_flash_methods(self):
        result = _match_models_by_ip("192.168.8.1", SAMPLE_MODELS)
        assert result == ["glinet-gl-ar150"]


class TestFormatResultsTable:
    def test_no_devices(self):
        targets = [ProbeTarget(ip="192.168.0.1", state="unreachable")]
        output = _format_results_table(targets)
        assert "No devices found" in output

    def test_with_responded_device(self):
        targets = [
            ProbeTarget(
                ip="192.168.0.1",
                state="uboot",
                model_candidates=["dlink-covr-x1860-a1"],
                evidence=[("ping", "reachable", "1ms"), ("http_get", "uboot", "U-Boot page")],
            ),
        ]
        output = _format_results_table(targets)
        assert "192.168.0.1" in output
        assert "uboot" in output
        assert "dlink-covr-x1860-a1" in output


class TestCmdProbe:
    @patch("conwrt.cmd_probe._cleanup_aliases")
    @patch("conwrt.cmd_probe._configure_interface", return_value="192.168.0")
    @patch("conwrt.cmd_probe._probe_target")
    @patch("conwrt.cmd_probe._match_models_by_ip", return_value=[])
    @patch("conwrt.cmd_probe._collect_probe_targets", return_value=["192.168.0.1"])
    @patch("conwrt.cmd_probe.list_models", return_value=[])
    @patch("conwrt.cmd_probe.auto_detect_interface", return_value=None)
    def test_no_interface_returns_1(self, mock_iface, mock_models, mock_targets,
                                    mock_match, mock_probe, mock_config, mock_cleanup):
        result = cmd_probe(_make_args())
        assert result == 1

    @patch("conwrt.cmd_probe._cleanup_aliases")
    @patch("conwrt.cmd_probe._configure_interface", return_value="192.168.0")
    @patch("conwrt.cmd_probe._probe_target", return_value=ProbeTarget(ip="192.168.0.1", state="uboot"))
    @patch("conwrt.cmd_probe._match_models_by_ip", return_value=["dlink-covr-x1860-a1"])
    @patch("conwrt.cmd_probe._collect_probe_targets", return_value=["192.168.0.1"])
    @patch("conwrt.cmd_probe.list_models", return_value=SAMPLE_MODELS)
    @patch("conwrt.cmd_probe.auto_detect_interface", return_value="en6")
    def test_device_found_returns_0(self, mock_iface, mock_models, mock_targets,
                                    mock_match, mock_probe, mock_config, mock_cleanup, capsys):
        result = cmd_probe(_make_args())
        assert result == 0
        captured = capsys.readouterr()
        assert "192.168.0.1" in captured.out

    @patch("conwrt.cmd_probe._cleanup_aliases")
    @patch("conwrt.cmd_probe._configure_interface", return_value="192.168.0")
    @patch("conwrt.cmd_probe._probe_target", return_value=ProbeTarget(ip="192.168.0.1", state="uboot"))
    @patch("conwrt.cmd_probe._match_models_by_ip", return_value=["dlink-covr-x1860-a1"])
    @patch("conwrt.cmd_probe._collect_probe_targets", return_value=["192.168.0.1"])
    @patch("conwrt.cmd_probe.list_models", return_value=SAMPLE_MODELS)
    @patch("conwrt.cmd_probe.auto_detect_interface", return_value="en6")
    def test_json_output(self, mock_iface, mock_models, mock_targets,
                         mock_match, mock_probe, mock_config, mock_cleanup, capsys):
        result = cmd_probe(_make_args(json_output=True))
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out.split("\n", 1)[1])  # skip "Probing..." line
        assert data["devices_found"] == 1
        assert data["results"][0]["ip"] == "192.168.0.1"
        assert data["results"][0]["state"] == "uboot"

    @patch("conwrt.cmd_probe._cleanup_aliases")
    @patch("conwrt.cmd_probe._configure_interface", return_value="192.168.0")
    @patch("conwrt.cmd_probe._probe_target", return_value=ProbeTarget(ip="192.168.0.1", state="uboot"))
    @patch("conwrt.cmd_probe._match_models_by_ip", return_value=[])
    @patch("conwrt.cmd_probe._collect_probe_targets", return_value=["192.168.0.1"])
    @patch("conwrt.cmd_probe.list_models", return_value=[])
    @patch("conwrt.cmd_probe.auto_detect_interface", return_value="en6")
    def test_quiet_only_ips(self, mock_iface, mock_models, mock_targets,
                            mock_match, mock_probe, mock_config, mock_cleanup, capsys):
        result = cmd_probe(_make_args(quiet=True))
        assert result == 0
        captured = capsys.readouterr()
        # Output should contain just the IP
        lines = [l for l in captured.out.strip().split("\n") if l.strip()]
        ip_lines = [l for l in lines if l.strip() == "192.168.0.1"]
        assert len(ip_lines) >= 1

    @patch("conwrt.cmd_probe._cleanup_aliases")
    @patch("conwrt.cmd_probe._configure_interface", return_value="192.168.0")
    @patch("conwrt.cmd_probe._probe_target", return_value=ProbeTarget(ip="192.168.0.1", state="unreachable"))
    @patch("conwrt.cmd_probe._match_models_by_ip", return_value=[])
    @patch("conwrt.cmd_probe._collect_probe_targets", return_value=["192.168.0.1"])
    @patch("conwrt.cmd_probe.list_models", return_value=[])
    @patch("conwrt.cmd_probe.auto_detect_interface", return_value="en6")
    def test_nothing_found_returns_1(self, mock_iface, mock_models, mock_targets,
                                     mock_match, mock_probe, mock_config, mock_cleanup, capsys):
        result = cmd_probe(_make_args())
        assert result == 1

    @patch("conwrt.cmd_probe._cleanup_aliases")
    @patch("conwrt.cmd_probe._configure_interface", return_value="192.168.0")
    @patch("conwrt.cmd_probe._probe_target")
    @patch("conwrt.cmd_probe._match_models_by_ip", return_value=[])
    @patch("conwrt.cmd_probe._collect_probe_targets", return_value=["192.168.0.1"])
    @patch("conwrt.cmd_probe.list_models", return_value=[])
    @patch("conwrt.cmd_probe.auto_detect_interface", return_value="en6")
    def test_cleanup_called_even_on_error(self, mock_iface, mock_models, mock_targets,
                                          mock_match, mock_probe_tgt, mock_config, mock_cleanup):
        mock_probe_tgt.side_effect = RuntimeError("probe failed")
        with pytest.raises(RuntimeError):
            cmd_probe(_make_args())
        mock_cleanup.assert_called_once()

    @patch("conwrt.cmd_probe._cleanup_aliases")
    @patch("conwrt.cmd_probe._configure_interface", return_value="192.168.0")
    @patch("conwrt.cmd_probe._probe_target")
    @patch("conwrt.cmd_probe._match_models_by_ip", return_value=[])
    @patch("conwrt.cmd_probe._collect_probe_targets", return_value=["192.168.0.1"])
    @patch("conwrt.cmd_probe.list_models", return_value=[])
    @patch("conwrt.cmd_probe.auto_detect_interface", return_value="en6")
    def test_explicit_interface_overrides_auto(self, mock_iface, mock_models, mock_targets,
                                               mock_match, mock_probe_tgt, mock_config, mock_cleanup):
        mock_probe_tgt.return_value = ProbeTarget(ip="192.168.0.1", state="unreachable")
        result = cmd_probe(_make_args(interface="en7"))
        assert result == 1
        # auto_detect_interface should NOT be called when interface is provided
        mock_iface.assert_not_called()
