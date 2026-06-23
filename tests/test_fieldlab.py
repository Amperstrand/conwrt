"""Unit tests for field-lab CLI and logic.

All tests are hardware-safe: SSH, tcpdump, and network operations are mocked.
No real SSH, SCP, or network connections are made.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _make_args(**overrides) -> SimpleNamespace:
    defaults = dict(
        host="root@192.168.1.1",
        probe_if=None,
        session=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# Host parsing
# ---------------------------------------------------------------------------

class TestHostParse:
    def test_user_at_ip(self):
        from fieldlab.transport import Host
        h = Host.parse("root@192.168.1.1")
        assert h.ip == "192.168.1.1"
        assert h.user == "root"

    def test_ip_only_defaults_root(self):
        from fieldlab.transport import Host
        h = Host.parse("10.0.0.1")
        assert h.ip == "10.0.0.1"
        assert h.user == "root"

    def test_custom_user(self):
        from fieldlab.transport import Host
        h = Host.parse("admin@192.168.8.1")
        assert h.user == "admin"
        assert h.ip == "192.168.8.1"

    def test_str_roundtrip(self):
        from fieldlab.transport import Host
        h = Host.parse("root@192.168.1.1")
        assert str(h) == "root@192.168.1.1"


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

class TestFieldlabParser:
    def _parse(self, *args):
        from fieldlab.cli import build_parser
        return build_parser().parse_args(args)

    def test_inspect_command(self):
        args = self._parse("inspect", "--host", "root@192.168.1.1")
        assert args.fieldlab_command == "inspect"
        assert args.host == "root@192.168.1.1"

    def test_capture_with_duration(self):
        args = self._parse("capture", "--host", "root@192.168.1.1",
                           "--probe-if", "internet", "--duration", "30")
        assert args.fieldlab_command == "capture"
        assert args.probe_if == "internet"
        assert args.duration == 30

    def test_capture_stdout_out(self):
        args = self._parse("capture", "--host", "r@10.0.0.1", "--out", "-")
        assert args.out == "-"

    def test_capture_filter(self):
        args = self._parse("capture", "--host", "r@10.0.0.1", "--filter", "not port 22")
        assert args.filter == "not port 22"

    def test_discover_command(self):
        args = self._parse("discover", "--host", "root@192.168.1.1")
        assert args.fieldlab_command == "discover"

    def test_discover_custom_ports(self):
        args = self._parse("discover", "--host", "r@1.2.3.4", "--ports", "80,443,8080")
        assert args.ports == "80,443,8080"

    def test_forward_command(self):
        args = self._parse("forward", "--host", "root@192.168.1.1",
                           "--target", "192.168.1.1:80")
        assert args.fieldlab_command == "forward"
        assert args.target == "192.168.1.1:80"

    def test_forward_exec_flag(self):
        args = self._parse("forward", "--host", "r@1.2.3.4",
                           "--target", "1.2.3.4:80", "--exec")
        assert args.exec is True

    def test_prepare_probe_command(self):
        args = self._parse("prepare-probe", "--host", "root@192.168.1.1")
        assert args.fieldlab_command == "prepare-probe"
        assert args.apply is False

    def test_prepare_probe_apply(self):
        args = self._parse("prepare-probe", "--host", "r@1.2.3.4", "--apply")
        assert args.apply is True

    def test_no_command_returns_none(self):
        from fieldlab.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([])
        assert args.fieldlab_command is None


# ---------------------------------------------------------------------------
# Run directory management
# ---------------------------------------------------------------------------

class TestFieldLabRun:
    def test_create_makes_directories(self, tmp_path):
        from fieldlab.rundir import FieldLabRun
        run = FieldLabRun.create(label="test-session", base_dir=tmp_path)
        assert run.run_dir.exists()
        assert run.inspect_dir.exists()
        assert run.captures_dir.exists()
        assert run.discover_dir.exists()
        assert run.manifest_path.exists()

    def test_manifest_has_session_id(self, tmp_path):
        from fieldlab.rundir import FieldLabRun
        run = FieldLabRun.create(label="test", base_dir=tmp_path)
        manifest = run.read_manifest()
        assert manifest["session_id"] == run.session_id
        assert manifest["session_id"].startswith("20")
        assert "test" in manifest["session_id"]
        assert manifest["status"] == "in_progress"

    def test_record_command_appends(self, tmp_path):
        from fieldlab.rundir import FieldLabRun
        run = FieldLabRun.create(base_dir=tmp_path)
        run.record_command("inspect", probe_interface="internet")
        run.record_command("capture", duration=30)
        manifest = run.read_manifest()
        assert len(manifest["commands_run"]) == 2
        assert manifest["commands_run"][0]["command"] == "inspect"
        assert manifest["commands_run"][1]["duration"] == 30

    def test_new_session_id_format(self):
        from fieldlab.rundir import new_session_id
        sid = new_session_id("fieldlab")
        assert sid.startswith("20")
        assert sid.endswith("fieldlab")
        assert len(sid) > 15


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

class TestTransport:
    @patch("fieldlab.transport.subprocess.run")
    def test_run_remote_builds_ssh_command(self, mock_run):
        mock_run.return_value = _completed(stdout="ok")
        from fieldlab.transport import Host, run_remote
        result = run_remote(Host.parse("root@192.168.1.1"), "uname -a")
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "ssh"
        assert "root@192.168.1.1" in cmd
        assert "uname -a" in cmd
        assert result.stdout == "ok"

    @patch("fieldlab.transport.subprocess.run")
    def test_check_ssh_success(self, mock_run):
        mock_run.return_value = _completed(stdout="SSH_OK")
        from fieldlab.transport import check_ssh
        assert check_ssh("root@192.168.1.1") is True

    @patch("fieldlab.transport.subprocess.run")
    def test_check_ssh_failure(self, mock_run):
        mock_run.return_value = _completed(stdout="", returncode=255)
        from fieldlab.transport import check_ssh
        assert check_ssh("root@192.168.1.1") is False

    @patch("fieldlab.transport.subprocess.run")
    def test_check_tool_found(self, mock_run):
        mock_run.return_value = _completed(stdout="/usr/bin/tcpdump")
        from fieldlab.transport import check_tool
        assert check_tool("root@192.168.1.1", "tcpdump") is True

    @patch("fieldlab.transport.subprocess.run")
    def test_check_tool_missing(self, mock_run):
        mock_run.return_value = _completed(stdout="")
        from fieldlab.transport import check_tool
        assert check_tool("root@192.168.1.1", "tcpdump") is False


# ---------------------------------------------------------------------------
# Capture command
# ---------------------------------------------------------------------------

class TestCaptureCommand:
    @patch("fieldlab.capture_cmd.check_tool")
    @patch("fieldlab.capture_cmd.check_ssh")
    def test_capture_missing_tcpdump_prints_install_hint(self, mock_ssh, mock_tool, capsys):
        mock_ssh.return_value = True
        mock_tool.return_value = False
        from fieldlab.capture_cmd import cmd_capture
        from fieldlab.transport import Host
        args = _make_args(probe_if="internet", duration=5, out="-", filter=None)
        result = cmd_capture(args, Host.parse("root@192.168.1.1"))
        assert result == 1
        err = capsys.readouterr().err
        assert "tcpdump" in err.lower()
        assert "opkg" in err

    @patch("fieldlab.capture_cmd.check_ssh")
    def test_capture_no_ssh_returns_1(self, mock_ssh):
        mock_ssh.return_value = False
        from fieldlab.capture_cmd import cmd_capture
        from fieldlab.transport import Host
        args = _make_args(probe_if="internet", duration=5, out="-", filter=None)
        assert cmd_capture(args, Host.parse("root@192.168.1.1")) == 1

    @patch("fieldlab.capture_cmd.check_tool")
    @patch("fieldlab.capture_cmd.check_ssh")
    @patch("fieldlab.capture_cmd._detect_probe_interface")
    def test_capture_no_interface_returns_1(self, mock_detect, mock_ssh, mock_tool):
        mock_detect.return_value = None
        mock_ssh.return_value = True
        mock_tool.return_value = True
        from fieldlab.capture_cmd import cmd_capture
        from fieldlab.transport import Host
        args = _make_args(probe_if=None, duration=5, out="-", filter=None)
        assert cmd_capture(args, Host.parse("root@192.168.1.1")) == 1


# ---------------------------------------------------------------------------
# Forward command
# ---------------------------------------------------------------------------

class TestForwardCommand:
    def test_parse_target_valid(self):
        from fieldlab.forward_cmd import _parse_target
        ip, port = _parse_target("192.168.1.1:80")
        assert ip == "192.168.1.1"
        assert port == 80

    def test_parse_target_no_port_raises(self):
        from fieldlab.forward_cmd import _parse_target
        with pytest.raises(ValueError):
            _parse_target("192.168.1.1")

    def test_parse_target_bad_port_raises(self):
        from fieldlab.forward_cmd import _parse_target
        with pytest.raises(ValueError):
            _parse_target("192.168.1.1:99999")

    def test_local_auto_select(self):
        from fieldlab.forward_cmd import _parse_local
        assert _parse_local(None, 80) == "127.0.0.1:18080"
        assert _parse_local(None, 22) == "127.0.0.1:18022"

    def test_local_explicit(self):
        from fieldlab.forward_cmd import _parse_local
        assert _parse_local("127.0.0.1:9090", 80) == "127.0.0.1:9090"

    def test_build_forward_command_has_dashL(self):
        from fieldlab.forward_cmd import build_forward_command
        from fieldlab.transport import Host
        cmd = build_forward_command(Host.parse("root@192.168.1.1"),
                                    "192.168.1.1", 80, "127.0.0.1:18080")
        assert "-L" in cmd
        assert "127.0.0.1:18080:192.168.1.1:80" in cmd
        assert "-N" in cmd
        assert "root@192.168.1.1" in cmd

    @patch("fieldlab.forward_cmd.check_ssh")
    def test_forward_print_only_returns_0(self, mock_ssh, capsys):
        mock_ssh.return_value = True
        from fieldlab.forward_cmd import cmd_forward
        from fieldlab.transport import Host
        args = _make_args(target="192.168.1.1:80", local=None, exec=False)
        assert cmd_forward(args, Host.parse("root@192.168.1.1")) == 0
        out = capsys.readouterr().out
        assert "ssh" in out
        assert "18080" in out


# ---------------------------------------------------------------------------
# Discover command
# ---------------------------------------------------------------------------

class TestDiscoverCommand:
    @patch("fieldlab.discover_cmd.run_remote")
    def test_read_neighbors_parses_arp(self, mock_run):
        mock_run.return_value = _completed(
            stdout="192.168.1.1 dev internet lladdr e4:95:6e:42:af:e8 REACHABLE\n"
                   "192.168.1.2 dev internet lladdr aa:bb:cc:dd:ee:ff STALE\n"
        )
        from fieldlab.discover_cmd import _read_neighbors
        from fieldlab.transport import Host
        neighbors = _read_neighbors(Host.parse("root@1.2.3.4"), "internet")
        assert len(neighbors) == 2
        assert neighbors[0]["ip"] == "192.168.1.1"
        assert neighbors[0]["mac"] == "e4:95:6e:42:af:e8"
        assert neighbors[0]["state"] == "reachable"

    @patch("fieldlab.discover_cmd.run_remote")
    def test_ping_target_reachable(self, mock_run):
        mock_run.return_value = _completed(
            stdout="PING 192.168.1.1: 56 data bytes\n"
                   "2 packets transmitted, 2 packets received, 0% packet loss\n"
                   "rtt min/avg/max = 0.432/0.488/0.545 ms\n",
            returncode=0,
        )
        from fieldlab.discover_cmd import _ping_target
        from fieldlab.transport import Host
        result = _ping_target(Host.parse("root@1.2.3.4"), "192.168.1.1", "internet")
        assert result["reachable"] is True
        assert "rtt" in result["rtt"]

    @patch("fieldlab.discover_cmd.run_remote")
    def test_ping_target_unreachable(self, mock_run):
        mock_run.return_value = _completed(
            stdout="2 packets transmitted, 0 packets received, 100% packet loss\n",
            returncode=1,
        )
        from fieldlab.discover_cmd import _ping_target
        from fieldlab.transport import Host
        result = _ping_target(Host.parse("root@1.2.3.4"), "192.168.1.1", "internet")
        assert result["reachable"] is False


# ---------------------------------------------------------------------------
# Inspect command
# ---------------------------------------------------------------------------

class TestInspectCommand:
    def test_parse_sections(self):
        from fieldlab.inspect_cmd import _parse_sections
        raw = "===BOARD===\nD-Link COVR\n===WAN_DEVICE===\ninternet\n"
        sections = _parse_sections(raw)
        assert "BOARD" in sections
        assert sections["BOARD"] == "D-Link COVR"
        assert sections["WAN_DEVICE"] == "internet"

    def test_parse_tools(self):
        from fieldlab.inspect_cmd import _parse_tools
        sections = {"TOOLS": "tcpdump=/usr/bin/tcpdump\ncurl=missing\nnc=/usr/bin/nc\n"}
        tools = _parse_tools(sections)
        assert tools["tcpdump"] == "/usr/bin/tcpdump"
        assert tools["curl"] == "missing"
        assert tools["nc"] == "/usr/bin/nc"
