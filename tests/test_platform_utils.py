import sys
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from platform_utils import (
    check_external_deps,
    configure_interface_ip,
    detect_platform,
    get_link_state,
    has_scapy,
    has_tcpdump,
    is_root,
    remove_interface_ip,
)


class TestDetectPlatform:
    @patch("platform_utils.os.path.isfile", return_value=True)
    def test_openwrt_when_release_file_exists(self, mock_isfile):
        assert detect_platform() == "openwrt"
        mock_isfile.assert_called_with("/etc/openwrt_release")

    @patch("platform_utils.os.path.isfile", return_value=False)
    @patch("platform_utils.platform.system", return_value="Darwin")
    def test_darwin_on_macos(self, mock_sys, mock_isfile):
        assert detect_platform() == "darwin"

    @patch("platform_utils.os.path.isfile", return_value=False)
    @patch("platform_utils.platform.system", return_value="Linux")
    def test_linux_on_linux(self, mock_sys, mock_isfile):
        assert detect_platform() == "linux"


class TestIsRoot:
    @patch("platform_utils.os.getuid", return_value=0)
    def test_root_when_uid_zero(self, mock_uid):
        assert is_root() is True

    @patch("platform_utils.os.getuid", return_value=1000)
    def test_not_root_when_uid_nonzero(self, mock_uid):
        assert is_root() is False

    @patch("platform_utils.os.getuid", side_effect=AttributeError)
    def test_not_root_when_no_getuid(self, mock_uid):
        assert is_root() is False


def _completed(returncode=0, stdout="", stderr=""):
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestConfigureInterfaceIPDarwin:
    @patch("platform_utils.is_root", return_value=True)
    @patch("platform_utils.detect_platform", return_value="darwin")
    @patch("platform_utils.subprocess.run")
    def test_returns_true_when_ip_already_present(self, mock_run, mock_plat, mock_root):
        mock_run.return_value = _completed(stdout="inet 10.0.0.1/24")
        assert configure_interface_ip("en0", "10.0.0.1") is True

    @patch("platform_utils.is_root", return_value=True)
    @patch("platform_utils.detect_platform", return_value="darwin")
    @patch("platform_utils.subprocess.run")
    def test_returns_false_when_interface_missing(self, mock_run, mock_plat, mock_root):
        mock_run.return_value = _completed(returncode=1)
        assert configure_interface_ip("en99", "10.0.0.1") is False

    @patch("platform_utils.is_root", return_value=True)
    @patch("platform_utils.detect_platform", return_value="darwin")
    @patch("platform_utils.subprocess.run")
    def test_returns_true_on_successful_add(self, mock_run, mock_plat, mock_root):
        mock_run.side_effect = [
            _completed(stdout="en0: flags=..."),
            _completed(returncode=0),
        ]
        assert configure_interface_ip("en0", "10.0.0.1") is True

    @patch("platform_utils.is_root", return_value=False)
    @patch("platform_utils.detect_platform", return_value="darwin")
    @patch("platform_utils.subprocess.run")
    def test_returns_false_on_permission_denied(self, mock_run, mock_plat, mock_root):
        mock_run.side_effect = [
            _completed(stdout="en0: flags=..."),
            _completed(returncode=1, stderr="ifconfig: permission denied"),
        ]
        assert configure_interface_ip("en0", "10.0.0.1") is False

    @patch("platform_utils.is_root", return_value=False)
    @patch("platform_utils.detect_platform", return_value="darwin")
    @patch("platform_utils.subprocess.run")
    def test_prepends_sudo_when_not_root(self, mock_run, mock_plat, mock_root):
        mock_run.side_effect = [
            _completed(stdout="en0: flags=..."),
            _completed(returncode=0),
        ]
        configure_interface_ip("en0", "10.0.0.1")
        add_cmd = mock_run.call_args_list[1][0][0]
        assert add_cmd[:2] == ["sudo", "-n"]


class TestConfigureInterfaceIPLinux:
    @patch("platform_utils.is_root", return_value=True)
    @patch("platform_utils.detect_platform", return_value="linux")
    @patch("platform_utils.subprocess.run")
    def test_returns_true_when_ip_already_present(self, mock_run, mock_plat, mock_root):
        mock_run.return_value = _completed(stdout="inet 10.0.0.1/24 scope global eth0")
        assert configure_interface_ip("eth0", "10.0.0.1") is True

    @patch("platform_utils.is_root", return_value=True)
    @patch("platform_utils.detect_platform", return_value="linux")
    @patch("platform_utils.subprocess.run")
    def test_returns_true_on_successful_add(self, mock_run, mock_plat, mock_root):
        mock_run.side_effect = [
            _completed(stdout="eth0: <BROADCAST>"),
            _completed(returncode=0),
            _completed(returncode=0),
        ]
        assert configure_interface_ip("eth0", "10.0.0.1") is True

    @patch("platform_utils.is_root", return_value=False)
    @patch("platform_utils.detect_platform", return_value="linux")
    @patch("platform_utils.subprocess.run")
    def test_retries_without_sudo_on_failure(self, mock_run, mock_plat, mock_root):
        mock_run.side_effect = [
            _completed(stdout="eth0: <BROADCAST>"),
            _completed(returncode=1, stderr="RTNETLINK answers: Operation not permitted"),
            _completed(returncode=0),
            _completed(returncode=0),
        ]
        assert configure_interface_ip("eth0", "10.0.0.1") is True


class TestRemoveInterfaceIPDarwin:
    @patch("platform_utils.is_root", return_value=True)
    @patch("platform_utils.detect_platform", return_value="darwin")
    @patch("platform_utils.subprocess.run")
    def test_returns_true_on_success(self, mock_run, mock_plat, mock_root):
        mock_run.return_value = _completed(returncode=0)
        assert remove_interface_ip("en0", "10.0.0.1") is True

    @patch("platform_utils.is_root", return_value=True)
    @patch("platform_utils.detect_platform", return_value="darwin")
    @patch("platform_utils.subprocess.run")
    def test_returns_false_on_failure(self, mock_run, mock_plat, mock_root):
        mock_run.return_value = _completed(returncode=1, stderr="not found")
        assert remove_interface_ip("en0", "10.0.0.1") is False


class TestRemoveInterfaceIPLinux:
    @patch("platform_utils.is_root", return_value=True)
    @patch("platform_utils.detect_platform", return_value="linux")
    @patch("platform_utils.subprocess.run")
    def test_returns_true_on_success(self, mock_run, mock_plat, mock_root):
        mock_run.return_value = _completed(returncode=0)
        assert remove_interface_ip("eth0", "10.0.0.1") is True

    @patch("platform_utils.is_root", return_value=True)
    @patch("platform_utils.detect_platform", return_value="linux")
    @patch("platform_utils.subprocess.run")
    def test_returns_true_when_device_not_found(self, mock_run, mock_plat, mock_root):
        mock_run.return_value = _completed(returncode=1, stderr="Cannot find device")
        assert remove_interface_ip("eth0", "10.0.0.1") is True

    @patch("platform_utils.is_root", return_value=False)
    @patch("platform_utils.detect_platform", return_value="linux")
    @patch("platform_utils.subprocess.run")
    def test_retries_without_sudo(self, mock_run, mock_plat, mock_root):
        mock_run.side_effect = [
            _completed(returncode=1, stderr="operation failed"),
            _completed(returncode=0),
        ]
        assert remove_interface_ip("eth0", "10.0.0.1") is True


class TestGetLinkState:
    @patch("platform_utils.subprocess.run")
    def test_returns_true_when_operstate_up(self, mock_run):
        mock_run.return_value = _completed(stdout="up\n")
        assert get_link_state("eth0") is True

    @patch("platform_utils.subprocess.run")
    def test_returns_false_when_operstate_down(self, mock_run):
        mock_run.return_value = _completed(stdout="down\n")
        assert get_link_state("eth0") is False

    @patch("platform_utils.subprocess.run")
    def test_falls_back_to_ifconfig_status_active(self, mock_run):
        mock_run.side_effect = [
            _completed(returncode=1),
            _completed(stdout="en0: ... status: active\n"),
        ]
        assert get_link_state("en0") is True

    @patch("platform_utils.subprocess.run", side_effect=OSError("timeout"))
    def test_returns_false_on_exception(self, mock_run):
        assert get_link_state("eth0") is False


class TestHasScapy:
    @patch.dict("sys.modules", {"scapy": MagicMock()})
    def test_returns_true_when_importable(self):
        assert has_scapy() is True

    @patch.dict("sys.modules", {"scapy": None})
    def test_returns_false_when_not_importable(self):
        assert has_scapy() is False


class TestHasTcpdump:
    @patch("platform_utils.subprocess.run")
    def test_returns_true_when_found(self, mock_run):
        mock_run.return_value = _completed(returncode=0)
        assert has_tcpdump() is True

    @patch("platform_utils.subprocess.run")
    def test_returns_false_when_not_found(self, mock_run):
        mock_run.return_value = _completed(returncode=1)
        assert has_tcpdump() is False

    @patch("platform_utils.subprocess.run", side_effect=OSError("fail"))
    def test_returns_false_on_exception(self, mock_run):
        assert has_tcpdump() is False


class TestCheckExternalDeps:
    @patch("platform_utils.subprocess.run")
    def test_returns_empty_when_all_present(self, mock_run):
        mock_run.return_value = _completed(returncode=0)
        assert check_external_deps() == []

    @patch("platform_utils.subprocess.run")
    def test_returns_curl_when_missing(self, mock_run):
        def side_effect(cmd, **kwargs):
            if "curl" in cmd:
                return _completed(returncode=1)
            return _completed(returncode=0)
        mock_run.side_effect = side_effect
        assert "curl" in check_external_deps()

    @patch("platform_utils.subprocess.run")
    def test_returns_ssh_when_missing(self, mock_run):
        def side_effect(cmd, **kwargs):
            if "ssh" in cmd:
                raise FileNotFoundError("no ssh")
            return _completed(returncode=0)
        mock_run.side_effect = side_effect
        assert any("ssh" in dep for dep in check_external_deps())
