from __future__ import annotations

from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest

from conwrt.cmd_reset import cmd_reset


def _args(**overrides):
    defaults = {
        "ip": "192.168.1.1",
        "ssh_key": "",
        "interface": "en0",
        "dry_run": False,
        "no_voice": True,
    }
    defaults.update(overrides)
    return Namespace(**defaults)


def _mock_result(returncode=0, stdout="", stderr=""):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


@pytest.fixture(autouse=True)
def _no_sleep():
    with patch("conwrt.cmd_reset.time.sleep"):
        yield


class TestCmdResetNoInterface:
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value=None)
    def test_returns_1_when_no_interface(self, mock_detect, mock_key):
        result = cmd_reset(_args(interface=None))
        assert result == 1


class TestCmdResetSshSuccess:
    @patch("conwrt.cmd_reset.say")
    @patch("conwrt.cmd_reset.run_ssh", return_value=_mock_result(0))
    @patch("conwrt.cmd_reset.check_ssh", return_value=True)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_ssh_firstboot_success_returns_0(self, mock_key, mock_iface, mock_check, mock_run, mock_say):
        result = cmd_reset(_args())
        assert result == 0
        mock_run.assert_called_once()

    @patch("conwrt.cmd_reset.say")
    @patch("conwrt.cmd_reset.run_ssh", return_value=_mock_result(0))
    @patch("conwrt.cmd_reset.check_ssh", return_value=True)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_ssh_success_calls_say_when_voice_enabled(self, mock_key, mock_iface, mock_check, mock_run, mock_say):
        result = cmd_reset(_args(no_voice=False))
        assert result == 0
        mock_say.assert_called()


class TestCmdResetSshDryRun:
    @patch("conwrt.cmd_reset.check_ssh", return_value=True)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_ssh_dry_run_returns_0_without_running_firstboot(self, mock_key, mock_iface, mock_check):
        with patch("conwrt.cmd_reset.run_ssh") as mock_run:
            result = cmd_reset(_args(dry_run=True))
        assert result == 0
        mock_run.assert_not_called()


class TestCmdResetSshConnectionClosed:
    @patch("conwrt.cmd_reset.say")
    @patch("conwrt.cmd_reset.run_ssh", return_value=_mock_result(1, stdout="", stderr=""))
    @patch("conwrt.cmd_reset.check_ssh", return_value=True)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_ssh_connection_closed_returns_0(self, mock_key, mock_iface, mock_check, mock_run, mock_say):
        result = cmd_reset(_args())
        assert result == 0


class TestCmdResetSshConnectionRefused:
    @patch("conwrt.cmd_reset.run_ssh", return_value=_mock_result(1, stderr="Connection refused"))
    @patch("conwrt.cmd_reset.check_ssh", return_value=True)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_ssh_connection_refused_returns_1(self, mock_key, mock_iface, mock_check, mock_run):
        result = cmd_reset(_args())
        assert result == 1


class TestCmdResetSshTimedOut:
    @patch("conwrt.cmd_reset.run_ssh", return_value=_mock_result(1, stderr="Connection timed out"))
    @patch("conwrt.cmd_reset.check_ssh", return_value=True)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_ssh_timed_out_returns_1(self, mock_key, mock_iface, mock_check, mock_run):
        result = cmd_reset(_args())
        assert result == 1


class TestCmdResetSshKeyDetection:
    @patch("conwrt.cmd_reset.say")
    @patch("conwrt.cmd_reset.run_ssh", return_value=_mock_result(0))
    @patch("conwrt.cmd_reset.check_ssh", return_value=True)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/auto/key")
    def test_auto_detects_ssh_key_when_not_provided(self, mock_key, mock_iface, mock_check, mock_run, mock_say):
        result = cmd_reset(_args(ssh_key=""))
        assert result == 0
        mock_key.assert_called_once()

    @patch("conwrt.cmd_reset.say")
    @patch("conwrt.cmd_reset.run_ssh", return_value=_mock_result(0))
    @patch("conwrt.cmd_reset.check_ssh", return_value=True)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/auto/key")
    def test_uses_provided_ssh_key(self, mock_key, mock_iface, mock_check, mock_run, mock_say):
        result = cmd_reset(_args(ssh_key="/my/custom/key"))
        assert result == 0
        mock_key.assert_not_called()


class TestCmdResetFailsafeNoBootDetected:
    @patch("conwrt.cmd_reset.say")
    @patch("conwrt.cmd_reset.subprocess")
    @patch("conwrt.cmd_reset.get_link_state", return_value=False)
    @patch("conwrt.cmd_reset.check_ssh", return_value=False)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_no_boot_packet_returns_1(self, mock_key, mock_iface, mock_check, mock_link, mock_sp, mock_say):
        mock_proc = MagicMock()
        mock_proc.stdout = iter([""])
        mock_proc.wait.return_value = 0
        mock_sp.Popen.return_value = mock_proc
        mock_sp.run.return_value = _mock_result(stdout="ether aa:bb:cc:dd:ee:ff")
        result = cmd_reset(_args())
        assert result == 1


class TestCmdResetFailsafeDryRun:
    @patch("conwrt.cmd_reset.subprocess")
    @patch("conwrt.cmd_reset.get_link_state", return_value=False)
    @patch("conwrt.cmd_reset.check_ssh", return_value=False)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_failsafe_dry_run_returns_0(self, mock_key, mock_iface, mock_check, mock_link, mock_sp):
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_sp.Popen.return_value = mock_proc
        mock_sp.run.return_value = _mock_result(stdout="ether aa:bb:cc:dd:ee:ff")
        result = cmd_reset(_args(dry_run=True))
        assert result == 0


class TestCmdResetFailsafeNoPingResponse:
    @patch("conwrt.cmd_reset.say")
    @patch("conwrt.cmd_reset.subprocess")
    @patch("conwrt.cmd_reset.get_link_state", return_value=False)
    @patch("conwrt.cmd_reset.check_ssh", return_value=False)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_failsafe_no_ping_returns_1(self, mock_key, mock_iface, mock_check, mock_link, mock_sp, mock_say):
        mock_proc = MagicMock()
        mock_proc.stdout = iter(["Please press button now"])
        mock_proc.wait.return_value = 0
        mock_sp.Popen.return_value = mock_proc
        mock_sp.run.side_effect = [
            _mock_result(stdout="ether aa:bb:cc:dd:ee:ff"),
            _mock_result(returncode=1),
        ]
        result = cmd_reset(_args())
        assert result == 1


class TestCmdResetFailsafeConfigureInterfaceFails:
    @patch("conwrt.cmd_reset.say")
    @patch("conwrt.cmd_reset.subprocess")
    @patch("conwrt.cmd_reset.configure_interface_ip", return_value=False)
    @patch("conwrt.cmd_reset.get_link_state", return_value=False)
    @patch("conwrt.cmd_reset.check_ssh", return_value=False)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_configure_interface_fails_returns_1(self, mock_key, mock_iface, mock_check, mock_link, mock_cfg, mock_sp, mock_say):
        mock_proc = MagicMock()
        mock_proc.stdout = iter(["Please press button now"])
        mock_proc.wait.return_value = 0
        mock_sp.Popen.return_value = mock_proc
        mock_sp.run.side_effect = [
            _mock_result(stdout="ether aa:bb:cc:dd:ee:ff"),
            _mock_result(returncode=0),
        ]
        result = cmd_reset(_args())
        assert result == 1


class TestCmdResetFailsafeSuccess:
    @patch("conwrt.cmd_reset.remove_interface_ip")
    @patch("conwrt.cmd_reset.say")
    @patch("conwrt.cmd_reset.run_ssh", return_value=_mock_result(0))
    @patch("conwrt.cmd_reset.configure_interface_ip", return_value=True)
    @patch("conwrt.cmd_reset.subprocess")
    @patch("conwrt.cmd_reset.get_link_state", return_value=False)
    @patch("conwrt.cmd_reset.check_ssh", return_value=False)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_failsafe_full_success_returns_0(self, mock_key, mock_iface, mock_check, mock_link, mock_sp, mock_cfg, mock_run, mock_say, mock_rm):
        mock_proc = MagicMock()
        mock_proc.stdout = iter(["Please press button now"])
        mock_proc.wait.return_value = 0
        mock_sp.Popen.return_value = mock_proc
        mock_sp.run.side_effect = [
            _mock_result(stdout="ether aa:bb:cc:dd:ee:ff"),
            _mock_result(returncode=0),
        ]
        result = cmd_reset(_args())
        assert result == 0
        mock_rm.assert_called_once_with("en0", "192.168.1.2", "24")


class TestCmdResetFailsafeSshFirstbootFails:
    @patch("conwrt.cmd_reset.say")
    @patch("conwrt.cmd_reset.run_ssh", return_value=_mock_result(1, stderr="error"))
    @patch("conwrt.cmd_reset.configure_interface_ip", return_value=True)
    @patch("conwrt.cmd_reset.subprocess")
    @patch("conwrt.cmd_reset.get_link_state", return_value=False)
    @patch("conwrt.cmd_reset.check_ssh", return_value=False)
    @patch("conwrt.cmd_reset.auto_detect_interface", return_value="en0")
    @patch("conwrt.cmd_reset._detect_ssh_key_path", return_value="/fake/key")
    def test_failsafe_ssh_firstboot_failure_returns_1(self, mock_key, mock_iface, mock_check, mock_link, mock_sp, mock_cfg, mock_run, mock_say):
        mock_proc = MagicMock()
        mock_proc.stdout = iter(["Please press button now"])
        mock_proc.wait.return_value = 0
        mock_sp.Popen.return_value = mock_proc
        mock_sp.run.side_effect = [
            _mock_result(stdout="ether aa:bb:cc:dd:ee:ff"),
            _mock_result(returncode=0),
        ]
        result = cmd_reset(_args())
        assert result == 1
