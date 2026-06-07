from __future__ import annotations

import argparse
import subprocess
from unittest import TestCase
from unittest.mock import MagicMock, patch

from conwrt.infrastructure import (
    TFTPServerManager,
    _auto_detect_serial_port,
    _generate_random_password,
    _validate_args,
)


class TestGenerateRandomPassword(TestCase):
    def test_returns_non_empty_string(self):
        pw = _generate_random_password()
        assert isinstance(pw, str)
        assert len(pw) > 0

    def test_returns_unique_values(self):
        pw1 = _generate_random_password()
        pw2 = _generate_random_password()
        assert pw1 != pw2

    def test_length_is_at_least_16_chars(self):
        pw = _generate_random_password()
        assert len(pw) >= 16


class TestValidateArgs(TestCase):
    def _ns(self, **kwargs):
        defaults = dict(
            image=None,
            request_image=None,
            ssh_key=None,
            password=None,
            no_password=None,
            wan_ssh=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_no_image_no_request_image_returns_error(self):
        args = self._ns()
        result = _validate_args(args)
        assert result is not None
        assert "--image" in result or "--request-image" in result

    def test_both_image_and_request_image_returns_error(self):
        args = self._ns(image="fw.bin", request_image=True)
        result = _validate_args(args)
        assert result is not None
        assert "mutually exclusive" in result

    def test_image_only_returns_none(self):
        args = self._ns(image="fw.bin")
        result = _validate_args(args)
        assert result is None

    def test_request_image_only_returns_none(self):
        args = self._ns(request_image=True)
        result = _validate_args(args)
        assert result is None

    def test_image_with_ssh_key_returns_error(self):
        args = self._ns(image="fw.bin", ssh_key="~/.ssh/id.pub")
        result = _validate_args(args)
        assert result is not None
        assert "--ssh-key" in result

    def test_image_with_password_returns_error(self):
        args = self._ns(image="fw.bin", password="secret")
        result = _validate_args(args)
        assert result is not None
        assert "--password" in result

    def test_image_with_no_password_returns_error(self):
        args = self._ns(image="fw.bin", no_password=True)
        result = _validate_args(args)
        assert result is not None
        assert "--no-password" in result

    def test_image_with_wan_ssh_returns_error(self):
        args = self._ns(image="fw.bin", wan_ssh=True)
        result = _validate_args(args)
        assert result is not None
        assert "--wan-ssh" in result

    def test_request_image_with_ssh_key_is_ok(self):
        args = self._ns(request_image=True, ssh_key="~/.ssh/id.pub")
        result = _validate_args(args)
        assert result is None


class TestAutoDetectSerialPort(TestCase):
    @patch("glob.glob")
    def test_returns_first_candidate(self, mock_glob):
        mock_glob.side_effect = [
            ["/dev/cu.usbserial-ABCD"],
            [],
        ]
        result = _auto_detect_serial_port()
        assert result == "/dev/cu.usbserial-ABCD"

    @patch("glob.glob")
    def test_raises_when_no_candidates(self, mock_glob):
        mock_glob.side_effect = [[], []]
        with self.assertRaises(FileNotFoundError) as ctx:
            _auto_detect_serial_port()
        assert "No serial adapter found" in str(ctx.exception)

    @patch("glob.glob")
    def test_sorted_candidates_picks_first_alphabetically(self, mock_glob):
        mock_glob.side_effect = [
            ["/dev/cu.usbserial-AAA", "/dev/cu.usbserial-BBB"],
            ["/dev/cu.SLAB_USBtoUART"],
        ]
        result = _auto_detect_serial_port()
        assert result == "/dev/cu.SLAB_USBtoUART"

    @patch("glob.glob")
    def test_falls_back_to_slab(self, mock_glob):
        mock_glob.side_effect = [
            [],
            ["/dev/cu.SLAB_USBtoUART"],
        ]
        result = _auto_detect_serial_port()
        assert result == "/dev/cu.SLAB_USBtoUART"


class TestTFTPServerManager(TestCase):
    def test_init_defaults(self):
        mgr = TFTPServerManager("/tmp/tftp")
        assert mgr.tftp_root == "/tmp/tftp"
        assert mgr.bind_ip == "0.0.0.0"
        assert mgr._proc is None

    def test_init_custom_bind_ip(self):
        mgr = TFTPServerManager("/tmp/tftp", bind_ip="192.168.1.1")
        assert mgr.bind_ip == "192.168.1.1"

    def test_is_running_false_when_no_proc(self):
        mgr = TFTPServerManager("/tmp/tftp")
        assert mgr.is_running is False

    @patch("conwrt.infrastructure.os.path.isdir", return_value=False)
    def test_start_returns_false_when_root_not_dir(self, _mock_isdir):
        mgr = TFTPServerManager("/nonexistent")
        assert mgr.start() is False

    @patch("conwrt.infrastructure.subprocess.Popen")
    @patch("conwrt.infrastructure.os.path.isfile", side_effect=[False, False])
    @patch("conwrt.infrastructure.os.path.isdir", return_value=True)
    @patch("conwrt.infrastructure.detect_platform", return_value="darwin")
    @patch("shutil.which", return_value="/usr/sbin/dnsmasq")
    def test_start_uses_dnsmasq_when_available(self, mock_which, mock_platform, mock_isdir, mock_isfile, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 12345
        mock_popen.return_value = mock_proc
        mgr = TFTPServerManager("/tmp/tftp", bind_ip="10.0.0.1")
        with patch("conwrt.infrastructure.time.sleep"):
            result = mgr.start()
        assert result is True
        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "/usr/sbin/dnsmasq"
        assert "--tftp-root=/tmp/tftp" in cmd

    @patch("conwrt.infrastructure.os.path.isfile", side_effect=[False, False])
    @patch("conwrt.infrastructure.os.path.isdir", return_value=True)
    @patch("conwrt.infrastructure.detect_platform", return_value="openwrt")
    def test_start_returns_false_on_openwrt_without_script(self, mock_platform, mock_isdir, mock_isfile):
        mgr = TFTPServerManager("/tmp/tftp")
        assert mgr.start() is False

    def test_stop_does_nothing_when_no_proc(self):
        mgr = TFTPServerManager("/tmp/tftp")
        mgr.stop()

    def test_stop_terminates_running_proc(self):
        mgr = TFTPServerManager("/tmp/tftp")
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mgr._proc = mock_proc
        mgr.stop()
        mock_proc.terminate.assert_called_once()
        mock_proc.wait.assert_called_once_with(timeout=5)

    def test_stop_kills_on_timeout(self):
        mgr = TFTPServerManager("/tmp/tftp")
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.wait.side_effect = subprocess.TimeoutExpired("cmd", 5)
        mgr._proc = mock_proc
        mgr.stop()
        mock_proc.kill.assert_called_once()

    def test_is_running_true_when_proc_alive(self):
        mgr = TFTPServerManager("/tmp/tftp")
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mgr._proc = mock_proc
        assert mgr.is_running is True

    def test_is_running_false_when_proc_exited(self):
        mgr = TFTPServerManager("/tmp/tftp")
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0
        mgr._proc = mock_proc
        assert mgr.is_running is False
