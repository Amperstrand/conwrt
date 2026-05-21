"""Tests for boot state detection."""
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.detect import check_ssh, detect_boot_state


def _mock_run(stdout="", stderr="", returncode=0):
    return MagicMock(stdout=stdout, stderr=stderr, returncode=returncode)


class TestCheckSsh(TestCase):
    @patch("flash.detect.subprocess.run")
    def test_ssh_ok(self, mock_run):
        mock_run.return_value = _mock_run(stdout="ok")
        self.assertTrue(check_ssh("192.168.1.1"))

    @patch("flash.detect.subprocess.run")
    def test_ssh_fail(self, mock_run):
        mock_run.return_value = _mock_run(stdout="", returncode=1)
        self.assertFalse(check_ssh("192.168.1.1"))

    @patch("flash.detect.subprocess.run")
    def test_ssh_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 10)
        self.assertFalse(check_ssh("192.168.1.1"))


class TestDetectBootState(TestCase):
    @patch("flash.detect.check_ssh", return_value=True)
    def test_openwrt_detected(self, mock_ssh):
        profile = SimpleNamespace(
            openwrt_ip="192.168.1.1", recovery_ip="192.168.0.1",
            flash_method="sysupgrade",
        )
        result = detect_boot_state("eth0", profile)
        self.assertEqual(result, "openwrt")

    @patch("flash.detect.check_ssh", return_value=False)
    @patch("flash.detect.subprocess.run")
    def test_zyxel_oem_detected(self, mock_run, mock_ssh):
        mock_run.return_value = _mock_run(
            stdout='<html>dispatcher.cgi password form</html>'
        )
        profile = SimpleNamespace(
            openwrt_ip="192.168.1.1", recovery_ip="192.168.0.1",
            flash_method="oem-http", stock_default_ip="192.168.1.1",
        )
        result = detect_boot_state("eth0", profile)
        self.assertEqual(result, "stock-zyxel")

    @patch("flash.detect.check_ssh", return_value=False)
    @patch("flash.detect.subprocess.run")
    def test_zyxel_oem_form_login(self, mock_run, mock_ssh):
        mock_run.return_value = _mock_run(
            stdout='<html>Login Password</html>', returncode=0
        )
        profile = SimpleNamespace(
            openwrt_ip="192.168.1.1", recovery_ip="192.168.0.1",
            flash_method="oem-ftp", stock_default_ip="192.168.1.1",
        )
        result = detect_boot_state("eth0", profile)
        self.assertEqual(result, "stock-zyxel")

    @patch("flash.detect.check_ssh", return_value=False)
    @patch("flash.detect.subprocess.run")
    def test_dlink_hnap_detected(self, mock_run, mock_ssh):
        mock_run.return_value = _mock_run(
            stdout='<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">HNAP</soap>'
        )
        profile = SimpleNamespace(
            openwrt_ip="192.168.1.1", recovery_ip="192.168.0.1",
            flash_method="dlink-hnap",
        )
        result = detect_boot_state("eth0", profile)
        self.assertEqual(result, "stock-hnap")

    @patch("flash.detect.check_ssh", return_value=False)
    @patch("flash.detect.subprocess.run")
    @patch("flash.detect.detect_uboot_http", return_value=(True, "firmware page"))
    def test_uboot_detected(self, mock_uboot, mock_run, mock_ssh):
        profile = SimpleNamespace(
            openwrt_ip="192.168.1.1", recovery_ip="192.168.0.1",
            flash_method="recovery-http",
        )
        result = detect_boot_state("eth0", profile)
        self.assertEqual(result, "uboot")

    @patch("flash.detect.check_ssh", return_value=False)
    @patch("flash.detect.subprocess.run")
    @patch("flash.detect.detect_uboot_http", return_value=(False, "no response"))
    def test_unknown_when_nothing_detected(self, mock_uboot, mock_run, mock_ssh):
        profile = SimpleNamespace(
            openwrt_ip="192.168.1.1", recovery_ip="192.168.0.1",
            flash_method="sysupgrade",
        )
        result = detect_boot_state("eth0", profile)
        self.assertEqual(result, "unknown")

    @patch("flash.detect.check_ssh", return_value=False)
    @patch("flash.detect.subprocess.run")
    @patch("flash.detect.detect_uboot_http", return_value=(False, "no response"))
    def test_no_profile_defaults_to_unknown(self, mock_uboot, mock_run, mock_ssh):
        result = detect_boot_state("eth0", None)
        self.assertEqual(result, "unknown")
