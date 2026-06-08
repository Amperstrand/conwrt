"""Tests for U-Boot HTTP upload and firmware detection."""
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.upload import detect_uboot_http, upload_firmware, trigger_flash


def _mock_run(stdout="", stderr="", returncode=0):
    return MagicMock(stdout=stdout, stderr=stderr, returncode=returncode)


class TestDetectUbootHttp(TestCase):
    @patch("flash.upload.subprocess.run")
    def test_firmware_update_page(self, mock_run):
        mock_run.return_value = _mock_run(stdout="<html>FIRMWARE UPDATE</html>")
        detected, reason = detect_uboot_http("192.168.1.1")
        self.assertTrue(detected)
        self.assertIn("firmware", reason)

    @patch("flash.upload.subprocess.run")
    def test_recovery_page(self, mock_run):
        mock_run.return_value = _mock_run(stdout="<html>Recovery Mode</html>")
        detected, reason = detect_uboot_http("192.168.1.1")
        self.assertTrue(detected)

    @patch("flash.upload.subprocess.run")
    def test_dlink_excluded(self, mock_run):
        mock_run.return_value = _mock_run(
            stdout="<html><title>D-LINK</title>FIRMWARE UPDATE</html>"
        )
        detected, _ = detect_uboot_http("192.168.1.1")
        self.assertFalse(detected)

    @patch("flash.upload.subprocess.run")
    def test_hnap_excluded(self, mock_run):
        mock_run.return_value = _mock_run(
            stdout='<!DOCTYPE html><html>HNAP1</html>'
        )
        detected, _ = detect_uboot_http("192.168.1.1")
        self.assertFalse(detected)

    @patch("flash.upload.subprocess.run")
    def test_empty_response(self, mock_run):
        mock_run.return_value = _mock_run(stdout="")
        detected, reason = detect_uboot_http("192.168.1.1")
        self.assertFalse(detected)
        self.assertIn("no response", reason)

    @patch("flash.upload.subprocess.run")
    def test_exception_returns_false(self, mock_run):
        mock_run.side_effect = OSError("Network error")
        detected, reason = detect_uboot_http("192.168.1.1")
        self.assertFalse(detected)
        self.assertIn("Network error", reason)

    @patch("flash.upload.subprocess.run")
    def test_dlink_mixed_case_excluded(self, mock_run):
        mock_run.return_value = _mock_run(
            stdout="<html><title>D-Link</title>FIRMWARE UPDATE</html>"
        )
        detected, _ = detect_uboot_http("192.168.1.1")
        self.assertFalse(detected)

    @patch("flash.upload.subprocess.run")
    def test_dlink_recovery_mixed_case_excluded(self, mock_run):
        mock_run.return_value = _mock_run(
            stdout="<html><title>D-Link Router</title>Recovery</html>"
        )
        detected, _ = detect_uboot_http("192.168.1.1")
        self.assertFalse(detected)

    @patch("flash.upload.subprocess.run")
    def test_recovery_with_recovery_mode_accepted(self, mock_run):
        mock_run.return_value = _mock_run(
            stdout="<html>D-Link Recovery Mode</html>"
        )
        detected, reason = detect_uboot_http("192.168.1.1")
        self.assertTrue(detected)

    @patch("flash.upload.subprocess.run")
    def test_lowercase_firmware_detected(self, mock_run):
        mock_run.return_value = _mock_run(
            stdout="<html>firmware update page</html>"
        )
        detected, reason = detect_uboot_http("192.168.1.1")
        self.assertTrue(detected)
        self.assertIn("firmware", reason)

    @patch("flash.upload.subprocess.run")
    def test_doctype_without_hnap_or_dlink(self, mock_run):
        mock_run.return_value = _mock_run(
            stdout="<!DOCTYPE html><html><body>Some page</body></html>"
        )
        detected, reason = detect_uboot_http("192.168.1.1")
        self.assertTrue(detected)
        self.assertIn("HTML", reason)

    @patch("flash.upload.subprocess.run")
    def test_non_html_response(self, mock_run):
        mock_run.return_value = _mock_run(stdout="Just some text")
        detected, reason = detect_uboot_http("192.168.1.1")
        self.assertFalse(detected)
        self.assertIn("Just some text", reason)

    @patch("flash.upload.subprocess.run")
    def test_uses_recovery_ip(self, mock_run):
        mock_run.return_value = _mock_run(stdout="")
        detect_uboot_http("10.0.0.1")
        call_args = mock_run.call_args[0][0]
        self.assertIn("http://10.0.0.1/", call_args)


class TestUploadFirmware(TestCase):
    @patch("flash.upload.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.upload.subprocess.run")
    def test_success_with_size_md5(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(stdout="5242880 abc123def456")
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            upload_endpoint="/firmware.cgi",
            upload_field="firmware",
        )
        success, response = upload_firmware("/tmp/fw.bin", profile)
        self.assertTrue(success)
        self.assertIn("5242880", response)

    @patch("flash.upload.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.upload.subprocess.run")
    def test_success_with_html_response(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(
            stdout="<!DOCTYPE html><html>OK</html>"
        )
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            upload_endpoint="/upload",
            upload_field="file",
        )
        success, response = upload_firmware("/tmp/fw.bin", profile)
        self.assertTrue(success)

    @patch("flash.upload.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.upload.subprocess.run")
    def test_failure_returns_false(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(
            stderr="Connection refused", returncode=7
        )
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            upload_endpoint="/upload",
            upload_field="file",
        )
        success, response = upload_firmware("/tmp/fw.bin", profile)
        self.assertFalse(success)

    @patch("flash.upload.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.upload.subprocess.run")
    def test_sends_upload_field(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(stdout="0 md5")
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            upload_endpoint="/fw.cgi",
            upload_field="myfield",
        )
        upload_firmware("/tmp/fw.bin", profile)
        call_args = " ".join(mock_run.call_args[0][0])
        self.assertIn("myfield=@/tmp/fw.bin", call_args)

    @patch("flash.upload.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.upload.subprocess.run")
    def test_timeout_returns_false(self, mock_run, mock_size):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("curl", 300)
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            upload_endpoint="/upload",
            upload_field="file",
        )
        success, response = upload_firmware("/tmp/fw.bin", profile)
        self.assertFalse(success)
        self.assertEqual(response, "timeout")

    @patch("flash.upload.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.upload.subprocess.run")
    def test_general_exception_returns_false(self, mock_run, mock_size):
        mock_run.side_effect = OSError("Permission denied")
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            upload_endpoint="/upload",
            upload_field="file",
        )
        success, response = upload_firmware("/tmp/fw.bin", profile)
        self.assertFalse(success)
        self.assertIn("Permission denied", response)

    @patch("flash.upload.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.upload.subprocess.run")
    def test_empty_stdout_returns_false(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(stdout="", returncode=0)
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            upload_endpoint="/upload",
            upload_field="file",
        )
        success, response = upload_firmware("/tmp/fw.bin", profile)
        self.assertFalse(success)

    @patch("flash.upload.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.upload.subprocess.run")
    def test_html_response_lowercase_html_tag(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(
            stdout="<html><body>Upload OK</body></html>"
        )
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            upload_endpoint="/upload",
            upload_field="file",
        )
        success, response = upload_firmware("/tmp/fw.bin", profile)
        self.assertTrue(success)

    @patch("flash.upload.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.upload.subprocess.run")
    def test_uses_custom_timeout(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(stdout="0 md5")
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            upload_endpoint="/fw.cgi",
            upload_field="fw",
        )
        upload_firmware("/tmp/fw.bin", profile, timeout=600)
        call_args = mock_run.call_args[0][0]
        self.assertIn("600", call_args)


class TestTriggerFlash(TestCase):
    @patch("flash.upload.subprocess.run")
    def test_success_response(self, mock_run):
        mock_run.return_value = _mock_run(stdout="success")
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            trigger_flash_endpoint="/flash.cgi",
            flash_time_seconds=120,
        )
        result = trigger_flash(profile)
        self.assertTrue(result)

    @patch("flash.upload.subprocess.run")
    def test_update_in_progress(self, mock_run):
        mock_run.return_value = _mock_run(stdout="Update in progress")
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            trigger_flash_endpoint="/flash.cgi",
            flash_time_seconds=120,
        )
        result = trigger_flash(profile)
        self.assertTrue(result)

    @patch("flash.upload.subprocess.run")
    def test_no_trigger_endpoint(self, mock_run):
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            trigger_flash_endpoint="",
            flash_time_seconds=120,
        )
        result = trigger_flash(profile)
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch("flash.upload.subprocess.run")
    def test_timeout_returns_true(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("curl", 180)
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            trigger_flash_endpoint="/flash.cgi",
            flash_time_seconds=120,
        )
        result = trigger_flash(profile)
        self.assertTrue(result)

    @patch("flash.upload.subprocess.run")
    def test_lowercase_success_in_response(self, mock_run):
        mock_run.return_value = _mock_run(stdout="Flash success confirmed")
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            trigger_flash_endpoint="/flash.cgi",
            flash_time_seconds=120,
        )
        result = trigger_flash(profile)
        self.assertTrue(result)

    @patch("flash.upload.subprocess.run")
    def test_empty_response_returns_true(self, mock_run):
        mock_run.return_value = _mock_run(stdout="")
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            trigger_flash_endpoint="/flash.cgi",
            flash_time_seconds=120,
        )
        result = trigger_flash(profile)
        self.assertTrue(result)

    @patch("flash.upload.subprocess.run")
    def test_general_exception_returns_false(self, mock_run):
        mock_run.side_effect = OSError("Connection reset")
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            trigger_flash_endpoint="/flash.cgi",
            flash_time_seconds=120,
        )
        result = trigger_flash(profile)
        self.assertFalse(result)

    @patch("flash.upload.subprocess.run")
    def test_non_success_response_returns_false(self, mock_run):
        mock_run.return_value = _mock_run(stdout="error: invalid firmware")
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            trigger_flash_endpoint="/flash.cgi",
            flash_time_seconds=120,
        )
        result = trigger_flash(profile)
        self.assertFalse(result)

    @patch("flash.upload.subprocess.run")
    def test_uses_profile_flash_time(self, mock_run):
        mock_run.return_value = _mock_run(stdout="success")
        profile = SimpleNamespace(
            recovery_ip="192.168.1.1",
            trigger_flash_endpoint="/flash.cgi",
            flash_time_seconds=300,
        )
        trigger_flash(profile)
        call_args = mock_run.call_args[0][0]
        self.assertIn("360", call_args)  # 300 + 60
