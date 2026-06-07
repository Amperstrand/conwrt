import os
import queue
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.context import OemState, RecoveryContext, State, Timeline
from conwrt.handlers_oem import (
    _handle_oem_login,
    _handle_oem_prepare,
    _handle_oem_uploading,
    _handle_oem_rebooting,
)


def _make_ctx(**overrides):
    profile = MagicMock()
    profile.flash_method = overrides.pop("flash_method", "oem-http")
    profile.stock_default_ip = overrides.pop("stock_default_ip", "192.168.1.1")
    profile.stock_default_user = overrides.pop("stock_default_user", "admin")
    profile.stock_default_password = overrides.pop("stock_default_password", "1234")
    profile.name = overrides.pop("name", "test-device")
    profile.flash_time_seconds = overrides.pop("flash_time_seconds", 90)
    profile.oem_http_upload_endpoint = overrides.pop("oem_http_upload_endpoint", "/cgi-bin/httpupload.cgi")
    profile.client_ip = overrides.pop("client_ip", "192.168.1.2")
    profile.oem_ftp_target = overrides.pop("oem_ftp_target", "ras-0")
    profile.openwrt_ip = overrides.pop("openwrt_ip", "192.168.1.1")
    defaults = {
        "profile": profile,
        "image_path": "/tmp/fw.bin",
        "interface": "en0",
        "pcap_path": "/tmp/cap.pcap",
        "initramfs_path": "/tmp/initramfs.bin",
        "state": State.OEM_LOGIN,
        "oem_state": {},
        "timeline": Timeline(),
        "_say_fn": MagicMock(),
    }
    defaults.update(overrides)
    ctx = RecoveryContext(**defaults)
    return ctx


def _mock_run(stdout="", stderr="", returncode=0):
    return MagicMock(stdout=stdout, stderr=stderr, returncode=returncode)


class TestHandleOemLoginHttpSuccess(TestCase):
    @patch("conwrt.handlers_oem.oem_has_prepare_step", return_value=False)
    @patch("conwrt.handlers_oem.oem_http_login", return_value=(True, "XSSID=abc"))
    @patch("conwrt.handlers_oem.os.path.isfile", return_value=True)
    def test_http_login_success_goes_to_uploading(self, mock_isfile, mock_login, mock_prep):
        ctx = _make_ctx(flash_method="oem-http", stock_default_password="1234")
        eq = queue.Queue()
        _handle_oem_login(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_UPLOADING)
        self.assertEqual(ctx.oem_state["cookie"], "XSSID=abc")
        self.assertEqual(ctx.oem_state["password"], "1234")


class TestHandleOemLoginHttpPrepare(TestCase):
    @patch("conwrt.handlers_oem.oem_has_prepare_step", return_value=True)
    @patch("conwrt.handlers_oem.oem_http_login", return_value=(True, "XSSID=abc"))
    @patch("conwrt.handlers_oem.os.path.isfile", return_value=True)
    def test_http_login_with_prepare_step_goes_to_prepare(self, mock_isfile, mock_login, mock_prep):
        ctx = _make_ctx(flash_method="oem-http", stock_default_password="1234")
        eq = queue.Queue()
        _handle_oem_login(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_PREPARE)


class TestHandleOemLoginHttpFailure(TestCase):
    @patch("conwrt.handlers_oem.oem_http_login", return_value=(False, "Login failed"))
    @patch("conwrt.handlers_oem.os.path.isfile", return_value=True)
    def test_http_login_failure_goes_to_failed(self, mock_isfile, mock_login):
        ctx = _make_ctx(flash_method="oem-http", stock_default_password="1234")
        eq = queue.Queue()
        _handle_oem_login(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleOemLoginMissingInitramfs(TestCase):
    @patch("conwrt.handlers_oem.os.path.isfile", return_value=False)
    def test_missing_initramfs_goes_to_failed(self, mock_isfile):
        ctx = _make_ctx(flash_method="oem-http", stock_default_password="1234")
        eq = queue.Queue()
        _handle_oem_login(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleOemLoginNoPassword(TestCase):
    @patch("conwrt.handlers_oem.oem_has_prepare_step", return_value=False)
    @patch("conwrt.handlers_oem.oem_http_login", return_value=(True, "XSSID=abc"))
    @patch("conwrt.handlers_oem.load_model")
    @patch("conwrt.handlers_oem.os.path.isfile", return_value=True)
    def test_loads_model_creds_when_no_password(self, mock_isfile, mock_load, mock_login, mock_prep):
        mock_load.return_value = {"stock_default_creds": {"username": "zyxel", "password": "admin"}}
        ctx = _make_ctx(flash_method="oem-http", stock_default_password="")
        eq = queue.Queue()
        _handle_oem_login(ctx, eq)
        mock_load.assert_called_once_with("test-device")
        mock_login.assert_called_once_with("192.168.1.1", "zyxel", "admin")


class TestHandleOemLoginPasswordChange(TestCase):
    @patch("conwrt.handlers_oem.oem_has_prepare_step", return_value=False)
    @patch("conwrt.handlers_oem.oem_http_login")
    @patch("conwrt.handlers_oem.oem_http_change_password", return_value=(True, "Password changed"))
    @patch("conwrt.handlers_oem.subprocess.run")
    @patch("conwrt.handlers_oem.os.path.isfile", return_value=True)
    def test_password_change_detected_and_relogin(self, mock_isfile, mock_run, mock_chpw, mock_login, mock_prep):
        mock_run.return_value = _mock_run(stdout="cmd=30&Password Change Required")
        mock_login.side_effect = [
            (True, "XSSID=old"),
            (True, "XSSID=new"),
        ]
        ctx = _make_ctx(flash_method="oem-http", stock_default_password="1234")
        eq = queue.Queue()
        _handle_oem_login(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_UPLOADING)
        self.assertEqual(ctx.oem_state["cookie"], "XSSID=new")
        self.assertEqual(mock_login.call_count, 2)


class TestHandleOemLoginPasswordChangeFailure(TestCase):
    @patch("conwrt.handlers_oem.oem_has_prepare_step", return_value=False)
    @patch("conwrt.handlers_oem.oem_http_login", return_value=(True, "XSSID=old"))
    @patch("conwrt.handlers_oem.oem_http_change_password", return_value=(False, "Change rejected"))
    @patch("conwrt.handlers_oem.subprocess.run")
    @patch("conwrt.handlers_oem.os.path.isfile", return_value=True)
    def test_password_change_failure_continues_with_old_cookie(self, mock_isfile, mock_run, mock_chpw, mock_login, mock_prep):
        mock_run.return_value = _mock_run(stdout="Password Change Required")
        ctx = _make_ctx(flash_method="oem-http", stock_default_password="1234")
        eq = queue.Queue()
        _handle_oem_login(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_UPLOADING)
        self.assertEqual(ctx.oem_state["cookie"], "XSSID=old")


class TestHandleOemLoginFtpSuccess(TestCase):
    @patch("conwrt.handlers_oem.oem_has_prepare_step", return_value=True)
    @patch("conwrt.handlers_oem.oem_ftp_login", return_value=(True, "/tmp/cookies.txt"))
    @patch("conwrt.handlers_oem.os.path.isfile", return_value=True)
    def test_ftp_login_success_goes_to_prepare(self, mock_isfile, mock_login, mock_prep):
        ctx = _make_ctx(flash_method="oem-ftp", stock_default_password="1234")
        eq = queue.Queue()
        _handle_oem_login(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_PREPARE)
        self.assertEqual(ctx.oem_state["cookie_file"], "/tmp/cookies.txt")


class TestHandleOemLoginFtpFailure(TestCase):
    @patch("conwrt.handlers_oem.oem_ftp_login", return_value=(False, "Auth failed"))
    @patch("conwrt.handlers_oem.os.path.isfile", return_value=True)
    def test_ftp_login_failure_goes_to_failed(self, mock_isfile, mock_login):
        ctx = _make_ctx(flash_method="oem-ftp", stock_default_password="1234")
        eq = queue.Queue()
        _handle_oem_login(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleOemLoginUnknownMethod(TestCase):
    @patch("conwrt.handlers_oem.os.path.isfile", return_value=True)
    def test_unknown_method_goes_to_failed(self, mock_isfile):
        ctx = _make_ctx(flash_method="oem-unknown", stock_default_password="1234")
        eq = queue.Queue()
        _handle_oem_login(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleOemPrepareFtp(TestCase):
    @patch("conwrt.handlers_oem.oem_ftp_enable_service", return_value=(True, "FTP enabled"))
    def test_ftp_prepare_success_goes_to_uploading(self, mock_enable):
        ctx = _make_ctx(flash_method="oem-ftp", state=State.OEM_PREPARE, oem_state={"cookie_file": "/tmp/cookies.txt"})
        eq = queue.Queue()
        _handle_oem_prepare(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_UPLOADING)
        mock_enable.assert_called_once_with("192.168.1.1", "/tmp/cookies.txt")


class TestHandleOemPrepareFtpFailure(TestCase):
    @patch("conwrt.handlers_oem.oem_ftp_enable_service", return_value=(False, "FTP error"))
    def test_ftp_prepare_failure_goes_to_failed(self, mock_enable):
        ctx = _make_ctx(flash_method="oem-ftp", state=State.OEM_PREPARE, oem_state={"cookie_file": "/tmp/cookies.txt"})
        eq = queue.Queue()
        _handle_oem_prepare(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleOemUploadingHttpSuccess(TestCase):
    @patch("conwrt.handlers_oem.oem_http_accept_reboot")
    @patch("conwrt.handlers_oem.oem_http_upload", return_value=(True, "Writing image to FLASH"))
    def test_http_upload_success_goes_to_rebooting(self, mock_upload, mock_accept):
        ctx = _make_ctx(
            flash_method="oem-http",
            state=State.OEM_UPLOADING,
            oem_state={"cookie": "XSSID=abc"},
            initramfs_path="/tmp/fw.bin",
        )
        eq = queue.Queue()
        _handle_oem_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_REBOOTING)
        self.assertIsNotNone(ctx.timeline.upload_start)
        self.assertIsNotNone(ctx.timeline.flash_triggered)
        mock_accept.assert_called_once()


class TestHandleOemUploadingHttpFailure(TestCase):
    @patch("conwrt.handlers_oem.oem_http_upload", return_value=(False, "Connection refused"))
    def test_http_upload_failure_goes_to_failed(self, mock_upload):
        ctx = _make_ctx(
            flash_method="oem-http",
            state=State.OEM_UPLOADING,
            oem_state={"cookie": "XSSID=abc"},
            initramfs_path="/tmp/fw.bin",
        )
        eq = queue.Queue()
        _handle_oem_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleOemUploadingLongFilename(TestCase):
    @patch("conwrt.handlers_oem.oem_http_accept_reboot")
    @patch("conwrt.handlers_oem.oem_http_upload", return_value=(True, "OK"))
    @patch("conwrt.handlers_oem.shutil.copy2")
    def test_long_filename_creates_temp_copy(self, mock_copy2, mock_upload, mock_accept):
        long_name = "a" * 65 + ".bin"
        long_path = os.path.join("/tmp", long_name)
        ctx = _make_ctx(
            flash_method="oem-http",
            state=State.OEM_UPLOADING,
            oem_state={"cookie": "XSSID=abc"},
            initramfs_path=long_path,
        )
        eq = queue.Queue()
        with patch("conwrt.handlers_oem.os.path.exists", return_value=False):
            _handle_oem_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_REBOOTING)
        mock_copy2.assert_called_once()


class TestHandleOemUploadingFtpSuccess(TestCase):
    @patch("conwrt.handlers_oem.oem_ftp_upload", return_value=(True, "226 Transfer complete"))
    def test_ftp_upload_success_goes_to_rebooting(self, mock_upload):
        ctx = _make_ctx(
            flash_method="oem-ftp",
            state=State.OEM_UPLOADING,
            oem_state={"password": "1234"},
            initramfs_path="/tmp/fw.bin",
        )
        eq = queue.Queue()
        _handle_oem_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_REBOOTING)
        mock_upload.assert_called_once()


class TestHandleOemUploadingFtpFailure(TestCase):
    @patch("conwrt.handlers_oem.oem_ftp_upload", return_value=(False, "500 Error"))
    def test_ftp_upload_failure_goes_to_failed(self, mock_upload):
        ctx = _make_ctx(
            flash_method="oem-ftp",
            state=State.OEM_UPLOADING,
            oem_state={"password": "1234"},
            initramfs_path="/tmp/fw.bin",
        )
        eq = queue.Queue()
        _handle_oem_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleOemUploadingUnknownMethod(TestCase):
    def test_unknown_upload_method_goes_to_failed(self):
        ctx = _make_ctx(
            flash_method="oem-unknown",
            state=State.OEM_UPLOADING,
            oem_state={},
            initramfs_path="/tmp/fw.bin",
        )
        eq = queue.Queue()
        _handle_oem_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleOemRebooting(TestCase):
    @patch("conwrt.handlers_oem.oem_reboot_wait_and_install", return_value=State.COMPLETE)
    @patch("conwrt.handlers_oem.get_oem_install_fn", return_value=lambda ctx, ip: None)
    def test_rebooting_success_sets_state(self, mock_get_fn, mock_wait):
        ctx = _make_ctx(
            flash_method="oem-http",
            state=State.OEM_REBOOTING,
        )
        eq = queue.Queue()
        _handle_oem_rebooting(ctx, eq)
        self.assertEqual(ctx.state, State.COMPLETE)
        mock_get_fn.assert_called_once_with("oem-http")
        mock_wait.assert_called_once()


class TestHandleOemRebootingReturnsNone(TestCase):
    @patch("conwrt.handlers_oem.oem_reboot_wait_and_install", return_value=None)
    @patch("conwrt.handlers_oem.get_oem_install_fn", return_value=lambda ctx, ip: None)
    def test_rebooting_returns_none_keeps_state(self, mock_get_fn, mock_wait):
        ctx = _make_ctx(
            flash_method="oem-http",
            state=State.OEM_REBOOTING,
        )
        eq = queue.Queue()
        _handle_oem_rebooting(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_REBOOTING)


class TestHandleOemLoginPasswordChangeException(TestCase):
    @patch("conwrt.handlers_oem.oem_has_prepare_step", return_value=False)
    @patch("conwrt.handlers_oem.oem_http_login", return_value=(True, "XSSID=abc"))
    @patch("conwrt.handlers_oem.subprocess.run", side_effect=Exception("curl crashed"))
    @patch("conwrt.handlers_oem.os.path.isfile", return_value=True)
    def test_password_check_exception_continues(self, mock_isfile, mock_run, mock_login, mock_prep):
        ctx = _make_ctx(flash_method="oem-http", stock_default_password="1234")
        eq = queue.Queue()
        _handle_oem_login(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_UPLOADING)
