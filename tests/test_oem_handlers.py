"""Tests for OEM flash method support (oem-http for GS1900-8HP, oem-ftp for GS1920-24)."""
import os
import sys
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.device_profile import build_profile_from_model, find_recovery_flash_method
from flash.context import State
from flash.oem_handlers import (
    zyxel_encode_password,
    OEM_METHOD_CONFIG,
    oem_http_login,
    oem_http_login_v200,
    oem_ftp_login,
    oem_ftp_enable_service,
    oem_ftp_upload,
    oem_http_upload,
    oem_http_accept_reboot,
    install_sysupgrade,
    install_mtd_write,
    _read_xssid_cookie,
)
from model_loader import load_model


def _import_conwrt_handlers():
    from conwrt.handlers_oem import (
        _handle_oem_login,
        _handle_oem_prepare,
        _handle_oem_uploading,
    )
    return (
        _handle_oem_login,
        _handle_oem_prepare,
        _handle_oem_uploading,
    )


class TestOemMethodSelection(TestCase):
    """Test that oem-http and oem-ftp are selected correctly."""

    def test_default_method_gs1900_8hp_a1(self):
        model = load_model("zyxel-gs1900-8hp-a1")
        name, _ = find_recovery_flash_method(model)
        self.assertEqual(name, "oem-http")

    def test_default_method_gs1900_8hp_b1(self):
        model = load_model("zyxel-gs1900-8hp-b1")
        name, _ = find_recovery_flash_method(model)
        self.assertEqual(name, "oem-http")

    def test_default_method_gs1920_24(self):
        model = load_model("zyxel-gs1920-24")
        name, _ = find_recovery_flash_method(model)
        self.assertEqual(name, "oem-ftp")

    def test_explicit_sysupgrade_override(self):
        model = load_model("zyxel-gs1920-24")
        name, _ = find_recovery_flash_method(model, method_hint="sysupgrade")
        self.assertEqual(name, "sysupgrade")

    def test_explicit_oem_http_hint(self):
        model = load_model("zyxel-gs1900-8hp-a1")
        name, _ = find_recovery_flash_method(model, method_hint="oem-http")
        self.assertEqual(name, "oem-http")

    def test_explicit_oem_ftp_hint(self):
        model = load_model("zyxel-gs1920-24")
        name, _ = find_recovery_flash_method(model, method_hint="oem-ftp")
        self.assertEqual(name, "oem-ftp")


class TestOemHttpProfile(TestCase):
    """Test profile building for oem-http (GS1900-8HP A1)."""

    def setUp(self):
        self.profile = build_profile_from_model(
            "zyxel-gs1900-8hp-a1", flash_method="oem-http"
        )

    def test_flash_method(self):
        self.assertEqual(self.profile.flash_method, "oem-http")

    def test_is_oem(self):
        self.assertTrue(self.profile.is_oem)

    def test_stock_default_ip(self):
        self.assertEqual(self.profile.stock_default_ip, "192.168.1.1")

    def test_stock_default_user(self):
        self.assertEqual(self.profile.stock_default_user, "admin")

    def test_stock_default_password_empty(self):
        self.assertEqual(self.profile.stock_default_password, "")

    def test_upload_endpoint(self):
        self.assertEqual(self.profile.upload_endpoint, "/cgi-bin/httpupload.cgi")

    def test_flash_time(self):
        self.assertEqual(self.profile.flash_time_seconds, 90)


class TestOemFtpProfile(TestCase):
    """Test profile building for oem-ftp (GS1920-24)."""

    def setUp(self):
        self.profile = build_profile_from_model(
            "zyxel-gs1920-24", flash_method="oem-ftp"
        )

    def test_flash_method(self):
        self.assertEqual(self.profile.flash_method, "oem-ftp")

    def test_is_oem(self):
        self.assertTrue(self.profile.is_oem)

    def test_stock_default_ip(self):
        self.assertEqual(self.profile.stock_default_ip, "192.168.1.1")

    def test_stock_default_user(self):
        self.assertEqual(self.profile.stock_default_user, "admin")

    def test_stock_default_password(self):
        self.assertEqual(self.profile.stock_default_password, "1234")

    def test_ftp_target(self):
        self.assertEqual(self.profile.oem_ftp_target, "ras-0")

    def test_ftp_active_mode(self):
        self.assertTrue(self.profile.oem_ftp_active_mode)

    def test_flash_time(self):
        self.assertEqual(self.profile.flash_time_seconds, 90)


class TestOemStates(TestCase):
    """Test that OEM states exist in the State enum."""

    def test_oem_login_state_exists(self):
        self.assertEqual(State.OEM_LOGIN.name, "OEM_LOGIN")

    def test_oem_prepare_state_exists(self):
        self.assertEqual(State.OEM_PREPARE.name, "OEM_PREPARE")

    def test_oem_uploading_state_exists(self):
        self.assertEqual(State.OEM_UPLOADING.name, "OEM_UPLOADING")

    def test_oem_rebooting_state_exists(self):
        self.assertEqual(State.OEM_REBOOTING.name, "OEM_REBOOTING")


class TestZyxelEncodePassword(TestCase):
    """Test the ZyXEL V2.80+ password obfuscation function."""

    def test_output_length(self):
        pw = "1234"
        enc = zyxel_encode_password(pw)
        self.assertEqual(len(enc), 321)

    def test_output_length_long_password(self):
        pw = "Zyxel2026!"
        enc = zyxel_encode_password(pw)
        self.assertEqual(len(enc), 321)

    def test_password_chars_embedded(self):
        pw = "abcd"
        enc = zyxel_encode_password(pw)
        # Password chars are at every 5th position backwards
        # remaining starts at len(pw)=4, chars placed at positions 5,10,15,20
        # remaining decrements: 4→3→2→1→0
        # So positions: 5(d), 10(c), 15(b), 20(a)
        self.assertEqual(enc[4], pw[3])  # position 5 (0-indexed: 4) = d
        self.assertEqual(enc[9], pw[2])  # position 10 (0-indexed: 9) = c
        self.assertEqual(enc[14], pw[1])  # position 15 (0-indexed: 14) = b
        self.assertEqual(enc[19], pw[0])  # position 20 (0-indexed: 19) = a

    def test_length_digit_at_position_123(self):
        pw = "12345678"
        enc = zyxel_encode_password(pw)
        # Position 123 (0-indexed: 122): length//10 = 0 for len<10
        self.assertEqual(enc[122], "0")

    def test_length_digit_at_position_123_two_digit(self):
        pw = "1234567890"
        enc = zyxel_encode_password(pw)
        # Position 123 (0-indexed: 122): length//10 = 1 for len=10
        self.assertEqual(enc[122], "1")

    def test_length_digit_at_position_289(self):
        pw = "1234"
        enc = zyxel_encode_password(pw)
        # Position 289 (0-indexed: 288): length % 10 = 4
        self.assertEqual(enc[288], "4")

    def test_only_alphanumeric(self):
        pw = "test"
        enc = zyxel_encode_password(pw)
        self.assertTrue(enc.isalnum(), f"Encoded contains non-alphanumeric: {enc}")

    def test_deterministic_password_positions(self):
        """Two calls produce different random chars but same password chars."""
        pw = "secret"
        enc1 = zyxel_encode_password(pw)
        enc2 = zyxel_encode_password(pw)
        # Password chars at same positions should match
        for i in range(len(enc1)):
            if (i + 1) % 5 == 0 and i < 20:  # first few password positions
                self.assertEqual(enc1[i], enc2[i])
        # Random chars will likely differ
        self.assertNotEqual(enc1, enc2)


class TestOemMethodConfig(TestCase):
    """Test the OEM method dispatch configuration."""

    def test_oem_http_config_exists(self):
        self.assertIn("oem-http", OEM_METHOD_CONFIG)

    def test_oem_ftp_config_exists(self):
        self.assertIn("oem-ftp", OEM_METHOD_CONFIG)

    def test_oem_http_no_prepare_step(self):
        self.assertFalse(OEM_METHOD_CONFIG["oem-http"]["has_prepare"])

    def test_oem_ftp_has_prepare_step(self):
        self.assertTrue(OEM_METHOD_CONFIG["oem-ftp"]["has_prepare"])

    def test_oem_http_uses_sysupgrade_install(self):
        from flash.oem_handlers import install_sysupgrade
        self.assertEqual(OEM_METHOD_CONFIG["oem-http"]["install_fn"], install_sysupgrade)

    def test_oem_ftp_uses_mtd_write_install(self):
        from flash.oem_handlers import install_mtd_write
        self.assertEqual(OEM_METHOD_CONFIG["oem-ftp"]["install_fn"], install_mtd_write)


def _mock_run(stdout="", stderr="", returncode=0):
    return MagicMock(stdout=stdout, stderr=stderr, returncode=returncode)


class TestOemHttpLoginV200(TestCase):
    @patch("flash.oem_handlers.subprocess.run")
    def test_successful_login_extracts_cookie(self, mock_run):
        mock_run.return_value = _mock_run(
            stdout="#HttpOnly_192.168.1.1\tFALSE\t/\tTRUE\t0\tXSSID\tabc123\n"
        )
        success, cookie = oem_http_login_v200("192.168.1.1", "admin", "1234")
        self.assertTrue(success)
        self.assertIn("XSSID=abc123", cookie)

    @patch("flash.oem_handlers.subprocess.run")
    def test_failed_login_returns_false(self, mock_run):
        mock_run.return_value = _mock_run(stdout="Login failed", returncode=1)
        success, msg = oem_http_login_v200("192.168.1.1", "admin", "wrong")
        self.assertFalse(success)

    @patch("flash.oem_handlers.subprocess.run")
    def test_login_sends_credentials_in_url(self, mock_run):
        mock_run.return_value = _mock_run(
            stdout="AUTHING\n#HttpOnly_192.168.1.1\tFALSE\t/\tTRUE\t0\tXSSID\tabc123\n"
        )
        oem_http_login_v200("192.168.1.1", "admin", "1234")
        first_call_args = " ".join(mock_run.call_args_list[0][0][0])
        self.assertIn("username=admin", first_call_args)
        self.assertIn("password=1234", first_call_args)


class TestReadXssidCookie(TestCase):
    def test_reads_http_xssid_from_cookie_jar(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cookies", delete=False) as f:
            f.write("# Netscape HTTP Cookie File\n")
            f.write("#HttpOnly_192.168.1.1\tFALSE\t/cgi-bin/\tFALSE\t0\tHTTP_XSSID\tABCDEF1234567890\n")
            f.flush()
            cookie_path = f.name
        try:
            result = _read_xssid_cookie(cookie_path)
            self.assertEqual(result, "HTTP_XSSID=ABCDEF1234567890")
        finally:
            os.unlink(cookie_path)

    def test_returns_empty_for_no_xssid(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cookies", delete=False) as f:
            f.write("# Netscape HTTP Cookie File\n")
            f.flush()
            cookie_path = f.name
        try:
            result = _read_xssid_cookie(cookie_path)
            self.assertEqual(result, "")
        finally:
            os.unlink(cookie_path)

    def test_returns_empty_for_missing_file(self):
        result = _read_xssid_cookie("/nonexistent/path/cookies.txt")
        self.assertEqual(result, "")


class TestOemHttpLoginV280(TestCase):
    """Tests for oem_http_login V2.80+ encode()-based auth flow."""

    @patch("flash.oem_handlers.log")
    @patch("flash.oem_handlers._read_xssid_cookie", return_value="HTTP_XSSID=AABBCCDD11223344")
    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.tempfile.mktemp", return_value="/tmp/test.cookies")
    @patch("flash.oem_handlers.subprocess.run")
    def test_successful_login_returns_http_xssid_cookie(self, mock_run, mock_mktemp, mock_sleep, mock_read_cookie, mock_log):
        mock_run.side_effect = [
            _mock_run(stdout="FAE885CD12345678ABCDEF0123456789"),
            _mock_run(stdout="OK"),
        ]
        success, cookie = oem_http_login("192.168.1.1", "admin", "Zyxel2026!")
        self.assertTrue(success)
        self.assertEqual(cookie, "HTTP_XSSID=AABBCCDD11223344")

    @patch("flash.oem_handlers.log")
    @patch("flash.oem_handlers._read_xssid_cookie", return_value="HTTP_XSSID=AA")
    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.tempfile.mktemp", return_value="/tmp/test.cookies")
    @patch("flash.oem_handlers.subprocess.run")
    def test_login_sends_encoded_password(self, mock_run, mock_mktemp, mock_sleep, mock_read_cookie, mock_log):
        mock_run.side_effect = [
            _mock_run(stdout="AABBCCDD12345678ABCDEF0123456789"),
            _mock_run(stdout="OK"),
        ]
        oem_http_login("192.168.1.1", "admin", "test_pw")
        login_call_args = " ".join(mock_run.call_args_list[0][0][0])
        self.assertIn("username=admin", login_call_args)
        self.assertIn("login=true", login_call_args)

    @patch("flash.oem_handlers.log")
    @patch("flash.oem_handlers._read_xssid_cookie", return_value="HTTP_XSSID=AA")
    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.tempfile.mktemp", return_value="/tmp/test.cookies")
    @patch("flash.oem_handlers.subprocess.run")
    def test_login_waits_500ms_before_login_chk(self, mock_run, mock_mktemp, mock_sleep, mock_read_cookie, mock_log):
        mock_run.side_effect = [
            _mock_run(stdout="AABBCCDD12345678ABCDEF0123456789"),
            _mock_run(stdout="OK"),
        ]
        oem_http_login("192.168.1.1", "admin", "test_pw")
        mock_sleep.assert_called_once_with(0.5)

    @patch("flash.oem_handlers.log")
    @patch("flash.oem_handlers._read_xssid_cookie", return_value="HTTP_XSSID=AA")
    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.tempfile.mktemp", return_value="/tmp/test.cookies")
    @patch("flash.oem_handlers.subprocess.run")
    def test_login_chk_sends_auth_id_and_cookie_jar(self, mock_run, mock_mktemp, mock_sleep, mock_read_cookie, mock_log):
        mock_run.side_effect = [
            _mock_run(stdout="DEADBEEF12345678"),
            _mock_run(stdout="OK"),
        ]
        oem_http_login("192.168.1.1", "admin", "pw")
        chk_args = " ".join(mock_run.call_args_list[1][0][0])
        self.assertIn("authId=DEADBEEF12345678", chk_args)
        self.assertIn("login_chk=true", chk_args)
        self.assertIn("-c", chk_args)
        self.assertIn("/tmp/test.cookies", chk_args)

    @patch("flash.oem_handlers.log")
    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.tempfile.mktemp", return_value="/tmp/test.cookies")
    @patch("flash.oem_handlers.subprocess.run")
    def test_fail_response_tries_v200_fallback(self, mock_run, mock_mktemp, mock_sleep, mock_log):
        mock_run.side_effect = [
            _mock_run(stdout="DEADBEEF12345678"),
            _mock_run(stdout="FAIL"),
            _mock_run(stdout="#HttpOnly_\tFALSE\t/\tTRUE\t0\tXSSID\tfallback\n"),
        ]
        success, cookie = oem_http_login("192.168.1.1", "admin", "wrong")
        self.assertTrue(success)
        self.assertIn("XSSID=fallback", cookie)

    @patch("flash.oem_handlers.log")
    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.tempfile.mktemp", return_value="/tmp/test.cookies")
    @patch("flash.oem_handlers.subprocess.run")
    def test_no_auth_id_tries_v200_fallback(self, mock_run, mock_mktemp, mock_sleep, mock_log):
        mock_run.side_effect = [
            _mock_run(stdout="not_a_hash"),
            _mock_run(stdout="#HttpOnly_\tFALSE\t/\tTRUE\t0\tXSSID\tfallback\n"),
        ]
        success, cookie = oem_http_login("192.168.1.1", "admin", "pw")
        self.assertTrue(success)
        self.assertIn("XSSID=fallback", cookie)

    @patch("flash.oem_handlers.log")
    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.tempfile.mktemp", return_value="/tmp/test.cookies")
    @patch("flash.oem_handlers.subprocess.run")
    def test_authing_response_tries_v200_fallback(self, mock_run, mock_mktemp, mock_sleep, mock_log):
        mock_run.side_effect = [
            _mock_run(stdout="AUTHING"),
            _mock_run(stdout="#HttpOnly_\tFALSE\t/\tTRUE\t0\tXSSID\tv200\n"),
        ]
        success, cookie = oem_http_login("192.168.1.1", "admin", "pw")
        self.assertTrue(success)
        self.assertIn("XSSID=v200", cookie)


class TestOemFtpLogin(TestCase):
    @patch("flash.oem_handlers.subprocess.run")
    def test_successful_login_returns_cookie_file(self, mock_run):
        mock_run.return_value = _mock_run(stdout="200")
        success, result = oem_ftp_login("192.168.1.1", "admin", "1234")
        self.assertTrue(success)
        self.assertTrue(result.endswith(".cookies") or len(result) > 0)

    @patch("flash.oem_handlers.subprocess.run")
    def test_login_posts_credentials(self, mock_run):
        mock_run.return_value = _mock_run(stdout="200")
        oem_ftp_login("192.168.1.1", "admin", "1234")
        call_args = " ".join(mock_run.call_args[0][0])
        self.assertIn("Username=admin", call_args)
        self.assertIn("Password=1234", call_args)

    @patch("flash.oem_handlers.subprocess.run")
    def test_failed_login_returns_error(self, mock_run):
        mock_run.return_value = _mock_run(stdout="403", returncode=1)
        success, msg = oem_ftp_login("192.168.1.1", "admin", "wrong")
        self.assertFalse(success)


class TestOemFtpEnableService(TestCase):
    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.subprocess.run")
    def test_enable_returns_true_on_200(self, mock_run, mock_sleep):
        mock_run.return_value = _mock_run(stdout="200")
        success, msg = oem_ftp_enable_service("192.168.1.1", "/tmp/cookies.txt")
        self.assertTrue(success)
        self.assertIn("200", msg)

    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.subprocess.run")
    def test_enable_returns_true_on_303(self, mock_run, mock_sleep):
        mock_run.return_value = _mock_run(stdout="303")
        success, msg = oem_ftp_enable_service("192.168.1.1", "/tmp/cookies.txt")
        self.assertTrue(success)

    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.subprocess.run")
    def test_enable_posts_ftp_checkbox(self, mock_run, mock_sleep):
        mock_run.return_value = _mock_run(stdout="200")
        oem_ftp_enable_service("192.168.1.1", "/tmp/cookies.txt")
        call_args = " ".join(mock_run.call_args[0][0])
        self.assertIn("RpAccessSv_ChkFTP=on", call_args)


class TestOemFtpUpload(TestCase):
    @patch("flash.oem_handlers.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.oem_handlers.subprocess.run")
    def test_upload_success_on_226(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(
            stdout="", stderr="226 Transfer complete"
        )
        success, msg = oem_ftp_upload(
            "192.168.1.1", "admin", "1234",
            "/tmp/firmware.bin", target="ras-0"
        )
        self.assertTrue(success)

    @patch("flash.oem_handlers.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.oem_handlers.subprocess.run")
    def test_upload_url_contains_target(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(stdout="", stderr="226 OK")
        oem_ftp_upload(
            "192.168.1.1", "admin", "1234",
            "/tmp/firmware.bin", target="ras-0"
        )
        call_args = " ".join(mock_run.call_args[0][0])
        self.assertIn("ras-0", call_args)
        self.assertNotIn("ras-1", call_args)

    @patch("flash.oem_handlers.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.oem_handlers.subprocess.run")
    def test_upload_uses_active_mode_with_client_ip(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(stdout="", stderr="226 OK")
        oem_ftp_upload(
            "192.168.1.1", "admin", "1234",
            "/tmp/firmware.bin", target="ras-0",
            client_ip="192.168.1.2"
        )
        call_args = " ".join(mock_run.call_args[0][0])
        self.assertIn("--ftp-port", call_args)
        self.assertIn("192.168.1.2", call_args)

    @patch("flash.oem_handlers.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.oem_handlers.subprocess.run")
    def test_upload_failure_returns_false(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(
            stdout="", stderr="500 Error", returncode=1
        )
        success, msg = oem_ftp_upload(
            "192.168.1.1", "admin", "1234",
            "/tmp/firmware.bin", target="ras-0"
        )
        self.assertFalse(success)


class TestOemHttpUpload(TestCase):
    @patch("flash.oem_handlers.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.oem_handlers.subprocess.run")
    def test_upload_success_writing_to_flash(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(stdout="Writing image to FLASH")
        success, msg = oem_http_upload(
            "192.168.1.1", "XSSID=abc", "/tmp/fw.bin",
            "/cgi-bin/httpupload.cgi"
        )
        self.assertTrue(success)

    @patch("flash.oem_handlers.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.oem_handlers.subprocess.run")
    def test_upload_sends_cookie(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(stdout="OK")
        oem_http_upload(
            "192.168.1.1", "XSSID=test123", "/tmp/fw.bin",
            "/cgi-bin/httpupload.cgi"
        )
        call_args = mock_run.call_args[0][0]
        self.assertIn("-b", call_args)
        self.assertIn("XSSID=test123", call_args)

    @patch("flash.oem_handlers.os.path.getsize", return_value=5*1024*1024)
    @patch("flash.oem_handlers.subprocess.run")
    def test_upload_failure_returns_false(self, mock_run, mock_size):
        mock_run.return_value = _mock_run(
            stdout="", stderr="Connection refused", returncode=7
        )
        success, msg = oem_http_upload(
            "192.168.1.1", "XSSID=abc", "/tmp/fw.bin",
            "/cgi-bin/httpupload.cgi"
        )
        self.assertFalse(success)


class TestOemHttpAcceptReboot(TestCase):
    @patch("flash.oem_handlers.subprocess.run")
    def test_reboot_returns_true_on_success(self, mock_run):
        mock_run.return_value = _mock_run(stdout="Rebooting now")
        result = oem_http_accept_reboot("192.168.1.1", "XSSID=abc")
        self.assertTrue(result)

    @patch("flash.oem_handlers.subprocess.run")
    def test_reboot_sends_reboot_param(self, mock_run):
        mock_run.return_value = _mock_run(stdout="OK")
        oem_http_accept_reboot("192.168.1.1", "XSSID=abc")
        call_args = " ".join(mock_run.call_args[0][0])
        self.assertIn("reboot=1", call_args)


class TestInstallSysupgrade(TestCase):
    @patch("flash.oem_handlers.subprocess.run", return_value=_mock_run())
    def test_install_scp_and_sysupgrade(self, mock_run):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 1024)
            tmp_path = f.name
        try:
            ctx = MagicMock()
            ctx.image_path = tmp_path
            ctx.ssh_key_path = ""
            result = install_sysupgrade(ctx, "192.168.1.1")
            self.assertTrue(result)
            self.assertEqual(mock_run.call_count, 2)
        finally:
            os.unlink(tmp_path)

    @patch("flash.oem_handlers.subprocess.run")
    def test_install_fails_on_scp_error(self, mock_run):
        mock_run.return_value = _mock_run(stderr="Permission denied", returncode=1)
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 1024)
            tmp_path = f.name
        try:
            ctx = MagicMock()
            ctx.image_path = tmp_path
            ctx.ssh_key_path = ""
            result = install_sysupgrade(ctx, "192.168.1.1")
            self.assertFalse(result)
        finally:
            os.unlink(tmp_path)


class TestInstallMtdWrite(TestCase):
    @patch("flash.oem_handlers.subprocess.run", return_value=_mock_run())
    def test_install_with_loader(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            sysupgrade = os.path.join(tmpdir, "sysupgrade.bin")
            loader = os.path.join(tmpdir, "loader.bin")
            with open(sysupgrade, "wb") as f:
                f.write(b"\x00" * 1024)
            with open(loader, "wb") as f:
                f.write(b"\x00" * 512)

            ctx = MagicMock()
            ctx.image_path = sysupgrade
            ctx.ssh_key_path = ""
            result = install_mtd_write(ctx, "192.168.1.1")
            self.assertTrue(result)
            self.assertEqual(mock_run.call_count, 3)

            last_call_args = " ".join(mock_run.call_args_list[-1][0][0])
            self.assertIn("mtd write /tmp/loader.bin loader", last_call_args)
            self.assertIn("mtd -r write /tmp/sysupgrade.bin firmware", last_call_args)

    @patch("flash.oem_handlers.subprocess.run", return_value=_mock_run())
    def test_install_without_loader(self, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            sysupgrade = os.path.join(tmpdir, "sysupgrade.bin")
            with open(sysupgrade, "wb") as f:
                f.write(b"\x00" * 1024)

            ctx = MagicMock()
            ctx.image_path = sysupgrade
            ctx.ssh_key_path = ""
            result = install_mtd_write(ctx, "192.168.1.1")
            self.assertTrue(result)
            self.assertEqual(mock_run.call_count, 2)

            last_call_args = " ".join(mock_run.call_args_list[-1][0][0])
            self.assertNotIn("loader.bin", last_call_args)
            self.assertIn("mtd -r write /tmp/sysupgrade.bin firmware", last_call_args)


class TestOemHttpStateTransitions(TestCase):
    def setUp(self):
        self._handle_oem_login, self._handle_oem_prepare, self._handle_oem_uploading = _import_conwrt_handlers()

    @patch("flash.oem_handlers.subprocess.run")
    @patch("conwrt.handlers_oem.load_model")
    def test_login_success_transitions_to_uploading(self, mock_load_model, mock_run):
        mock_load_model.return_value = {
            "stock_default_creds": {"username": "admin", "password": "1234"}
        }
        mock_run.return_value = _mock_run(
            stdout="AABBCCDD11223344\n#HttpOnly_192.168.1.1\tFALSE\t/\tTRUE\t0\tXSSID\tabc\nOK\nXSSID\tabc\n"
        )

        profile = build_profile_from_model("zyxel-gs1900-8hp-a1", flash_method="oem-http")
        ctx = MagicMock()
        ctx.profile = profile
        ctx.state = State.OEM_LOGIN
        ctx.initramfs_path = "/tmp/initramfs.bin"
        ctx.oem_state = {}
        with patch("os.path.isfile", return_value=True):
            self._handle_oem_login(ctx, MagicMock())

        self.assertEqual(ctx.state, State.OEM_UPLOADING)
        self.assertIn("cookie", ctx.oem_state)

    @patch("flash.oem_handlers.subprocess.run")
    @patch("conwrt.handlers_oem.load_model")
    def test_login_failure_transitions_to_failed(self, mock_load_model, mock_run):
        mock_load_model.return_value = {
            "stock_default_creds": {"username": "admin", "password": "1234"}
        }
        mock_run.return_value = _mock_run(stdout="Login failed", returncode=1)

        profile = build_profile_from_model("zyxel-gs1900-8hp-a1", flash_method="oem-http")
        ctx = MagicMock()
        ctx.profile = profile
        ctx.state = State.OEM_LOGIN
        ctx.initramfs_path = "/tmp/initramfs.bin"
        ctx.oem_state = {}
        with patch("os.path.isfile", return_value=True):
            self._handle_oem_login(ctx, MagicMock())

        self.assertEqual(ctx.state, State.FAILED)

    @patch("flash.oem_handlers.subprocess.run")
    @patch("flash.oem_handlers.os.path.getsize", return_value=5*1024*1024)
    def test_uploading_success_transitions_to_rebooting(self, mock_size, mock_run):
        mock_run.return_value = _mock_run(stdout="Writing image to FLASH")
        profile = build_profile_from_model("zyxel-gs1900-8hp-a1", flash_method="oem-http")
        ctx = MagicMock()
        ctx.profile = profile
        ctx.state = State.OEM_UPLOADING
        ctx.oem_state = {"cookie": "XSSID=abc"}
        ctx.initramfs_path = "/tmp/initramfs.bin"

        with patch("os.path.isfile", return_value=True):
            self._handle_oem_uploading(ctx, MagicMock())

        self.assertEqual(ctx.state, State.OEM_REBOOTING)

    @patch("flash.oem_handlers.subprocess.run")
    @patch("flash.oem_handlers.os.path.getsize", return_value=5*1024*1024)
    def test_uploading_failure_transitions_to_failed(self, mock_size, mock_run):
        mock_run.return_value = _mock_run(stderr="Connection refused", returncode=7)
        profile = build_profile_from_model("zyxel-gs1900-8hp-a1", flash_method="oem-http")
        ctx = MagicMock()
        ctx.profile = profile
        ctx.state = State.OEM_UPLOADING
        ctx.oem_state = {"cookie": "XSSID=abc"}
        ctx.initramfs_path = "/tmp/initramfs.bin"

        with patch("os.path.isfile", return_value=True):
            self._handle_oem_uploading(ctx, MagicMock())

        self.assertEqual(ctx.state, State.FAILED)


class TestOemFtpStateTransitions(TestCase):
    def setUp(self):
        self._handle_oem_login, self._handle_oem_prepare, self._handle_oem_uploading = _import_conwrt_handlers()

    @patch("flash.oem_handlers.subprocess.run")
    def test_login_success_transitions_to_prepare(self, mock_run):
        mock_run.return_value = _mock_run(stdout="200")

        profile = build_profile_from_model("zyxel-gs1920-24", flash_method="oem-ftp")
        ctx = MagicMock()
        ctx.profile = profile
        ctx.state = State.OEM_LOGIN
        ctx.initramfs_path = "/tmp/initramfs.bin"
        ctx.oem_state = {}

        with patch("os.path.isfile", return_value=True):
            self._handle_oem_login(ctx, MagicMock())

        self.assertEqual(ctx.state, State.OEM_PREPARE)
        self.assertIn("cookie_file", ctx.oem_state)

    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.subprocess.run")
    def test_prepare_success_transitions_to_uploading(self, mock_run, mock_sleep):
        mock_run.return_value = _mock_run(stdout="200")

        profile = build_profile_from_model("zyxel-gs1920-24", flash_method="oem-ftp")
        ctx = MagicMock()
        ctx.profile = profile
        ctx.state = State.OEM_PREPARE
        ctx.oem_state = {"cookie_file": "/tmp/cookies.txt"}

        self._handle_oem_prepare(ctx, MagicMock())

        self.assertEqual(ctx.state, State.OEM_UPLOADING)

    @patch("flash.oem_handlers.time.sleep")
    @patch("flash.oem_handlers.subprocess.run")
    def test_prepare_failure_transitions_to_failed(self, mock_run, mock_sleep):
        mock_run.return_value = _mock_run(stdout="500", returncode=1)

        profile = build_profile_from_model("zyxel-gs1920-24", flash_method="oem-ftp")
        ctx = MagicMock()
        ctx.profile = profile
        ctx.state = State.OEM_PREPARE
        ctx.oem_state = {"cookie_file": "/tmp/cookies.txt"}

        self._handle_oem_prepare(ctx, MagicMock())

        self.assertEqual(ctx.state, State.FAILED)

    @patch("flash.oem_handlers.subprocess.run")
    @patch("flash.oem_handlers.os.path.getsize", return_value=5*1024*1024)
    def test_uploading_success_transitions_to_rebooting(self, mock_size, mock_run):
        mock_run.return_value = _mock_run(stdout="", stderr="226 Transfer complete")
        profile = build_profile_from_model("zyxel-gs1920-24", flash_method="oem-ftp")
        ctx = MagicMock()
        ctx.profile = profile
        ctx.state = State.OEM_UPLOADING
        ctx.oem_state = {"password": "1234"}
        ctx.initramfs_path = "/tmp/initramfs.bin"

        with patch("os.path.isfile", return_value=True):
            self._handle_oem_uploading(ctx, MagicMock())

        self.assertEqual(ctx.state, State.OEM_REBOOTING)
