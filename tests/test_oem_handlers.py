"""Tests for OEM flash method support (oem-http for GS1900-8HP, oem-ftp for GS1920-24)."""
import sys
from pathlib import Path
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.device_profile import build_profile_from_model, find_recovery_flash_method
from flash.context import State
from flash.oem_handlers import zyxel_encode_password, OEM_METHOD_CONFIG
from model_loader import load_model


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
        self.assertEqual(len(enc), 322 - len(pw))

    def test_output_length_long_password(self):
        pw = "Zyxel2026!"
        enc = zyxel_encode_password(pw)
        self.assertEqual(len(enc), 322 - len(pw))

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
