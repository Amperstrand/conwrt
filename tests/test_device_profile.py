"""Tests for device profile builder from model JSON."""
import sys
from pathlib import Path
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.device_profile import build_profile_from_model, find_recovery_flash_method
from model_loader import load_model


class TestFindRecoveryFlashMethod(TestCase):
    def test_hint_overrides_default(self):
        model = load_model("zyxel-gs1920-24")
        name, _ = find_recovery_flash_method(model, method_hint="sysupgrade")
        self.assertEqual(name, "sysupgrade")

    def test_invalid_hint_falls_through_to_default(self):
        model = load_model("zyxel-gs1920-24")
        name, _ = find_recovery_flash_method(model, method_hint="nonexistent-method")
        self.assertEqual(name, "oem-ftp")

    def test_oem_http_preferred_over_sysupgrade(self):
        model = load_model("zyxel-gs1900-8hp-a1")
        name, _ = find_recovery_flash_method(model)
        self.assertEqual(name, "oem-http")

    def test_oem_ftp_preferred_over_sysupgrade(self):
        model = load_model("zyxel-gs1920-24")
        name, _ = find_recovery_flash_method(model)
        self.assertEqual(name, "oem-ftp")

    def test_edgeos_preferred_first(self):
        model = load_model("ubnt-edgerouter-6p")
        name, _ = find_recovery_flash_method(model)
        self.assertEqual(name, "edgeos-kernel-swap")

    def test_returns_method_config(self):
        model = load_model("zyxel-gs1920-24")
        _, cfg = find_recovery_flash_method(model, method_hint="oem-ftp")
        self.assertIn("description", cfg)
        self.assertEqual(cfg["ftp_target"], "ras-0")


class TestProfileForSysupgrade(TestCase):
    def setUp(self):
        self.profile = build_profile_from_model(
            "dlink-covr-x1860-a1", flash_method="sysupgrade"
        )

    def test_flash_method(self):
        self.assertEqual(self.profile.flash_method, "sysupgrade")

    def test_is_oem_false(self):
        self.assertFalse(self.profile.is_oem)

    def test_openwrt_ip(self):
        self.assertEqual(self.profile.openwrt_ip, "192.168.1.1")

    def test_default_flash_time(self):
        self.assertEqual(self.profile.flash_time_seconds, 120)

    def test_vendor(self):
        self.assertEqual(self.profile.vendor, "D-Link")


class TestProfileForEdgeos(TestCase):
    def setUp(self):
        self.profile = build_profile_from_model("ubnt-edgerouter-6p")

    def test_flash_method(self):
        self.assertEqual(self.profile.flash_method, "edgeos-kernel-swap")

    def test_is_edgeos(self):
        self.assertTrue(self.profile.is_edgeos_kernel_swap)

    def test_edgeos_ip(self):
        self.assertEqual(self.profile.edgeos_ip, "192.168.1.1")

    def test_edgeos_credentials(self):
        self.assertEqual(self.profile.edgeos_user, "ubnt")
        self.assertEqual(self.profile.edgeos_password, "ubnt")

    def test_boot_partition(self):
        self.assertEqual(self.profile.boot_partition, "/dev/mmcblk0p1")


class TestProfileForExtreme(TestCase):
    def setUp(self):
        self.profile = build_profile_from_model("extreme-networks-ws-ap3915i")

    def test_flash_method(self):
        self.assertEqual(self.profile.flash_method, "extreme-rdwr-tftp-initramfs")

    def test_is_extreme(self):
        self.assertTrue(self.profile.is_extreme_rdwr_tftp)

    def test_uboot_vars(self):
        self.assertIn("AP_MODE", self.profile.required_uboot_vars)

    def test_bootcmd_flash(self):
        self.assertEqual(self.profile.bootcmd_flash, "run boot_openwrt")

    def test_final_uboot_vars(self):
        self.assertEqual(
            self.profile.final_uboot_vars["bootcmd"], "run boot_openwrt; run boot_net"
        )


class TestProfileDefaults(TestCase):
    def test_all_models_build_without_error(self):
        from model_loader import list_models
        for model_info in list_models():
            profile = build_profile_from_model(model_info["id"])
            self.assertTrue(hasattr(profile, "flash_method"))
            self.assertTrue(hasattr(profile, "recovery_ip"))
            self.assertTrue(hasattr(profile, "openwrt_ip"))
            self.assertEqual(profile.name, model_info["id"])

    def test_default_client_subnet(self):
        profile = build_profile_from_model("zyxel-gs1920-24", flash_method="oem-ftp")
        self.assertEqual(profile.client_subnet, "255.255.255.0")

    def test_default_silence_timeout(self):
        profile = build_profile_from_model("zyxel-gs1920-24", flash_method="oem-ftp")
        self.assertEqual(profile.silence_timeout, 30)
