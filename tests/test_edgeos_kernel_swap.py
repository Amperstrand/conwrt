"""Tests for edgeos-kernel-swap flash method support."""
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# Add scripts to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from model_loader import load_model
from flash.device_profile import build_profile_from_model, find_recovery_flash_method
from flash.context import Event, State


class TestEdgeosKernelSwapMethodSelection(unittest.TestCase):
    """Test that edgeos-kernel-swap is selected correctly."""

    def test_default_method_for_er6p(self):
        """Default method for ER-6P should be edgeos-kernel-swap."""
        model = load_model("ubnt-edgerouter-6p")
        name, _ = find_recovery_flash_method(model)
        self.assertEqual(name, "edgeos-kernel-swap")

    def test_explicit_sysupgrade_hint(self):
        """Explicit sysupgrade hint should override default."""
        model = load_model("ubnt-edgerouter-6p")
        name, _ = find_recovery_flash_method(model, method_hint="sysupgrade")
        self.assertEqual(name, "sysupgrade")

    def test_explicit_tftp_hint(self):
        """Explicit tftp hint should override default."""
        model = load_model("ubnt-edgerouter-6p")
        name, _ = find_recovery_flash_method(model, method_hint="tftp")
        self.assertEqual(name, "tftp")


class TestEdgeosKernelSwapProfile(unittest.TestCase):
    """Test profile building for edgeos-kernel-swap."""

    def setUp(self):
        self.profile = build_profile_from_model(
            "ubnt-edgerouter-6p", flash_method="edgeos-kernel-swap"
        )

    def test_flash_method(self):
        self.assertEqual(self.profile.flash_method, "edgeos-kernel-swap")

    def test_is_edgeos_kernel_swap_flag(self):
        self.assertTrue(self.profile.is_edgeos_kernel_swap)

    def test_edgeos_ip(self):
        self.assertEqual(self.profile.edgeos_ip, "192.168.1.1")

    def test_edgeos_user(self):
        self.assertEqual(self.profile.edgeos_user, "ubnt")

    def test_edgeos_password(self):
        self.assertEqual(self.profile.edgeos_password, "ubnt")

    def test_boot_partition(self):
        self.assertEqual(self.profile.boot_partition, "/dev/mmcblk0p1")

    def test_kernel_path(self):
        self.assertEqual(self.profile.kernel_path, "/vmlinux.64")

    def test_md5_path(self):
        self.assertEqual(self.profile.md5_path, "/vmlinux.64.md5")

    def test_port_swap_required(self):
        self.assertTrue(self.profile.port_swap_required)

    def test_openwrt_ip(self):
        self.assertEqual(self.profile.openwrt_ip, "192.168.1.1")

    def test_openwrt_client_ip(self):
        self.assertEqual(self.profile.openwrt_client_ip, "192.168.1.2")

    def test_initramfs_file_pattern(self):
        self.assertIn("initramfs", self.profile.initramfs_file)

    def test_sysupgrade_file_pattern(self):
        self.assertIn("sysupgrade", self.profile.sysupgrade_file)


class TestEdgeosKernelSwapStates(unittest.TestCase):
    """Test that new states and events exist."""

    def test_stage1_state_exists(self):
        self.assertIsNotNone(State.EDGEOS_STAGE1)

    def test_stage1_rebooting_state_exists(self):
        self.assertIsNotNone(State.EDGEOS_STAGE1_REBOOTING)

    def test_port_swap_state_exists(self):
        self.assertIsNotNone(State.EDGEOS_PORT_SWAP)

    def test_stage2_uploading_state_exists(self):
        self.assertIsNotNone(State.EDGEOS_STAGE2_UPLOADING)

    def test_stage2_flashing_state_exists(self):
        self.assertIsNotNone(State.EDGEOS_STAGE2_FLASHING)

    def test_port_swap_done_event_exists(self):
        self.assertIsNotNone(Event.EDGEOS_PORT_SWAP_DONE)


class TestEdgeosDetection(unittest.TestCase):
    """Test EdgeOS boot state detection."""

    @patch("flash.detect.subprocess.run")
    def test_detects_stock_edgeos(self, mock_run):
        """Should return 'stock-edgeos' when EdgeOS SSH responds."""
        from flash.detect import detect_boot_state
        import shutil

        # Mock shutil.which to return sshpass
        with patch.object(shutil, 'which', return_value="/usr/bin/sshpass"):
            mock_run.return_value = MagicMock(returncode=0, stdout="2.0.9-hotfix.7\n")
            profile = SimpleNamespace(
                openwrt_ip="192.168.1.1",
                recovery_ip="192.168.1.20",
                flash_method="edgeos-kernel-swap",
                edgeos_ip="192.168.1.1",
                edgeos_user="ubnt",
                edgeos_password="ubnt",
            )
            result = detect_boot_state("", profile)
            self.assertEqual(result, "stock-edgeos")

    @patch("flash.detect.check_ssh", return_value=True)
    def test_detects_openwrt_over_edgeos(self, mock_ssh):
        """When OpenWrt SSH is up, should return 'openwrt' even with edgeos-kernel-swap."""
        from flash.detect import detect_boot_state

        profile = SimpleNamespace(
            openwrt_ip="192.168.1.1",
            recovery_ip="192.168.1.20",
            flash_method="edgeos-kernel-swap",
            edgeos_ip="192.168.1.1",
            edgeos_user="ubnt",
            edgeos_password="ubnt",
        )
        result = detect_boot_state("", profile)
        self.assertEqual(result, "openwrt")


if __name__ == "__main__":
    unittest.main()
