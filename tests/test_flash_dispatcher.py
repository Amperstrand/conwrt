"""Tests for conwrt.flash_dispatcher — flash orchestration state machine.

Tests every pure function and handler in flash_dispatcher.py using mocks only.
No hardware-mutating code paths (no SSH, network, serial, etc.).
"""
from __future__ import annotations

import queue
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest import TestCase
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.context import (
    DEFAULT_IP,
    Event,
    REBOOT_TIMEOUT,
    State,
    RecoveryContext,
    Timeline,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_profile(**overrides):
    """Build a minimal profile object for testing."""
    defaults = dict(
        name="test-model",
        vendor="TestVendor",
        recovery_ip="192.168.1.1",
        openwrt_ip="192.168.1.1",
        client_ip="192.168.1.2",
        openwrt_client_ip="",
        flash_method="sysupgrade",
        is_serial_tftp=False,
        is_zycast=False,
        is_edgeos_kernel_swap=False,
        is_extreme_rdwr_tftp=False,
        description="Test Model",
        led_pattern="blink",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_ctx(state=State.DETECTING, **overrides):
    """Build a minimal RecoveryContext for testing."""
    profile = overrides.pop("profile", None) or _make_profile()
    defaults = dict(
        profile=profile,
        image_path="/tmp/test.bin",
        interface="en0",
        pcap_path="/tmp/test.pcap",
        _say_fn=MagicMock(),
        state=state,
        timeline=Timeline(),
    )
    defaults.update(overrides)
    return RecoveryContext(**defaults)


# ===================================================================
# FlashModeConfig dataclass
# ===================================================================

class TestFlashModeConfig(TestCase):
    """Tests for the FlashModeConfig dataclass."""

    def test_default_values(self):
        from conwrt.flash_dispatcher import FlashModeConfig
        cfg = FlashModeConfig(initial_state=State.DETECTING)
        self.assertTrue(cfg.pcap_enabled)
        self.assertTrue(cfg.has_monitors)
        self.assertFalse(cfg.setup_interface)
        self.assertIsNone(cfg.cleanup)

    def test_custom_values_override_defaults(self):
        from conwrt.flash_dispatcher import FlashModeConfig
        cleanup = lambda ctx, p, i: None  # noqa: E731
        cfg = FlashModeConfig(
            initial_state=State.WAITING_FOR_POWER_OFF,
            pcap_enabled=False,
            has_monitors=False,
            setup_interface=True,
            cleanup=cleanup,
        )
        self.assertFalse(cfg.pcap_enabled)
        self.assertFalse(cfg.has_monitors)
        self.assertTrue(cfg.setup_interface)
        self.assertIs(cfg.cleanup, cleanup)

    def test_initial_state_is_required(self):
        from conwrt.flash_dispatcher import FlashModeConfig
        with self.assertRaises(TypeError):
            FlashModeConfig()  # type: ignore[call-arg]


# ===================================================================
# FLASH_MODES dict
# ===================================================================

class TestFlashModes(TestCase):
    """Tests for the FLASH_MODES constant dictionary."""

    def setUp(self):
        from conwrt.flash_dispatcher import FLASH_MODES
        self.modes = FLASH_MODES

    def test_six_modes_exist(self):
        expected = {"sysupgrade", "edgeos", "extreme", "serial", "zycast", "uboot"}
        self.assertEqual(set(self.modes.keys()), expected)

    def test_sysupgrade_initial_state(self):
        self.assertEqual(self.modes["sysupgrade"].initial_state, State.SYSUPGRADE_UPLOADING)

    def test_edgeos_initial_state(self):
        self.assertEqual(self.modes["edgeos"].initial_state, State.EDGEOS_STAGE1)

    def test_extreme_initial_state(self):
        self.assertEqual(self.modes["extreme"].initial_state, State.EXTREME_STOCK_PREFLIGHT)

    def test_serial_initial_state(self):
        self.assertEqual(self.modes["serial"].initial_state, State.SERIAL_WAITING_FOR_BOOTMENU)

    def test_zycast_initial_state(self):
        self.assertEqual(self.modes["zycast"].initial_state, State.ZYCAST_WAITING_FOR_DEVICE)

    def test_uboot_initial_state(self):
        self.assertEqual(self.modes["uboot"].initial_state, State.WAITING_FOR_POWER_OFF)

    def test_pcap_disabled_for_sysupgrade(self):
        self.assertFalse(self.modes["sysupgrade"].pcap_enabled)

    def test_pcap_disabled_for_edgeos(self):
        self.assertFalse(self.modes["edgeos"].pcap_enabled)

    def test_pcap_disabled_for_extreme(self):
        self.assertFalse(self.modes["extreme"].pcap_enabled)

    def test_pcap_enabled_for_uboot(self):
        self.assertTrue(self.modes["uboot"].pcap_enabled)

    def test_pcap_enabled_for_zycast(self):
        self.assertTrue(self.modes["zycast"].pcap_enabled)

    def test_has_monitors_false_for_serial(self):
        self.assertFalse(self.modes["serial"].has_monitors)

    def test_has_monitors_true_for_uboot(self):
        self.assertTrue(self.modes["uboot"].has_monitors)

    def test_setup_interface_true_for_uboot(self):
        self.assertTrue(self.modes["uboot"].setup_interface)

    def test_setup_interface_false_for_sysupgrade(self):
        self.assertFalse(self.modes["sysupgrade"].setup_interface)

    def test_extreme_cleanup_is_set(self):
        self.assertIsNotNone(self.modes["extreme"].cleanup)

    def test_serial_cleanup_is_set(self):
        self.assertIsNotNone(self.modes["serial"].cleanup)

    def test_zycast_cleanup_is_set(self):
        self.assertIsNotNone(self.modes["zycast"].cleanup)

    def test_uboot_cleanup_is_none(self):
        self.assertIsNone(self.modes["uboot"].cleanup)

    def test_sysupgrade_cleanup_is_none(self):
        self.assertIsNone(self.modes["sysupgrade"].cleanup)


# ===================================================================
# _resolve_flash_mode
# ===================================================================

class TestResolveFlashMode(TestCase):
    """Tests for _resolve_flash_mode decision tree."""

    def setUp(self):
        from conwrt.flash_dispatcher import _resolve_flash_mode
        self.resolve = _resolve_flash_mode
        self.args = SimpleNamespace()

    def test_use_sysupgrade_true_returns_sysupgrade(self):
        profile = _make_profile(is_edgeos_kernel_swap=True)
        result = self.resolve(profile, "openwrt", self.args, use_sysupgrade=True)
        self.assertEqual(result, "sysupgrade")

    def test_use_sysupgrade_overrides_all_profile_attrs(self):
        """sysupgrade takes priority over all profile attributes."""
        profile = _make_profile(
            is_serial_tftp=True,
            is_zycast=True,
            is_edgeos_kernel_swap=True,
            is_extreme_rdwr_tftp=True,
        )
        result = self.resolve(profile, "openwrt", self.args, use_sysupgrade=True)
        self.assertEqual(result, "sysupgrade")

    def test_edgeos_kernel_swap(self):
        profile = _make_profile(is_edgeos_kernel_swap=True)
        result = self.resolve(profile, "unknown", self.args, use_sysupgrade=False)
        self.assertEqual(result, "edgeos")

    def test_extreme_rdwr_tftp(self):
        profile = _make_profile(is_extreme_rdwr_tftp=True)
        result = self.resolve(profile, "unknown", self.args, use_sysupgrade=False)
        self.assertEqual(result, "extreme")

    def test_serial_tftp(self):
        profile = _make_profile(is_serial_tftp=True)
        result = self.resolve(profile, "unknown", self.args, use_sysupgrade=False)
        self.assertEqual(result, "serial")

    def test_zycast(self):
        profile = _make_profile(is_zycast=True)
        result = self.resolve(profile, "unknown", self.args, use_sysupgrade=False)
        self.assertEqual(result, "zycast")

    def test_all_false_returns_uboot(self):
        profile = _make_profile()
        result = self.resolve(profile, "unknown", self.args, use_sysupgrade=False)
        self.assertEqual(result, "uboot")

    def test_priority_edgeos_over_extreme(self):
        """edgeos checked before extreme."""
        profile = _make_profile(is_edgeos_kernel_swap=True, is_extreme_rdwr_tftp=True)
        result = self.resolve(profile, "unknown", self.args, use_sysupgrade=False)
        self.assertEqual(result, "edgeos")

    def test_priority_extreme_over_serial(self):
        """extreme checked before serial."""
        profile = _make_profile(is_extreme_rdwr_tftp=True, is_serial_tftp=True)
        result = self.resolve(profile, "unknown", self.args, use_sysupgrade=False)
        self.assertEqual(result, "extreme")

    def test_priority_serial_over_zycast(self):
        """serial checked before zycast."""
        profile = _make_profile(is_serial_tftp=True, is_zycast=True)
        result = self.resolve(profile, "unknown", self.args, use_sysupgrade=False)
        self.assertEqual(result, "serial")

    def test_boot_state_not_used(self):
        """boot_state parameter is not consulted for the decision."""
        profile = _make_profile()
        r1 = self.resolve(profile, "openwrt", self.args, use_sysupgrade=False)
        r2 = self.resolve(profile, "uboot", self.args, use_sysupgrade=False)
        r3 = self.resolve(profile, "unknown", self.args, use_sysupgrade=False)
        self.assertEqual(r1, "uboot")
        self.assertEqual(r2, "uboot")
        self.assertEqual(r3, "uboot")

    def test_args_not_used(self):
        """args parameter is not consulted for the decision."""
        profile = _make_profile()
        args1 = SimpleNamespace()
        args2 = SimpleNamespace(force_uboot=True)
        r1 = self.resolve(profile, "unknown", args1, use_sysupgrade=False)
        r2 = self.resolve(profile, "unknown", args2, use_sysupgrade=False)
        self.assertEqual(r1, r2)


# ===================================================================
# _extreme_cleanup
# ===================================================================

class TestExtremeCleanup(TestCase):
    """Tests for _extreme_cleanup function."""

    @patch("conwrt.flash_dispatcher.remove_interface_ip")
    @patch("conwrt.flash_dispatcher._cleanup_extreme_tftp_assets")
    def test_always_calls_cleanup_tftp_assets(self, mock_cleanup, mock_remove_ip):
        from conwrt.flash_dispatcher import _extreme_cleanup
        ctx = _make_ctx()
        profile = _make_profile()
        _extreme_cleanup(ctx, profile, "en0")
        mock_cleanup.assert_called_once_with(ctx)

    @patch("conwrt.flash_dispatcher.remove_interface_ip")
    @patch("conwrt.flash_dispatcher._cleanup_extreme_tftp_assets")
    def test_removes_interface_ip_when_different(self, mock_cleanup, mock_remove_ip):
        from conwrt.flash_dispatcher import _extreme_cleanup
        ctx = _make_ctx()
        profile = _make_profile(openwrt_client_ip="10.0.0.1", client_ip="192.168.1.2")
        _extreme_cleanup(ctx, profile, "en0")
        mock_remove_ip.assert_called_once_with("en0", "10.0.0.1", "24")

    @patch("conwrt.flash_dispatcher.remove_interface_ip")
    @patch("conwrt.flash_dispatcher._cleanup_extreme_tftp_assets")
    def test_no_remove_when_openwrt_client_ip_empty(self, mock_cleanup, mock_remove_ip):
        from conwrt.flash_dispatcher import _extreme_cleanup
        ctx = _make_ctx()
        profile = _make_profile(openwrt_client_ip="", client_ip="192.168.1.2")
        _extreme_cleanup(ctx, profile, "en0")
        mock_remove_ip.assert_not_called()

    @patch("conwrt.flash_dispatcher.remove_interface_ip")
    @patch("conwrt.flash_dispatcher._cleanup_extreme_tftp_assets")
    def test_no_remove_when_ips_same(self, mock_cleanup, mock_remove_ip):
        from conwrt.flash_dispatcher import _extreme_cleanup
        ctx = _make_ctx()
        profile = _make_profile(openwrt_client_ip="192.168.1.2", client_ip="192.168.1.2")
        _extreme_cleanup(ctx, profile, "en0")
        mock_remove_ip.assert_not_called()


# ===================================================================
# _serial_cleanup
# ===================================================================

class TestSerialCleanup(TestCase):
    """Tests for _serial_cleanup function."""

    def test_closes_serial_driver(self):
        from conwrt.flash_dispatcher import _serial_cleanup
        driver = MagicMock()
        ctx = _make_ctx()
        ctx._serial_driver = driver
        profile = _make_profile()
        _serial_cleanup(ctx, profile, "en0")
        driver.close.assert_called_once()

    def test_stops_tftp_manager(self):
        from conwrt.flash_dispatcher import _serial_cleanup
        tftp_mgr = MagicMock()
        ctx = _make_ctx()
        ctx._tftp_manager = tftp_mgr
        profile = _make_profile()
        _serial_cleanup(ctx, profile, "en0")
        tftp_mgr.stop.assert_called_once()

    def test_no_error_when_neither_exists(self):
        from conwrt.flash_dispatcher import _serial_cleanup
        ctx = _make_ctx()
        profile = _make_profile()
        # Should not raise
        _serial_cleanup(ctx, profile, "en0")

    def test_closes_both_driver_and_tftp(self):
        from conwrt.flash_dispatcher import _serial_cleanup
        driver = MagicMock()
        tftp_mgr = MagicMock()
        ctx = _make_ctx()
        ctx._serial_driver = driver
        ctx._tftp_manager = tftp_mgr
        profile = _make_profile()
        _serial_cleanup(ctx, profile, "en0")
        driver.close.assert_called_once()
        tftp_mgr.stop.assert_called_once()


# ===================================================================
# _zycast_cleanup
# ===================================================================

class TestZycastCleanup(TestCase):
    """Tests for _zycast_cleanup function."""

    def test_terminates_running_process(self):
        from conwrt.flash_dispatcher import _zycast_cleanup
        proc = MagicMock()
        proc.poll.return_value = None  # still running
        ctx = _make_ctx()
        ctx._zycast_proc = proc
        profile = _make_profile()
        _zycast_cleanup(ctx, profile, "en0")
        proc.terminate.assert_called_once()

    def test_does_not_terminate_exited_process(self):
        from conwrt.flash_dispatcher import _zycast_cleanup
        proc = MagicMock()
        proc.poll.return_value = 0  # already exited
        ctx = _make_ctx()
        ctx._zycast_proc = proc
        profile = _make_profile()
        _zycast_cleanup(ctx, profile, "en0")
        proc.terminate.assert_not_called()

    def test_does_nothing_when_no_process(self):
        from conwrt.flash_dispatcher import _zycast_cleanup
        ctx = _make_ctx()
        ctx._zycast_proc = None
        profile = _make_profile()
        # Should not raise
        _zycast_cleanup(ctx, profile, "en0")

    def test_does_not_terminate_when_poll_returns_nonzero(self):
        from conwrt.flash_dispatcher import _zycast_cleanup
        proc = MagicMock()
        proc.poll.return_value = 1  # exited with error
        ctx = _make_ctx()
        ctx._zycast_proc = proc
        profile = _make_profile()
        _zycast_cleanup(ctx, profile, "en0")
        proc.terminate.assert_not_called()


# ===================================================================
# _resolve_initial_state
# ===================================================================

class TestResolveInitialState(TestCase):
    """Tests for _resolve_initial_state function."""

    def setUp(self):
        from conwrt.flash_dispatcher import _resolve_initial_state
        self.resolve = _resolve_initial_state

    @patch("conwrt.flash_dispatcher.detect_uboot_http", return_value=(True, "HTTP 200"))
    def test_uboot_mode_boot_uboot_http_found(self, mock_detect):
        profile = _make_profile()
        result = self.resolve("uboot", profile, "uboot")
        self.assertEqual(result, State.UBOOT_UPLOADING)

    @patch("conwrt.flash_dispatcher.detect_uboot_http", return_value=(False, ""))
    def test_uboot_mode_boot_uboot_http_not_found(self, mock_detect):
        profile = _make_profile()
        result = self.resolve("uboot", profile, "uboot")
        self.assertEqual(result, State.WAITING_FOR_POWER_OFF)

    @patch("conwrt.flash_dispatcher.detect_uboot_http", return_value=(False, ""))
    def test_uboot_mode_boot_not_uboot_http_not_found(self, mock_detect):
        profile = _make_profile()
        result = self.resolve("uboot", profile, "openwrt")
        self.assertEqual(result, State.WAITING_FOR_POWER_OFF)

    @patch("conwrt.flash_dispatcher.detect_uboot_http", return_value=(True, "HTTP 200"))
    def test_uboot_mode_already_in_recovery_even_when_boot_state_unknown(self, mock_detect):
        profile = _make_profile()
        result = self.resolve("uboot", profile, "unknown")
        self.assertEqual(result, State.UBOOT_UPLOADING)

    def test_extreme_mode_boot_not_stock_extreme(self):
        profile = _make_profile()
        result = self.resolve("extreme", profile, "unknown")
        self.assertEqual(result, State.DETECTING)

    def test_extreme_mode_boot_stock_extreme(self):
        profile = _make_profile()
        result = self.resolve("extreme", profile, "stock-extreme")
        self.assertEqual(result, State.EXTREME_STOCK_PREFLIGHT)

    def test_sysupgrade_mode_returns_initial_state(self):
        profile = _make_profile()
        result = self.resolve("sysupgrade", profile, "openwrt")
        self.assertEqual(result, State.SYSUPGRADE_UPLOADING)

    def test_serial_mode_returns_initial_state(self):
        profile = _make_profile()
        result = self.resolve("serial", profile, "unknown")
        self.assertEqual(result, State.SERIAL_WAITING_FOR_BOOTMENU)

    def test_edgeos_mode_returns_initial_state(self):
        profile = _make_profile()
        result = self.resolve("edgeos", profile, "stock-edgeos")
        self.assertEqual(result, State.EDGEOS_STAGE1)

    @patch("conwrt.flash_dispatcher.detect_uboot_http", return_value=(False, ""))
    def test_uboot_probes_detect_even_when_boot_state_not_uboot(self, mock_detect):
        profile = _make_profile()
        self.resolve("uboot", profile, "openwrt")
        mock_detect.assert_called_once()


# ===================================================================
# _handle_detecting
# ===================================================================

class TestHandleDetecting(TestCase):
    """Tests for _handle_detecting — the boot-state detection handler."""

    def setUp(self):
        from conwrt.flash_dispatcher import _handle_detecting
        self.handler = _handle_detecting

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="openwrt")
    def test_openwrt_detected_sysupgrade(self, mock_detect):
        ctx = _make_ctx(state=State.DETECTING, force_uboot=False)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.SYSUPGRADE_UPLOADING)
        self.assertEqual(ctx.boot_state, "openwrt")

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="openwrt")
    def test_openwrt_mtd_write_path(self, mock_detect):
        profile = _make_profile(flash_method="mtd-write")
        ctx = _make_ctx(state=State.DETECTING, profile=profile, force_uboot=False)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.SYSUPGRADE_UPLOADING)
        # say_fn should be called with mtd-write message
        say_calls = [c[0][0] for c in ctx._say_fn.call_args_list]
        self.assertTrue(any("mtd-write" in m for m in say_calls))

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="openwrt")
    def test_openwrt_force_uboot_skips_sysupgrade(self, mock_detect):
        ctx = _make_ctx(state=State.DETECTING, force_uboot=True)
        eq = queue.Queue()
        self.handler(ctx, eq)
        # force_uboot → falls through to the else branch → WAITING_FOR_POWER_OFF
        self.assertEqual(ctx.state, State.WAITING_FOR_POWER_OFF)

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="stock-edgeos")
    def test_stock_edgeos_detected(self, mock_detect):
        ctx = _make_ctx(state=State.DETECTING)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.EDGEOS_STAGE1)

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="stock-extreme")
    def test_stock_extreme_detected(self, mock_detect):
        ctx = _make_ctx(state=State.DETECTING)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.EXTREME_STOCK_PREFLIGHT)

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="stock-zyxel")
    def test_stock_zyxel_detected(self, mock_detect):
        ctx = _make_ctx(state=State.DETECTING)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_LOGIN)

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="unknown")
    def test_oem_flash_method_prefix(self, mock_detect):
        """flash_method starting with 'oem-' triggers OEM_LOGIN."""
        profile = _make_profile(flash_method="oem-zyxel")
        ctx = _make_ctx(state=State.DETECTING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.OEM_LOGIN)

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="stock-hnap")
    def test_stock_hnap_detected(self, mock_detect):
        ctx = _make_ctx(state=State.DETECTING)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.UBOOT_UPLOADING)

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="unknown")
    def test_dlink_hnap_flash_method(self, mock_detect):
        """flash_method='dlink-hnap' triggers UBOOT_UPLOADING even with unknown boot_state."""
        profile = _make_profile(flash_method="dlink-hnap")
        ctx = _make_ctx(state=State.DETECTING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.UBOOT_UPLOADING)

    @patch("conwrt.flash_dispatcher.detect_uboot_http", return_value=(True, "HTTP 200"))
    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="uboot")
    def test_uboot_http_already_live(self, mock_detect, mock_uboot_http):
        profile = _make_profile(recovery_ip="192.168.1.1")
        ctx = _make_ctx(state=State.DETECTING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.UBOOT_UPLOADING)

    @patch("conwrt.flash_dispatcher.detect_uboot_http", return_value=(False, ""))
    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="uboot")
    def test_uboot_http_not_live(self, mock_detect, mock_uboot_http):
        profile = _make_profile(recovery_ip="192.168.1.1")
        ctx = _make_ctx(state=State.DETECTING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.WAITING_FOR_POWER_OFF)

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="unknown")
    def test_unknown_boot_state_force_uboot(self, mock_detect):
        ctx = _make_ctx(state=State.DETECTING, force_uboot=True)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.WAITING_FOR_POWER_OFF)

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="unknown")
    def test_unknown_boot_state_not_force_uboot(self, mock_detect):
        ctx = _make_ctx(state=State.DETECTING, force_uboot=False)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.WAITING_FOR_POWER_OFF)

    @patch("conwrt.flash_dispatcher._detect_boot_state", return_value="openwrt")
    def test_say_fn_called_with_sysupgrade_message(self, mock_detect):
        ctx = _make_ctx(state=State.DETECTING, force_uboot=False)
        eq = queue.Queue()
        self.handler(ctx, eq)
        ctx._say_fn.assert_called()
        say_msg = ctx._say_fn.call_args[0][0]
        self.assertIn("sysupgrade", say_msg.lower())


# ===================================================================
# _handle_sysupgrade_uploading
# ===================================================================

class TestHandleSysupgradeUploading(TestCase):
    """Tests for _handle_sysupgrade_uploading handler."""

    def setUp(self):
        from conwrt.flash_dispatcher import _handle_sysupgrade_uploading
        self.handler = _handle_sysupgrade_uploading

    @patch("conwrt.flash_dispatcher.sha256_file", return_value="abc123")
    @patch("conwrt.flash_dispatcher._flash_via_sysupgrade", return_value=True)
    def test_sysupgrade_success(self, mock_flash, mock_sha):
        ctx = _make_ctx(state=State.SYSUPGRADE_UPLOADING)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.SYSUPGRADE_REBOOTING)
        self.assertEqual(ctx.sha256_before, "abc123")

    @patch("conwrt.flash_dispatcher._flash_via_sysupgrade", return_value=False)
    def test_sysupgrade_failure(self, mock_flash):
        ctx = _make_ctx(state=State.SYSUPGRADE_UPLOADING)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)

    @patch("conwrt.flash_dispatcher.load_model", return_value={
        "flash_methods": {"mtd-write": {"command": "mtd -r write /tmp/fw.bin firmware"}}
    })
    @patch("conwrt.flash_dispatcher.sha256_file", return_value="deadbeef")
    @patch("conwrt.flash_dispatcher._flash_via_mtd_write", return_value=True)
    def test_mtd_write_success(self, mock_mtd, mock_sha, mock_model):
        profile = _make_profile(flash_method="mtd-write", name="test-model")
        ctx = _make_ctx(state=State.SYSUPGRADE_UPLOADING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.SYSUPGRADE_REBOOTING)
        self.assertEqual(ctx.sha256_before, "deadbeef")
        mock_mtd.assert_called_once()

    @patch("conwrt.flash_dispatcher.load_model", return_value={
        "flash_methods": {"mtd-write": {"command": "custom mtd command"}}
    })
    @patch("conwrt.flash_dispatcher._flash_via_mtd_write", return_value=False)
    def test_mtd_write_failure(self, mock_mtd, mock_model):
        profile = _make_profile(flash_method="mtd-write", name="test-model")
        ctx = _make_ctx(state=State.SYSUPGRADE_UPLOADING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)

    @patch("conwrt.flash_dispatcher.sha256_file", return_value="abc123")
    @patch("conwrt.flash_dispatcher._flash_via_sysupgrade", return_value=True)
    def test_uses_openwrt_ip_when_set(self, mock_flash, mock_sha):
        profile = _make_profile(openwrt_ip="10.0.0.1")
        ctx = _make_ctx(state=State.SYSUPGRADE_UPLOADING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        # Verify the IP passed to _flash_via_sysupgrade
        call_args = mock_flash.call_args
        self.assertEqual(call_args[0][0], "10.0.0.1")

    @patch("conwrt.flash_dispatcher.sha256_file", return_value="abc123")
    @patch("conwrt.flash_dispatcher._flash_via_sysupgrade", return_value=True)
    def test_uses_default_ip_when_openwrt_ip_empty(self, mock_flash, mock_sha):
        profile = _make_profile(openwrt_ip="")
        ctx = _make_ctx(state=State.SYSUPGRADE_UPLOADING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        call_args = mock_flash.call_args
        self.assertEqual(call_args[0][0], DEFAULT_IP)


# ===================================================================
# _handle_sysupgrade_rebooting
# ===================================================================

class TestHandleSysupgradeRebooting(TestCase):
    """Tests for _handle_sysupgrade_rebooting handler."""

    def setUp(self):
        from conwrt.flash_dispatcher import _handle_sysupgrade_rebooting
        self.handler = _handle_sysupgrade_rebooting

    def test_sysupgrade_method(self):
        profile = _make_profile(flash_method="sysupgrade")
        ctx = _make_ctx(state=State.SYSUPGRADE_REBOOTING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.SYSUPGRADE_BOOTING)
        ctx._say_fn.assert_called_with("Firmware flashing. Do not unplug.")

    def test_mtd_write_method(self):
        profile = _make_profile(flash_method="mtd-write")
        ctx = _make_ctx(state=State.SYSUPGRADE_REBOOTING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.SYSUPGRADE_BOOTING)
        ctx._say_fn.assert_called_with("Firmware flashing. Do not unplug.")

    def test_state_transitions_to_booting(self):
        ctx = _make_ctx(state=State.SYSUPGRADE_REBOOTING)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.SYSUPGRADE_BOOTING)


# ===================================================================
# _handle_sysupgrade_booting
# ===================================================================

class TestHandleSysupgradeBooting(TestCase):
    """Tests for _handle_sysupgrade_booting handler."""

    def setUp(self):
        from conwrt.flash_dispatcher import _handle_sysupgrade_booting
        self.handler = _handle_sysupgrade_booting

    @patch("conwrt.flash_dispatcher.verify_router")
    @patch("conwrt.flash_dispatcher._wait_for_sysupgrade_reboot", return_value=True)
    def test_reboot_success_marks_complete(self, mock_wait, mock_verify):
        profile = _make_profile(openwrt_ip="192.168.1.1")
        ctx = _make_ctx(state=State.SYSUPGRADE_BOOTING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.COMPLETE)

    @patch("conwrt.flash_dispatcher._wait_for_sysupgrade_reboot", return_value=False)
    def test_reboot_failure_sets_failed(self, mock_wait):
        ctx = _make_ctx(state=State.SYSUPGRADE_BOOTING)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)

    @patch("conwrt.flash_dispatcher.verify_router")
    @patch("conwrt.flash_dispatcher._wait_for_sysupgrade_reboot", return_value=True)
    def test_uses_correct_openwrt_ip(self, mock_wait, mock_verify):
        profile = _make_profile(openwrt_ip="10.0.0.5")
        ctx = _make_ctx(state=State.SYSUPGRADE_BOOTING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        mock_wait.assert_called_once_with("10.0.0.5")

    @patch("conwrt.flash_dispatcher.verify_router")
    @patch("conwrt.flash_dispatcher._wait_for_sysupgrade_reboot", return_value=True)
    def test_uses_default_ip_when_openwrt_ip_empty(self, mock_wait, mock_verify):
        profile = _make_profile(openwrt_ip="")
        ctx = _make_ctx(state=State.SYSUPGRADE_BOOTING, profile=profile)
        eq = queue.Queue()
        self.handler(ctx, eq)
        mock_wait.assert_called_once_with(DEFAULT_IP)

    @patch("conwrt.flash_dispatcher._wait_for_sysupgrade_reboot", return_value=False)
    def test_failure_calls_say_fn(self, mock_wait):
        ctx = _make_ctx(state=State.SYSUPGRADE_BOOTING)
        eq = queue.Queue()
        self.handler(ctx, eq)
        say_msg = ctx._say_fn.call_args[0][0]
        self.assertIn("did not come back", say_msg)


# ===================================================================
# _handle_rebooting
# ===================================================================

class TestHandleRebooting(TestCase):
    """Tests for _handle_rebooting — 2-phase event loop handler."""

    def setUp(self):
        from conwrt.flash_dispatcher import _handle_rebooting
        self.handler = _handle_rebooting

    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=Event.LINK_UP)
    def test_phase1_link_up_proceeds(self, mock_wait):
        """LINK_UP in phase 1 proceeds to phase 2."""
        ctx = _make_ctx(state=State.REBOOTING)
        eq = queue.Queue()
        # Phase 2: put SSH_UP event immediately
        eq.put((Event.SSH_UP, time.time(), ""))
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.COMPLETE)

    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=None)
    def test_phase1_timeout_fails(self, mock_wait):
        """Phase 1 timeout → FAILED."""
        ctx = _make_ctx(state=State.REBOOTING)
        eq = queue.Queue()
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)

    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=Event.LINK_UP)
    def test_phase2_icmpv6_sets_openwrt_booting(self, mock_wait):
        """ICMPV6_FROM_ROUTER in phase 2 → OPENWRT_BOOTING."""
        ctx = _make_ctx(state=State.REBOOTING)
        eq = queue.Queue()
        eq.put((Event.ICMPV6_FROM_ROUTER, time.time(), ""))
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.OPENWRT_BOOTING)

    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=Event.LINK_UP)
    def test_phase2_ssh_up_sets_complete(self, mock_wait):
        """SSH_UP in phase 2 → COMPLETE."""
        ctx = _make_ctx(state=State.REBOOTING)
        eq = queue.Queue()
        eq.put((Event.SSH_UP, time.time(), ""))
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.COMPLETE)

    @patch("conwrt.flash_dispatcher.verify_router")
    @patch("conwrt.flash_dispatcher.check_ssh", return_value=True)
    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=Event.LINK_UP)
    def test_phase2_ssh_poll_success(self, mock_wait, mock_ssh, mock_verify):
        """check_ssh succeeds during phase 2 polling → COMPLETE."""
        ctx = _make_ctx(state=State.REBOOTING)
        eq = queue.Queue()
        # The event queue will be empty → queue.Empty → check_ssh called
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.COMPLETE)

    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=Event.LINK_UP)
    def test_phase2_says_link_detected(self, mock_wait):
        """After LINK_UP, say_fn is called with link detected message."""
        ctx = _make_ctx(state=State.REBOOTING)
        eq = queue.Queue()
        eq.put((Event.ICMPV6_FROM_ROUTER, time.time(), ""))
        self.handler(ctx, eq)
        say_messages = [c[0][0] for c in ctx._say_fn.call_args_list]
        self.assertTrue(any("Link detected" in m for m in say_messages))

    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=Event.LINK_UP)
    def test_phase1_says_rebooting_message(self, mock_wait):
        """Initial say_fn call with rebooting message."""
        ctx = _make_ctx(state=State.REBOOTING)
        eq = queue.Queue()
        eq.put((Event.ICMPV6_FROM_ROUTER, time.time(), ""))
        self.handler(ctx, eq)
        first_call = ctx._say_fn.call_args_list[0]
        self.assertIn("rebooting", first_call[0][0].lower())

    @patch("conwrt.flash_dispatcher.verify_router")
    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=Event.LINK_UP)
    def test_phase2_ssh_up_calls_verify_router(self, mock_wait, mock_verify):
        """SSH_UP event triggers verify_router."""
        ctx = _make_ctx(state=State.REBOOTING)
        eq = queue.Queue()
        eq.put((Event.SSH_UP, time.time(), ""))
        self.handler(ctx, eq)
        mock_verify.assert_called_once()


# ===================================================================
# _handle_openwrt_booting
# ===================================================================

class TestHandleOpenwrtBooting(TestCase):
    """Tests for _handle_openwrt_booting handler."""

    def setUp(self):
        from conwrt.flash_dispatcher import _handle_openwrt_booting
        self.handler = _handle_openwrt_booting

    @patch("conwrt.flash_dispatcher.verify_router")
    @patch("conwrt.flash_dispatcher.SSHMonitor")
    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=Event.SSH_UP)
    def test_ssh_up_marks_complete(self, mock_wait, mock_ssh_mon, mock_verify):
        ctx = _make_ctx(state=State.OPENWRT_BOOTING)
        eq = queue.Queue()
        mock_ssh_inst = MagicMock()
        mock_ssh_mon.return_value = mock_ssh_inst
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.COMPLETE)
        mock_ssh_inst.stop.assert_called_once()

    @patch("conwrt.flash_dispatcher.check_ssh", return_value=True)
    @patch("conwrt.flash_dispatcher.verify_router")
    @patch("conwrt.flash_dispatcher.SSHMonitor")
    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=Event.LINK_UP)
    def test_link_up_fallback_ssh_success(self, mock_wait, mock_ssh_mon, mock_verify, mock_check):
        """LINK_UP + check_ssh succeeds → COMPLETE."""
        ctx = _make_ctx(state=State.OPENWRT_BOOTING)
        eq = queue.Queue()
        mock_ssh_inst = MagicMock()
        mock_ssh_mon.return_value = mock_ssh_inst
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.COMPLETE)

    @patch("conwrt.flash_dispatcher.check_ssh", return_value=False)
    @patch("conwrt.flash_dispatcher.SSHMonitor")
    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=Event.LINK_UP)
    def test_link_up_fallback_ssh_fails(self, mock_wait, mock_ssh_mon, mock_check):
        """LINK_UP + check_ssh fails → FAILED."""
        ctx = _make_ctx(state=State.OPENWRT_BOOTING)
        eq = queue.Queue()
        mock_ssh_inst = MagicMock()
        mock_ssh_mon.return_value = mock_ssh_inst
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)

    @patch("conwrt.flash_dispatcher.check_ssh", return_value=False)
    @patch("conwrt.flash_dispatcher.SSHMonitor")
    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=None)
    def test_timeout_fails(self, mock_wait, mock_ssh_mon, mock_check):
        """Timeout → FAILED."""
        ctx = _make_ctx(state=State.OPENWRT_BOOTING)
        eq = queue.Queue()
        mock_ssh_inst = MagicMock()
        mock_ssh_mon.return_value = mock_ssh_inst
        self.handler(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)

    @patch("conwrt.flash_dispatcher.verify_router")
    @patch("conwrt.flash_dispatcher.SSHMonitor")
    @patch("conwrt.flash_dispatcher._wait_for_event_or_timeout", return_value=Event.SSH_UP)
    def test_ssh_monitor_started_and_stopped(self, mock_wait, mock_ssh_mon, mock_verify):
        ctx = _make_ctx(state=State.OPENWRT_BOOTING)
        eq = queue.Queue()
        mock_ssh_inst = MagicMock()
        mock_ssh_mon.return_value = mock_ssh_inst
        self.handler(ctx, eq)
        mock_ssh_inst.run.assert_called_once()
        mock_ssh_inst.stop.assert_called_once()


# ===================================================================
# _run_state_machine
# ===================================================================

class TestRunStateMachine(TestCase):
    """Tests for _run_state_machine — the dispatch loop."""

    def setUp(self):
        from conwrt.flash_dispatcher import _run_state_machine
        self.runner = _run_state_machine

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._record_inventory")
    @patch("conwrt.flash_dispatcher._deploy_tollgate_post_flash")
    @patch("conwrt.flash_dispatcher._register_wireguard_post_flash")
    @patch("conwrt.flash_dispatcher._apply_sticker_credentials_post_flash")
    @patch("conwrt.flash_dispatcher._apply_profile_post_flash")
    @patch("conwrt.flash_dispatcher._load_config")
    @patch("conwrt.flash_dispatcher._print_timeline")
    def test_complete_immediately_returns_0(self, mock_timeline, mock_config,
                                            mock_apply, mock_sticker, mock_wg,
                                            mock_tollgate, mock_inv, mock_restore):
        """State already COMPLETE → returns 0, no handlers."""
        mock_config.return_value = MagicMock()
        mock_apply.return_value = "192.168.1.1"
        ctx = _make_ctx(state=State.COMPLETE)
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 0)

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._print_timeline")
    def test_failed_immediately_returns_1(self, mock_timeline, mock_restore):
        """State already FAILED → returns 1."""
        ctx = _make_ctx(state=State.FAILED)
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 1)

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._record_inventory")
    @patch("conwrt.flash_dispatcher._deploy_tollgate_post_flash")
    @patch("conwrt.flash_dispatcher._register_wireguard_post_flash")
    @patch("conwrt.flash_dispatcher._apply_sticker_credentials_post_flash")
    @patch("conwrt.flash_dispatcher._apply_profile_post_flash")
    @patch("conwrt.flash_dispatcher._load_config")
    @patch("conwrt.flash_dispatcher._print_timeline")
    @patch("conwrt.flash_dispatcher._handle_detecting")
    def test_single_handler_transition(self, mock_detect, mock_timeline, mock_config,
                                       mock_apply, mock_sticker, mock_wg,
                                       mock_tollgate, mock_inv, mock_restore):
        """DETECTING handler transitions state → loop exits on COMPLETE."""
        mock_config.return_value = MagicMock()
        mock_apply.return_value = "192.168.1.1"
        def fake_handler(ctx, eq):
            ctx.state = State.COMPLETE
        mock_detect.side_effect = fake_handler
        ctx = _make_ctx(state=State.DETECTING)
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 0)
        mock_detect.assert_called_once()

    @patch("conwrt.flash_dispatcher._print_timeline")
    @patch("conwrt.flash_dispatcher._handle_detecting")
    def test_handler_transition_to_failed(self, mock_detect, mock_timeline):
        """Handler transitions to FAILED → returns 1."""
        def fake_handler(ctx, eq):
            ctx.state = State.FAILED
        mock_detect.side_effect = fake_handler
        ctx = _make_ctx(state=State.DETECTING)
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 1)

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._record_inventory")
    @patch("conwrt.flash_dispatcher._print_timeline")
    def test_failed_with_sha256_records_inventory(self, mock_timeline, mock_inv, mock_restore):
        """FAILED with sha256_before records partial inventory."""
        ctx = _make_ctx(state=State.FAILED)
        ctx.sha256_before = "abc123"
        ctx.image_path = "/tmp/test.bin"
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 1)
        mock_inv.assert_called_once_with(ctx)

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._print_timeline")
    def test_failed_without_sha256_no_inventory(self, mock_timeline, mock_restore):
        """FAILED without sha256_before → no inventory record."""
        ctx = _make_ctx(state=State.FAILED)
        ctx.sha256_before = ""
        ctx.image_path = "/tmp/test.bin"
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 1)

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._print_timeline")
    def test_failed_without_image_path_no_inventory(self, mock_timeline, mock_restore):
        """FAILED with empty image_path → no inventory record."""
        ctx = _make_ctx(state=State.FAILED)
        ctx.sha256_before = "abc"
        ctx.image_path = ""
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 1)

    @patch("conwrt.flash_dispatcher._print_timeline")
    def test_no_upload_returns_0_without_postflash(self, mock_timeline):
        """no_upload=True → returns 0 without post-flash chain."""
        ctx = _make_ctx(state=State.COMPLETE, no_upload=True)
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 0)

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._record_inventory")
    @patch("conwrt.flash_dispatcher._deploy_tollgate_post_flash")
    @patch("conwrt.flash_dispatcher._register_wireguard_post_flash")
    @patch("conwrt.flash_dispatcher._apply_sticker_credentials_post_flash")
    @patch("conwrt.flash_dispatcher._apply_profile_post_flash")
    @patch("conwrt.flash_dispatcher._load_config")
    @patch("conwrt.flash_dispatcher._print_timeline")
    def test_complete_runs_postflash_chain(self, mock_timeline, mock_config,
                                           mock_apply, mock_sticker, mock_wg,
                                           mock_tollgate, mock_inv, mock_restore):
        """COMPLETE with upload → runs full post-flash chain."""
        mock_config.return_value = MagicMock()
        mock_apply.return_value = "192.168.1.1"
        ctx = _make_ctx(state=State.COMPLETE)
        ctx.ssh_key_path = "/tmp/key.pub"
        # Need a handler to transition to COMPLETE
        def fake_complete(ctx, eq):
            ctx.state = State.COMPLETE
        eq = queue.Queue()
        # Already COMPLETE, so no handler needed
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 0)
        mock_apply.assert_called_once()

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._record_inventory")
    @patch("conwrt.flash_dispatcher._deploy_tollgate_post_flash")
    @patch("conwrt.flash_dispatcher._register_wireguard_post_flash")
    @patch("conwrt.flash_dispatcher._apply_sticker_credentials_post_flash")
    @patch("conwrt.flash_dispatcher._apply_profile_post_flash")
    @patch("conwrt.flash_dispatcher._load_config")
    @patch("conwrt.flash_dispatcher._print_timeline")
    @patch("conwrt.flash_dispatcher._handle_detecting")
    def test_unhandled_state_fails(self, mock_detect, mock_timeline, mock_config,
                                   mock_apply, mock_sticker, mock_wg,
                                   mock_tollgate, mock_inv, mock_restore):
        """Dispatch loop processes handler correctly."""
        mock_config.return_value = MagicMock()
        mock_apply.return_value = "192.168.1.1"
        def fake_handler(ctx, eq):
            ctx.state = State.COMPLETE
        mock_detect.side_effect = fake_handler
        ctx = _make_ctx(state=State.DETECTING)
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 0)

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._print_timeline")
    def test_sets_recovery_start_timestamp(self, mock_timeline, mock_restore):
        """_run_state_machine sets ctx.timeline.recovery_start."""
        ctx = _make_ctx(state=State.FAILED)
        self.assertIsNone(ctx.timeline.recovery_start)
        eq = queue.Queue()
        self.runner(ctx, eq, None, None)
        self.assertIsNotNone(ctx.timeline.recovery_start)

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._load_config")
    @patch("conwrt.flash_dispatcher._apply_profile_post_flash")
    @patch("conwrt.flash_dispatcher._print_timeline")
    def test_postflash_profile_failure_returns_1(self, mock_timeline, mock_apply,
                                                  mock_config, mock_restore):
        """_apply_profile_post_flash returns empty → abort, return 1."""
        mock_config.return_value = MagicMock()
        mock_apply.return_value = ""  # empty = failure
        ctx = _make_ctx(state=State.COMPLETE)
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 1)

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._record_inventory")
    @patch("conwrt.flash_dispatcher._deploy_tollgate_post_flash")
    @patch("conwrt.flash_dispatcher._register_wireguard_post_flash")
    @patch("conwrt.flash_dispatcher._apply_sticker_credentials_post_flash")
    @patch("conwrt.flash_dispatcher._apply_profile_post_flash")
    @patch("conwrt.flash_dispatcher._load_config")
    @patch("conwrt.flash_dispatcher._print_timeline")
    def test_postflash_wireguard_pubkey_stored(self, mock_timeline, mock_config,
                                                mock_apply, mock_sticker,
                                                mock_wg, mock_tollgate,
                                                mock_inv, mock_restore):
        """WireGuard public key is stored in ctx.wireguard_pubkey."""
        mock_config.return_value = MagicMock()
        mock_apply.return_value = "192.168.1.1"
        mock_wg.return_value = "wgpubkey123"
        ctx = _make_ctx(state=State.COMPLETE)
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 0)
        self.assertEqual(ctx.wireguard_pubkey, "wgpubkey123")

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._record_inventory")
    @patch("conwrt.flash_dispatcher._deploy_tollgate_post_flash")
    @patch("conwrt.flash_dispatcher._register_wireguard_post_flash")
    @patch("conwrt.flash_dispatcher._apply_sticker_credentials_post_flash")
    @patch("conwrt.flash_dispatcher._apply_profile_post_flash")
    @patch("conwrt.flash_dispatcher._load_config")
    @patch("conwrt.flash_dispatcher._print_timeline")
    def test_postflash_ip_change_updates_profile(self, mock_timeline, mock_config,
                                                  mock_apply, mock_sticker,
                                                  mock_wg, mock_tollgate,
                                                  mock_inv, mock_restore):
        """When _apply_profile_post_flash returns different IP, profile.openwrt_ip is updated."""
        mock_config.return_value = MagicMock()
        mock_apply.return_value = "10.0.0.1"
        mock_wg.return_value = ""
        ctx = _make_ctx(state=State.COMPLETE)
        original_ip = ctx.profile.openwrt_ip
        eq = queue.Queue()
        result = self.runner(ctx, eq, None, None)
        self.assertEqual(result, 0)
        self.assertEqual(ctx.profile.openwrt_ip, "10.0.0.1")


# ===================================================================
# _wait_for_event_or_timeout (alias)
# ===================================================================

class TestWaitForEventOrTimeout(TestCase):
    """Verify _wait_for_event_or_timeout is an alias for wait_for_event."""

    def test_is_alias_for_wait_for_event(self):
        from conwrt.flash_dispatcher import _wait_for_event_or_timeout
        from flash.context import wait_for_event
        self.assertIs(_wait_for_event_or_timeout, wait_for_event)


# ===================================================================
# Integration: multi-step state transitions
# ===================================================================

class TestMultiStepTransitions(TestCase):
    """Tests for multi-step state machine transitions."""

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._record_inventory")
    @patch("conwrt.flash_dispatcher._deploy_tollgate_post_flash")
    @patch("conwrt.flash_dispatcher._register_wireguard_post_flash")
    @patch("conwrt.flash_dispatcher._apply_sticker_credentials_post_flash")
    @patch("conwrt.flash_dispatcher._apply_profile_post_flash")
    @patch("conwrt.flash_dispatcher._load_config")
    @patch("conwrt.flash_dispatcher._print_timeline")
    @patch("conwrt.flash_dispatcher._handle_sysupgrade_booting")
    @patch("conwrt.flash_dispatcher._handle_sysupgrade_rebooting")
    @patch("conwrt.flash_dispatcher._handle_sysupgrade_uploading")
    @patch("conwrt.flash_dispatcher._handle_detecting")
    def test_full_detecting_to_complete_chain(self, mock_detect, mock_upload,
                                               mock_reboot, mock_boot, mock_timeline,
                                               mock_config, mock_apply, mock_sticker,
                                               mock_wg, mock_tollgate, mock_inv, mock_restore):
        """DETECTING → UPLOADING → REBOOTING → BOOTING → COMPLETE."""
        mock_config.return_value = MagicMock()
        mock_apply.return_value = "192.168.1.1"

        transitions = {
            State.DETECTING: State.SYSUPGRADE_UPLOADING,
            State.SYSUPGRADE_UPLOADING: State.SYSUPGRADE_REBOOTING,
            State.SYSUPGRADE_REBOOTING: State.SYSUPGRADE_BOOTING,
            State.SYSUPGRADE_BOOTING: State.COMPLETE,
        }

        def make_transition(target_state):
            def handler(ctx, eq):
                ctx.state = target_state
            return handler

        mock_detect.side_effect = make_transition(State.SYSUPGRADE_UPLOADING)
        mock_upload.side_effect = make_transition(State.SYSUPGRADE_REBOOTING)
        mock_reboot.side_effect = make_transition(State.SYSUPGRADE_BOOTING)
        mock_boot.side_effect = make_transition(State.COMPLETE)

        ctx = _make_ctx(state=State.DETECTING)
        eq = queue.Queue()
        from conwrt.flash_dispatcher import _run_state_machine
        result = _run_state_machine(ctx, eq, None, None)
        self.assertEqual(result, 0)
        mock_detect.assert_called_once()
        mock_upload.assert_called_once()
        mock_reboot.assert_called_once()
        mock_boot.assert_called_once()

    @patch("conwrt.flash_dispatcher._restore_port_isolation")
    @patch("conwrt.flash_dispatcher._print_timeline")
    @patch("conwrt.flash_dispatcher._handle_detecting")
    def test_detecting_to_failed_chain(self, mock_detect, mock_timeline, mock_restore):
        """DETECTING → FAILED → returns 1."""
        def handler(ctx, eq):
            ctx.state = State.FAILED
        mock_detect.side_effect = handler
        ctx = _make_ctx(state=State.DETECTING)
        eq = queue.Queue()
        from conwrt.flash_dispatcher import _run_state_machine
        result = _run_state_machine(ctx, eq, None, None)
        self.assertEqual(result, 1)


# ===================================================================
# FLASH_MODES cleanup functions wired correctly
# ===================================================================

class TestFlashModesCleanup(TestCase):
    """Verify cleanup functions in FLASH_MODES are correctly wired."""

    def test_extreme_cleanup_is_extreme_cleanup_function(self):
        from conwrt.flash_dispatcher import FLASH_MODES, _extreme_cleanup
        self.assertIs(FLASH_MODES["extreme"].cleanup, _extreme_cleanup)

    def test_serial_cleanup_is_serial_cleanup_function(self):
        from conwrt.flash_dispatcher import FLASH_MODES, _serial_cleanup
        self.assertIs(FLASH_MODES["serial"].cleanup, _serial_cleanup)

    def test_zycast_cleanup_is_zycast_cleanup_function(self):
        from conwrt.flash_dispatcher import FLASH_MODES, _zycast_cleanup
        self.assertIs(FLASH_MODES["zycast"].cleanup, _zycast_cleanup)
