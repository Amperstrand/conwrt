"""Tests for conwrt.flash_dispatcher.cmd_flash — the flash CLI entry point.

cmd_flash is the ~340-line orchestration function that resolves the model,
builds the profile, runs preflight, picks the flash mode, and drives the
state machine. These tests mock every external effect (SSH, fingerprinting,
preflight, monitors, the state machine itself) and verify the wiring:
argument validation, auto-detection fallbacks, request-image auth branches,
initramfs requirements, mode resolution, and cleanup invocation.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.context import State


def _make_profile(**overrides):
    """Profile object with every attribute cmd_flash touches."""
    defaults = dict(
        name="test-model",
        vendor="TestVendor",
        description="Test Model",
        led_pattern="blink",
        flash_method="sysupgrade",
        recovery_ip="192.168.1.1",
        openwrt_ip="192.168.1.1",
        client_ip="192.168.1.2",
        openwrt_client_ip="",
        is_serial_tftp=False,
        is_zycast=False,
        is_edgeos_kernel_swap=False,
        is_extreme_rdwr_tftp=False,
        serial_baud=115200,
        lan_port="",
        uboot_commands=["bootm 0x82000000"],
        zycast_multicast_group="239.255.76.78",
        zycast_multicast_port=50076,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


_DEFAULT_IMAGE = "/tmp/conwrt-test-firmware.bin"


def _make_args(**overrides):
    """argparse.Namespace shaped like `conwrt flash`."""
    defaults = dict(
        model_id="test-model",
        image=_DEFAULT_IMAGE,
        request_image=False,
        ssh_key=None,
        password=None,
        no_password=False,
        wan_ssh=False,
        no_voice=True,
        no_upload=False,
        force_uboot=False,
        interface="en0",
        capture="/tmp/conwrt-test.pcap",
        initramfs=None,
        serial_method="",
        serial_port="",
        serial_baud=None,
        tftp_root="",
        router_mac=None,
        uboot_mac=None,
        keep_config=False,
        isolate_port=None,
        no_pcap=False,
        yes=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_cfg(**overrides):
    cfg = MagicMock()
    cfg.ssh_public_key_path = overrides.pop("ssh_public_key_path", "")
    cfg.password_is_key_only = overrides.pop("password_is_key_only", False)
    cfg.password_is_random = overrides.pop("password_is_random", False)
    cfg.password_literal = overrides.pop("password_literal", "")
    cfg.wan_ssh = overrides.pop("wan_ssh", False)
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


def _passing_preflight():
    return [SimpleNamespace(status="pass", name="check", message="ok")]


class CmdFlashTestCase(TestCase):
    """Base: patches every external effect cmd_flash touches.

    Subclasses call self.run_cmd_flash(args); it returns the rc (or raises
    SystemExit for parser.error paths).
    """

    def setUp(self):
        patches = {
            "_build_parser": patch("conwrt.flash_dispatcher._build_parser"),
            "_validate_args": patch(
                "conwrt.flash_dispatcher._validate_args", return_value=None),
            "detect_platform": patch(
                "conwrt.flash_dispatcher.detect_platform", return_value="darwin"),
            "check_external_deps": patch(
                "conwrt.flash_dispatcher.check_external_deps", return_value=[]),
            "_load_config": patch(
                "conwrt.flash_dispatcher._load_config", return_value=_make_cfg()),
            "_detect_ssh_key_path": patch(
                "conwrt.flash_dispatcher._detect_ssh_key_path", return_value="/tmp/key"),
            "fingerprint_router": patch(
                "conwrt.flash_dispatcher.fingerprint_router", return_value=None),
            "_find_model_id_by_board": patch(
                "conwrt.flash_dispatcher._find_model_id_by_board", return_value=None),
            "_active_fingerprint": patch(
                "conwrt.flash_dispatcher._active_fingerprint",
                return_value=SimpleNamespace(candidates=[])),
            "_match_models": patch(
                "conwrt.flash_dispatcher._match_models", return_value=[]),
            "_build_profile_from_model": patch(
                "conwrt.flash_dispatcher._build_profile_from_model"),
            "load_model": patch("conwrt.flash_dispatcher.load_model", return_value={}),
            "_detect_boot_state": patch(
                "conwrt.flash_dispatcher._detect_boot_state", return_value="openwrt"),
            "_request_custom_image": patch(
                "conwrt.flash_dispatcher._request_custom_image", return_value=("", {})),
            "run_preflight_checks": patch(
                "conwrt.flash_dispatcher.run_preflight_checks",
                return_value=_passing_preflight()),
            "auto_detect_interface": patch(
                "conwrt.flash_dispatcher.auto_detect_interface", return_value="en0"),
            "monitor_lifecycle": patch("conwrt.flash_dispatcher.monitor_lifecycle"),
            "_run_state_machine": patch(
                "conwrt.flash_dispatcher._run_state_machine", return_value=0),
            "detect_uboot_http": patch(
                "conwrt.flash_dispatcher.detect_uboot_http", return_value=(False, "")),
            "_setup_interface_ips": patch("conwrt.flash_dispatcher._setup_interface_ips"),
            "_restore_port_isolation": patch(
                "conwrt.flash_dispatcher._restore_port_isolation"),
            "_record_inventory": patch("conwrt.flash_dispatcher._record_inventory"),
            "_generate_random_password": patch(
                "conwrt.flash_dispatcher._generate_random_password",
                return_value="rand-pw"),
        }
        self.mocks = {}
        for name, p in patches.items():
            self.mocks[name] = p.start()
            self.addCleanup(p.stop)

        parser = MagicMock()
        parser.error.side_effect = SystemExit(2)
        self.mocks["_build_parser"].return_value = parser

        monitor_cm = self.mocks["monitor_lifecycle"].return_value
        monitor_cm.__enter__.return_value = (None, None)
        monitor_cm.__exit__.return_value = None

        # Real temp image file so cmd_flash's os.path.isfile check passes.
        fd, self.image_path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, b"firmware")
        os.close(fd)
        self.addCleanup(os.unlink, self.image_path)
        self.mocks["_build_profile_from_model"].return_value = _make_profile()

    def run_cmd_flash(self, args=None):
        from conwrt.flash_dispatcher import cmd_flash
        args = args or _make_args()
        if not args.request_image and args.image == _DEFAULT_IMAGE:
            args.image = self.image_path
        return cmd_flash(args)

    def captured_ctx(self):
        """Capture fields of the RecoveryContext handed to _run_state_machine."""
        captured = SimpleNamespace()

        def capture(c, eq, pcap, link):
            captured.state = c.state
            captured.no_upload = c.no_upload
            captured.keep_config = c.keep_config
            captured.profile = c.profile
            captured.force_uboot = c.force_uboot
            captured.auth_type = c.auth_type
            captured.password_set = c.password_set
            captured.wan_ssh_enabled = c.wan_ssh_enabled
            return 0

        self.mocks["_run_state_machine"].side_effect = capture
        return captured


class TestCmdFlashValidation(CmdFlashTestCase):
    def test_validation_error_calls_parser_error(self):
        self.mocks["_validate_args"].return_value = "some error"
        with self.assertRaises(SystemExit):
            self.run_cmd_flash()

    def test_missing_image_on_disk_returns_1(self):
        rc = self.run_cmd_flash(_make_args(image="/nonexistent/fw.bin"))
        self.assertEqual(rc, 1)

    def test_no_interface_returns_1(self):
        self.mocks["auto_detect_interface"].return_value = ""
        rc = self.run_cmd_flash(_make_args(interface=None))
        self.assertEqual(rc, 1)
        self.mocks["run_preflight_checks"].assert_not_called()

    def test_preflight_failure_returns_1(self):
        self.mocks["run_preflight_checks"].return_value = [
            SimpleNamespace(status="fail", name="image", message="bad image")]
        rc = self.run_cmd_flash()
        self.assertEqual(rc, 1)
        self.mocks["_run_state_machine"].assert_not_called()


class TestCmdFlashModelAutoDetect(CmdFlashTestCase):
    def test_board_fingerprint_autodetects_model(self):
        self.mocks["fingerprint_router"].return_value = {
            "identity": {"board": "test-board,name"},
        }
        self.mocks["_find_model_id_by_board"].return_value = "detected-model"
        rc = self.run_cmd_flash(_make_args(model_id=None))
        self.assertEqual(rc, 0)
        self.mocks["_build_profile_from_model"].assert_called_once_with(
            "detected-model", serial_method="", flash_method="")

    def test_active_fingerprint_autodetects_model(self):
        self.mocks["_active_fingerprint"].return_value = SimpleNamespace(candidates=["c"])
        self.mocks["_match_models"].return_value = [
            SimpleNamespace(model_id="active-model", confidence=0.9, evidence=["mac"])]
        rc = self.run_cmd_flash(_make_args(model_id=None))
        self.assertEqual(rc, 0)
        build_args = self.mocks["_build_profile_from_model"].call_args[0]
        self.assertEqual(build_args[0], "active-model")

    def test_no_autodetect_errors(self):
        with self.assertRaises(SystemExit):
            self.run_cmd_flash(_make_args(model_id=None))


class TestCmdFlashRequestImage(CmdFlashTestCase):
    def _request_args(self, **overrides):
        overrides.setdefault("request_image", True)
        overrides.setdefault("image", None)
        overrides.setdefault("ssh_key", "/tmp/key.pub")
        return _make_args(**overrides)

    def test_key_only_auth(self):
        cfg = _make_cfg(password_is_key_only=True)
        self.mocks["_load_config"].return_value = cfg
        self.mocks["_request_custom_image"].return_value = (
            self.image_path, {"request_hash": "h"})
        ctx = self.captured_ctx()
        rc = self.run_cmd_flash(self._request_args())
        self.assertEqual(rc, 0)
        self.assertIsNone(self.mocks["_request_custom_image"].call_args.kwargs["password"])
        self.assertEqual(ctx.auth_type, "key-only")
        self.assertFalse(ctx.password_set)

    def test_random_password_auth(self):
        cfg = _make_cfg(password_is_random=True)
        self.mocks["_load_config"].return_value = cfg
        self.mocks["_request_custom_image"].return_value = (self.image_path, {})
        ctx = self.captured_ctx()
        rc = self.run_cmd_flash(self._request_args())
        self.assertEqual(rc, 0)
        self.mocks["_generate_random_password"].assert_called_once()
        self.assertEqual(
            self.mocks["_request_custom_image"].call_args.kwargs["password"], "rand-pw")
        self.assertEqual(ctx.auth_type, "key-and-password")
        self.assertTrue(ctx.password_set)

    def test_config_literal_password_auth(self):
        cfg = _make_cfg(password_literal="secret-pw")
        self.mocks["_load_config"].return_value = cfg
        self.mocks["_request_custom_image"].return_value = (self.image_path, {})
        rc = self.run_cmd_flash(self._request_args())
        self.assertEqual(rc, 0)
        self.assertEqual(
            self.mocks["_request_custom_image"].call_args.kwargs["password"], "secret-pw")

    def test_password_flag_auth(self):
        self.mocks["_request_custom_image"].return_value = (self.image_path, {})
        rc = self.run_cmd_flash(self._request_args(password="flag-pw"))
        self.assertEqual(rc, 0)
        self.assertEqual(
            self.mocks["_request_custom_image"].call_args.kwargs["password"], "flag-pw")

    def test_no_password_flag_key_only(self):
        self.mocks["_request_custom_image"].return_value = (self.image_path, {})
        ctx = self.captured_ctx()
        rc = self.run_cmd_flash(self._request_args(no_password=True))
        self.assertEqual(rc, 0)
        self.assertIsNone(self.mocks["_request_custom_image"].call_args.kwargs["password"])
        self.assertEqual(ctx.auth_type, "key-only")

    def test_request_failure_returns_1(self):
        self.mocks["_request_custom_image"].return_value = ("", {})
        rc = self.run_cmd_flash(self._request_args())
        self.assertEqual(rc, 1)

    def test_no_ssh_key_errors(self):
        cfg = _make_cfg(ssh_public_key_path="")
        self.mocks["_load_config"].return_value = cfg
        with self.assertRaises(SystemExit):
            self.run_cmd_flash(self._request_args(ssh_key=None))

    def test_wan_ssh_enabled_propagates(self):
        self.mocks["_request_custom_image"].return_value = (self.image_path, {})
        ctx = self.captured_ctx()
        rc = self.run_cmd_flash(self._request_args(wan_ssh=True))
        self.assertEqual(rc, 0)
        self.assertTrue(ctx.wan_ssh_enabled)

    def test_mtd_write_profile_keeps_flash_method(self):
        """With an mtd-write profile on an OpenWrt device, the requested
        image keeps flash_method=mtd-write (not rewritten to sysupgrade)."""
        self.mocks["_build_profile_from_model"].return_value = _make_profile(
            flash_method="mtd-write")
        self.mocks["_request_custom_image"].return_value = (self.image_path, {})
        rc = self.run_cmd_flash(self._request_args())
        self.assertEqual(rc, 0)
        self.assertEqual(
            self.mocks["_request_custom_image"].call_args.kwargs["flash_method"],
            "mtd-write")

    def test_non_mtd_profile_requests_sysupgrade_image(self):
        self.mocks["_request_custom_image"].return_value = (self.image_path, {})
        rc = self.run_cmd_flash(self._request_args())
        self.assertEqual(rc, 0)
        self.assertEqual(
            self.mocks["_request_custom_image"].call_args.kwargs["flash_method"],
            "sysupgrade")


class TestCmdFlashSerialMode(CmdFlashTestCase):
    def _serial_profile(self):
        return _make_profile(is_serial_tftp=True, flash_method="serial-tftp-base64")

    def test_single_serial_method_autoselected(self):
        self.mocks["_build_profile_from_model"].return_value = self._serial_profile()
        self.mocks["load_model"].return_value = {
            "flash_methods": {"serial-tftp-base64": {}}}
        rc = self.run_cmd_flash(_make_args(serial_method=""))
        self.assertEqual(rc, 0)
        # Profile rebuilt with the auto-selected method suffix
        calls = self.mocks["_build_profile_from_model"].call_args_list
        self.assertEqual(calls[-1].kwargs.get("serial_method"), "base64")
        # Serial mode has no monitors: state machine gets (None, None)
        sm_args = self.mocks["_run_state_machine"].call_args[0]
        self.assertIsNone(sm_args[2])
        self.assertIsNone(sm_args[3])
        self.mocks["monitor_lifecycle"].assert_not_called()

    def test_multiple_serial_methods_error(self):
        self.mocks["_build_profile_from_model"].return_value = self._serial_profile()
        self.mocks["load_model"].return_value = {
            "flash_methods": {"serial-tftp-base64": {}, "serial-tftp-xmodem": {}}}
        rc = self.run_cmd_flash(_make_args(serial_method=""))
        self.assertEqual(rc, 1)


class TestCmdFlashModeResolution(CmdFlashTestCase):
    def test_sysupgrade_mode_wiring(self):
        ctx = self.captured_ctx()
        rc = self.run_cmd_flash(_make_args(keep_config=True, no_upload=True))
        self.assertEqual(rc, 0)
        self.assertEqual(ctx.state, State.SYSUPGRADE_UPLOADING)
        self.assertTrue(ctx.keep_config)
        self.assertTrue(ctx.no_upload)
        ml_kwargs = self.mocks["monitor_lifecycle"].call_args.kwargs
        self.assertFalse(ml_kwargs["pcap_enabled"])

    def test_uboot_mode_wiring(self):
        self.mocks["_detect_boot_state"].return_value = "unknown"
        ctx = self.captured_ctx()
        rc = self.run_cmd_flash()
        self.assertEqual(rc, 0)
        self.assertEqual(ctx.state, State.WAITING_FOR_POWER_OFF)
        self.mocks["_setup_interface_ips"].assert_called_once()
        ml_kwargs = self.mocks["monitor_lifecycle"].call_args.kwargs
        self.assertTrue(ml_kwargs["pcap_enabled"])

    def test_force_uboot_overrides_openwrt(self):
        self.mocks["_detect_boot_state"].return_value = "openwrt"
        self.mocks["detect_uboot_http"].return_value = (True, "HTTP 200")
        ctx = self.captured_ctx()
        rc = self.run_cmd_flash(_make_args(force_uboot=True))
        self.assertEqual(rc, 0)
        # Recovery HTTP live → skip power cycle
        self.assertEqual(ctx.state, State.UBOOT_UPLOADING)

    def test_extreme_requires_initramfs_returns_1(self):
        self.mocks["_build_profile_from_model"].return_value = _make_profile(
            is_extreme_rdwr_tftp=True)
        self.mocks["_detect_boot_state"].return_value = "stock-extreme"
        rc = self.run_cmd_flash()
        self.assertEqual(rc, 1)

    def test_ip_flag_overrides_profile_ips(self):
        self.mocks["_detect_boot_state"].return_value = "unknown"
        ctx = self.captured_ctx()
        rc = self.run_cmd_flash(_make_args(ip="10.0.0.9"))
        self.assertEqual(rc, 0)
        self.assertEqual(ctx.profile.openwrt_ip, "10.0.0.9")
        self.assertEqual(ctx.profile.recovery_ip, "10.0.0.9")

    def test_state_machine_keyboard_interrupt_returns_1(self):
        self.mocks["_run_state_machine"].side_effect = KeyboardInterrupt
        rc = self.run_cmd_flash()
        self.assertEqual(rc, 1)

    def test_zycast_mode_calls_cleanup(self):
        from conwrt.flash_dispatcher import FLASH_MODES, FlashModeConfig
        self.mocks["_detect_boot_state"].return_value = "unknown"
        self.mocks["_build_profile_from_model"].return_value = _make_profile(is_zycast=True)
        cleanup = MagicMock()
        zycast_cfg = FlashModeConfig(
            initial_state=State.ZYCAST_WAITING_FOR_DEVICE, cleanup=cleanup)
        with patch.dict(FLASH_MODES, {"zycast": zycast_cfg}):
            rc = self.run_cmd_flash()
        self.assertEqual(rc, 0)
        cleanup.assert_called_once()
        # cleanup(ctx, profile, interface)
        self.assertEqual(cleanup.call_args[0][2], "en0")

    def test_openwrt_platform_missing_deps_only_warns(self):
        self.mocks["detect_platform"].return_value = "openwrt"
        self.mocks["check_external_deps"].return_value = ["scapy"]
        rc = self.run_cmd_flash()
        self.assertEqual(rc, 0)


class TestCmdFlashFingerprintLog(CmdFlashTestCase):
    def test_fingerprint_block_logs_and_sets_router_mac(self):
        self.mocks["fingerprint_router"].return_value = {
            "identity": {"model": "Test Model", "board": "test-board"},
            "firmware": {"version": "24.10.2", "target": "x86/64", "kernel": "6.1"},
            "hardware": {"memory_mb": {"total": "512000", "free": "400000"}},
            "network": {"macs": {"br-lan": "AA:BB:CC:DD:EE:FF"}},
            "security": {"packages_installed": 12},
            "diagnostics": {"uptime": "1 day"},
        }
        args = _make_args(image=self.image_path)
        rc = self.run_cmd_flash(args)
        self.assertEqual(rc, 0)
        # br-lan MAC adopted as router_mac when not explicitly given
        self.assertEqual(args.router_mac, "AA:BB:CC:DD:EE:FF")
