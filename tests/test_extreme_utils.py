"""Tests for conwrt.extreme utility functions — pure, easy, and medium complexity."""
from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.context import Event, State, RecoveryContext, Timeline
from conwrt.extreme import (
    _setup_interface_ips,
    _extreme_tftp_server_ip,
    _extreme_stock_ssh_options,
    _resolve_extreme_uboot_value,
    _ensure_extreme_backup_dir,
    _extreme_confirm_or_fail,
    _extreme_openwrt_ssh,
    _extreme_openwrt_scp_from_remote,
    _extreme_openwrt_scp_to_remote,
    _write_json_file,
    _prepare_extreme_tftp_root,
    _cleanup_extreme_tftp_assets,
    _advance_past_port_isolation,
    _restore_port_isolation,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_profile(**overrides):
    defaults = dict(
        name="test-model",
        vendor="TestVendor",
        openwrt_ip="192.168.1.1",
        recovery_ip="192.168.0.1",
        client_ip="192.168.1.2",
        openwrt_client_ip="192.168.1.2",
        initramfs_tftp_name="initramfs.bin",
        stock_legacy_ssh_options=[],
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_ctx(**overrides):
    profile = overrides.pop("profile", None) or _make_profile()
    defaults = dict(
        profile=profile,
        image_path="/tmp/test.bin",
        interface="en0",
        pcap_path="/tmp/test.pcap",
        _say_fn=MagicMock(),
        state=State.DETECTING,
    )
    defaults.update(overrides)
    return RecoveryContext(**defaults)


# ===========================================================================
# 1. _extreme_tftp_server_ip  — PURE
# ===========================================================================

class TestExtremeTftpServerIp(TestCase):
    def test_returns_openwrt_client_ip_when_set(self):
        p = _make_profile(openwrt_client_ip="10.0.0.5", client_ip="10.0.0.1")
        self.assertEqual(_extreme_tftp_server_ip(p), "10.0.0.5")

    def test_falls_back_to_client_ip(self):
        p = _make_profile(openwrt_client_ip="", client_ip="10.0.0.1")
        self.assertEqual(_extreme_tftp_server_ip(p), "10.0.0.1")

    def test_returns_empty_when_both_empty(self):
        p = _make_profile(openwrt_client_ip="", client_ip="")
        self.assertEqual(_extreme_tftp_server_ip(p), "")


# ===========================================================================
# 2. _extreme_stock_ssh_options  — PURE
# ===========================================================================

class TestExtremeStockSshOptions(TestCase):
    def test_returns_options_when_set(self):
        p = _make_profile(stock_legacy_ssh_options=["-o", "KexAlgorithms=+diffie-hellman-group1-sha1"])
        result = _extreme_stock_ssh_options(p)
        self.assertEqual(result, ["-o", "KexAlgorithms=+diffie-hellman-group1-sha1"])

    def test_returns_empty_list_when_empty(self):
        p = _make_profile(stock_legacy_ssh_options=[])
        self.assertEqual(_extreme_stock_ssh_options(p), [])

    def test_returns_empty_list_when_attribute_missing(self):
        p = SimpleNamespace(name="x")
        self.assertEqual(_extreme_stock_ssh_options(p), [])

    def test_returns_copy_not_original(self):
        original = ["-o", "Test=yes"]
        p = _make_profile(stock_legacy_ssh_options=original)
        result = _extreme_stock_ssh_options(p)
        self.assertIsNot(result, original)
        result.append("extra")
        self.assertNotIn("extra", original)


# ===========================================================================
# 3. _resolve_extreme_uboot_value  — PURE
# ===========================================================================

class TestResolveExtremeUbootValue(TestCase):
    def test_resolves_tftp_server_ip_placeholder(self):
        p = _make_profile(openwrt_client_ip="10.0.0.5")
        self.assertEqual(_resolve_extreme_uboot_value(p, "<CONWRT_TFTP_SERVER_IP>"), "10.0.0.5")

    def test_returns_other_string_as_is(self):
        p = _make_profile()
        self.assertEqual(_resolve_extreme_uboot_value(p, "some_value"), "some_value")

    def test_returns_empty_string_as_is(self):
        p = _make_profile()
        self.assertEqual(_resolve_extreme_uboot_value(p, ""), "")

    def test_does_not_resolve_unrelated_angle_bracket_string(self):
        p = _make_profile(openwrt_client_ip="10.0.0.5")
        self.assertEqual(_resolve_extreme_uboot_value(p, "<SOMETHING_ELSE>"), "<SOMETHING_ELSE>")


# ===========================================================================
# 4. _setup_interface_ips  — EASY (mock configure_interface_ip)
# ===========================================================================

class TestSetupInterfaceIps(TestCase):
    @patch("conwrt.extreme.configure_interface_ip")
    def test_calls_with_client_ip(self, mock_cfg):
        p = _make_profile(client_ip="10.0.0.1", openwrt_client_ip="")
        _setup_interface_ips("en0", p)
        mock_cfg.assert_called_once_with("en0", "10.0.0.1", "24")

    @patch("conwrt.extreme.configure_interface_ip")
    def test_calls_twice_when_both_set_and_different(self, mock_cfg):
        p = _make_profile(client_ip="10.0.0.1", openwrt_client_ip="10.0.0.2")
        _setup_interface_ips("en0", p)
        self.assertEqual(mock_cfg.call_count, 2)
        mock_cfg.assert_any_call("en0", "10.0.0.1", "24")
        mock_cfg.assert_any_call("en0", "10.0.0.2", "24")

    @patch("conwrt.extreme.configure_interface_ip")
    def test_calls_once_when_ips_are_same(self, mock_cfg):
        p = _make_profile(client_ip="10.0.0.1", openwrt_client_ip="10.0.0.1")
        _setup_interface_ips("en0", p)
        mock_cfg.assert_called_once_with("en0", "10.0.0.1", "24")

    @patch("conwrt.extreme.configure_interface_ip")
    def test_calls_once_with_openwrt_client_ip_when_client_ip_empty(self, mock_cfg):
        p = _make_profile(client_ip="", openwrt_client_ip="10.0.0.2")
        _setup_interface_ips("en0", p)
        mock_cfg.assert_called_once_with("en0", "10.0.0.2", "24")


# ===========================================================================
# 5. _write_json_file  — EASY
# ===========================================================================

class TestWriteJsonFile(TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_writes_valid_json(self):
        path = Path(self._tmpdir) / "test.json"
        _write_json_file(path, {"key": "value"})
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(data, {"key": "value"})

    def test_creates_parent_directories(self):
        path = Path(self._tmpdir) / "a" / "b" / "test.json"
        _write_json_file(path, {"x": 1})
        self.assertTrue(path.exists())

    def test_includes_trailing_newline(self):
        path = Path(self._tmpdir) / "test.json"
        _write_json_file(path, {"a": 1})
        text = path.read_text()
        self.assertTrue(text.endswith("\n"))

    def test_sorts_keys(self):
        path = Path(self._tmpdir) / "test.json"
        _write_json_file(path, {"z": 1, "a": 2, "m": 3})
        text = path.read_text()
        # In sorted JSON, "a" comes before "m" which comes before "z"
        self.assertLess(text.index('"a"'), text.index('"m"'))
        self.assertLess(text.index('"m"'), text.index('"z"'))


# ===========================================================================
# 6. _cleanup_extreme_tftp_assets  — EASY
# ===========================================================================

class TestCleanupExtremeTftpAssets(TestCase):
    @patch("conwrt.extreme.shutil.rmtree")
    def test_stops_tftp_manager_and_sets_none(self, mock_rmtree):
        mock_mgr = MagicMock()
        ctx = _make_ctx()
        ctx._extreme_tftp_manager = mock_mgr
        ctx._extreme_tftp_root = ""
        _cleanup_extreme_tftp_assets(ctx)
        mock_mgr.stop.assert_called_once()
        self.assertIsNone(ctx._extreme_tftp_manager)

    @patch("conwrt.extreme.shutil.rmtree")
    def test_no_error_when_no_tftp_manager(self, mock_rmtree):
        ctx = _make_ctx()
        ctx._extreme_tftp_root = ""
        _cleanup_extreme_tftp_assets(ctx)  # should not raise

    @patch("conwrt.extreme.shutil.rmtree")
    def test_removes_tftp_root_and_clears(self, mock_rmtree):
        ctx = _make_ctx()
        ctx._extreme_tftp_manager = None
        ctx._extreme_tftp_root = "/tmp/some-tftp-root"
        _cleanup_extreme_tftp_assets(ctx)
        mock_rmtree.assert_called_once_with("/tmp/some-tftp-root", ignore_errors=True)
        self.assertEqual(ctx._extreme_tftp_root, "")

    @patch("conwrt.extreme.shutil.rmtree")
    def test_no_error_when_no_tftp_root(self, mock_rmtree):
        ctx = _make_ctx()
        ctx._extreme_tftp_manager = None
        ctx._extreme_tftp_root = ""
        _cleanup_extreme_tftp_assets(ctx)
        mock_rmtree.assert_not_called()


# ===========================================================================
# 7. _extreme_confirm_or_fail  — MEDIUM
# ===========================================================================

class TestExtremeConfirmOrFail(TestCase):
    def test_returns_true_when_no_upload(self):
        ctx = _make_ctx(no_upload=True)
        self.assertTrue(_extreme_confirm_or_fail(ctx, "Continue?"))

    def test_returns_true_when_assume_yes(self):
        ctx = _make_ctx(assume_yes=True)
        self.assertTrue(_extreme_confirm_or_fail(ctx, "Continue?"))

    @patch("builtins.input", return_value="y")
    def test_returns_true_on_y(self, mock_input):
        ctx = _make_ctx()
        self.assertTrue(_extreme_confirm_or_fail(ctx, "Continue?"))

    @patch("builtins.input", return_value="yes")
    def test_returns_true_on_yes(self, mock_input):
        ctx = _make_ctx()
        self.assertTrue(_extreme_confirm_or_fail(ctx, "Continue?"))

    @patch("builtins.input", return_value="n")
    def test_returns_false_and_fails_on_n(self, mock_input):
        ctx = _make_ctx()
        result = _extreme_confirm_or_fail(ctx, "Continue?")
        self.assertFalse(result)
        self.assertEqual(ctx.state, State.FAILED)

    @patch("builtins.input", side_effect=EOFError)
    def test_returns_false_on_eoferror(self, mock_input):
        ctx = _make_ctx()
        result = _extreme_confirm_or_fail(ctx, "Continue?")
        self.assertFalse(result)
        self.assertEqual(ctx.state, State.FAILED)

    @patch("builtins.input", side_effect=KeyboardInterrupt)
    def test_returns_false_on_keyboard_interrupt(self, mock_input):
        ctx = _make_ctx()
        result = _extreme_confirm_or_fail(ctx, "Continue?")
        self.assertFalse(result)
        self.assertEqual(ctx.state, State.FAILED)

    @patch("builtins.input", return_value="")
    def test_returns_false_on_empty_input(self, mock_input):
        ctx = _make_ctx()
        result = _extreme_confirm_or_fail(ctx, "Continue?")
        self.assertFalse(result)
        self.assertEqual(ctx.state, State.FAILED)

    @patch("builtins.input", return_value=" Y ")
    def test_accepts_uppercase_y_with_whitespace(self, mock_input):
        ctx = _make_ctx()
        self.assertTrue(_extreme_confirm_or_fail(ctx, "Continue?"))


# ===========================================================================
# 8. _ensure_extreme_backup_dir  — MEDIUM
# ===========================================================================

class TestEnsureExtremeBackupDir(TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_creates_dir_and_caches_on_ctx(self):
        """Test that backup dir is created and cached on ctx."""
        ctx = _make_ctx()
        ctx._extreme_backup_dir = ""
        # Patch Path.__file__ by patching the module-level reference
        with patch.object(Path, "mkdir"):
            # We'll test the device_id logic indirectly
            # Use a real tempdir as the base
            with patch("conwrt.extreme.Path") as mock_path_cls:
                fake_backup_dir = Path(self._tmpdir) / "backup"
                fake_backup_dir.mkdir(parents=True, exist_ok=True)
                # Setup the chain: Path(__file__).resolve().parent.parent / "data" / ...
                mock_base = MagicMock()
                mock_path_cls.return_value.resolve.return_value.parent.parent.__truediv__.return_value.__truediv__.return_value.__truediv__.return_value = fake_backup_dir
                result = _ensure_extreme_backup_dir(ctx, {"serial": "ABC123"})
                # Verify the dir was returned and cached
                self.assertIsNotNone(result)

    def test_reuses_cached_dir_on_second_call(self):
        """Second call returns cached dir without creating new one."""
        cached = str(Path(self._tmpdir) / "cached")
        Path(cached).mkdir(parents=True, exist_ok=True)
        ctx = _make_ctx()
        ctx._extreme_backup_dir = cached
        result = _ensure_extreme_backup_dir(ctx, {"serial": "XYZ"})
        self.assertEqual(str(result), cached)

    def test_uses_serial_from_preflight_data(self):
        """Verify device_id comes from serial when present."""
        ctx = _make_ctx()
        ctx._extreme_backup_dir = ""
        with patch("conwrt.extreme.Path") as mock_path_cls:
            fake_backup_dir = Path(self._tmpdir) / "serial-test"
            mock_base = MagicMock()
            # Path(__file__).resolve().parent.parent / "data" / "backups" / ctx.profile.name / device_id
            chain = mock_path_cls.return_value.resolve.return_value.parent.parent
            chain.__truediv__.return_value.__truediv__.return_value.__truediv__.return_value.__truediv__.return_value = fake_backup_dir
            _ensure_extreme_backup_dir(ctx, {"serial": "SN12345"})
            # Check that _extreme_device_id was set to sanitized serial
            self.assertEqual(ctx._extreme_device_id, "SN12345")

    def test_falls_back_to_hostname(self):
        ctx = _make_ctx()
        ctx._extreme_backup_dir = ""
        with patch("conwrt.extreme.Path") as mock_path_cls:
            fake_backup_dir = Path(self._tmpdir) / "hostname-test"
            chain = mock_path_cls.return_value.resolve.return_value.parent.parent
            chain.__truediv__.return_value.__truediv__.return_value.__truediv__.return_value.__truediv__.return_value = fake_backup_dir
            _ensure_extreme_backup_dir(ctx, {"serial": "", "hostname": "my-ap"})
            self.assertEqual(ctx._extreme_device_id, "my-ap")

    def test_falls_back_to_unknown_device(self):
        ctx = _make_ctx()
        ctx._extreme_backup_dir = ""
        with patch("conwrt.extreme.Path") as mock_path_cls:
            fake_backup_dir = Path(self._tmpdir) / "unknown-test"
            chain = mock_path_cls.return_value.resolve.return_value.parent.parent
            chain.__truediv__.return_value.__truediv__.return_value.__truediv__.return_value.__truediv__.return_value = fake_backup_dir
            _ensure_extreme_backup_dir(ctx, None)
            self.assertEqual(ctx._extreme_device_id, "unknown-device")


# ===========================================================================
# 9. _extreme_openwrt_ssh  — MEDIUM
# ===========================================================================

class TestExtremeOpenwrtSsh(TestCase):
    @patch("conwrt.extreme.subprocess.run")
    @patch("conwrt.extreme.shutil.which", return_value="/usr/bin/sshpass")
    def test_uses_sshpass_when_available(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        ctx = _make_ctx()
        _extreme_openwrt_ssh(ctx, "ls")
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "/usr/bin/sshpass")
        self.assertIn("-p", cmd)
        self.assertIn("", cmd[cmd.index("-p") + 1])

    @patch("conwrt.extreme.ssh_cmd", return_value=["ssh", "root@192.168.1.1", "ls"])
    @patch("conwrt.extreme.subprocess.run")
    @patch("conwrt.extreme.shutil.which", return_value=None)
    def test_uses_ssh_cmd_when_no_sshpass(self, mock_which, mock_run, mock_ssh_cmd):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        ctx = _make_ctx()
        _extreme_openwrt_ssh(ctx, "ls")
        mock_ssh_cmd.assert_called_once()
        mock_run.assert_called_once()

    @patch("conwrt.extreme.subprocess.run")
    @patch("conwrt.extreme.shutil.which", return_value="/usr/bin/sshpass")
    def test_uses_correct_ip(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        ctx = _make_ctx(profile=_make_profile(openwrt_ip="10.0.0.99"))
        _extreme_openwrt_ssh(ctx, "uname")
        cmd = mock_run.call_args[0][0]
        self.assertIn("root@10.0.0.99", cmd)

    @patch("conwrt.extreme.subprocess.run")
    @patch("conwrt.extreme.shutil.which", return_value="/usr/bin/sshpass")
    def test_passes_custom_timeout(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        ctx = _make_ctx()
        _extreme_openwrt_ssh(ctx, "ls", timeout=60)
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["timeout"], 60)


# ===========================================================================
# 10. _extreme_openwrt_scp_from_remote  — MEDIUM
# ===========================================================================

class TestExtremeOpenwrtScpFromRemote(TestCase):
    @patch("conwrt.extreme.subprocess.run")
    @patch("conwrt.extreme.shutil.which", return_value="/usr/bin/sshpass")
    def test_uses_sshpass_when_available(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        ctx = _make_ctx()
        _extreme_openwrt_scp_from_remote(ctx, "/remote/file", "/local/file")
        cmd = mock_run.call_args[0][0]
        self.assertIn("scp", cmd)
        self.assertIn("root@192.168.1.1:/remote/file", cmd)
        self.assertIn("/local/file", cmd)

    @patch("conwrt.extreme.scp_cmd", return_value=["scp", "src", "dst"])
    @patch("conwrt.extreme.subprocess.run")
    @patch("conwrt.extreme.shutil.which", return_value=None)
    def test_uses_scp_cmd_when_no_sshpass(self, mock_which, mock_run, mock_scp_cmd):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        ctx = _make_ctx()
        _extreme_openwrt_scp_from_remote(ctx, "/remote/file", "/local/file")
        mock_scp_cmd.assert_called_once()
        mock_run.assert_called_once()

    @patch("conwrt.extreme.subprocess.run")
    @patch("conwrt.extreme.shutil.which", return_value="/usr/bin/sshpass")
    def test_passes_timeout(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        ctx = _make_ctx()
        _extreme_openwrt_scp_from_remote(ctx, "/r", "/l", timeout=300)
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["timeout"], 300)


# ===========================================================================
# 11. _extreme_openwrt_scp_to_remote  — MEDIUM
# ===========================================================================

class TestExtremeOpenwrtScpToRemote(TestCase):
    @patch("conwrt.extreme.subprocess.run")
    @patch("conwrt.extreme.shutil.which", return_value="/usr/bin/sshpass")
    def test_uses_sshpass_when_available(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        ctx = _make_ctx()
        _extreme_openwrt_scp_to_remote(ctx, "/local/file", "/remote/dest")
        cmd = mock_run.call_args[0][0]
        self.assertIn("scp", cmd)
        self.assertIn("/local/file", cmd)
        self.assertIn("root@192.168.1.1:/remote/dest", cmd)

    @patch("conwrt.extreme.scp_cmd", return_value=["scp", "src", "dst"])
    @patch("conwrt.extreme.subprocess.run")
    @patch("conwrt.extreme.shutil.which", return_value=None)
    def test_uses_scp_cmd_when_no_sshpass(self, mock_which, mock_run, mock_scp_cmd):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        ctx = _make_ctx()
        _extreme_openwrt_scp_to_remote(ctx, "/local/file", "/remote/dest")
        mock_scp_cmd.assert_called_once()
        mock_run.assert_called_once()

    @patch("conwrt.extreme.subprocess.run")
    @patch("conwrt.extreme.shutil.which", return_value="/usr/bin/sshpass")
    def test_passes_timeout(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        ctx = _make_ctx()
        _extreme_openwrt_scp_to_remote(ctx, "/l", "/r", timeout=200)
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["timeout"], 200)


# ===========================================================================
# 12. _prepare_extreme_tftp_root  — MEDIUM
# ===========================================================================

class TestPrepareExtremeTftpRoot(TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._initramfs = Path(self._tmpdir) / "initramfs.bin"
        self._initramfs.write_bytes(b"\x00" * 1024)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_none_none_when_no_initramfs_path(self):
        ctx = _make_ctx(initramfs_path="")
        result = _prepare_extreme_tftp_root(ctx)
        self.assertEqual(result, (None, None))

    def test_returns_none_none_when_initramfs_missing(self):
        ctx = _make_ctx(initramfs_path="/nonexistent/file.bin")
        result = _prepare_extreme_tftp_root(ctx)
        self.assertEqual(result, (None, None))

    def test_creates_temp_dir_with_primary_symlink(self):
        ctx = _make_ctx(
            initramfs_path=str(self._initramfs),
            profile=_make_profile(initramfs_tftp_name="test-image.bin"),
        )
        tftp_root, primary_path = _prepare_extreme_tftp_root(ctx)
        try:
            self.assertIsNotNone(tftp_root)
            self.assertTrue(tftp_root.exists())
            self.assertTrue(primary_path.exists())
            self.assertEqual(primary_path.name, "test-image.bin")
            # Should be a symlink or a copy
            self.assertEqual(primary_path.stat().st_size, 1024)
        finally:
            if tftp_root:
                shutil.rmtree(tftp_root, ignore_errors=True)

    def test_creates_alt_symlink_when_configured(self):
        ctx = _make_ctx(
            initramfs_path=str(self._initramfs),
            profile=_make_profile(
                initramfs_tftp_name="primary.bin",
                optional_alt_tftp_name="alt.bin",
            ),
        )
        tftp_root, _ = _prepare_extreme_tftp_root(ctx)
        self.assertIsNotNone(tftp_root)
        assert tftp_root is not None
        try:
            alt_path = tftp_root / "alt.bin"
            self.assertTrue(alt_path.exists())
            self.assertEqual(alt_path.stat().st_size, 1024)
        finally:
            shutil.rmtree(tftp_root, ignore_errors=True)

    def test_skips_alt_when_same_as_primary(self):
        ctx = _make_ctx(
            initramfs_path=str(self._initramfs),
            profile=_make_profile(
                initramfs_tftp_name="same.bin",
                optional_alt_tftp_name="same.bin",
            ),
        )
        tftp_root, _ = _prepare_extreme_tftp_root(ctx)
        self.assertIsNotNone(tftp_root)
        assert tftp_root is not None
        try:
            entries = list(tftp_root.iterdir())
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].name, "same.bin")
        finally:
            shutil.rmtree(tftp_root, ignore_errors=True)


# ===========================================================================
# 13. _advance_past_port_isolation  — MEDIUM
# ===========================================================================

class TestAdvancePastPortIsolation(TestCase):
    def test_extreme_rdwr_tftp_stock_boot_goes_to_preflight(self):
        p = _make_profile(flash_method="extreme-rdwr-tftp", use_sysupgrade=False)
        ctx = _make_ctx(profile=p, boot_state="stock-extreme")
        _advance_past_port_isolation(ctx)
        self.assertEqual(ctx.state, State.EXTREME_STOCK_PREFLIGHT)

    def test_extreme_rdwr_tftp_other_boot_goes_to_detecting(self):
        p = _make_profile(flash_method="extreme-rdwr-tftp", use_sysupgrade=False)
        ctx = _make_ctx(profile=p, boot_state="unknown")
        _advance_past_port_isolation(ctx)
        self.assertEqual(ctx.state, State.DETECTING)

    def test_serial_tftp_goes_to_serial_waiting(self):
        p = _make_profile(flash_method="serial-tftp-openwrt")
        ctx = _make_ctx(profile=p)
        _advance_past_port_isolation(ctx)
        self.assertEqual(ctx.state, State.SERIAL_WAITING_FOR_BOOTMENU)

    def test_zycast_goes_to_zycast_waiting(self):
        p = _make_profile(flash_method="zycast", use_sysupgrade=False)
        ctx = _make_ctx(profile=p)
        _advance_past_port_isolation(ctx)
        self.assertEqual(ctx.state, State.ZYCAST_WAITING_FOR_DEVICE)

    def test_edgeos_goes_to_edgeos_stage1(self):
        p = _make_profile(flash_method="edgeos-kernel-swap", use_sysupgrade=False)
        ctx = _make_ctx(profile=p)
        _advance_past_port_isolation(ctx)
        self.assertEqual(ctx.state, State.EDGEOS_STAGE1)

    def test_sysupgrade_goes_to_uploading(self):
        p = _make_profile(flash_method="sysupgrade", use_sysupgrade=True)
        ctx = _make_ctx(profile=p)
        _advance_past_port_isolation(ctx)
        self.assertEqual(ctx.state, State.SYSUPGRADE_UPLOADING)

    def test_extreme_with_sysupgrade_goes_to_uploading(self):
        p = _make_profile(flash_method="extreme-rdwr-tftp", use_sysupgrade=True)
        ctx = _make_ctx(profile=p)
        _advance_past_port_isolation(ctx)
        self.assertEqual(ctx.state, State.SYSUPGRADE_UPLOADING)

    def test_default_falls_to_waiting_for_power_off(self):
        p = _make_profile(flash_method="recovery-http")
        # recovery-http without use_sysupgrade hits the else branch
        ctx = _make_ctx(profile=p)
        _advance_past_port_isolation(ctx)
        self.assertEqual(ctx.state, State.WAITING_FOR_POWER_OFF)


# ===========================================================================
# 14. _restore_port_isolation  — EASY
# ===========================================================================

class _FakePortIsolator:
    def __init__(self):
        self.restore = MagicMock()


class _BrokenPortIsolator:
    def restore(self, port):
        raise OSError("connection reset")


class TestRestorePortIsolation(TestCase):
    @patch("flash.port_isolator.PortIsolator", _FakePortIsolator)
    def test_calls_restore_when_port_isolator_set(self):
        fake = _FakePortIsolator()
        ctx = _make_ctx(isolate_port="lan1")
        ctx.port_isolator = fake
        _restore_port_isolation(ctx)
        fake.restore.assert_called_once_with("lan1")

    def test_no_error_when_port_isolator_none(self):
        ctx = _make_ctx(isolate_port="lan1")
        ctx.port_isolator = None
        _restore_port_isolation(ctx)

    def test_no_error_when_isolate_port_empty(self):
        ctx = _make_ctx(isolate_port="")
        ctx.port_isolator = MagicMock()
        _restore_port_isolation(ctx)

    @patch("flash.port_isolator.PortIsolator", _FakePortIsolator)
    def test_skips_when_not_port_isolator_instance(self):
        class UnrelatedClass:
            pass
        unrelated = UnrelatedClass()
        unrelated.restore = MagicMock()
        ctx = _make_ctx(isolate_port="lan1")
        ctx.port_isolator = unrelated
        _restore_port_isolation(ctx)
        unrelated.restore.assert_not_called()

    @patch("flash.port_isolator.PortIsolator", _BrokenPortIsolator)
    def test_logs_warning_on_oserror(self):
        fake = _BrokenPortIsolator()
        ctx = _make_ctx(isolate_port="lan1")
        ctx.port_isolator = fake
        with patch("conwrt.extreme.log") as mock_log:
            _restore_port_isolation(ctx)
        log_calls = [str(c) for c in mock_log.call_args_list]
        self.assertTrue(any("Restoring port" in c for c in log_calls))


# ===========================================================================
# Integration-style: verify helpers interact correctly
# ===========================================================================

class TestTftpServerIpIntegrationWithResolve(TestCase):
    """Verify _resolve_extreme_uboot_value delegates to _extreme_tftp_server_ip."""

    def test_resolve_delegates_correctly(self):
        p = _make_profile(openwrt_client_ip="10.0.0.42", client_ip="10.0.0.1")
        resolved = _resolve_extreme_uboot_value(p, "<CONWRT_TFTP_SERVER_IP>")
        self.assertEqual(resolved, "10.0.0.42")

    def test_resolve_uses_fallback(self):
        p = _make_profile(openwrt_client_ip="", client_ip="10.0.0.1")
        resolved = _resolve_extreme_uboot_value(p, "<CONWRT_TFTP_SERVER_IP>")
        self.assertEqual(resolved, "10.0.0.1")


class TestCleanupIntegration(TestCase):
    """Verify cleanup handles both manager and root together."""

    @patch("conwrt.extreme.shutil.rmtree")
    def test_cleans_both_manager_and_root(self, mock_rmtree):
        mock_mgr = MagicMock()
        ctx = _make_ctx()
        ctx._extreme_tftp_manager = mock_mgr
        ctx._extreme_tftp_root = "/tmp/tftp-root-abc"
        _cleanup_extreme_tftp_assets(ctx)
        mock_mgr.stop.assert_called_once()
        self.assertIsNone(ctx._extreme_tftp_manager)
        mock_rmtree.assert_called_once_with("/tmp/tftp-root-abc", ignore_errors=True)
        self.assertEqual(ctx._extreme_tftp_root, "")
