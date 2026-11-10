"""Tests for conwrt.extreme state handlers and profile helpers."""
from __future__ import annotations

import json
import queue
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.context import State
from conwrt.extreme import (
    _resolve_extreme_uboot_value,
    _extreme_tftp_server_ip,
    _extreme_stock_ssh_options,
    _setup_interface_ips,
    _write_json_file,
)


class TestResolveExtremeUbootValue(TestCase):
    def test_placeholder_resolved(self):
        profile = SimpleNamespace(openwrt_client_ip="10.0.0.1")
        self.assertEqual(
            _resolve_extreme_uboot_value(profile, "<CONWRT_TFTP_SERVER_IP>"),
            "10.0.0.1",
        )

    def test_literal_passthrough(self):
        profile = SimpleNamespace(openwrt_client_ip="10.0.0.1")
        self.assertEqual(
            _resolve_extreme_uboot_value(profile, "some_literal"),
            "some_literal",
        )

    def test_empty_value(self):
        profile = SimpleNamespace(openwrt_client_ip="10.0.0.1")
        self.assertEqual(_resolve_extreme_uboot_value(profile, ""), "")


class TestExtremeTftpServerIp(TestCase):
    def test_openwrt_client_ip_preferred(self):
        profile = SimpleNamespace(openwrt_client_ip="10.0.0.5", client_ip="10.0.0.1")
        self.assertEqual(_extreme_tftp_server_ip(profile), "10.0.0.5")

    def test_fallback_to_client_ip(self):
        profile = SimpleNamespace(openwrt_client_ip="", client_ip="10.0.0.1")
        self.assertEqual(_extreme_tftp_server_ip(profile), "10.0.0.1")

    def test_neither_returns_empty(self):
        profile = SimpleNamespace()
        self.assertEqual(_extreme_tftp_server_ip(profile), "")


class TestExtremeStockSshOptions(TestCase):
    def test_with_options(self):
        profile = SimpleNamespace(stock_legacy_ssh_options=["-o", "KexAlgorithms=+legacy"])
        result = _extreme_stock_ssh_options(profile)
        self.assertEqual(result, ["-o", "KexAlgorithms=+legacy"])

    def test_without_options(self):
        profile = SimpleNamespace()
        self.assertEqual(_extreme_stock_ssh_options(profile), [])

    def test_none_options(self):
        profile = SimpleNamespace(stock_legacy_ssh_options=None)
        self.assertEqual(_extreme_stock_ssh_options(profile), [])

    def test_empty_list(self):
        profile = SimpleNamespace(stock_legacy_ssh_options=[])
        self.assertEqual(_extreme_stock_ssh_options(profile), [])


class TestSetupInterfaceIps(TestCase):
    @patch("conwrt.extreme.configure_interface_ip", return_value=True)
    def test_client_ip_set(self, mock_cfg):
        profile = SimpleNamespace(client_ip="10.0.0.1", openwrt_client_ip="")
        _setup_interface_ips("en0", profile)
        mock_cfg.assert_called_once_with("en0", "10.0.0.1", "24")

    @patch("conwrt.extreme.configure_interface_ip", return_value=True)
    def test_both_ips_different(self, mock_cfg):
        profile = SimpleNamespace(client_ip="10.0.0.1", openwrt_client_ip="10.0.0.5")
        _setup_interface_ips("en0", profile)
        self.assertEqual(mock_cfg.call_count, 2)
        mock_cfg.assert_any_call("en0", "10.0.0.1", "24")
        mock_cfg.assert_any_call("en0", "10.0.0.5", "24")

    @patch("conwrt.extreme.configure_interface_ip", return_value=True)
    def test_same_ip_not_duplicated(self, mock_cfg):
        profile = SimpleNamespace(client_ip="10.0.0.1", openwrt_client_ip="10.0.0.1")
        _setup_interface_ips("en0", profile)
        mock_cfg.assert_called_once_with("en0", "10.0.0.1", "24")

    @patch("conwrt.extreme.configure_interface_ip", return_value=True)
    def test_no_client_ip(self, mock_cfg):
        profile = SimpleNamespace(client_ip="", openwrt_client_ip="")
        _setup_interface_ips("en0", profile)
        mock_cfg.assert_not_called()


class TestWriteJsonFile(TestCase):
    def test_writes_json_file(self):
        tmpdir = tempfile.mkdtemp()
        try:
            path = Path(tmpdir) / "sub" / "test.json"
            data = {"key": "value", "number": 42}
            _write_json_file(path, data)
            self.assertTrue(path.exists())
            loaded = json.loads(path.read_text())
            self.assertEqual(loaded, data)
        finally:
            shutil.rmtree(tmpdir)

    def test_sorted_keys(self):
        tmpdir = tempfile.mkdtemp()
        try:
            path = Path(tmpdir) / "sorted.json"
            _write_json_file(path, {"z": 1, "a": 2})
            content = path.read_text()
            z_pos = content.index('"z"')
            a_pos = content.index('"a"')
            self.assertLess(a_pos, z_pos)
        finally:
            shutil.rmtree(tmpdir)


class TestExtremeStockPreflight(TestCase):
    """Test _handle_extreme_stock_preflight via conwrt module (re-exported names)."""

    def _make_ctx(self, **overrides):
        defaults = dict(
            profile=SimpleNamespace(
                name="test-model",
                stock_default_ip="192.168.1.1",
                stock_default_user="admin",
                stock_default_password="secret",
                openwrt_client_ip="10.0.0.5",
                client_ip="10.0.0.1",
                initramfs_tftp_name="initramfs.bin",
                required_uboot_vars={"bootcmd": "run boot_flash"},
                stock_ssh_timeout_disable_commands=[],
                stock_legacy_ssh_options=[],
                rdwr_boot_cfg_binary="rdwr_boot_cfg",
            ),
            interface="en0",
            initramfs_path="/tmp/initramfs.bin",
            image_path="/tmp/sysupgrade.bin",
            no_upload=False,
            assume_yes=True,
            _say_fn=lambda _msg: None,
        )
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    @patch("conwrt.extreme.os.path.isfile", return_value=True)
    @patch("conwrt.extreme.configure_interface_ip", return_value=True)
    @patch("conwrt.extreme._write_json_file")
    @patch("conwrt.extreme._ensure_extreme_backup_dir")
    @patch("conwrt.extreme._setup_interface_ips")
    @patch("conwrt.extreme._prepare_extreme_tftp_root")
    @patch("conwrt.extreme._ssh_with_password")
    @patch("conwrt.extreme.TFTPServerManager")
    def test_preflight_success_sets_next_state(
        self, mock_tftp, mock_ssh, mock_prepare_tftp, mock_setup, mock_backup_dir,
        mock_write_json, mock_cfg_ip, mock_isfile,
    ):
        from conwrt.extreme import _handle_extreme_stock_preflight

        ctx = self._make_ctx()
        event_queue = queue.Queue()
        tmpdir = tempfile.mkdtemp()
        tftp_tmpdir = tempfile.mkdtemp()
        try:
            tftp_root = Path(tftp_tmpdir)
            (tftp_root / "initramfs.bin").write_bytes(b"\x00" * 64)
            mock_prepare_tftp.return_value = (tftp_root, tftp_root / "initramfs.bin")
            mock_backup_dir.return_value = Path(tmpdir)
            mock_tftp_inst = MagicMock()
            mock_tftp_inst.start.return_value = True
            mock_tftp.return_value = mock_tftp_inst

            def ssh_side_effect(_ip, _user, _pw, command, timeout=30, *, extra_ssh_options=None):
                if command.startswith("which"):
                    return MagicMock(returncode=0, stdout="/usr/bin/rdwr_boot_cfg\n", stderr="")
                if "read_all" in command:
                    return MagicMock(returncode=255, stdout="", stderr="broken")
                return MagicMock(returncode=0, stdout="ok\n", stderr="")

            mock_ssh.side_effect = ssh_side_effect
            _handle_extreme_stock_preflight(ctx, event_queue)

            self.assertEqual(ctx.state, State.EXTREME_STOCK_WRITING_UBOOT)
        finally:
            shutil.rmtree(tmpdir, True)
            shutil.rmtree(tftp_tmpdir, True)


class TestEnsureExtremeBackupDir(TestCase):
    @patch("conwrt.extreme.TFTPServerManager")
    def test_uses_serial_for_device_id(self, _mock_tftp):
        from conwrt.extreme import _ensure_extreme_backup_dir

        ctx = SimpleNamespace(
            profile=SimpleNamespace(name="test-model"),
            _extreme_backup_dir="",
        )
        preflight = {"serial": "SN12345", "hostname": "", "primary_mac": ""}
        result = _ensure_extreme_backup_dir(ctx, preflight)
        self.assertEqual(ctx._extreme_device_id, "SN12345")
        self.assertIn("test-model", str(result))
        shutil.rmtree(str(result), ignore_errors=True)
