"""Tests for backup command and model backup configuration."""
import argparse
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from model_loader import load_model


class TestBackupModelConfig(TestCase):
    def test_nr7101_has_ssh_backup_config(self):
        model = load_model("zyxel-nr7101")
        backup = model.get("backup", {})
        self.assertEqual(backup.get("method"), "ssh")

    def test_nr7101_has_critical_partitions(self):
        model = load_model("zyxel-nr7101")
        backup = model.get("backup", {})
        self.assertIn("Factory", backup.get("critical_partitions", []))

    def test_nr7101_has_password_tool(self):
        model = load_model("zyxel-nr7101")
        backup = model.get("backup", {})
        self.assertIn("password_tool", backup)

    def test_gs1920_24_no_backup_config(self):
        model = load_model("zyxel-gs1920-24")
        backup = model.get("backup", {})
        self.assertEqual(backup, {})


class TestCmdBackup(TestCase):
    def test_none_model_id_returns_1(self):
        import conwrt
        args = argparse.Namespace(
            model_id=None, ip="192.168.1.1",
            password="test", serial=None, output_dir=None,
            partitions=None, user="root",
        )
        rc = conwrt.cmd_backup(args)
        self.assertEqual(rc, 1)

    def test_requires_password_or_serial(self):
        import conwrt
        args = argparse.Namespace(
            model_id="zyxel-nr7101", ip="192.168.1.1",
            password=None, serial=None, output_dir=None,
            partitions=None, user="root",
        )
        rc = conwrt.cmd_backup(args)
        self.assertEqual(rc, 1)

    @patch("conwrt._ssh_with_password")
    def test_ssh_failure_returns_1(self, mock_ssh):
        import conwrt
        mock_ssh.return_value = MagicMock(
            returncode=1, stderr="Connection refused", stdout=""
        )
        args = argparse.Namespace(
            model_id="zyxel-nr7101", ip="192.168.1.1",
            password="test", serial=None, output_dir=None,
            partitions=None, user="root",
        )
        rc = conwrt.cmd_backup(args)
        self.assertEqual(rc, 1)


class TestBackupSubcommandParser(TestCase):
    def test_backup_in_command_list(self):
        import conwrt
        source = Path(conwrt.__file__).read_text()
        self.assertIn('"backup"', source)

    def test_backup_parser_accepts_model_id(self):
        import conwrt
        with patch("sys.argv", ["conwrt", "backup", "--model-id", "zyxel-nr7101"]):
            parser = conwrt._build_parser()
            args = parser.parse_args()
            self.assertEqual(args.model_id, "zyxel-nr7101")

    def test_backup_parser_accepts_ip(self):
        import conwrt
        with patch("sys.argv", ["conwrt", "backup", "--model-id", "zyxel-nr7101", "--ip", "10.0.0.1"]):
            parser = conwrt._build_parser()
            args = parser.parse_args()
            self.assertEqual(args.ip, "10.0.0.1")

    def test_backup_parser_defaults(self):
        import conwrt
        with patch("sys.argv", ["conwrt", "backup"]):
            parser = conwrt._build_parser()
            args = parser.parse_args()
            self.assertEqual(args.model_id, "zyxel-nr7101")
            self.assertEqual(args.user, "root")
            self.assertIsNone(args.password)
            self.assertIsNone(args.serial)
