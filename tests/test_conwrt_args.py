from __future__ import annotations

import py_compile
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "scripts"))


def test_conwrt_script_compiles() -> None:
    py_compile.compile(str(ROOT / "scripts" / "conwrt.py"), doraise=True)


def test_firmware_manager_script_compiles() -> None:
    py_compile.compile(str(ROOT / "scripts" / "firmware-manager.py"), doraise=True)


class TestFlashParser:
    def _parse(self, *args: str):
        import conwrt
        with patch("sys.argv", ["conwrt", "flash", *args]):
            return conwrt._build_parser().parse_args()

    def test_image_flag(self):
        args = self._parse("--image", "/tmp/fw.bin")
        assert args.image == "/tmp/fw.bin"

    def test_model_id_flag(self):
        args = self._parse("--model-id", "zyxel-gs1920-24")
        assert args.model_id == "zyxel-gs1920-24"

    def test_request_image_flag(self):
        args = self._parse("--request-image")
        assert args.request_image is True

    def test_no_upload_flag(self):
        args = self._parse("--no-upload")
        assert args.no_upload is True

    def test_wan_ssh_flag(self):
        args = self._parse("--request-image", "--wan-ssh")
        assert args.wan_ssh is True

    def test_flash_method_flag(self):
        args = self._parse("--flash-method", "oem-ftp")
        assert args.flash_method == "oem-ftp"

    def test_defaults(self):
        args = self._parse("--image", "/tmp/fw.bin")
        assert args.no_upload is False
        assert args.no_voice is False
        assert args.force_uboot is False


class TestSubcommandRouting:
    def test_flash_command(self):
        import conwrt
        with patch("sys.argv", ["conwrt", "flash", "--image", "/tmp/fw.bin"]):
            args = conwrt._build_parser().parse_args()
            assert args.command == "flash"

    def test_list_command(self):
        import conwrt
        with patch("sys.argv", ["conwrt", "list"]):
            args = conwrt._build_parser().parse_args()
            assert args.command == "list"

    def test_cache_command(self):
        import conwrt
        with patch("sys.argv", ["conwrt", "cache", "list"]):
            args = conwrt._build_parser().parse_args()
            assert args.command == "cache"

    def test_backup_command(self):
        import conwrt
        with patch("sys.argv", ["conwrt", "backup"]):
            args = conwrt._build_parser().parse_args()
            assert args.command == "backup"

    def test_profile_command(self):
        import conwrt
        with patch("sys.argv", ["conwrt", "profile", "plan"]):
            args = conwrt._build_parser().parse_args()
            assert args.command == "profile"


class TestConfigureParser:
    def _parse(self, *args: str):
        import conwrt
        with patch("sys.argv", ["conwrt", "configure", *args]):
            return conwrt._build_parser().parse_args()

    def test_transport_default_ssh(self):
        args = self._parse("--ip", "192.168.1.1")
        assert args.transport == "ssh"

    def test_transport_ubus(self):
        args = self._parse("--ip", "192.168.1.1", "--transport", "ubus")
        assert args.transport == "ubus"

    def test_ubus_user_default(self):
        args = self._parse("--ip", "192.168.1.1", "--transport", "ubus")
        assert args.ubus_user == "root"

    def test_ubus_password_default(self):
        args = self._parse("--ip", "192.168.1.1", "--transport", "ubus")
        assert args.ubus_password == ""

    def test_ubus_credentials(self):
        args = self._parse("--ip", "192.168.1.1", "--transport", "ubus",
                           "--ubus-user", "admin", "--ubus-password", "secret")
        assert args.ubus_user == "admin"
        assert args.ubus_password == "secret"

    def test_transport_invalid_rejected(self):
        import argparse
        import pytest
        with pytest.raises(SystemExit):
            self._parse("--ip", "192.168.1.1", "--transport", "telnet")
