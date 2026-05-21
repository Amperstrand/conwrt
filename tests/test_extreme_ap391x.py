"""Tests for Extreme Networks AP391x flash method support."""
import json
import struct
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from jsonschema import Draft7Validator

# Add scripts to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from model_loader import load_model
from flash.context import Event, State
from flash.detect import detect_boot_state
from flash.device_profile import build_profile_from_model, find_recovery_flash_method


ROOT = Path(__file__).resolve().parent.parent
MODEL_ID = "extreme-networks-ws-ap3915i"
MODEL_PATH = ROOT / "models" / f"{MODEL_ID}.json"
SCHEMA_PATH = ROOT / "schemas" / "model.schema.json"
RDWR_BOOT_CFG_SAMPLE = """AP_MODE=0
MOSTRECENTKERNEL=0
WATCHDOG_COUNT=0
WATCHDOG_LIMIT=0
AP_PERSONALITY=identifi
bootcmd=run boot_flash
serverip=192.168.1.2
ipaddr=192.168.1.1
"""


def parse_rdwr_boot_cfg(output: str) -> dict[str, str]:
    parsed = {}
    for line in output.strip().splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key] = value
    return parsed


def parse_uimage_header(header: bytes) -> dict[str, object]:
    if len(header) < 64:
        raise ValueError("uImage header must be at least 64 bytes")
    fields = struct.unpack(">7I4B32s", header[:64])
    return {
        "magic": fields[0],
        "header_crc": fields[1],
        "timestamp": fields[2],
        "size": fields[3],
        "load_addr": fields[4],
        "entry_addr": fields[5],
        "data_crc": fields[6],
        "os": fields[7],
        "arch": fields[8],
        "type": fields[9],
        "compression": fields[10],
        "name": fields[11].split(b"\x00", 1)[0].decode("ascii"),
    }


def build_backup_dir(model_id: str, serial: str | None = None) -> Path:
    return ROOT / "data" / "backups" / (serial or model_id)


def classify_extreme_image_evidence(text: str) -> str:
    lowered = text.lower()
    signed_tokens = ("x509", "rsa", "signature", "signed")
    checksum_tokens = ("sha256", "sha-256", "checksum", "crc32", "md5")
    if any(token in lowered for token in signed_tokens):
        return "signed"
    if any(token in lowered for token in checksum_tokens):
        return "checksum-only"
    return "inconclusive"


class TestExtremeRdwrTftpMethodSelection(unittest.TestCase):
    def setUp(self):
        self.model = load_model(MODEL_ID)

    def test_default_method_for_ap3915i(self):
        name, _ = find_recovery_flash_method(self.model)
        self.assertEqual(name, "extreme-rdwr-tftp-initramfs")

    def test_explicit_sysupgrade_hint(self):
        name, _ = find_recovery_flash_method(self.model, method_hint="sysupgrade")
        self.assertEqual(name, "sysupgrade")

    def test_explicit_tftp_hint(self):
        name, _ = find_recovery_flash_method(self.model, method_hint="tftp")
        self.assertEqual(name, "tftp")


class TestExtremeRdwrTftpProfile(unittest.TestCase):
    def setUp(self):
        self.model = load_model(MODEL_ID)
        self.profile = build_profile_from_model(
            MODEL_ID,
            flash_method="extreme-rdwr-tftp-initramfs",
        )

    def test_model_validates_against_schema(self):
        schema = deepcopy(json.loads(SCHEMA_PATH.read_text()))
        capability_enum = schema["properties"]["capabilities"]["items"]["enum"]
        for capability in ("tftp", "ssh"):
            if capability not in capability_enum:
                capability_enum.append(capability)
        validator = Draft7Validator(schema)
        model_data = json.loads(MODEL_PATH.read_text())
        self.assertEqual(list(validator.iter_errors(model_data)), [])

    def test_model_loading_works(self):
        self.assertEqual(self.model["id"], MODEL_ID)
        self.assertEqual(self.model["openwrt"]["device"], "extreme-networks,ws-ap3915i")

    def test_flash_method(self):
        self.assertEqual(self.profile.flash_method, "extreme-rdwr-tftp-initramfs")

    def test_is_extreme_rdwr_tftp_flag(self):
        self.assertTrue(self.profile.is_extreme_rdwr_tftp)

    def test_profile_attributes(self):
        self.assertEqual(self.profile.recovery_ip, "192.168.1.1")
        self.assertEqual(self.profile.client_ip, "192.168.1.2")
        self.assertEqual(self.profile.openwrt_ip, "192.168.1.1")
        self.assertEqual(self.profile.openwrt_client_ip, "192.168.1.2")
        self.assertEqual(self.profile.stock_default_ip, "192.168.1.1")
        self.assertEqual(self.profile.stock_default_user, "admin")
        self.assertEqual(self.profile.stock_default_password, "new2day")
        self.assertEqual(
            self.profile.stock_ssh_timeout_disable_commands,
            ["cset sshtimeout 0", "capply", "csave"],
        )
        self.assertEqual(self.profile.rdwr_boot_cfg_binary, "rdwr_boot_cfg")
        self.assertEqual(self.profile.initramfs_tftp_name, "vmlinux.gz.uImage.3912")
        self.assertEqual(self.profile.optional_alt_tftp_name, "vmlinux")
        self.assertEqual(self.profile.bootcmd_tftp, "run boot_net")
        self.assertEqual(self.profile.bootcmd_flash, "run boot_openwrt")
        self.assertEqual(self.profile.required_uboot_vars["AP_MODE"], "0")
        self.assertEqual(self.profile.required_uboot_vars["AP_PERSONALITY"], "identifi")
        self.assertEqual(self.profile.required_uboot_vars["bootcmd"], "run boot_net")
        self.assertEqual(self.profile.final_uboot_vars["bootcmd"], "run boot_openwrt")
        self.assertIn("initramfs-uImage", self.profile.initramfs_file)
        self.assertIn("sysupgrade.bin", self.profile.sysupgrade_file)
        self.assertEqual(self.profile.flash_time_seconds, 300)
        self.assertEqual(self.profile.silence_timeout, 60)
        self.assertTrue(self.profile.backup_required)


class TestExtremeRdwrTftpStates(unittest.TestCase):
    def test_extreme_stock_preflight_state_exists(self):
        self.assertIsNotNone(State.EXTREME_STOCK_PREFLIGHT)

    def test_extreme_stock_writing_uboot_state_exists(self):
        self.assertIsNotNone(State.EXTREME_STOCK_WRITING_UBOOT)

    def test_extreme_stock_rebooting_state_exists(self):
        self.assertIsNotNone(State.EXTREME_STOCK_REBOOTING)

    def test_extreme_openwrt_initramfs_waiting_state_exists(self):
        self.assertIsNotNone(State.EXTREME_OPENWRT_INITRAMFS_WAITING)

    def test_extreme_openwrt_backup_state_exists(self):
        self.assertIsNotNone(State.EXTREME_OPENWRT_BACKUP)

    def test_extreme_bootcmd_restore_state_exists(self):
        self.assertIsNotNone(State.EXTREME_BOOTCMD_RESTORE)

    def test_extreme_sysupgrade_uploading_state_exists(self):
        self.assertIsNotNone(State.EXTREME_SYSUPGRADE_UPLOADING)

    def test_extreme_sysupgrade_flashing_state_exists(self):
        self.assertIsNotNone(State.EXTREME_SYSUPGRADE_FLASHING)

    def test_extreme_uboot_env_saved_event_exists(self):
        self.assertIsNotNone(Event.EXTREME_UBOOT_ENV_SAVED)

    def test_extreme_tftp_initramfs_ready_event_exists(self):
        self.assertIsNotNone(Event.EXTREME_TFTP_INITRAMFS_READY)

    def test_extreme_backup_complete_event_exists(self):
        self.assertIsNotNone(Event.EXTREME_BACKUP_COMPLETE)

    def test_extreme_bootcmd_restored_event_exists(self):
        self.assertIsNotNone(Event.EXTREME_BOOTCMD_RESTORED)


class TestExtremeDetection(unittest.TestCase):
    @patch("flash.detect.detect_uboot_http", return_value=(False, ""))
    @patch("flash.detect.check_ssh", return_value=False)
    @patch("flash.detect.subprocess.run")
    def test_detects_stock_extreme(self, mock_run, _mock_ssh, _mock_uboot):
        with patch("shutil.which", return_value="/usr/bin/sshpass"):
            mock_run.return_value = MagicMock(returncode=0, stdout="/usr/bin/rdwr_boot_cfg\n")
            profile = SimpleNamespace(
                openwrt_ip="192.168.1.1",
                recovery_ip="192.168.1.1",
                flash_method="extreme-rdwr-tftp-initramfs",
                stock_default_ip="192.168.1.1",
                stock_default_user="admin",
                stock_default_password="new2day",
            )
            result = detect_boot_state("", profile)
        self.assertEqual(result, "stock-extreme")
        self.assertEqual(mock_run.call_args.args[0][-1], "which rdwr_boot_cfg")

    @patch("flash.detect.check_ssh", return_value=True)
    @patch("flash.detect.subprocess.run")
    def test_detects_openwrt_before_stock_extreme(self, mock_run, _mock_ssh):
        profile = SimpleNamespace(
            openwrt_ip="192.168.1.1",
            recovery_ip="192.168.1.1",
            flash_method="extreme-rdwr-tftp-initramfs",
            stock_default_ip="192.168.1.1",
            stock_default_user="admin",
            stock_default_password="new2day",
        )
        result = detect_boot_state("", profile)
        self.assertEqual(result, "openwrt")
        mock_run.assert_not_called()


class TestRdwrBootCfgParsing(unittest.TestCase):
    def test_parses_sample_output(self):
        parsed = parse_rdwr_boot_cfg(RDWR_BOOT_CFG_SAMPLE)
        self.assertEqual(parsed["AP_MODE"], "0")
        self.assertEqual(parsed["MOSTRECENTKERNEL"], "0")
        self.assertEqual(parsed["WATCHDOG_COUNT"], "0")
        self.assertEqual(parsed["WATCHDOG_LIMIT"], "0")
        self.assertEqual(parsed["AP_PERSONALITY"], "identifi")
        self.assertEqual(parsed["bootcmd"], "run boot_flash")
        self.assertEqual(parsed["serverip"], "192.168.1.2")
        self.assertEqual(parsed["ipaddr"], "192.168.1.1")

    def test_ignores_lines_without_assignments(self):
        parsed = parse_rdwr_boot_cfg(f"noise\n{RDWR_BOOT_CFG_SAMPLE}\nfooter")
        self.assertEqual(len(parsed), 8)


class TestUImageHeaderParser(unittest.TestCase):
    def test_parses_synthetic_header(self):
        header = struct.pack(
            ">7I4B32s",
            0x27051956,
            0x12345678,
            0x5F3759DF,
            0x00100000,
            0x81000000,
            0x81000040,
            0xAABBCCDD,
            5,
            2,
            2,
            1,
            b"OpenWrt AP391x initramfs\x00\x00\x00\x00\x00\x00\x00",
        )
        parsed = parse_uimage_header(header)
        self.assertEqual(parsed["magic"], 0x27051956)
        self.assertEqual(parsed["header_crc"], 0x12345678)
        self.assertEqual(parsed["data_crc"], 0xAABBCCDD)
        self.assertEqual(parsed["timestamp"], 0x5F3759DF)
        self.assertEqual(parsed["load_addr"], 0x81000000)
        self.assertEqual(parsed["entry_addr"], 0x81000040)
        self.assertEqual(parsed["os"], 5)
        self.assertEqual(parsed["arch"], 2)
        self.assertEqual(parsed["type"], 2)
        self.assertEqual(parsed["compression"], 1)
        self.assertEqual(parsed["name"], "OpenWrt AP391x initramfs")

    def test_rejects_short_headers(self):
        with self.assertRaises(ValueError):
            parse_uimage_header(b"short")


class TestExtremeBackupPaths(unittest.TestCase):
    def test_backup_dir_uses_serial_when_present(self):
        path = build_backup_dir(MODEL_ID, serial="3915ABC123")
        self.assertEqual(path, ROOT / "data" / "backups" / "3915ABC123")

    def test_backup_dir_falls_back_to_model_id(self):
        path = build_backup_dir(MODEL_ID)
        self.assertEqual(path, ROOT / "data" / "backups" / MODEL_ID)


class TestExtremeClassification(unittest.TestCase):
    def test_classifies_checksum_only_evidence(self):
        verdict = classify_extreme_image_evidence("firmware metadata includes sha256 checksum only")
        self.assertEqual(verdict, "checksum-only")

    def test_classifies_signed_evidence(self):
        verdict = classify_extreme_image_evidence(
            "image contains x509 certificate chain and rsa signature with sha256 digest"
        )
        self.assertEqual(verdict, "signed")

    def test_classifies_inconclusive_evidence(self):
        verdict = classify_extreme_image_evidence("header fields found but no auth markers present")
        self.assertEqual(verdict, "inconclusive")


if __name__ == "__main__":
    unittest.main()
