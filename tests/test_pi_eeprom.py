"""Tests for pi_eeprom.py pure helpers (BOOT_ORDER codec, sig generation)."""
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from pi_eeprom import (
    decode_boot_order,
    encode_boot_order,
    make_sig,
    parse_boot_order_arg,
    render_boot_conf,
    verify_sig,
)


class TestDecode(unittest.TestCase):
    def test_decode_f142(self):
        # rightmost nibble first: 2=network, 4=usb, 1=sd, f=restart
        self.assertEqual(decode_boot_order("0xf142"),
                         ["network", "usb", "sd", "restart"])

    def test_decode_f241(self):
        self.assertEqual(decode_boot_order("0xf241"),
                         ["sd", "usb", "network", "restart"])

    def test_decode_int(self):
        self.assertEqual(decode_boot_order(0x21), ["sd", "network"])

    def test_unknown_nibble_raises(self):
        with self.assertRaises(ValueError):
            decode_boot_order("0x99")


class TestEncode(unittest.TestCase):
    def test_encode_network_first(self):
        self.assertEqual(encode_boot_order(["network", "usb", "sd"]), "0xf142")

    def test_encode_appends_restart(self):
        self.assertEqual(encode_boot_order(["sd", "usb"]), "0xf41")

    def test_roundtrip(self):
        for order in ("0xf142", "0xf41", "0xf21", "0xf241"):
            modes = decode_boot_order(order)
            self.assertEqual(encode_boot_order(modes), order)

    def test_unknown_mode_raises(self):
        with self.assertRaises(ValueError):
            encode_boot_order(["floppy"])


class TestParseArg(unittest.TestCase):
    def test_hex(self):
        self.assertEqual(parse_boot_order_arg("0xf142"),
                         ["network", "usb", "sd", "restart"])

    def test_names(self):
        self.assertEqual(parse_boot_order_arg("network usb sd"),
                         ["network", "usb", "sd"])


class TestBootConf(unittest.TestCase):
    def test_render(self):
        conf = render_boot_conf({"BOOT_ORDER": "0xf142", "BOOT_UART": "1"})
        self.assertTrue(conf.startswith("[all]\n"))
        self.assertIn("BOOT_ORDER=0xf142\n", conf)
        self.assertIn("BOOT_UART=1\n", conf)


class TestSig(unittest.TestCase):
    def test_make_sig_format(self):
        data = b"pretend-eeprom-image"
        sig = make_sig(data, ts=1700000000)
        lines = sig.decode().splitlines()
        self.assertEqual(lines[0], hashlib.sha256(data).hexdigest())
        self.assertTrue(lines[1].startswith("ts: 1700000000"))

    def test_verify_roundtrip(self):
        data = b"x" * 100
        sig = make_sig(data)
        self.assertTrue(verify_sig(data, sig))
        self.assertFalse(verify_sig(data + b"tampered", sig))


if __name__ == "__main__":
    unittest.main()


class TestHttpBootMode(unittest.TestCase):
    def test_decode_http(self):
        self.assertEqual(decode_boot_order("0xf7"), ["http", "restart"])

    def test_encode_http(self):
        self.assertEqual(encode_boot_order(["http", "usb"]), "0xf47")

    def test_roundtrip_http(self):
        modes = decode_boot_order("0xf27")
        self.assertEqual(modes, ["http", "network", "restart"])
        self.assertEqual(encode_boot_order(modes), "0xf27")


class TestResolveRecovery(unittest.TestCase):
    def test_local_file_copied_into_package(self):
        import tempfile
        from pi_eeprom import resolve_recovery
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "my-recovery.bin"
            src.write_bytes(b"RECOVERY")
            out_dir = Path(td) / "pkg"
            out_dir.mkdir()
            dest = resolve_recovery(str(src), out_dir)
            self.assertEqual(dest, out_dir / "recovery.bin")
            self.assertEqual((out_dir / "recovery.bin").read_bytes(), b"RECOVERY")

    def test_local_file_missing_refuses(self):
        import tempfile
        from pi_eeprom import resolve_recovery
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit):
                resolve_recovery(str(Path(td) / "nope.bin"), Path(td))


class TestCmdBuildNameFormBootOrder(unittest.TestCase):
    def test_name_form_build_exits_zero(self):
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        import pi_eeprom

        def fake_fetch(url, dest):
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"eeprom-image")
            return dest

        def fake_run(cmd, **kwargs):
            upd = Path(cmd[cmd.index("--out") + 1])
            upd.write_bytes(b"upd-data")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as td:
            tool = Path(td) / "rpi-eeprom-config"
            tool.write_text("#!/bin/sh\n")
            args = SimpleNamespace(boot_order="network usb sd", set=[],
                                   boot_uart=False, pieeprom=None,
                                   recovery=None, out=td)
            with mock.patch.object(pi_eeprom, "fetch", fake_fetch), \
                 mock.patch.object(pi_eeprom, "find_tool",
                                   lambda out_dir, name: tool), \
                 mock.patch("subprocess.run", fake_run):
                self.assertEqual(pi_eeprom.cmd_build(args), 0)
