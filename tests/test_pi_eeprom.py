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
