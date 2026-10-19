"""Tests for pi_eeprom.py pure helpers (BOOT_ORDER codec, sig generation)."""
import hashlib
import sys
import unittest
from unittest import mock
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

    def test_local_copy_invalidates_stale_origin_sidecar(self):
        """Review of #294: a leftover .origin from a previous URL fetch must
        not make a later default build reuse the custom local binary."""
        import tempfile
        from pi_eeprom import resolve_recovery
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "pkg"
            dest = out_dir / "recovery.bin"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"from-url")
            dest.with_name(dest.name + ".origin").write_text("http://old/recovery.bin\n")
            src = Path(td) / "custom.bin"
            src.write_bytes(b"CUSTOM")
            got = resolve_recovery(str(src), out_dir)
            self.assertEqual(got, dest)
            self.assertEqual(dest.read_bytes(), b"CUSTOM")
            self.assertFalse(dest.with_name(dest.name + ".origin").exists())

    def test_local_path_equal_to_dest_is_reused_not_copied(self):
        """Review of #294: --recovery <out>/recovery.bin is a valid local
        path; shutil.copyfile onto itself would raise SameFileError."""
        import tempfile
        from pi_eeprom import resolve_recovery
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "recovery.bin"
            dest.write_bytes(b"ALREADY")
            got = resolve_recovery(str(dest), Path(td))
            self.assertEqual(got, dest)
            self.assertEqual(dest.read_bytes(), b"ALREADY")


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


class TestFetchOriginRecord(unittest.TestCase):
    def _fake_urlopen(self, url, timeout=0):
        from types import SimpleNamespace

        class Resp:
            def __init__(self, data):
                self._data = data
                self._done = False

            def read(self, n=-1):
                if self._done:
                    return b""
                self._done = True
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        self.fetched_urls.append(url)
        return Resp(b"FRESH-" + url.encode())

    def setUp(self):
        import tempfile
        import pi_eeprom
        self.pi = pi_eeprom
        self.fetched_urls = []
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.patcher = mock.patch.object(pi_eeprom.urllib.request,
                                         "urlopen", self._fake_urlopen)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self._tmp.cleanup()

    def test_same_url_uses_cache(self):
        dest = self.dir / "pieeprom.bin"
        dest.write_bytes(b"CACHED")
        (self.dir / "pieeprom.bin.origin").write_text("http://x/pieeprom.bin\n")
        result = self.pi.fetch("http://x/pieeprom.bin", dest)
        self.assertEqual(result.read_bytes(), b"CACHED")
        self.assertEqual(self.fetched_urls, [])

    def test_different_url_refetches_and_rewrites_origin(self):
        dest = self.dir / "pieeprom.bin"
        dest.write_bytes(b"STALE")
        (self.dir / "pieeprom.bin.origin").write_text("http://old/pieeprom.bin\n")
        result = self.pi.fetch("http://new/pieeprom.bin", dest)
        self.assertEqual(self.fetched_urls, ["http://new/pieeprom.bin"])
        self.assertEqual(result.read_bytes(), b"FRESH-http://new/pieeprom.bin")
        self.assertEqual(
            (self.dir / "pieeprom.bin.origin").read_text().strip(),
            "http://new/pieeprom.bin")

    def test_fresh_fetch_records_origin(self):
        dest = self.dir / "recovery.bin"
        self.pi.fetch("http://x/recovery.bin", dest)
        self.assertEqual(
            (self.dir / "recovery.bin.origin").read_text().strip(),
            "http://x/recovery.bin")

    def test_legacy_cache_without_origin_refetches(self):
        dest = self.dir / "pieeprom.bin"
        dest.write_bytes(b"LEGACY")
        self.pi.fetch("http://x/pieeprom.bin", dest)
        self.assertEqual(self.fetched_urls, ["http://x/pieeprom.bin"])


class TestPushSpecimenGate(unittest.TestCase):
    def setUp(self):
        import tempfile
        import pi_eeprom
        self.pi = pi_eeprom
        self._tmp = tempfile.TemporaryDirectory()
        pkg = Path(self._tmp.name)
        for name in ("recovery.bin", "pieeprom.upd", "pieeprom.sig"):
            (pkg / name).write_bytes(b"x")
        self.pkg = pkg

    def tearDown(self):
        self._tmp.cleanup()

    def _args(self):
        from types import SimpleNamespace
        return SimpleNamespace(router="192.168.1.1", tftp_root="/tmp/tftp",
                               package_dir=str(self.pkg),
                               expect_mac="E4:5F:01:12:34:56")

    def test_not_armed_refuses(self):
        with mock.patch.object(self.pi, "read_remote_config",
                               return_value=""), \
             mock.patch.object(self.pi, "is_armed", return_value=False):
            with self.assertRaises(SystemExit):
                self.pi.cmd_push(self._args())

    def test_multiple_armed_macs_refuse(self):
        conf = "dhcp-host=e4:5f:01:12:34:56,set:pinetboot\ndhcp-host=dc:a6:32:11:22:33,set:pinetboot\n"
        with mock.patch.object(self.pi, "read_remote_config",
                               return_value=conf), \
             mock.patch.object(self.pi, "is_armed", return_value=True), \
             mock.patch.object(self.pi, "armed_macs",
                               return_value=["e4:5f:01:12:34:56",
                                             "dc:a6:32:11:22:33"]):
            with self.assertRaises(SystemExit):
                self.pi.cmd_push(self._args())

    def test_wrong_mac_refuses(self):
        with mock.patch.object(self.pi, "read_remote_config",
                               return_value="dhcp-host=dc:a6:32:11:22:33,set:pinetboot\n"), \
             mock.patch.object(self.pi, "is_armed", return_value=True), \
             mock.patch.object(self.pi, "armed_macs",
                               return_value=["dc:a6:32:11:22:33"]):
            with self.assertRaises(SystemExit):
                self.pi.cmd_push(self._args())

    def test_exact_mac_match_stages(self):
        from types import SimpleNamespace
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(self.pi, "read_remote_config",
                               return_value="dhcp-host=e4:5f:01:12:34:56,set:pinetboot\n"), \
             mock.patch.object(self.pi, "is_armed", return_value=True), \
             mock.patch.object(self.pi, "armed_macs",
                               return_value=["e4:5f:01:12:34:56"]), \
             mock.patch("subprocess.run", fake_run):
            self.assertEqual(self.pi.cmd_push(self._args()), 0)
        self.assertIn("root@192.168.1.1:/tmp/tftp/", " ".join(seen["cmd"]))
