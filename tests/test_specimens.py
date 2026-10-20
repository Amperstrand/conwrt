"""Tests for the specimen ledger (#296)."""
import json
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import specimens  # noqa: E402


class TestLedgerRoundtrip(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.path = Path(self._tmp.name) / "specimens.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_record_creates_0600_with_0700_parent(self):
        entry = specimens.record(mac="DC:A6:32:11:22:33",
                                 serial="10000000abcd1234", label="pi4-bench",
                                 host="192.168.4.52", source="test",
                                 path=self.path)
        self.assertEqual(entry["mac"], "dc:a6:32:11:22:33")  # normalized
        self.assertTrue(self.path.is_file())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        parent_mode = self.path.parent.stat().st_mode & 0o777
        if self.path.parent != Path(self._tmp.name):
            self.assertEqual(parent_mode, 0o700)
        data = json.loads(self.path.read_text())
        self.assertEqual(len(data["specimens"]), 1)
        self.assertEqual(data["specimens"][0]["serial"], "10000000abcd1234")

    def test_upsert_by_mac_updates_and_does_not_duplicate(self):
        specimens.record(mac="dc:a6:32:11:22:33", label="old",
                         path=self.path)
        entry = specimens.record(mac="DC:A6:32:11:22:33", label="new",
                                 serial="S1", path=self.path)
        self.assertEqual(entry["label"], "new")
        data = json.loads(self.path.read_text())
        self.assertEqual(len(data["specimens"]), 1)
        self.assertEqual(data["specimens"][0]["serial"], "s1")

    def test_conflated_mac_serial_refuses(self):
        """A MAC rebound to a different serial is two units conflated —
        this refusal IS the specimen-gate guarantee the ledger exists for."""
        specimens.record(mac="aa:aa:aa:aa:aa:aa", serial="serial-one",
                         path=self.path)
        with self.assertRaises(SystemExit):
            specimens.record(mac="aa:aa:aa:aa:aa:aa", serial="serial-two",
                             path=self.path)
        data = json.loads(self.path.read_text())
        self.assertEqual(data["specimens"][0]["serial"], "serial-one")

    def test_multi_interface_unit_appends_not_refuses(self):
        """One unit, several interface MACs sharing a serial — normal for
        Pis (eth0/wlan0): each MAC gets its own entry, nothing refuses."""
        for mac in ("dc:a6:32:11:22:33", "dc:a6:32:11:22:34"):
            specimens.record(mac=mac, serial="10000000abcd1234",
                             path=self.path)
        self.assertEqual(specimens.known_macs(path=self.path),
                         {"dc:a6:32:11:22:33", "dc:a6:32:11:22:34"})
        data = json.loads(self.path.read_text())
        self.assertEqual(len(data["specimens"]), 2)
        self.assertTrue(all(e["serial"] == "10000000abcd1234"
                            for e in data["specimens"]))

    def test_known_macs_and_remove(self):
        specimens.record(mac="dc:a6:32:11:22:33", path=self.path)
        specimens.record(mac="e4:5f:01:12:34:56", path=self.path)
        self.assertEqual(specimens.known_macs(path=self.path),
                         {"dc:a6:32:11:22:33", "e4:5f:01:12:34:56"})
        self.assertTrue(specimens.remove("DC:A6:32:11:22:33",
                                          path=self.path))
        self.assertEqual(specimens.known_macs(path=self.path),
                         {"e4:5f:01:12:34:56"})
        self.assertFalse(specimens.remove("dc:a6:32:11:22:33",
                                          path=self.path))

    def test_corrupt_ledger_refuses_loudly(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("{not json")
        with self.assertRaises(SystemExit):
            specimens.load(self.path)

    def test_default_path_honors_env(self):
        old = os.environ.get("CONWRT_SPECIMENS")
        try:
            os.environ["CONWRT_SPECIMENS"] = "/tmp/wherever/specimens.json"
            self.assertEqual(str(specimens.default_ledger_path()),
                             "/tmp/wherever/specimens.json")
        finally:
            if old is None:
                os.environ.pop("CONWRT_SPECIMENS", None)
            else:
                os.environ["CONWRT_SPECIMENS"] = old


class TestSpecimensCLI(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.ledger = Path(self._tmp.name) / "specimens.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_add_list_roundtrip(self):
        import contextlib
        import io
        self.assertEqual(specimens.main([
            "--ledger", str(self.ledger), "add",
            "--mac", "DC:A6:32:11:22:33", "--serial", "S", "--label",
            "pi4-bench", "--host", "192.168.4.52"]), 0)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(
                specimens.main(["--ledger", str(self.ledger), "list"]), 0)
        self.assertIn("dc:a6:32:11:22:33", out.getvalue())
        self.assertIn("pi4-bench", out.getvalue())

    def test_add_requires_mac_or_serial(self):
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(specimens.main(
                ["--ledger", str(self.ledger), "add"]), 1)
        self.assertIn("--mac", err.getvalue())

    def test_empty_list_prints_bootstrap_hint(self):
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(
                specimens.main(["--ledger", str(self.ledger), "list"]), 0)
        self.assertIn("specimens read", out.getvalue())

    def test_read_records_live_identity(self):
        import contextlib
        import io
        import pi_image
        orig = pi_image.remote_specimen
        pi_image.remote_specimen = (
            lambda host: ("10000000abcd1234",
                          ["dc:a6:32:11:22:33", "e4:5f:01:12:34:56"]))
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(specimens.main([
                    "--ledger", str(self.ledger), "read",
                    "--host", "192.168.4.52"]), 0)
        finally:
            pi_image.remote_specimen = orig
        self.assertIn("serial=10000000abcd1234", out.getvalue())
        self.assertEqual(specimens.known_macs(path=self.ledger),
                         {"dc:a6:32:11:22:33", "e4:5f:01:12:34:56"})


class TestProvisionAutoRecord(unittest.TestCase):
    """pi_image provision records the verified live identity (#296)."""

    def test_record_helper_wired_into_provision(self):
        import inspect
        import pi_image
        src = inspect.getsource(pi_image.cmd_provision)
        self.assertIn("from specimens import record", src)
