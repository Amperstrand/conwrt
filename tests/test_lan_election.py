"""Offline tests for the LAN-role-election fragment (profile.lan_election).

The shell script is executed for real in a stub environment: PATH-injected
fake `udhcpc` (both exit branches) and a fake `uci` that records its calls.
This is the FakeDoor pattern — the decision logic is provable without any
hardware. Hardware validation: conwrt campaign #841 E5.
"""
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ELECTION_LOG = Path("/tmp/conwrt-election.log")


def _write_stub(dirpath: Path, name: str, body: str) -> None:
    p = dirpath / name
    p.write_text(body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


class TestElectionScript(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="election-test-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.uci_calls = self.tmp / "uci-calls.log"
        if ELECTION_LOG.exists():
            ELECTION_LOG.unlink()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)
        if ELECTION_LOG.exists():
            ELECTION_LOG.unlink()

    def _arm_stubs(self, udhcpc_exit: int) -> None:
        _write_stub(self.bin, "udhcpc", f"#!/bin/sh\nexit {udhcpc_exit}\n")
        # record args AND heredoc stdin so the test asserts the exact uci
        # mutations the election performed (value readbacks, not shapes)
        _write_stub(
            self.bin, "uci",
            f"#!/bin/sh\necho \"$@\" >> {self.uci_calls}\n"
            f"cat >> {self.uci_calls}\nexit 0\n")
        _write_stub(self.bin, "ip", "#!/bin/sh\nexit 0\n")
        _write_stub(self.bin, "date", "#!/bin/sh\necho 2026-11-26T00:00:00Z\n")

    def _run_script(self, script: bytes) -> "subprocess.CompletedProcess":
        script_path = self.tmp / "96-conwrt-lan-election"
        script_path.write_bytes(script)
        script_path.chmod(script_path.stat().st_mode | stat.S_IEXEC)
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env['PATH']}"
        return subprocess.run(["sh", str(script_path)], env=env,
                              capture_output=True, timeout=30)

    def test_render_contains_probe_and_uci_batch(self):
        from profile.lan_election import election_script
        text = election_script(iface="eth0").decode()
        self.assertIn("IFACE='eth0'", text)
        self.assertIn("-n -q -T 5 -t 12", text)
        self.assertIn("set network.lan.proto='dhcp'", text)
        self.assertIn("set dhcp.lan.ignore='1'", text)
        self.assertIn("exit 0", text)

    def test_render_rejects_hostile_iface_names(self):
        from profile.lan_election import election_script
        for bad in ("eth0; reboot", "eth0'", "eth 0", "$(reboot)", ""):
            with self.assertRaises(ValueError):
                election_script(iface=bad)

    def test_lease_branch_switches_to_lan_citizen(self):
        from profile.lan_election import election_script
        self._arm_stubs(udhcpc_exit=0)
        res = self._run_script(election_script(iface="eth0"))
        self.assertEqual(res.returncode, 0, res.stderr)
        calls = self.uci_calls.read_text()
        self.assertIn("set network.lan.proto='dhcp'", calls)
        self.assertIn("set dhcp.lan.ignore='1'", calls)
        log = ELECTION_LOG.read_text()
        self.assertIn("LAN-citizen mode", log)

    def test_no_lease_branch_keeps_gateway_default(self):
        from profile.lan_election import election_script
        self._arm_stubs(udhcpc_exit=1)
        res = self._run_script(election_script(iface="eth0"))
        self.assertEqual(res.returncode, 0, res.stderr)
        if self.uci_calls.exists():
            self.assertEqual(
                self.uci_calls.read_text().strip(), "",
                "no-lease branch must not touch any config")
        log = ELECTION_LOG.read_text()
        self.assertIn("gateway mode", log)

    def test_script_is_idempotent_safe_and_deletes_itself_contract(self):
        # uci-defaults contract: exit 0 => deleted after first successful
        # run; the script must always exit 0 even on probe weirdness.
        from profile.lan_election import election_script
        self._arm_stubs(udhcpc_exit=0)
        res = self._run_script(election_script(iface="eth0"))
        self.assertEqual(res.returncode, 0)


class TestOverlayWiring(unittest.TestCase):
    def test_overlay_contains_election_fragment(self):
        from profile.overlay import build_overlay_tarball
        path = build_overlay_tarball(disable_dhcp=True, lan_election=True,
                                     election_iface="eth0")
        try:
            with tarfile.open(path, "r:gz") as tar:
                member = tar.getmember("etc/uci-defaults/96-conwrt-lan-election")
                self.assertEqual(member.mode, 0o755)
                content = tar.extractfile(member).read().decode()
                self.assertIn("IFACE='eth0'", content)
                self.assertIn("udhcpc", content)
        finally:
            os.unlink(path)

    def test_election_and_static_ip_are_mutually_exclusive(self):
        from profile.overlay import build_overlay_tarball
        with self.assertRaises(ValueError):
            build_overlay_tarball(lan_ip="192.168.5.1", lan_election=True)


if __name__ == "__main__":
    unittest.main()
