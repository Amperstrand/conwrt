"""Offline tests for the LAN-role-election fragment (profile.lan_election, v2).

v2 shape: a uci-defaults INSTALLER drops an ifup HOTPLUG hook; the hook
(the real election) runs when netifd first brings 'lan' up. Tests execute
the REAL rendered hook in a stub environment (PATH-injected fake udhcpc
with both exit branches, fake uci recording heredoc stdin, fake ubus
reporting br-lan) under a simulated hotplug context. FakeDoor pattern —
the decision logic is provable without hardware. Hardware validation:
conwrt campaign #841 E5B.
"""
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


def _write_stub(dirpath: Path, name: str, body: str) -> None:
    p = dirpath / name
    p.write_text(body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


class ElectionHarness(unittest.TestCase):
    """Shared stub environment: bin dir + marker/uci recording."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="election2-test-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.etc = self.tmp / "etc"
        self.etc.mkdir()
        self.uci_calls = self.tmp / "uci-calls.log"
        self.network_cmds = self.tmp / "network-cmds.log"
        self.log = self.tmp / "election.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _arm(self, udhcpc_exit: int, bridge: str = "br-lan") -> None:
        _write_stub(self.bin, "udhcpc", f"#!/bin/sh\nexit {udhcpc_exit}\n")
        _write_stub(
            self.bin, "uci",
            f"#!/bin/sh\necho \"$@\" >> {self.uci_calls}\n"
            f"cat >> {self.uci_calls}\nexit 0\n")
        _write_stub(self.bin, "ubus",
            f"#!/bin/sh\necho '{{\"l3_device\": \"{bridge}\"}}'\nexit 0\n")
        _write_stub(self.bin, "date", "#!/bin/sh\necho 2026-11-26T01:00:00Z\n")
        # /etc/init.d/network stub (the hook's reload/restart target);
        # NEVER stub "sh" itself — subprocess.run(["sh", …]) would resolve
        # the stub via PATH and silently not run the script under test.
        initd = self.etc / "init.d"
        initd.mkdir(exist_ok=True)
        (initd / "network").write_text("#!/bin/sh\nexit 0\n")
        (initd / "network").chmod(
            (initd / "network").stat().st_mode | stat.S_IEXEC)

    def _run_hook(self, script: bytes, *, interface: str = "lan",
                  action: str = "ifup", marker: bool = False) -> "subprocess.CompletedProcess":
        if marker:
            (self.etc / "conwrt-election.done").write_text("")
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env['PATH']}"
        env["INTERFACE"] = interface
        env["ACTION"] = action
        # the hook writes /tmp/conwrt-election.log and reads /etc/...:
        # remap via a chroot-lite: run with cwd sandbox and the /etc and
        # /tmp paths overridden through a wrapper shell
        script_path = self.tmp / "96-conwrt-election"
        script_path.write_bytes(script)
        script_path.chmod(script_path.stat().st_mode | stat.S_IEXEC)
        wrapper = self.tmp / "wrapper.sh"
        wrapper.write_text(
            "#!/bin/sh\n"
            f"export PATH={self.bin}:$PATH\n"
            f'export INTERFACE={interface} ACTION={action}\n'
            f"mount --bind {self.tmp} /mnt 2>/dev/null || true\n"
            f"sh {script_path}\n")
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
        # simplest hermetic approach: sed the absolute paths to the sandbox
        patched = script.decode().replace("/etc/", f"{self.etc}/")
        patched = patched.replace("/tmp/conwrt-election.log", str(self.log))
        patched_path = self.tmp / "hook-patched"
        patched_path.write_text(patched)
        patched_path.chmod(patched_path.stat().st_mode | stat.S_IEXEC)
        return subprocess.run(
            ["sh", str(patched_path)], env=env,
            capture_output=True, timeout=30)

    def _uci_saw(self) -> str:
        return self.uci_calls.read_text() if self.uci_calls.exists() else ""


class TestElectionV2(ElectionHarness):
    def test_installer_embeds_hotplug_hook(self):
        from profile.lan_election import election_installer, election_hook
        installer = election_installer().decode()
        self.assertIn("/etc/hotplug.d/iface/96-conwrt-election", installer)
        self.assertIn("udhcpc -i \"$BRIDGE\"", installer)
        self.assertIn("conwrt-election.done", installer)
        # the installer must carry the hook verbatim
        hook = election_hook().decode()
        self.assertIn(hook[:200], installer)

    def test_hook_lease_branch_switches_to_lan_citizen(self):
        from profile.lan_election import election_hook
        self._arm(udhcpc_exit=0)
        res = self._run_hook(election_hook())
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("set network.lan.proto='dhcp'", self._uci_saw())
        self.assertIn("set dhcp.lan.ignore='1'", self._uci_saw())
        self.assertTrue((self.etc / "conwrt-election.done").exists())
        self.assertIn("LAN-citizen mode", self.log.read_text())

    def test_hook_no_lease_branch_keeps_gateway(self):
        from profile.lan_election import election_hook
        self._arm(udhcpc_exit=1)
        res = self._run_hook(election_hook())
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual("", self._uci_saw().strip())
        self.assertTrue((self.etc / "conwrt-election.done").exists())
        self.assertIn("gateway mode", self.log.read_text())

    def test_hook_marker_gates_repeats(self):
        from profile.lan_election import election_hook
        self._arm(udhcpc_exit=0)
        res = self._run_hook(election_hook(), marker=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        # no probe ran: the log was never written
        self.assertFalse(self.log.exists())
        self.assertEqual("", self._uci_saw().strip())

    def test_hook_ignores_other_interfaces_and_actions(self):
        from profile.lan_election import election_hook
        self._arm(udhcpc_exit=0)
        for iface, action in (("wan", "ifup"), ("lan", "ifdown")):
            res = self._run_hook(election_hook(), interface=iface, action=action)
            self.assertEqual(res.returncode, 0)
            self.assertEqual("", self._uci_saw().strip(),
                             f"must not act on {action}/{iface}")


class TestOverlayWiring(unittest.TestCase):
    def test_overlay_contains_election_installer(self):
        from profile.overlay import build_overlay_tarball
        path = build_overlay_tarball(disable_dhcp=True, lan_election=True)
        try:
            with tarfile.open(path, "r:gz") as tar:
                member = tar.getmember("etc/uci-defaults/96-conwrt-lan-election")
                self.assertEqual(member.mode, 0o755)
                content = tar.extractfile(member).read().decode()
                self.assertIn("/etc/hotplug.d/iface/96-conwrt-election", content)
                self.assertIn("udhcpc -i \"$BRIDGE\"", content)
        finally:
            os.unlink(path)

    def test_election_and_static_ip_are_mutually_exclusive(self):
        from profile.overlay import build_overlay_tarball
        with self.assertRaises(ValueError):
            build_overlay_tarball(lan_ip="192.168.5.1", lan_election=True)


if __name__ == "__main__":
    unittest.main()
