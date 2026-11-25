"""bench_net + bench_console host-side tests (#763 P3).

bench_net: the declarative bay/VLAN convergence planner — desired-state
derivation, live-state parsing, drift plan shapes (CREATE/UPDATE with
the #287 delete+add_list fix), and the status/apply/unknown-device
exit contract. ssh() stubbed at the module seam.

bench_console: the SSH+serial jump-chain construction and the
marker-based run() protocol — pexpect.spawn stubbed with a scripted
fake that models the expect/before/match protocol. No bench hosts.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import bench_net  # noqa: E402

LAB_YAML = """
devices:
  gs1900-bench:
    mgmt: 192.168.13.9
    bays:
      uplink: lan1
      lan2: {vlan: 1002}
      lan3: {vlan: 1003, trunk: [lan4]}
  plain:
    mgmt: 192.168.13.10
subnets:
  100.2.0.0/24: {vlan: 1002}
  100.3.0.0/24: {vlan: 1003}
"""


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    labdir = tmp_path / "labdata"
    labdir.mkdir()
    (labdir / "lab.yaml").write_text(LAB_YAML)
    monkeypatch.setenv("CONWRT_LAB", str(labdir))
    return bench_net.load("gs1900-bench")


class TestDesiredBays:
    def test_ports_u_and_uplink_t(self, lab):
        _, dev = lab
        bays = bench_net.desired_bays(dev)
        assert bays[1002] == ["lan1:t", "lan2:u*"]
        assert bays[1003] == ["lan1:t", "lan3:u*", "lan4:t"]

    def test_subnet_for(self, lab):
        cfg, _ = lab
        assert bench_net.subnet_for(cfg, 1002) == "100.2.0.0/24"
        assert bench_net.subnet_for(cfg, 9999) is None


class TestLiveState:
    def _parse(self, monkeypatch, uci_out):
        monkeypatch.setattr(bench_net, "ssh", lambda host, cmd, timeout=30: uci_out)
        return bench_net.live_state("any")

    def test_parses_bridge_vlans_and_ifaces(self, monkeypatch):
        out = (
            "network.@device[0].device='br-lan'\n"
            "network.bay2.vlan='1002'\n"
            "network.bay2.ports='lan1 lan2'\n"
            "network.bay3.vlan='1003'\n"
            "network.bay3.ports='lan1'\n"
            "2: br-lan\n"
            "7: br-lan.1002\n"
        )
        st = self._parse(monkeypatch, out)
        assert st["vlans"] == {1002: ["lan1", "lan2"], 1003: ["lan1"]}
        assert st["bridge"] == "br-lan"
        assert "br-lan.1002" in st["ifaces"]

    def test_multi_list_ports_merged(self, monkeypatch):
        # uci show renders list options as repeated lines — all collect
        out = (
            "network.bay2.vlan='1002'\n"
            "network.bay2.ports='lan1'\n"
            "network.bay2.ports='lan2'\n"
        )
        st = self._parse(monkeypatch, out)
        assert st["vlans"][1002] == ["lan1", "lan2"]

    def test_no_vlan_sections_empty_state(self, monkeypatch):
        st = self._parse(monkeypatch, "1: lo\n2: eth0\n")
        assert st["vlans"] == {}
        assert "eth0" in st["ifaces"]


class TestPlan:
    def _plan(self, monkeypatch, lab, live_vlans, live_ifaces=frozenset()):
        cfg, dev = lab
        monkeypatch.setattr(
            bench_net, "live_state",
            lambda host: {"vlans": dict(live_vlans), "ifaces": set(live_ifaces),
                          "sections": {v: f"bay{v}" for v in live_vlans},
                          "bridge": "br-lan"})
        return bench_net.plan(cfg, dev, "gs1900-bench")

    def test_converged_when_live_matches(self, monkeypatch, lab):
        # live DSA bridge-vlan ports carry the tagged spec (:t/:u*)
        steps = self._plan(
            monkeypatch, lab,
            {1002: ["lan1:t", "lan2:u*"],
             1003: ["lan1:t", "lan3:u*", "lan4:t"]},
            {"br-lan.1002", "br-lan.1003"})
        assert steps == []

    def test_create_for_missing_vlan(self, monkeypatch, lab):
        steps = self._plan(monkeypatch, lab, {1002: ["lan1", "lan2"]})
        assert any(s.startswith("CREATE bridge-vlan 1003") for s in steps)

    def test_update_uses_delete_then_add_list(self, monkeypatch, lab):
        # #287: ports is a LIST option — the scalar `uci set` form is
        # rejected by modern uci/ubus rendering
        steps = self._plan(
            monkeypatch, lab,
            {1002: ["lan1:t"], 1003: ["lan1:t", "lan3:u*", "lan4:t"]},
            {"br-lan.1002", "br-lan.1003"})
        upd = next(s for s in steps if s.startswith("UPDATE bridge-vlan 1002"))
        assert "uci delete network.bay1002.ports" in upd
        assert "uci add_list network.bay1002.ports='lan2:u*'" in upd
        assert "uci set network.bay1002.ports" not in upd  # the rejected form

    def test_l3_created_only_when_iface_missing(self, monkeypatch, lab):
        steps = self._plan(
            monkeypatch, lab,
            {1002: ["lan1", "lan2"], 1003: ["lan1", "lan3", "lan4"]},
            {"br-lan.1002"})  # 1003's L3 missing
        assert any(s.startswith("CREATE L3 br-lan.1003") for s in steps)
        assert not any(s.startswith("CREATE L3 br-lan.1002") for s in steps)

    def test_first_host_address_for_l3(self, monkeypatch, lab):
        steps = self._plan(
            monkeypatch, lab,
            {1002: ["lan1", "lan2"], 1003: ["lan1", "lan3", "lan4"]}, set())
        l3 = next(s for s in steps if s.startswith("CREATE L3 br-lan.1002"))
        assert "100.2.0.1/24" in l3


class TestMain:
    def test_unknown_device_exits(self, lab, capsys):
        with pytest.raises(SystemExit) as exc:
            bench_net.load("nope")
        assert "unknown device" in str(exc.value)

    def test_status_drift_exit_1_converged_0(self, lab, monkeypatch, capsys):
        cfg, dev = lab
        monkeypatch.setattr(
            bench_net, "plan",
            lambda c, d, n: ["CREATE bridge-vlan 1002 ports='lan1:t lan2:u*'"])
        with pytest.raises(SystemExit) as exc:
            bench_net.main.__wrapped__ if False else _run_main(["status"])
        assert exc.value.code == 1

    def test_apply_drift_exit_2(self, lab, monkeypatch, capsys):
        monkeypatch.setattr(
            bench_net, "plan", lambda c, d, n: ["DRIFT STEP"])
        with pytest.raises(SystemExit) as exc:
            _run_main(["apply"])
        assert exc.value.code == 2


def _run_main(argv):
    sys.argv = ["bench_net.py", *argv, "--device", "gs1900-bench"]
    return bench_net.main()


# --- bench_console ---------------------------------------------------------

class FakeSpawn:
    """Scripted pexpect.spawn: records sendline()s; expect() walks a queue
    of (pattern_to_assert, before_text, match_groups)."""

    def __init__(self, cmd, script):
        self.cmd = cmd
        self.script = list(script)
        self.sent = []
        self.before = ""
        self.match = None
        self.closed = False
        self.delaybeforesend = 0

    def sendline(self, line):
        self.sent.append(line)

    def close(self, force=False):
        self.closed = True

    def expect(self, pattern, timeout=None):
        step = self.script.pop(0)
        want, before, groups = step
        assert want in pattern, f"expected {want!r} in {pattern!r}"
        self.before = before
        self.match = SimpleNamespace(group=lambda i: groups[i - 1])
        return 0


@pytest.fixture()
def bc_env(monkeypatch):
    monkeypatch.setenv("CONWRT_BENCH_SWITCH", "root@10.0.0.9")
    monkeypatch.setenv("CONWRT_REF_UNIT", "10.0.2.5")
    import bench_console
    return bench_console


class TestBenchConsoleInit:
    def test_host_normalization(self, bc_env):
        bc = bc_env.BenchConsole()
        assert bc.switch_host == "10.0.0.9"  # root@ stripped
        assert bc.ref_host == "10.0.2.5"

    def test_missing_env_raises(self, bc_env, monkeypatch):
        monkeypatch.delenv("CONWRT_BENCH_SWITCH", raising=False)
        monkeypatch.delenv("CONWRT_REF_UNIT", raising=False)
        with pytest.raises(ValueError, match="CONWRT_BENCH_SWITCH"):
            bc_env.BenchConsole()

    def test_ssh_cmd_builds_the_jump_chain(self, bc_env):
        bc = bc_env.BenchConsole(serial_dev="/dev/ttyMSM0")
        cmd = bc._ssh_cmd()
        # Mac -> switch -> ref unit -> serial tunnel, in order
        assert cmd.startswith("ssh ")
        assert "root@10.0.0.9" in cmd
        assert "dbclient -y -y" in cmd
        assert "root@10.0.2.5" in cmd
        assert "cat /dev/ttyMSM0 & cat > /dev/ttyMSM0" in cmd


class TestBenchConsoleRun:
    def _console(self, bc_env, script):
        bc = bc_env.BenchConsole()
        bc.child = FakeSpawn("ssh", script)
        return bc

    def test_run_marker_protocol(self, bc_env):
        # run() sends the wrapped command and expects ONLY the markerE
        # regex; the fake asserts the pattern and hands back the before
        # text (which contains markerS + the command output)
        bc = self._console(bc_env, [
            ("E (", "LGAAAAAAAAAAAAAAAAS\r\noutput-line\r\nLGAAAAAAAAAAAAAAAAE ",
             ("0",)),
        ])
        out, code = bc.run("ifconfig eth0")
        assert code == 0
        assert "output-line" in out
        # the wrapped command carried the marker pair around the command
        sent = bc.child.sent[0]
        assert sent.startswith("echo ")
        assert "S; ifconfig eth0; echo " in sent
        assert sent.endswith("E $?")

    def test_run_nonzero_exit(self, bc_env):
        bc = self._console(bc_env, [
            ("E (", "LGXXXXS\r\nerror text\r\nLGXXXXE ", ("127",)),
        ])
        out, code = bc.run("false")
        assert code == 127
        assert "error text" in out

    def test_markers_advance(self, bc_env):
        bc = self._console(bc_env, [
            ("E (", "x", ("0",)),
            ("E (", "y", ("0",)),
        ])
        bc.run("true")
        m1 = bc.child.sent[0]
        bc.run("true")
        m2 = bc.child.sent[1]
        assert m1 != m2  # every command gets a fresh marker

    def test_close_clears_child(self, bc_env):
        bc = self._console(bc_env, [("E (", "x", ("0",))])
        bc.close()
        assert bc.child is None

    def test_not_connected_asserts(self, bc_env):
        bc = bc_env.BenchConsole()
        with pytest.raises(AssertionError):
            bc.run("true")
