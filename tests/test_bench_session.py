"""bench_session — protocol conformance for both backends (hardware-safe).

DirectBench: mocked subprocess — assertions pin the EXACT ssh argv and
script text (today's wire forms from conwrt_poe / bench_adopt / bench_flash),
so a silently-wrong command sequence cannot pass on return values alone.

LabgridBench: mocked labgrid client (stub package + fake session/target
factories) — assertions pin the acquire -> driver -> release ordering.
The labgrid package itself is NOT required to run these tests; the
no-labgrid behavior is proven in-process AND via a subprocess import check.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

import bench_adopt as ba
import bench_flash as bf
import bench_session as bs
from config import load_config

REPO_ROOT = Path(__file__).resolve().parent.parent
PLACE = ba.Place("ap-lan4", "b4:2d:56:25:79:b1", "192.168.104.51")
NO_IP_PLACE = ba.Place("ap-lan5", "b4:2d:56:24:ad:97", "")


def _run_recorder(out: str, results: list, rc: int = 0):
    def fake_run(argv, **kwargs):
        results.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, rc, stdout=out, stderr="")
    return fake_run


# ------------------------------------------------------------------ stubs

@pytest.fixture
def labgrid_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the exact labgrid API surface bench_session touches, so the
    LabgridBench tests run on machines without the package."""
    pkg = types.ModuleType("labgrid")
    driver = types.ModuleType("labgrid.driver")
    driver.NetworkPowerDriver = type("NetworkPowerDriver", (), {})
    driver.SerialDriver = type("SerialDriver", (), {})
    pkg.driver = driver
    monkeypatch.setitem(sys.modules, "labgrid", pkg)
    monkeypatch.setitem(sys.modules, "labgrid.driver", driver)


class FakeLoop:
    """Drives no-await coroutines to completion (the fakes never await)."""

    def run_until_complete(self, coro):
        try:
            coro.send(None)
        except StopIteration:
            pass


class FakeSession:
    def __init__(self, events: list) -> None:
        self.loop = FakeLoop()
        self.events = events
        self.resources: dict = {}

    async def _acquire_place(self, name: str) -> None:
        self.events.append(("acquire", name))

    async def _release_place(self, name: str) -> None:
        self.events.append(("release", name))

    async def close(self) -> None:
        self.events.append(("close",))

    def get_place(self, name: str):
        self.events.append(("get_place", name))
        return SimpleNamespace(name=name)

    def get_target_resources(self, place):
        return self.resources


class FakeDriver:
    def __init__(self, events: list) -> None:
        self.events = events

    def on(self) -> None:
        self.events.append("power-on")

    def off(self) -> None:
        self.events.append("power-off")

    def cycle(self) -> None:
        self.events.append("power-cycle")

    def read(self, size: int = 256, timeout: float | None = None) -> bytes:
        return b"boot marker\n"

    def write(self, data: bytes) -> int:
        self.events.append(("serial-write", bytes(data)))
        return len(data)


class FakeTarget:
    def __init__(self, events: list) -> None:
        self.events = events
        self.driver = FakeDriver(events)

    def get_driver(self, cls):
        self.events.append(("get_driver", cls.__name__))
        return self.driver

    def deactivate(self, drv) -> None:
        self.events.append("deactivate")


class FakeSock:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.timeouts: list = []
        self.closed = False

    def settimeout(self, t) -> None:
        self.timeouts.append(t)

    def recv(self, size: int) -> bytes:
        return b"Z-LOADER V1.30\n"

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True


# --------------------------------------------------------- protocol shape

class TestProtocolConformance:
    def test_direct_bench_satisfies_protocol(self) -> None:
        assert isinstance(bs.DirectBench(), bs.BenchSession)

    def test_labgrid_bench_satisfies_protocol(self, labgrid_stub) -> None:
        assert isinstance(bs.LabgridBench(coordinator="c:1"), bs.BenchSession)


# -------------------------------------------------------- DirectBench.power

class TestDirectPower:
    def test_on_sends_exact_ubus_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list = []
        monkeypatch.setattr(bs.subprocess, "run", _run_recorder("", calls))
        bs.DirectBench().power(PLACE, "on")
        argv, kwargs = calls[0]
        assert argv == ["ssh", *bs.SSH_OPTS, "root@192.168.13.2",
                        'ubus call poe manage \'{"port":"lan4","action":"enable"}\'']
        assert kwargs["capture_output"] is True and kwargs["text"] is True

    def test_off_maps_to_disable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list = []
        monkeypatch.setattr(bs.subprocess, "run", _run_recorder("", calls))
        bs.DirectBench(switch_host="10.9.9.9").power("ap-lan7", "off")
        assert calls[0][0] == ["ssh", *bs.SSH_OPTS, "root@10.9.9.9",
                               'ubus call poe manage \'{"port":"lan7","action":"disable"}\'']

    def test_cycle_is_one_ssh_round_trip_off_settle_on(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list = []
        monkeypatch.setattr(bs.subprocess, "run", _run_recorder("", calls))
        bs.DirectBench().power("ap-lan4", "cycle")
        assert len(calls) == 1, "a cycle must never span multiple connections"
        assert calls[0][0][-1] == (
            'ubus call poe manage \'{"port":"lan4","action":"disable"}\'; '
            'sleep 8; '
            'ubus call poe manage \'{"port":"lan4","action":"enable"}\'')

    def test_ssh_failure_raises_despite_stdout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # misleading-success guard: ubus output on stdout must not fake success
        calls: list = []
        monkeypatch.setattr(bs.subprocess, "run",
                            _run_recorder('{"status":"ok"}', calls, rc=255))
        with pytest.raises(bs.BenchError, match="switch command failed"):
            bs.DirectBench().power(PLACE, "on")

    def test_unknown_action_typed_error(self) -> None:
        with pytest.raises(bs.BenchError, match="unknown power action 'reboot'"):
            bs.DirectBench().power(PLACE, "reboot")


# ------------------------------------------------------ DirectBench.console

class TestDirectConsole:
    def test_no_endpoint_is_typed_error(self) -> None:
        with pytest.raises(bs.ConsoleUnavailableError, match="ap-lan4"):
            with bs.DirectBench().console("ap-lan4"):
                pass

    def test_socket_stream_read_write_and_close(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sock = FakeSock()
        seen: list = []
        monkeypatch.setattr(bs.socket, "create_connection",
                            lambda endpoint, timeout=None: seen.append(endpoint) or sock)
        bench = bs.DirectBench(serial_endpoints={"ap-lan2": ("127.0.0.1", 4002)})
        with bench.console("ap-lan2") as stream:
            assert stream.write(b"\r\n") == 2
            assert stream.read(64, timeout=2.0) == b"Z-LOADER V1.30\n"
        assert seen == [("127.0.0.1", 4002)]
        assert sock.sent == [b"\r\n"] and sock.timeouts == [2.0]
        assert sock.closed, "context exit must close the bridge socket"


# --------------------------------------------------- DirectBench.ssh_target

class TestDirectSshTarget:
    def test_static_ip_coordinates(self) -> None:
        t = bs.DirectBench().ssh_target(PLACE)
        assert t == bs.SshTarget(host="192.168.104.51", user="root",
                                 jump="192.168.13.2", zone="")

    def test_no_ip_falls_back_to_scoped_link_local(self) -> None:
        t = bs.DirectBench().ssh_target(NO_IP_PLACE)
        assert t.host == "fe80::b62d:56ff:fe24:ad97"
        assert t.zone == "switch.1005" and t.jump == "192.168.13.2"

    def test_bare_name_needs_place_record(self) -> None:
        with pytest.raises(bs.BenchError, match="Place record"):
            bs.DirectBench().ssh_target("ap-lan4")


# ----------------------------------------------------- DirectBench.tftp_arm

class TestDirectTftpArm:
    def test_sends_exact_lifeline_script(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list = []
        monkeypatch.setattr(bs.subprocess, "run", _run_recorder("LIFELINE-OK", calls))
        handle = bs.DirectBench().tftp_arm(1004, "img.bin")
        assert handle == bs.TftpLifeline(vlan=1004, tftproot="/tmp/bench-tftp",
                                          switch="192.168.13.2", log="/tmp/tftp-1004.log")
        assert handle.interface == "switch.1004"
        argv, kwargs = calls[0]
        assert argv == ["ssh", *bs.SSH_OPTS, "root@192.168.13.2", "sh -s"]
        staging = ba.Place("ap-lan4", "00:00:00:00:00:00", "")
        assert kwargs["input"] == "\n".join(
            bf.lifeline_lines(staging, "img.bin", "/tmp/bench-tftp")) + "\n"

    def test_broken_lifeline_refuses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list = []
        monkeypatch.setattr(bs.subprocess, "run", _run_recorder("LIFELINE-BROKEN", calls))
        with pytest.raises(bs.BenchError, match="not verifiably serving"):
            bs.DirectBench().tftp_arm(1005, "img.bin")


# ------------------------------------------------ DirectBench switch access

class TestDirectSwitchAccess:
    """The three switch-infrastructure primitives the bench_* scripts were
    rewired onto (plan task 11) — argv pinned to today's wire forms:
    switch_exec = bench_inventory's collect/probe ssh form, switch_sh =
    bench_adopt's make_ssh_transport form, switch_put = bench_flash's
    push_to_switch scp -O form."""

    def test_switch_exec_sends_exact_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list = []
        monkeypatch.setattr(bs.subprocess, "run", _run_recorder("ubus-out", calls))
        out = bs.DirectBench().switch_exec("ubus call poe info")
        assert out == "ubus-out", "command form returns stdout only (inventory parse shape)"
        argv, kwargs = calls[0]
        assert argv == ["ssh", *bs.SSH_OPTS, "root@192.168.13.2", "ubus call poe info"]
        assert kwargs["capture_output"] is True and kwargs["text"] is True
        assert kwargs["timeout"] == 60

    def test_switch_exec_timeout_is_caller_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list = []
        monkeypatch.setattr(bs.subprocess, "run", _run_recorder("", calls))
        bs.DirectBench(switch_host="10.9.9.9").switch_exec("ip neigh show dev switch.1004",
                                                           timeout_s=15)
        argv, kwargs = calls[0]
        assert argv[-2] == "root@10.9.9.9" and argv[-1] == "ip neigh show dev switch.1004"
        assert kwargs["timeout"] == 15

    def test_switch_exec_failure_is_typed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bs.subprocess, "run",
                            _run_recorder("", [], rc=255))
        with pytest.raises(bs.BenchError, match="switch command failed"):
            bs.DirectBench().switch_exec("ubus call poe info")

    def test_switch_sh_feeds_script_and_returns_combined(self,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout="LIFELINE-OK\n", stderr="warn\n")

        monkeypatch.setattr(bs.subprocess, "run", fake_run)
        out = bs.DirectBench().switch_sh("echo LIFELINE-OK\n")
        assert out == "LIFELINE-OK\nwarn\n", "script form returns stdout+stderr ungated"
        argv, kwargs = calls[0]
        assert argv == ["ssh", *bs.SSH_OPTS, "root@192.168.13.2", "sh -s"]
        assert kwargs["input"] == "echo LIFELINE-OK\n"
        assert kwargs["timeout"] == 90, "bench_adopt's Mac-side hang guard"

    def test_switch_put_sends_exact_scp_argv(self, monkeypatch: pytest.MonkeyPatch,
                                             tmp_path: Path) -> None:
        calls: list = []
        monkeypatch.setattr(bs.subprocess, "run", _run_recorder("", calls))
        img = tmp_path / "img.bin"
        img.write_bytes(b"x")
        bs.DirectBench(switch_host="10.9.9.9").switch_put(img, "/tmp/bench-tftp/img.bin")
        argv, kwargs = calls[0]
        assert argv == ["scp", "-O", *bs.SSH_OPTS, str(img), "root@10.9.9.9:/tmp/bench-tftp/img.bin"]
        assert kwargs["timeout"] == 300

    def test_switch_put_failure_is_typed(self, monkeypatch: pytest.MonkeyPatch,
                                         tmp_path: Path) -> None:
        monkeypatch.setattr(bs.subprocess, "run", _run_recorder("", [], rc=1))
        with pytest.raises(bs.BenchError, match="switch file push failed"):
            bs.DirectBench().switch_put(tmp_path / "img.bin", "/tmp/x")


# ---------------------------------------------------------- LabgridBench

def _labgrid_bench(events: list, resources: dict | None = None) -> bs.LabgridBench:
    session = FakeSession(events)
    if resources is not None:
        session.resources = resources
    return bs.LabgridBench(coordinator="192.168.13.221:20408",
                           session_factory=lambda c: session,
                           target_factory=lambda name: FakeTarget(events))


class TestLabgridBench:
    def test_power_acquire_driver_release_order(self, labgrid_stub) -> None:
        events: list = []
        lb = _labgrid_bench(events)
        lb.power("ap-lan4", "cycle")
        lb.close()
        assert events == [("acquire", "ap-lan4"),
                          ("get_driver", "NetworkPowerDriver"),
                          "power-cycle",
                          ("release", "ap-lan4"),
                          ("close",)]

    def test_power_actions_map_to_driver_methods(self, labgrid_stub) -> None:
        for action, marker in (("on", "power-on"), ("off", "power-off")):
            events: list = []
            _labgrid_bench(events).power(PLACE, action)
            assert events == [("acquire", "ap-lan4"),
                              ("get_driver", "NetworkPowerDriver"), marker]

    def test_acquired_once_per_session_not_per_call(self, labgrid_stub) -> None:
        events: list = []
        lb = _labgrid_bench(events)
        lb.power("ap-lan4", "on")
        lb.power("ap-lan4", "off")
        assert events.count(("acquire", "ap-lan4")) == 1

    def test_console_binds_serial_driver_and_deactivates(self, labgrid_stub) -> None:
        events: list = []
        lb = _labgrid_bench(events)
        with lb.console("ap-lan2") as stream:
            assert stream.read(16) == b"boot marker\n"
            assert stream.write(b"s") == 1
        assert events == [("acquire", "ap-lan2"),
                          ("get_driver", "SerialDriver"),
                          ("serial-write", b"s"),
                          "deactivate"]

    def test_ssh_target_from_network_service(self, labgrid_stub) -> None:
        events: list = []
        resources = {("dut", "NetworkService"):
                     SimpleNamespace(cls="NetworkService",
                                     address="192.168.102.51", username="root")}
        t = _labgrid_bench(events, resources).ssh_target("ap-lan2")
        assert t == bs.SshTarget(host="192.168.102.51", user="root")
        assert events[0] == ("acquire", "ap-lan2")

    def test_ssh_target_without_network_service_refuses(self, labgrid_stub) -> None:
        with pytest.raises(bs.BenchError, match="no NetworkService"):
            _labgrid_bench([], resources={}).ssh_target("ap-lan3")

    def test_tftp_arm_delegates_to_direct_path(self, labgrid_stub,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list = []
        monkeypatch.setattr(bs.subprocess, "run", _run_recorder("LIFELINE-OK", calls))
        handle = _labgrid_bench([]).tftp_arm(1002, "img.bin")
        assert handle.vlan == 1002 and handle.switch == "192.168.13.2"
        assert calls[0][0][-1] == "sh -s"

    def test_switch_infra_primitives_are_typed_unsupported(self, labgrid_stub) -> None:
        """switch_exec/sh/put are bench-switch infrastructure: labgrid models
        per-place DUT resources only — typed refusal, never a silent direct
        fallback (task 11 rule)."""
        lb = _labgrid_bench([])
        for call in (lambda: lb.switch_exec("ubus call poe info"),
                     lambda: lb.switch_sh("echo hi\n"),
                     lambda: lb.switch_put(Path("/tmp/img"), "/tmp/x")):
            with pytest.raises(bs.UnsupportedOperationError, match="bench-switch infrastructure"):
                call()

    def test_unknown_action_typed_error(self, labgrid_stub) -> None:
        with pytest.raises(bs.BenchError, match="unknown power action"):
            _labgrid_bench([]).power("ap-lan4", "toggle")

    def test_missing_package_is_typed_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "labgrid", None)  # import -> ImportError
        with pytest.raises(bs.LabgridNotInstalledError, match="pip install labgrid"):
            bs.LabgridBench(coordinator="c:1")

    def test_missing_coordinator_is_typed_error(self, labgrid_stub) -> None:
        with pytest.raises(bs.BackendError, match="coordinator"):
            bs.LabgridBench(coordinator="")


# ------------------------------------------------------------- get_session

def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
             body: str = "") -> Path:
    monkeypatch.delenv("CONWRT_BENCH", raising=False)
    monkeypatch.delenv("LG_COORDINATOR", raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text(body)
    monkeypatch.setenv("CONWRT_CONFIG", str(cfg))
    return cfg


class TestGetSession:
    def test_unset_env_and_plain_config_select_direct(self, monkeypatch: pytest.MonkeyPatch,
                                                      tmp_path: Path) -> None:
        _isolate(monkeypatch, tmp_path, "[password]\nmode = \"random\"\n")
        s = bs.get_session()
        assert isinstance(s, bs.DirectBench)
        assert s.switch_host == "192.168.13.2"

    def test_missing_config_file_selects_direct(self, monkeypatch: pytest.MonkeyPatch,
                                                tmp_path: Path) -> None:
        _isolate(monkeypatch, tmp_path)  # nothing written -> path absent
        assert isinstance(bs.get_session(), bs.DirectBench)

    def test_config_labgrid_enabled(self, monkeypatch: pytest.MonkeyPatch,
                                    tmp_path: Path, labgrid_stub) -> None:
        _isolate(monkeypatch, tmp_path,
                 "[labgrid]\nenabled = true\ncoordinator = \"10.1.2.3:20408\"\n")
        s = bs.get_session()
        assert isinstance(s, bs.LabgridBench)
        assert s.coordinator == "10.1.2.3:20408"

    def test_config_section_without_enabled_stays_direct(self, monkeypatch: pytest.MonkeyPatch,
                                                         tmp_path: Path) -> None:
        _isolate(monkeypatch, tmp_path, "[labgrid]\ncoordinator = \"10.1.2.3:20408\"\n")
        assert isinstance(bs.get_session(), bs.DirectBench)

    def test_env_direct_wins_over_enabled_config(self, monkeypatch: pytest.MonkeyPatch,
                                                  tmp_path: Path) -> None:
        _isolate(monkeypatch, tmp_path, "[labgrid]\nenabled = true\n")
        monkeypatch.setenv("CONWRT_BENCH", "direct")
        assert isinstance(bs.get_session(), bs.DirectBench)

    def test_env_labgrid_uses_env_coordinator(self, monkeypatch: pytest.MonkeyPatch,
                                              tmp_path: Path, labgrid_stub) -> None:
        _isolate(monkeypatch, tmp_path)
        monkeypatch.setenv("CONWRT_BENCH", "labgrid")
        monkeypatch.setenv("LG_COORDINATOR", "192.168.13.221:20408")
        s = bs.get_session()
        assert isinstance(s, bs.LabgridBench)
        assert s.coordinator == "192.168.13.221:20408"

    def test_unknown_backend_name_is_typed_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CONWRT_BENCH", "banana")
        with pytest.raises(bs.BackendError, match="unknown bench backend 'banana'"):
            bs.get_session()


class TestConfigLabgridSection:
    def test_absent_section_keeps_default(self, tmp_path: Path) -> None:
        cfg = tmp_path / "c.toml"
        cfg.write_text("[password]\nmode = \"random\"\n")
        assert load_config(cfg).labgrid is None

    def test_section_parses_coordinator_and_enabled(self, tmp_path: Path) -> None:
        cfg = tmp_path / "c.toml"
        cfg.write_text("[labgrid]\ncoordinator = \"h:1\"\nenabled = true\n")
        lg = load_config(cfg).labgrid
        assert lg is not None
        assert lg.coordinator == "h:1" and lg.enabled is True

    def test_enabled_defaults_false(self, tmp_path: Path) -> None:
        cfg = tmp_path / "c.toml"
        cfg.write_text("[labgrid]\ncoordinator = \"h:1\"\n")
        lg = load_config(cfg).labgrid
        assert lg is not None and lg.enabled is False


# --------------------------------------------- no-labgrid import guarantee

class TestNoLabgridEnvironment:
    def test_import_and_direct_selection_without_labgrid(self) -> None:
        """Prove in a pristine interpreter that conwrt imports and selects
        the direct backend with labgrid unimportable, and that REQUESTING
        the labgrid backend fails with the typed error (not ImportError)."""
        code = (
            "import sys\n"
            "sys.modules['labgrid'] = None\n"  # blocker: import labgrid -> ImportError
            "import bench_session\n"
            "s = bench_session.get_session(backend='direct')\n"
            "assert type(s).__name__ == 'DirectBench', s\n"
            "try:\n"
            "    bench_session.get_session(backend='labgrid', coordinator='c:1')\n"
            "except bench_session.LabgridNotInstalledError:\n"
            "    print('TYPED-ERROR-OK')\n"
            "else:\n"
            "    raise AssertionError('labgrid request must fail typed')\n"
        )
        proc = subprocess.run([sys.executable, "-c", code],
                              cwd=REPO_ROOT / "scripts",
                              capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, proc.stderr
        assert "TYPED-ERROR-OK" in proc.stdout

    @pytest.mark.skipif(importlib.util.find_spec("labgrid") is not None,
                        reason="labgrid installed here — real client covered by stub tests")
    def test_real_labgrid_absent_would_still_import(self) -> None:
        # Informational mirror of the subprocess test for environments
        # where labgrid genuinely is absent.
        import bench_session  # noqa: F401 — must not raise
