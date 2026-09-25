"""Tests for the optional `conwrt flash --serial` boot-milestone monitor.

Covers flash.serial_monitor (spec parsing, milestone parsing over a scripted
TCP stream, UART-break recovery, disconnect-fallback semantics), the
timeline integration in flash.context (apply_serial_milestone /
drain_serial_milestones / wait_for_event precedence), and the
monitor_lifecycle wiring in conwrt.monitors.

CI rule: localhost sockets only — no hardware, no network beyond loopback.
Marker vocabulary comes from data/bench/ap-lan2/20260923-serial-via-lan4/
lan2-boot.log (the real AP3915i boot signature).
"""
from __future__ import annotations

import argparse
import queue
import socket
import threading
import time
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

import pytest

from flash.context import (
    Event,
    RecoveryContext,
    Timeline,
    drain_serial_milestones,
    apply_serial_milestone,
    wait_for_event,
)


# ─── Real marker vocabulary (lan2-boot.log, 2026-09-23) ─────────────────────

UBOOT_BANNER_BACKUP = "U-Boot 2012.07.19-r00020.1 (Jul 17 2017 - 17:24:13) (back-up)"
UBOOT_BANNER_PRIMARY = "U-Boot 2012.07.22 (Jul 19 2022 - 10:26:07) (primary)"
STARTING_KERNEL = "Starting kernel ..."
KERNEL_CMDLINE_ECHO = (
    '[    0.000000] Kernel command line: console=ttyMSM0,115200n81 ubi.mtd=0  panic=30 '
    f'BOOT_BOOTROM="U-Boot 2012.07.19-r00020.1 (Jul 17 2017 - 17:24:13)"'
)
INIT_PREINIT = "[    3.873775] init: - preinit -"
PROCD_INIT = "13.054844] procd: - init -"
LOGIN_PROMPT = "root@OpenWrt:~# "


def _boot_chunks() -> list[bytes]:
    """The full AP3915i boot milestone sequence as stream chunks."""
    return [
        (UBOOT_BANNER_BACKUP + "\r\n").encode(),
        (UBOOT_BANNER_PRIMARY + "\r\n").encode(),
        (KERNEL_CMDLINE_ECHO + "\r\n").encode(),  # echo must NOT re-fire the banner
        (STARTING_KERNEL + "\r\n").encode(),
        (INIT_PREINIT + "\r\n").encode(),
        (PROCD_INIT + "\r\n").encode(),
        (LOGIN_PROMPT).encode(),  # prompt has NO trailing newline
    ]


class ScriptedSerialServer:
    """Local TCP server feeding each accepted connection a byte-chunk script.

    scripts[i] is the list of chunks connection i receives (chunk_delay apart);
    later connections (beyond the script list) are held open silently. A
    chunk of None means "close the connection now" (mid-stream disconnect).
    """

    def __init__(self, scripts: list[list[object]] | None = None, chunk_delay: float = 0.05):
        self._srv = socket.create_server(("127.0.0.1", 0))
        self._srv.settimeout(0.2)
        self.port = self._srv.getsockname()[1]
        self.scripts = scripts or []
        self.chunk_delay = chunk_delay
        self.accepted = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    @property
    def url(self) -> str:
        return f"tcp://127.0.0.1:{self.port}"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._srv.close()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            idx = self.accepted
            self.accepted += 1
            script = self.scripts[idx] if idx < len(self.scripts) else []
            threading.Thread(target=self._serve, args=(conn, script), daemon=True).start()

    def _serve(self, conn: socket.socket, script: list[object]) -> None:
        try:
            for chunk in script:
                if self._stop.is_set():
                    return
                if chunk is None:
                    conn.close()
                    return
                conn.sendall(chunk)
                time.sleep(self.chunk_delay)
            # hold the connection open (like a real bridge) until stopped
            while not self._stop.is_set():
                time.sleep(0.05)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _drain(q: queue.Queue) -> list[tuple]:
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            break
    return items


def _collect(q: queue.Queue, want: int, timeout: float = 10.0) -> list[tuple]:
    """Collect up to `want` events within `timeout` seconds."""
    items: list[tuple] = []
    deadline = time.time() + timeout
    while len(items) < want and time.time() < deadline:
        try:
            items.append(q.get(timeout=0.2))
        except queue.Empty:
            pass
    return items


# ─── Spec parsing ───────────────────────────────────────────────────────────


class TestParseSerialSpec(TestCase):
    def test_tcp_without_baud(self):
        from flash.serial_monitor import parse_serial_spec
        assert parse_serial_spec("tcp://127.0.0.1:4002") == ("tcp://127.0.0.1:4002", None)

    def test_tcp_with_baud(self):
        from flash.serial_monitor import parse_serial_spec
        assert parse_serial_spec("tcp://127.0.0.1:4002,57600") == ("tcp://127.0.0.1:4002", 57600)

    def test_dev_path_with_baud(self):
        from flash.serial_monitor import parse_serial_spec
        assert parse_serial_spec("/dev/cu.usbserial-BG02QAPG,57600") == (
            "/dev/cu.usbserial-BG02QAPG", 57600)

    def test_dev_path_without_baud(self):
        from flash.serial_monitor import parse_serial_spec
        assert parse_serial_spec("/dev/cu.usbserial-BG02QAPG") == (
            "/dev/cu.usbserial-BG02QAPG", None)

    def test_bad_tcp_endpoint_raises(self):
        from serial_transport import SerialConnectionError
        from flash.serial_monitor import parse_serial_spec
        with pytest.raises(SerialConnectionError):
            parse_serial_spec("tcp://host-only")

    def test_bad_baud_raises(self):
        from serial_transport import SerialConnectionError
        from flash.serial_monitor import parse_serial_spec
        with pytest.raises(SerialConnectionError):
            parse_serial_spec("tcp://127.0.0.1:4002,notanint")

    def test_bare_hostport_rejected(self):
        from serial_transport import SerialConnectionError
        from flash.serial_monitor import parse_serial_spec
        with pytest.raises(SerialConnectionError):
            parse_serial_spec("127.0.0.1:4002")


# ─── Milestone parsing over a scripted stream ───────────────────────────────


class TestSerialBootMonitorMilestones(TestCase):
    def _run_monitor(self, server: ScriptedSerialServer, timeout: float = 10.0):
        """Run a SerialBootMonitor against `server` until it goes idle."""
        from flash.serial_monitor import SerialBootMonitor
        q: queue.Queue = queue.Queue()
        mon = SerialBootMonitor(server.url, 115200, q)
        t = threading.Thread(target=mon.run, daemon=True)
        t.start()
        return mon, t, q

    def test_full_boot_drives_all_milestones(self):
        # connection 1 carries only the UART break (power cycle); the monitor
        # closes and reconnects, and connection 2 carries the boot sequence
        server = ScriptedSerialServer(
            scripts=[[b"\x00" * 32], _boot_chunks()], chunk_delay=0.05)
        server.start()
        try:
            with patch("flash.serial_monitor.BREAK_RECOVERY_WAIT", 0.05):
                mon, t, q = self._run_monitor(server)
                events = _collect(q, want=5, timeout=15)
                mon.stop()
                t.join(timeout=5)
            kinds = [e[0] for e in events]
            assert kinds == [
                Event.SERIAL_UBOOT_BANNER,
                Event.SERIAL_KERNEL_START,
                Event.SERIAL_PROCD_PREINIT,
                Event.SERIAL_PROCD_INIT,
                Event.SERIAL_LOGIN_PROMPT,
            ]
            # detail = the matching U-Boot banner (back-up or primary, not the cmdline echo)
            assert "back-up" in events[0][2] or "primary" in events[0][2]
            assert events[1][2] == STARTING_KERNEL
            assert events[2][2] == INIT_PREINIT
            assert events[3][2] == PROCD_INIT
            # every tuple is (Event, float ts, str detail) — the pcap shape
            for _kind, ets, detail in events:
                assert isinstance(ets, float)
                assert isinstance(detail, str)
        finally:
            server.stop()

    def test_marker_split_across_chunks_still_detected(self):
        halves = [
            b"[    3.873775] init: - pre",
            b"init -\r\n",
        ]
        server = ScriptedSerialServer(scripts=[halves], chunk_delay=0.4)
        server.start()
        try:
            mon, t, q = self._run_monitor(server)
            events = _collect(q, want=1, timeout=10)
            mon.stop()
            t.join(timeout=5)
            assert events and events[0][0] == Event.SERIAL_PROCD_PREINIT
            assert events[0][2] == "[    3.873775] init: - preinit -"
        finally:
            server.stop()

    def test_banner_echo_does_not_refire(self):
        server = ScriptedSerialServer(
            scripts=[[(UBOOT_BANNER_PRIMARY + "\r\n").encode(),
                      (KERNEL_CMDLINE_ECHO + "\r\n").encode()]],
            chunk_delay=0.05)
        server.start()
        try:
            mon, t, q = self._run_monitor(server)
            events = _collect(q, want=1, timeout=10)
            time.sleep(0.3)  # allow a spurious duplicate to arrive
            mon.stop()
            t.join(timeout=5)
            banners = [e for e in _drain(q) + events if e[0] == Event.SERIAL_UBOOT_BANNER]
            assert len(banners) == 1
        finally:
            server.stop()

    def test_null_break_chunk_reconnects_and_continues(self):
        """A relayed UART break (0x00 run) must not kill the monitor: it
        reconnects and keeps parsing the following connection's stream."""
        from flash.serial_monitor import BREAK_RECOVERY_WAIT
        server = ScriptedSerialServer(
            scripts=[
                [b"\x00" * 16],                                  # conn 1: break only
                [(UBOOT_BANNER_PRIMARY + "\r\n").encode(),       # conn 2: boot continues
                 (STARTING_KERNEL + "\r\n").encode()],
            ],
            chunk_delay=0.05)
        server.start()
        try:
            with patch("flash.serial_monitor.BREAK_RECOVERY_WAIT", 0.05):
                from flash.serial_monitor import SerialBootMonitor
                q: queue.Queue = queue.Queue()
                mon = SerialBootMonitor(server.url, 115200, q)
                t = threading.Thread(target=mon.run, daemon=True)
                t.start()
                events = _collect(q, want=2, timeout=15)
                mon.stop()
                t.join(timeout=5)
            assert [e[0] for e in events] == [
                Event.SERIAL_UBOOT_BANNER, Event.SERIAL_KERNEL_START]
            assert server.accepted >= 2  # reconnect happened
            assert BREAK_RECOVERY_WAIT == 3.0  # patch was scoped, default intact
        finally:
            server.stop()


# ─── Disconnect semantics: warn once, pcap-only, no abort ───────────────────


class TestSerialDisconnectFallsBackToPcapOnly(TestCase):
    def test_mid_flash_disconnect_warns_and_ends_thread(self):
        from flash.serial_monitor import SerialBootMonitor
        # connection 1 delivers the banner then dies (None = close)
        server = ScriptedSerialServer(
            scripts=[[(UBOOT_BANNER_PRIMARY + "\r\n").encode(), None]],
            chunk_delay=0.05)
        server.start()
        try:
            q: queue.Queue = queue.Queue()
            mon = SerialBootMonitor(server.url, 115200, q)
            with patch("flash.serial_monitor.log") as mock_log:
                t = threading.Thread(target=mon.run, daemon=True)
                t.start()
                # milestone before death must still be delivered
                events = _collect(q, want=1, timeout=10)
                # thread ends by itself after the disconnect
                t.join(timeout=5)
                assert not t.is_alive()
            assert events and events[0][0] == Event.SERIAL_UBOOT_BANNER
            logged = " ".join(str(c.args[0]) for c in mock_log.call_args_list)
            assert "pcap-only" in logged
        finally:
            server.stop()

    def test_refused_open_warns_and_ends_thread(self):
        from flash.serial_monitor import SerialBootMonitor
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]
        s.close()
        q: queue.Queue = queue.Queue()
        mon = SerialBootMonitor(f"tcp://127.0.0.1:{dead_port}", 115200, q)
        with patch("flash.serial_monitor.log") as mock_log:
            t = threading.Thread(target=mon.run, daemon=True)
            t.start()
            t.join(timeout=5)
            assert not t.is_alive()
        logged = " ".join(str(c.args[0]) for c in mock_log.call_args_list)
        assert "continuing without" in logged
        assert _drain(q) == []


# ─── Timeline integration (flash.context) ───────────────────────────────────


def _make_ctx() -> RecoveryContext:
    return RecoveryContext(
        profile=SimpleNamespace(openwrt_ip="192.168.1.1", recovery_ip="192.168.1.1"),
        image_path="/tmp/fw.bin",
        interface="en0",
        pcap_path="/tmp/x.pcap",
    )


class TestApplySerialMilestone(TestCase):
    def test_each_milestone_records_its_timeline_field(self):
        ctx = _make_ctx()
        apply_serial_milestone(ctx, Event.SERIAL_UBOOT_BANNER, 100.0)
        apply_serial_milestone(ctx, Event.SERIAL_KERNEL_START, 101.0)
        apply_serial_milestone(ctx, Event.SERIAL_PROCD_PREINIT, 102.0)
        apply_serial_milestone(ctx, Event.SERIAL_PROCD_INIT, 103.0)
        apply_serial_milestone(ctx, Event.SERIAL_LOGIN_PROMPT, 104.0)
        tl = ctx.timeline
        assert tl.serial_uboot_banner == 100.0
        assert tl.serial_kernel_start == 101.0
        assert tl.serial_procd_preinit == 102.0
        assert tl.serial_procd_init == 103.0
        assert tl.serial_login_prompt == 104.0

    def test_kernel_start_claims_first_openwrt_packet(self):
        ctx = _make_ctx()
        apply_serial_milestone(ctx, Event.SERIAL_KERNEL_START, 101.0)
        assert ctx.timeline.first_openwrt_packet == 101.0

    def test_serial_wins_over_earlier_pcap_first_packet(self):
        """Conflict rule: serial is ground truth — a later serial kernel
        start overwrites the pcap-derived first_openwrt_packet."""
        ctx = _make_ctx()
        ctx.timeline.first_openwrt_packet = 90.0  # pcap ICMPv6 wrote this first
        say_calls: list[str] = []
        ctx._say_fn = lambda m: say_calls.append(m)
        apply_serial_milestone(ctx, Event.SERIAL_KERNEL_START, 101.0)
        assert ctx.timeline.first_openwrt_packet == 101.0
        assert say_calls == []  # already announced by the pcap path

    def test_login_prompt_does_not_claim_ssh_available(self):
        ctx = _make_ctx()
        apply_serial_milestone(ctx, Event.SERIAL_LOGIN_PROMPT, 104.0)
        assert ctx.timeline.ssh_available is None  # SSH verification stays the gate


class TestWaitForEventSerialPrecedence(TestCase):
    def _wait(self, ctx, events):
        q: queue.Queue = queue.Queue()
        for ev, at in events:
            q.put((ev, at, ""))
        result = wait_for_event(
            q, timeout=1, target_events={Event.SSH_UP},
            success_state=None, fail_message="x", fail_say="y", ctx=ctx)
        return result

    def test_icmpv6_after_serial_does_not_overwrite(self):
        ctx = _make_ctx()
        ctx._say_fn = lambda m: None
        self._wait(ctx, [
            (Event.SERIAL_KERNEL_START, 100.0),
            (Event.ICMPV6_FROM_ROUTER, 105.0),  # pcap arrives later
        ])
        assert ctx.timeline.first_openwrt_packet == 100.0
        assert ctx.timeline.serial_kernel_start == 100.0

    def test_icmpv6_alone_still_works(self):
        """Flag absent = no serial events: pcap path unchanged."""
        ctx = _make_ctx()
        ctx._say_fn = lambda m: None
        self._wait(ctx, [(Event.ICMPV6_FROM_ROUTER, 105.0)])
        assert ctx.timeline.first_openwrt_packet == 105.0


class TestDrainSerialMilestones(TestCase):
    def test_drain_applies_milestones_and_empties_queue(self):
        ctx = _make_ctx()
        q: queue.Queue = queue.Queue()
        q.put((Event.SERIAL_UBOOT_BANNER, 100.0, "banner"))
        q.put((Event.SERIAL_KERNEL_START, 101.0, "kernel"))
        drain_serial_milestones(q, ctx)
        assert ctx.timeline.serial_uboot_banner == 100.0
        assert ctx.timeline.serial_kernel_start == 101.0
        assert ctx.timeline.first_openwrt_packet == 101.0
        assert _drain(q) == []


# ─── monitor_lifecycle wiring (conwrt.monitors) ─────────────────────────────


class _StubSerialMonitor:
    instances: list["_StubSerialMonitor"] = []

    def __init__(self, port: str, baud: int, event_queue: queue.Queue) -> None:
        self.port = port
        self.baud = baud
        self.event_queue = event_queue
        self.stopped = False
        _StubSerialMonitor.instances.append(self)

    def stop(self) -> None:
        self.stopped = True

    def run(self) -> None:
        while not self.stopped:
            time.sleep(0.02)


def _lifecycle_args(**overrides) -> argparse.Namespace:
    defaults = dict(
        router_mac="",
        uboot_mac="",
        silence_timeout=30,
        no_pcap=True,
        serial=None,
        serial_baud=115200,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _lifecycle_profile() -> SimpleNamespace:
    return SimpleNamespace(
        recovery_ip="192.168.1.1",
        zycast_multicast_group="",
        zycast_multicast_port=0,
    )


class TestMonitorLifecycleSerialWiring(TestCase):
    """No-flag parity + flag wiring + teardown for the serial monitor."""

    def test_no_flag_never_constructs_serial_monitor(self):
        from conwrt.monitors import monitor_lifecycle
        _StubSerialMonitor.instances = []
        q: queue.Queue = queue.Queue()
        with patch("flash.serial_monitor.SerialBootMonitor", _StubSerialMonitor):
            # args namespace WITHOUT a serial attr at all (older callers)
            args = argparse.Namespace(
                router_mac="", uboot_mac="", silence_timeout=30, no_pcap=True)
            with monitor_lifecycle("en6", q, "/tmp/c.pcap", _lifecycle_profile(), args):
                pass
        assert _StubSerialMonitor.instances == []

    def test_none_flag_never_constructs_serial_monitor(self):
        from conwrt.monitors import monitor_lifecycle
        _StubSerialMonitor.instances = []
        q: queue.Queue = queue.Queue()
        with patch("flash.serial_monitor.SerialBootMonitor", _StubSerialMonitor):
            with monitor_lifecycle("en6", q, "/tmp/c.pcap", _lifecycle_profile(),
                                   _lifecycle_args(serial=None)):
                pass
        assert _StubSerialMonitor.instances == []

    def test_flag_constructs_monitor_with_parsed_spec_and_stops_on_exit(self):
        from conwrt.monitors import monitor_lifecycle
        _StubSerialMonitor.instances = []
        q: queue.Queue = queue.Queue()
        with patch("flash.serial_monitor.SerialBootMonitor", _StubSerialMonitor):
            with monitor_lifecycle("en6", q, "/tmp/c.pcap", _lifecycle_profile(),
                                   _lifecycle_args(serial="tcp://127.0.0.1:4002,57600")):
                assert len(_StubSerialMonitor.instances) == 1
                mon = _StubSerialMonitor.instances[0]
                assert mon.port == "tcp://127.0.0.1:4002"
                assert mon.baud == 57600
                assert mon.event_queue is q
                assert not mon.stopped
        assert _StubSerialMonitor.instances[0].stopped

    def test_flag_baud_falls_back_to_serial_baud_arg(self):
        from conwrt.monitors import monitor_lifecycle
        _StubSerialMonitor.instances = []
        q: queue.Queue = queue.Queue()
        with patch("flash.serial_monitor.SerialBootMonitor", _StubSerialMonitor):
            with monitor_lifecycle("en6", q, "/tmp/c.pcap", _lifecycle_profile(),
                                   _lifecycle_args(serial="tcp://127.0.0.1:4002",
                                                   serial_baud=57600)):
                pass
        assert _StubSerialMonitor.instances[0].baud == 57600

    def test_malformed_spec_warns_and_flow_continues(self):
        """A bad spec degrades to pcap-only inside the lifecycle — no raise."""
        from conwrt.monitors import monitor_lifecycle
        _StubSerialMonitor.instances = []
        q: queue.Queue = queue.Queue()
        with patch("flash.serial_monitor.SerialBootMonitor", _StubSerialMonitor), \
                patch("conwrt.monitors.log") as mock_log:
            with monitor_lifecycle("en6", q, "/tmp/c.pcap", _lifecycle_profile(),
                                   _lifecycle_args(serial="tcp://host-only")):
                pass
        assert _StubSerialMonitor.instances == []
        logged = " ".join(str(c.args[0]) for c in mock_log.call_args_list)
        assert "serial" in logged.lower()

    def test_missing_pyserial_warns_and_flow_continues(self):
        from conwrt.monitors import monitor_lifecycle
        _StubSerialMonitor.instances = []
        q: queue.Queue = queue.Queue()

        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) \
            else __builtins__.__import__

        def _no_serial(name, *a, **k):
            if name == "flash.serial_monitor" or name == "serial_transport":
                raise ImportError("No module named 'serial'")
            return real_import(name, *a, **k)

        with patch("builtins.__import__", side_effect=_no_serial), \
                patch("conwrt.monitors.log") as mock_log:
            with monitor_lifecycle("en6", q, "/tmp/c.pcap", _lifecycle_profile(),
                                   _lifecycle_args(serial="tcp://127.0.0.1:4002")):
                pass
        assert _StubSerialMonitor.instances == []
        logged = " ".join(str(c.args[0]) for c in mock_log.call_args_list)
        assert "pyserial" in logged.lower()


    def test_real_monitor_in_lifecycle_feeds_queue(self):
        """End-to-end through monitor_lifecycle: real SerialBootMonitor (lazy
        import path), milestones land on the shared queue, teardown joins."""
        from conwrt.monitors import monitor_lifecycle
        server = ScriptedSerialServer(scripts=[_boot_chunks()], chunk_delay=0.05)
        server.start()
        try:
            q: queue.Queue = queue.Queue()
            args = _lifecycle_args(serial=server.url)
            with monitor_lifecycle("en6", q, "/tmp/c.pcap", _lifecycle_profile(), args):
                events = _collect(q, want=5, timeout=15)
            kinds = [e[0] for e in events]
            assert kinds == [
                Event.SERIAL_UBOOT_BANNER,
                Event.SERIAL_KERNEL_START,
                Event.SERIAL_PROCD_PREINIT,
                Event.SERIAL_PROCD_INIT,
                Event.SERIAL_LOGIN_PROMPT,
            ]
        finally:
            server.stop()


# ─── Timeline dataclass ─────────────────────────────────────────────────────


class TestTimelineSerialFields(TestCase):
    def test_new_fields_default_none(self):
        tl = Timeline()
        assert tl.serial_uboot_banner is None
        assert tl.serial_kernel_start is None
        assert tl.serial_procd_preinit is None
        assert tl.serial_procd_init is None
        assert tl.serial_login_prompt is None
