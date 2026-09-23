#!/usr/bin/env python3
"""bench_session — the BenchSession abstraction: one bench, two control planes.

Formalizes what bench_flash.py's docstring called "the labgrid Strategy
pattern, adapted": four bench primitives behind one interface so the bench_*
scripts stop hand-rolling SSH/ubus/dbclient paths (that rewiring is plan
task 11 — this module changes nothing by itself).

Primitives:
  power(place, "on"|"off"|"cycle")   PoE control for the place's switch port
  console(place)                     context manager -> readable+writable
                                     stream (serial bridge pair, or labgrid
                                     NetworkSerialPort)
  ssh_target(place)                  (host, user, jump) coordinates for the DUT
  tftp_arm(vlan, image_name)         stage + verify the dnsmasq TFTP lifeline
                                     on the switch, return the handle

Backends:
  DirectBench  (default) — today's exact command paths, zero new deps:
      power:   ssh root@<switch> + ubus call poe manage {"port":"lanN",...}
               (conwrt_poe / bench_inventory wire form)
      ssh:     root@dut_ip (or fe80 link-local) via jump through the switch
               (bench_adopt dbclient form)
      tftp:    dnsmasq staging lines from bench_flash.lifeline_lines
      console: TCP socket to a conwrt_serial_bridge endpoint, when a pair
               exists (pass serial_endpoints={"ap-lanN": (host, port)})
  LabgridBench (optional) — the labgrid python client, ALL imports lazy so
      conwrt imports/behaves identically without the package:
      power via NetworkPowerDriver, console via SerialDriver on
      NetworkSerialPort, ssh via NetworkService; the place is acquired for
      the session and released on close(). TFTP lifelines are switch
      infrastructure labgrid has no resource for, so that primitive
      delegates to the direct path.

Selection (get_session): CONWRT_BENCH=direct|labgrid env wins; else a
config.toml [labgrid] section with enabled=true selects labgrid; else
direct. Requesting labgrid without the package raises
LabgridNotInstalledError — never an ImportError, never a fallback.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Protocol, runtime_checkable

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_adopt import Place  # noqa: E402
from bench_flash import lifeline_lines  # noqa: E402
from config import LabgridConfig, load_config  # noqa: E402

DEFAULT_SWITCH = "192.168.13.2"
DEFAULT_TFTPROOT = "/tmp/bench-tftp"
CYCLE_OFF_S = 8
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
POWER_ACTIONS = ("on", "off", "cycle")


class BenchError(Exception):
    """Bench primitive failed (command failure, gate refusal, bad input)."""


class BackendError(BenchError):
    """Backend selection failed: unknown name or missing coordinator."""


class LabgridNotInstalledError(BenchError):
    """Labgrid backend requested but the labgrid package is not installed."""


class ConsoleUnavailableError(BenchError):
    """No serial console endpoint exists for the place."""


PowerAction = str  # validated against POWER_ACTIONS at runtime


@dataclass(frozen=True)
class SshTarget:
    """Coordinates for reaching a DUT. zone is set for fe80 link-locals
    (render host%zone — scoped dialing must happen on the zone's link,
    i.e. from the jump host)."""
    host: str
    user: str
    jump: str | None = None
    zone: str = ""


@dataclass(frozen=True)
class TftpLifeline:
    """Handle for an armed per-VLAN TFTP lifeline. Runtime-only state on the
    switch: the dnsmasq instance and its log die on switch reboot — re-arm
    rather than trust an old handle."""
    vlan: int
    tftproot: str
    switch: str
    log: str

    @property
    def interface(self) -> str:
        return f"switch.{self.vlan}"


@runtime_checkable
class ConsoleStream(Protocol):
    def read(self, size: int = 256, timeout: float | None = None) -> bytes: ...
    def write(self, data: bytes) -> int: ...


@runtime_checkable
class BenchSession(Protocol):
    def power(self, place: Place | str, action: PowerAction) -> None: ...
    def console(self, place: Place | str) -> AbstractContextManager[ConsoleStream]: ...
    def ssh_target(self, place: Place | str) -> SshTarget: ...
    def tftp_arm(self, vlan: int, image_name: str,
                 tftproot: str = DEFAULT_TFTPROOT) -> TftpLifeline: ...


def _name(place: Place | str) -> str:
    return place.name if isinstance(place, Place) else place


def _check_action(action: str) -> None:
    if action not in POWER_ACTIONS:
        raise BenchError(f"unknown power action {action!r}; expected one of {POWER_ACTIONS}")


class _SocketConsole:
    """Readable+writable view over the serial-bridge TCP socket."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def read(self, size: int = 256, timeout: float | None = None) -> bytes:
        self._sock.settimeout(timeout)
        return self._sock.recv(size)

    def write(self, data: bytes) -> int:
        self._sock.sendall(data)
        return len(data)


class DirectBench:
    """Today's bench paths, verbatim: switch SSH + ubus PoE, dbclient/ssh-jump
    coordinates, dnsmasq TFTP staging, TCP serial bridge for consoles."""

    def __init__(self, switch_host: str = DEFAULT_SWITCH,
                 serial_endpoints: Mapping[str, tuple[str, int]] | None = None,
                 cycle_off_s: int = CYCLE_OFF_S) -> None:
        self.switch_host = switch_host
        self.serial_endpoints = dict(serial_endpoints or {})
        self.cycle_off_s = cycle_off_s

    def _switch_cmd(self, cmd: str, timeout_s: int = 60) -> str:
        proc = subprocess.run(["ssh", *SSH_OPTS, f"root@{self.switch_host}", cmd],
                              capture_output=True, text=True, timeout=timeout_s)
        if proc.returncode != 0:
            raise BenchError(f"switch command failed ({proc.returncode}): "
                             f"{(proc.stderr or proc.stdout)[-300:]}")
        return proc.stdout + proc.stderr

    def _switch_sh(self, script: str, timeout_s: int = 60) -> str:
        proc = subprocess.run(["ssh", *SSH_OPTS, f"root@{self.switch_host}", "sh -s"],
                              input=script, capture_output=True, text=True, timeout=timeout_s)
        return proc.stdout + proc.stderr

    def power(self, place: Place | str, action: PowerAction) -> None:
        _check_action(action)
        port = _name(place).removeprefix("ap-")
        if action in ("on", "off"):
            ubus_action = "enable" if action == "on" else "disable"
            self._switch_cmd(f"ubus call poe manage "
                             f"'{{\"port\":\"{port}\",\"action\":\"{ubus_action}\"}}'")
        else:
            # one SSH round-trip: off -> settle -> on (bench_flash's proven 8s;
            # never split a cycle across connections — AGENTS macOS eth rule)
            self._switch_cmd(f"ubus call poe manage '{{\"port\":\"{port}\",\"action\":\"disable\"}}'; "
                             f"sleep {self.cycle_off_s}; "
                             f"ubus call poe manage '{{\"port\":\"{port}\",\"action\":\"enable\"}}'")

    @contextmanager
    def console(self, place: Place | str) -> Iterator[ConsoleStream]:
        name = _name(place)
        endpoint = self.serial_endpoints.get(name)
        if endpoint is None:
            raise ConsoleUnavailableError(
                f"no serial console endpoint registered for {name} — pass "
                f"serial_endpoints {{{name!r}: (host, port)}} for a live bridge pair")
        sock = socket.create_connection(endpoint, timeout=10)
        try:
            yield _SocketConsole(sock)
        finally:
            sock.close()

    def ssh_target(self, place: Place | str) -> SshTarget:
        if not isinstance(place, Place):
            raise BenchError(f"direct ssh_target needs a Place record with dut_ip/mac "
                             f"(load places.json); got bare name {place!r}")
        if place.dut_ip:
            return SshTarget(host=place.dut_ip, user="root", jump=self.switch_host)
        return SshTarget(host=place.linklocal, user="root",
                         jump=self.switch_host, zone=f"switch.{place.vlan}")

    def tftp_arm(self, vlan: int, image_name: str,
                 tftproot: str = DEFAULT_TFTPROOT) -> TftpLifeline:
        # lifeline_lines reads only place.vlan; the image must already be in
        # tftproot (caller pushes it — bench_flash push_to_switch order).
        staging = Place(name=f"ap-lan{vlan - 1000}", mac="00:00:00:00:00:00", dut_ip="")
        out = self._switch_sh("\n".join(lifeline_lines(staging, image_name, tftproot)) + "\n")
        if "LIFELINE-OK" not in out:
            raise BenchError(f"TFTP lifeline not verifiably serving on switch.{vlan} "
                             f"({tftproot}):\n{out[:300]}")
        return TftpLifeline(vlan=vlan, tftproot=tftproot, switch=self.switch_host,
                            log=f"/tmp/tftp-{vlan}.log")


class LabgridBench:
    """Bench primitives through the labgrid python client (optional dep).

    The place is acquired for the session on first use and released on
    close() — the labgrid/README locking discipline. session_factory and
    target_factory are the client seam (tests inject fakes; production
    lazily imports labgrid, so this class is constructible only where the
    package exists — LabgridNotInstalledError otherwise).
    """

    def __init__(self, coordinator: str = "",
                 session_factory=None, target_factory=None,
                 switch_host: str = DEFAULT_SWITCH) -> None:
        try:
            import labgrid  # noqa: F401 — fail fast, typed, before any use
        except ImportError as e:
            raise LabgridNotInstalledError(
                "labgrid backend requested but the labgrid package is not "
                "installed (pip install labgrid); the direct backend needs "
                "nothing extra") from e
        if not coordinator:
            raise BackendError("labgrid backend needs a coordinator address: "
                               "[labgrid] coordinator in config.toml or LG_COORDINATOR")
        self.coordinator = coordinator
        self.switch_host = switch_host
        self._session = None
        self._acquired: set[str] = set()
        self._session_factory = session_factory or self._start_session
        self._target_factory = target_factory or self._labgrid_target
        self._direct = DirectBench(switch_host=switch_host)

    @staticmethod
    def _start_session(coordinator: str):
        from labgrid.remote.client import start_session
        return start_session(coordinator)

    def _ensure_session(self):
        if self._session is None:
            self._session = self._session_factory(self.coordinator)
        return self._session

    def _labgrid_target(self, name: str):
        # dynamic import on purpose: labgrid's legacy @attr.s codegen defeats
        # pyright's constructor synthesis; this seam must stay statically Any.
        import importlib
        remote = importlib.import_module("labgrid.resource.remote")
        target_mod = importlib.import_module("labgrid.target")
        session = self._ensure_session()
        manager = remote.RemotePlaceManager.get()
        manager.session = session
        manager.loop = session.loop
        target = target_mod.Target(name)
        remote.RemotePlace(target, name=name)
        return target

    def _acquire(self, name: str) -> None:
        if name in self._acquired:
            return
        session = self._ensure_session()
        session.loop.run_until_complete(session._acquire_place(name))
        self._acquired.add(name)

    def _release(self, name: str) -> None:
        session = self._ensure_session()
        session.loop.run_until_complete(session._release_place(name))
        self._acquired.discard(name)

    def power(self, place: Place | str, action: PowerAction) -> None:
        _check_action(action)
        from labgrid.driver import NetworkPowerDriver
        name = _name(place)
        self._acquire(name)
        drv = self._target_factory(name).get_driver(NetworkPowerDriver)
        if action == "on":
            drv.on()
        elif action == "off":
            drv.off()
        else:
            drv.cycle()

    @contextmanager
    def console(self, place: Place | str) -> Iterator[ConsoleStream]:
        from labgrid.driver import SerialDriver
        name = _name(place)
        self._acquire(name)
        target = self._target_factory(name)
        drv = target.get_driver(SerialDriver)
        try:
            yield drv
        finally:
            target.deactivate(drv)

    def ssh_target(self, place: Place | str) -> SshTarget:
        name = _name(place)
        self._acquire(name)
        session = self._ensure_session()
        resources = session.get_target_resources(session.get_place(name))
        for (_rname, cls), resource in resources.items():
            if cls == "NetworkService":
                return SshTarget(host=resource.address, user=resource.username)
        raise BenchError(f"place {name} has no NetworkService resource exported")

    def tftp_arm(self, vlan: int, image_name: str,
                 tftproot: str = DEFAULT_TFTPROOT) -> TftpLifeline:
        # labgrid has no TFTP resource — the lifeline is switch infrastructure
        # either way (labgrid/README image-per-run pattern, cost note 5).
        return self._direct.tftp_arm(vlan, image_name, tftproot)

    def close(self) -> None:
        if self._session is None:
            return
        for name in sorted(self._acquired):
            self._release(name)
        self._session.loop.run_until_complete(self._session.close())

    def __enter__(self) -> "LabgridBench":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def get_session(backend: str | None = None, switch_host: str | None = None,
                coordinator: str | None = None) -> BenchSession:
    """Pick the bench backend.

    Precedence: explicit backend arg > CONWRT_BENCH env > config.toml
    [labgrid] enabled > direct. Reading config only happens when no explicit
    selection was made, so CONWRT_BENCH=direct is byte-identical to today.
    """
    name = backend or os.environ.get("CONWRT_BENCH", "")
    lg_cfg: LabgridConfig | None = None
    if not name:
        lg_cfg = load_config().labgrid
        name = "labgrid" if (lg_cfg and lg_cfg.enabled) else "direct"

    if name == "direct":
        return DirectBench(switch_host=switch_host or DEFAULT_SWITCH)
    if name == "labgrid":
        coord = coordinator or (lg_cfg.coordinator if lg_cfg else "") \
            or os.environ.get("LG_COORDINATOR", "")
        return LabgridBench(coordinator=coord, switch_host=switch_host or DEFAULT_SWITCH)
    raise BackendError(f"unknown bench backend {name!r}; expected 'direct' or 'labgrid' "
                       "(CONWRT_BENCH or [labgrid] config)")
