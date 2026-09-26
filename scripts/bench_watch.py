#!/usr/bin/env python3
"""bench_watch — reboot-proof bench log/metrics watcher (generalizes switch-watch).

Replaces ad-hoc `ssh root@host 'logread -f'` tailing and the
data/bench/switch-watch/record.sh shell script with one supervised process:

  * per-device SSH stream readers with reconnect+backoff (everything ON a
    device dies with it — this loop lives on the Mac and survives reboots,
    capturing the fresh boot's log too, which no on-device recorder can)
  * 64 KiB ring buffer per stream; on disconnect the tail is persisted as
    tail-64k.txt (KernelCI "dying words" pattern)
  * periodic SNAP polling (device kind aware: switch = poe daemon RSS/ports,
    openwrt = boot_id/uptime/mem) with a reboot oracle (boot_id change OR
    monotonic-uptime decrease; log gaps alone are NEVER reboot evidence —
    UDP/syslog lossiness rule)
  * structured events.jsonl for alerting (bench_alert.py consumes it)
  * disk-quota guard (warning events; raw writes refused when over quota)

Read-only with respect to every device: streams logs, runs read-only snap
commands. NEVER power-controls anything (AGENTS: never toggle to "discover").

Config: data/bench/watch.json (gitignored; labgrid/watch.json.example is the
committed pattern). Run: nohup python3 scripts/bench_watch.py --config ... &
Stop: pkill -f bench_watch.py

Design notes: fieldlab.transport-shaped (Host.parse-style hosts) so a future
consolidation can swap the transport; two threads per device (stream + snap).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

TAIL_BYTES = 64 * 1024
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=15"]
BACKOFF_MIN_S = 5
BACKOFF_MAX_S = 60
SNAP_KINDS = ("none", "openwrt", "switch")

SNAP_CMDS = {
    # switch: poe daemon health (leak instrument) + port digest (record.sh shape)
    "switch": ("echo poe_pid=$(pidof realtek-poe) "
               "rss=$(grep VmRSS /proc/$(pidof realtek-poe)/status 2>/dev/null "
               "| awk '{print $2}')kB "
               "avail=$(awk '/MemAvailable/{print $2}' /proc/meminfo)kB "
               "ports=$(ubus call poe info 2>/dev/null | jsonfilter "
               "-e @.ports.lan2.status -e @.ports.lan4.status -e @.ports.lan6.status "
               "-e @.ports.lan7.status 2>/dev/null | tr '\\n' ',')"),
    # generic OpenWrt DUT: reboot oracle inputs + memory pressure
    "openwrt": ("echo boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) "
                "uptime=$(cut -d. -f1 /proc/uptime) "
                "avail=$(awk '/MemAvailable/{print $2}' /proc/meminfo)kB"),
}


class WatchError(Exception):
    """Config invalid or the watcher cannot run."""


# ------------------------------------------------------------------- config


@dataclass(frozen=True)
class DeviceConfig:
    name: str
    host: str
    user: str = "root"
    streams: tuple[str, ...] = ("logread -f", "dmesg -w")
    snap_kind: str = "openwrt"
    snap_interval_s: int = 60

    def ssh_target(self) -> str:
        return f"{self.user}@{self.host}"


@dataclass(frozen=True)
class WatchConfig:
    outputs_dir: Path
    max_dir_mb: int
    devices: tuple[DeviceConfig, ...] = field(default_factory=tuple)


def load_config(path: Path) -> WatchConfig:
    raw = json.loads(path.read_text())
    devices = []
    names: set[str] = set()
    for d in raw.get("devices", []):
        name, host = str(d.get("name", "")), str(d.get("host", ""))
        if not name or not host:
            raise WatchError(f"device entry needs name+host: {d!r}")
        if name in names:
            raise WatchError(f"duplicate device name {name!r}")
        names.add(name)
        streams = tuple(d.get("streams") or ("logread -f", "dmesg -w"))
        kind = str(d.get("snap", "openwrt"))
        if kind not in SNAP_KINDS:
            raise WatchError(f"device {name}: snap kind {kind!r} not in {SNAP_KINDS}")
        devices.append(DeviceConfig(name=name, host=host, user=str(d.get("user", "root")),
                                    streams=streams, snap_kind=kind,
                                    snap_interval_s=int(d.get("snap_interval_s", 60))))
    if not devices:
        raise WatchError("no devices configured")
    out = Path(raw.get("outputs_dir", "data/bench/watch"))
    return WatchConfig(outputs_dir=out, max_dir_mb=int(raw.get("max_dir_mb", 512)),
                       devices=tuple(devices))


# ------------------------------------------------------------------ parsing


@dataclass(frozen=True)
class SnapState:
    boot_id: str = ""
    uptime_s: int = 0
    rss_kb: int = 0
    mem_avail_kb: int = 0
    ports: str = ""


def parse_snap(kind: str, raw: str) -> SnapState:
    """Parse a SNAP command's echo output ('k=v k=v ...')."""
    fields: dict[str, str] = {}
    for token in raw.split():
        if "=" in token:
            k, v = token.split("=", 1)
            fields[k] = v
    def _int(key: str) -> int:
        v = fields.get(key, "0").rstrip("kB") or "0"
        return int(v) if v.isdigit() else 0
    if kind == "switch":
        return SnapState(rss_kb=_int("rss"), mem_avail_kb=_int("avail"),
                         ports=fields.get("ports", ""))
    return SnapState(boot_id=fields.get("boot_id", ""), uptime_s=_int("uptime"),
                     mem_avail_kb=_int("avail"))


def reboot_oracle(prev: SnapState | None, cur: SnapState) -> dict | None:
    """Reboot detection: boot_id change is CONFIRMED; uptime decrease is LIKELY.

    Log gaps are deliberately not evidence (UDP loss / stopped daemon).
    Returns an event payload dict, or None when no reboot is indicated.
    """
    if prev is None:
        return None
    if prev.boot_id and cur.boot_id and prev.boot_id != cur.boot_id:
        return {"event": "reboot", "confidence": "confirmed",
                "prev_boot_id": prev.boot_id, "boot_id": cur.boot_id}
    if prev.uptime_s and cur.uptime_s and cur.uptime_s < prev.uptime_s:
        return {"event": "reboot", "confidence": "likely",
                "prev_uptime_s": prev.uptime_s, "uptime_s": cur.uptime_s}
    return None


class RingBuffer:
    """Bounded byte tail (KernelCI dying-words pattern)."""

    def __init__(self, max_bytes: int = TAIL_BYTES) -> None:
        self._buf: deque[bytes] = deque()
        self._size = 0
        self._max = max_bytes

    def extend(self, chunk: bytes) -> None:
        self._buf.append(chunk)
        self._size += len(chunk)
        while len(self._buf) > 1 and self._size - len(self._buf[0]) >= self._max:
            self._size -= len(self._buf.popleft())
        if self._size > self._max and self._buf:
            excess = self._size - self._max
            self._buf[0] = self._buf[0][excess:]
            self._size -= excess

    def drain(self) -> bytes:
        return b"".join(self._buf)


# ------------------------------------------------------------------ events


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EventLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def emit(self, device: str, event: str, **fields: object) -> None:
        record = {"ts": utcnow(), "device": device, "event": event, **fields}
        line = json.dumps(record, sort_keys=True) + "\n"
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a") as f:
                f.write(line)


# ----------------------------------------------------------------- watcher


class DeviceWatcher(threading.Thread):
    """One stream thread + one snap thread per device.

    Spawn/run_call are injectable for hardware-free tests: production uses
    ssh; tests use local echo/sleep processes.
    """

    def __init__(self, cfg: DeviceConfig, out_dir: Path, events: EventLog,
                 max_dir_mb: int,
                 spawn=None,
                 run_call=None,
                 backoff_min_s: float = BACKOFF_MIN_S) -> None:
        super().__init__(daemon=True, name=f"watch-{cfg.name}")
        self.cfg = cfg
        self.out_dir = out_dir
        self.events = events
        self.max_dir_mb = max_dir_mb
        # NOT `self._stop`: that name clobbers threading.Thread's internal
        # _stop hook (join() after the thread exits raises TypeError).
        self._stop_evt = threading.Event()
        self._backoff = backoff_min_s
        self._spawn = spawn or self._ssh_spawn
        self._run_call = run_call or self._ssh_run
        self._last_snap: SnapState | None = None
        self._quota_warned_at = 0.0

    def _stream_shell(self) -> str:
        joined = "; ".join(self.cfg.streams)
        return f'echo "=== connected ==="; ({joined}) & wait'

    def _ssh_spawn(self, cmd: str) -> subprocess.Popen:
        return subprocess.Popen(["ssh", *SSH_OPTS, self.cfg.ssh_target(), cmd],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True)

    def _ssh_run(self, cmd: str) -> str:
        proc = subprocess.run(["ssh", *SSH_OPTS, self.cfg.ssh_target(), cmd],
                              capture_output=True, text=True, timeout=30)
        return proc.stdout + proc.stderr

    # -- stream lifecycle -------------------------------------------------

    def run(self) -> None:  # thread: raw stream
        dev_dir = self.out_dir / self.cfg.name
        dev_dir.mkdir(parents=True, exist_ok=True)
        while not self._stop_evt.is_set():
            raw_path = dev_dir / f"{time.strftime('%Y%m%d')}.log"
            ring = RingBuffer()
            try:
                proc = self._spawn(self._stream_shell())
            except OSError as e:
                self.events.emit(self.cfg.name, "spawn_error", error=str(e)[:200])
                self._sleep_backoff()
                continue
            self.events.emit(self.cfg.name, "connected")
            assert proc.stdout is not None
            # Recompute periodically, not once: a stream that connects below
            # the quota and then runs for days must still hit the guard —
            # a once-per-connection check never fires on long-lived streams.
            quota = self._quota_exceeded()
            quota_checked_at = time.monotonic()
            with raw_path.open("a") as raw:
                raw.write(f"=== connected {utcnow()} ===\n")
                for line in proc.stdout:
                    if self._stop_evt.is_set():
                        proc.kill()
                        break
                    if time.monotonic() - quota_checked_at > 60:
                        quota = self._quota_exceeded()
                        quota_checked_at = time.monotonic()
                    ring.extend(line.encode())
                    if quota:
                        if time.monotonic() - self._quota_warned_at > 3600:
                            self.events.emit(self.cfg.name, "quota_warning",
                                             dir_mb=self.max_dir_mb)
                            self._quota_warned_at = time.monotonic()
                        continue
                    raw.write(line)
                    raw.flush()
            rc = proc.wait()
            tail = ring.drain()
            if tail:
                # never clobber a good tail with an empty instant-EOF reconnect
                (dev_dir / "tail-64k.txt").write_bytes(tail)
            self.events.emit(self.cfg.name, "disconnected", rc=rc,
                             tail_bytes=len(tail))
            self._sleep_backoff()

    def _sleep_backoff(self) -> None:
        self._stop_evt.wait(self._backoff)
        self._backoff = min(self._backoff * 2, BACKOFF_MAX_S)

    # -- snapshot loop ----------------------------------------------------

    def snap_forever(self) -> None:  # thread: SNAP polling + reboot oracle
        if self.cfg.snap_kind == "none":
            return
        while not self._stop_evt.wait(self.cfg.snap_interval_s):
            self.snap_once()

    def snap_once(self) -> SnapState | None:
        raw = self._run_call(SNAP_CMDS[self.cfg.snap_kind])
        state = parse_snap(self.cfg.snap_kind, raw)
        if not any((state.boot_id, state.uptime_s, state.rss_kb, state.mem_avail_kb)):
            self.events.emit(self.cfg.name, "snap_unparsable", raw=raw.strip()[:120])
            return None
        reboot = reboot_oracle(self._last_snap, state)
        if reboot:
            self.events.emit(self.cfg.name, **reboot)
        self.events.emit(self.cfg.name, "snap", **{
            "boot_id": state.boot_id, "uptime_s": state.uptime_s,
            "rss_kb": state.rss_kb, "mem_avail_kb": state.mem_avail_kb,
            "ports": state.ports})
        self._last_snap = state
        return state

    def _quota_exceeded(self) -> bool:
        try:
            used = sum(f.stat().st_size for f in self.out_dir.rglob("*.log"))
        except OSError:
            return False
        return used > self.max_dir_mb * 1024 * 1024

    def stop(self) -> None:
        self._stop_evt.set()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", required=True, help="watch config JSON")
    ap.add_argument("--validate-config", action="store_true")
    ap.add_argument("--once", action="store_true",
                    help="one snap round for every device, then exit (probe mode)")
    ap.add_argument("--duration", type=int, default=0,
                    help="stop after N seconds (0 = forever)")
    args = ap.parse_args(argv)

    try:
        cfg = load_config(Path(args.config))
    except (OSError, json.JSONDecodeError, WatchError) as e:
        print(f"FAIL: config: {e}")
        return 2
    if args.validate_config:
        print(f"OK: {len(cfg.devices)} devices -> {cfg.outputs_dir}")
        return 0

    cfg.outputs_dir.mkdir(parents=True, exist_ok=True)
    events = EventLog(cfg.outputs_dir / "events.jsonl")
    events.emit("watch", "starting", devices=[d.name for d in cfg.devices],
                pid=str(__import__("os").getpid()))

    watchers = [DeviceWatcher(d, cfg.outputs_dir, events, cfg.max_dir_mb)
                for d in cfg.devices]
    if args.once:
        for w in watchers:
            w.snap_once()
        return 0
    snaps: list[threading.Thread] = []
    for w in watchers:
        w.start()
        t = threading.Thread(target=w.snap_forever, daemon=True,
                             name=f"snap-{w.cfg.name}")
        t.start()
        snaps.append(t)
    try:
        stop_at = time.monotonic() + args.duration if args.duration else None
        while True:
            if stop_at and time.monotonic() > stop_at:
                break
            if not any(w.is_alive() for w in watchers):
                print("FAIL: all stream threads died", file=sys.stderr)
                return 1
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        for w in watchers:
            w.stop()
        events.emit("watch", "stopping")
    return 0


if __name__ == "__main__":
    sys.exit(main())
