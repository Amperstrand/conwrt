"""Hardware-free checks for bench_watch — config, parsers, oracle, ring
buffer, event log, and the watcher reconnect lifecycle against local fake
streams. No SSH, no network (spawn/run_call are injected)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

import bench_watch as bw


# ----------------------------------------------------------------- config


def test_load_config_rejects_duplicates_and_bad_snap(tmp_path: Path) -> None:
    cfg = tmp_path / "w.json"
    cfg.write_text(json.dumps({"devices": [
        {"name": "a", "host": "10.0.0.1"}, {"name": "a", "host": "10.0.0.2"}]}))
    with pytest.raises(bw.WatchError):
        bw.load_config(cfg)
    cfg.write_text(json.dumps({"devices": [{"name": "a", "host": "h", "snap": "bogus"}]}))
    with pytest.raises(bw.WatchError):
        bw.load_config(cfg)
    cfg.write_text(json.dumps({"devices": []}))
    with pytest.raises(bw.WatchError):
        bw.load_config(cfg)


def test_load_config_defaults(tmp_path: Path) -> None:
    cfg = tmp_path / "w.json"
    cfg.write_text(json.dumps({"devices": [{"name": "sw", "host": "h", "snap": "switch"}]}))
    loaded = bw.load_config(cfg)
    dev = loaded.devices[0]
    assert dev.user == "root" and dev.ssh_target() == "root@h"
    assert dev.streams == ("logread -f", "dmesg -w")
    assert dev.snap_interval_s == 60 and dev.snap_kind == "switch"


# ---------------------------------------------------------------- parsing


def test_parse_snap_switch_shape() -> None:
    raw = ("poe_pid=5261 rss=1080kB avail=57688kB "
           "ports=Delivering power,Delivering power,Other fault,")
    st = bw.parse_snap("switch", raw)
    assert st.rss_kb == 1080 and st.mem_avail_kb == 57688
    assert st.ports.startswith("Delivering") and st.uptime_s == 0


def test_parse_snap_openwrt_shape() -> None:
    raw = "boot_id=1a2b3c uptime=12345 avail=98000kB"
    st = bw.parse_snap("openwrt", raw)
    assert st.boot_id == "1a2b3c" and st.uptime_s == 12345
    assert st.mem_avail_kb == 98000


def test_reboot_oracle_boot_id_beats_all() -> None:
    prev = bw.SnapState(boot_id="aaa", uptime_s=99999)
    cur = bw.SnapState(boot_id="bbb", uptime_s=5)
    ev = bw.reboot_oracle(prev, cur)
    assert ev and ev["event"] == "reboot" and ev["confidence"] == "confirmed"


def test_reboot_oracle_uptime_decrease_is_likely() -> None:
    prev = bw.SnapState(boot_id="", uptime_s=5000)
    ev = bw.reboot_oracle(prev, bw.SnapState(boot_id="", uptime_s=10))
    assert ev and ev["confidence"] == "likely"


def test_reboot_oracle_silent_on_normal() -> None:
    assert bw.reboot_oracle(None, bw.SnapState(uptime_s=5)) is None
    prev = bw.SnapState(boot_id="x", uptime_s=10)
    assert bw.reboot_oracle(prev, bw.SnapState(boot_id="x", uptime_s=20)) is None


# ------------------------------------------------------------- ringbuffer


def test_ring_buffer_keeps_tail_only() -> None:
    rb = bw.RingBuffer(max_bytes=100)
    rb.extend(b"a" * 60)
    rb.extend(b"b" * 60)
    rb.extend(b"c" * 60)
    tail = rb.drain()
    assert len(tail) == 100 and tail.startswith(b"b") and tail.endswith(b"c")


def test_ring_buffer_drain_does_not_clear() -> None:
    rb = bw.RingBuffer(10)
    rb.extend(b"0123456789")
    assert rb.drain() == rb.drain()


# ------------------------------------------------------------------ events


def test_eventlog_writes_sorted_jsonl(tmp_path: Path) -> None:
    log = bw.EventLog(tmp_path / "ev" / "events.jsonl")
    log.emit("dev", "connected", rc=0)
    log.emit("dev", "snap", rss_kb=10)
    lines = (tmp_path / "ev" / "events.jsonl").read_text().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["device"] == "dev" and first["event"] == "connected"
    assert "ts" in first and first["rc"] == 0


# -------------------------------------------------------------- lifecycle


class _FakeProc:
    """Minimal Popen stand-in: emits lines once, then EOF."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self.stdout = iter(lines)

    def wait(self) -> int:
        return 0

    def kill(self) -> None:
        return None


def test_watcher_reconnect_writes_tail_and_events(tmp_path: Path) -> None:
    cfg = bw.DeviceConfig(name="fake", host="unused", snap_kind="none",
                          snap_interval_s=9999)
    events = bw.EventLog(tmp_path / "events.jsonl")
    spawns: list = [lambda cmd: _FakeProc(["line-one\n", "line-two\n"]),
                    lambda cmd: _FakeProc(["line-three\n"]),
                    lambda cmd: _FakeProc([])]

    def fake_spawn(cmd: str) -> _FakeProc:
        return spawns.pop(0)(cmd)

    w = bw.DeviceWatcher(cfg, tmp_path, events, max_dir_mb=10,
                         spawn=fake_spawn,
                         run_call=lambda cmd: "", backoff_min_s=0.05)
    w.start()
    deadline = time.monotonic() + 5
    while len(spawns) > 0 and time.monotonic() < deadline:
        time.sleep(0.02)
    w.stop()
    w.join(timeout=5)
    ev = [json.loads(line) for line in
          (tmp_path / "events.jsonl").read_text().splitlines()]
    kinds = [e["event"] for e in ev]
    # two connects, two disconnects, tail persisted with the last lines
    assert kinds.count("connected") >= 2 and kinds.count("disconnected") >= 2
    tail = (tmp_path / "fake" / "tail-64k.txt").read_bytes()
    assert b"line-three" in tail or b"line-two" in tail
    raws = list((tmp_path / "fake").glob("*.log"))
    assert raws and "=== connected" in raws[0].read_text()


def test_snap_once_emits_snap_and_reboot(tmp_path: Path) -> None:
    cfg = bw.DeviceConfig(name="fake", host="unused", snap_kind="openwrt",
                          snap_interval_s=9999)
    events = bw.EventLog(tmp_path / "events.jsonl")
    outputs = iter([
        "boot_id=aaa uptime=100 avail=1kB",
        "boot_id=bbb uptime=3 avail=1kB",
    ])
    w = bw.DeviceWatcher(cfg, tmp_path, events, max_dir_mb=10,
                         spawn=lambda cmd: _FakeProc([]),
                         run_call=lambda cmd: next(outputs))
    assert w.snap_once() is not None
    assert w.snap_once() is not None
    ev = [json.loads(line) for line in
          (tmp_path / "events.jsonl").read_text().splitlines()]
    by_kind = {e["event"]: e for e in ev}
    assert by_kind["reboot"]["confidence"] == "confirmed"
    assert by_kind["snap"]["uptime_s"] == 3


def test_snap_unparsable_emits_event(tmp_path: Path) -> None:
    cfg = bw.DeviceConfig(name="fake", host="unused", snap_kind="openwrt")
    events = bw.EventLog(tmp_path / "events.jsonl")
    w = bw.DeviceWatcher(cfg, tmp_path, events, max_dir_mb=10,
                         spawn=lambda cmd: _FakeProc([]),
                         run_call=lambda cmd: "total garbage no equals")
    assert w.snap_once() is None
    ev = [json.loads(line) for line in
          (tmp_path / "events.jsonl").read_text().splitlines()]
    assert ev and ev[-1]["event"] == "snap_unparsable"


def test_validate_config_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = tmp_path / "w.json"
    cfg.write_text(json.dumps({"devices": [{"name": "x", "host": "y"}]}))
    assert bw.main(["--config", str(cfg), "--validate-config"]) == 0
    assert "1 devices" in capsys.readouterr().out
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert bw.main(["--config", str(bad), "--validate-config"]) == 2


def test_no_committed_coordinates() -> None:
    source = Path(bw.__file__).read_text()
    assert "192.168.13." not in source and ":20408" not in source
