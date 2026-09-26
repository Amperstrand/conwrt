"""Hardware-free checks for bench_alert — rules, flap guard, leak-slope
synthesis, and sinks (file + fake HTTP/mac). No network."""

from __future__ import annotations

import json
from pathlib import Path

import bench_alert as ba


def ev(event: str, device: str = "sw", **fields: object) -> dict:
    return {"ts": "t", "ts_epoch": 1000.0, "device": device, "event": event,
            **fields}


def test_rule_for_maps_severities() -> None:
    assert ba.rule_for(ev("reboot")) == ("reboot", "critical")
    assert ba.rule_for(ev("spawn_error")) == ("spawn_error", "warning")
    assert ba.rule_for(ev("snap_unparsable")) == ("snap_unparsable", "info")
    assert ba.rule_for(ev("snap")) is None
    assert ba.rule_for(ev("connected")) is None


def test_disconnected_requires_three_in_window() -> None:
    cooldowns: dict[tuple[str, str], float] = {}
    history: list[dict] = []
    e1 = ev("disconnected", ts_epoch=1000.0)
    assert not ba.should_fire("disconnected", "warning", e1, history, cooldowns, 1000.0)
    history.append(e1)
    history.append(ev("disconnected", ts_epoch=1100.0))
    third = ev("disconnected", ts_epoch=1200.0)
    assert ba.should_fire("disconnected", "warning", third, history, cooldowns, 1200.0)


def test_cooldown_blocks_refire() -> None:
    cooldowns: dict[tuple[str, str], float] = {}
    first = ev("reboot", ts_epoch=1000.0)
    assert ba.should_fire("reboot", "critical", first, [], cooldowns, 1000.0)
    again = ev("reboot", ts_epoch=1100.0)
    assert not ba.should_fire("reboot", "critical", again, [], cooldowns, 1100.0)
    later = ev("reboot", ts_epoch=1400.0)
    assert ba.should_fire("reboot", "critical", later, [], cooldowns, 1400.0)


def test_poe_rss_growth_synthesis() -> None:
    prev = ev("snap", device="switch", ts_epoch=1000.0, rss_kb=1000)
    cur = ev("snap", device="switch", ts_epoch=4600.0, rss_kb=1010)  # +10kB/h
    out = ba.poe_rss_growth(prev, cur)
    assert out and out["event"] == "poe_rss_growth"
    assert out["rate_kb_per_h"] == 10.0
    # below floor or tiny absolute rss -> silent
    small = ba.poe_rss_growth(prev, ev("snap", device="switch", ts_epoch=4600.0,
                                       rss_kb=1001))
    assert small is None
    other = ba.poe_rss_growth(prev, ev("snap", device="ap-lan4", ts_epoch=4600.0,
                                       rss_kb=5000))
    assert other is None


def test_sink_file_appends(tmp_path: Path) -> None:
    p = tmp_path / "sub" / "alerts.jsonl"
    assert ba.sink_file(p, {"severity": "critical", "x": 1})
    assert ba.sink_file(p, {"severity": "warning"})
    lines = p.read_text().splitlines()
    assert len(lines) == 2 and json.loads(lines[0])["x"] == 1


def test_sink_ntfy_requires_configured_url() -> None:
    assert ba.sink_ntfy({}, {"severity": "critical", "device": "d", "rule": "r",
                             "fields": {}}) is False
    assert ba.sink_ntfy({"ntfy_url": "not-a-url", "topics": {}},
                        {"severity": "x", "device": "d", "rule": "r",
                         "fields": {}}) is False


def test_sink_mac_disabled_by_default(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(ba.subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd))
    assert ba.sink_mac({}, {"severity": "critical", "device": "d",
                            "rule": "r"}) is False
    assert calls == []
    assert ba.sink_mac({"mac_notify": True},
                       {"severity": "critical", "device": "d", "rule": "r"})
    assert any("osascript" in c[0] for c in calls)
    assert any(c[0] == "say" for c in calls)


def test_process_event_fires_file_sink(tmp_path: Path) -> None:
    alerts = tmp_path / "alerts.jsonl"
    out = ba.process_event(ev("reboot", device="switch", confidence="confirmed"),
                           [], {}, alerts, {})
    assert out and out["severity"] == "critical"
    assert "confidence" in out["fields"]
    written = json.loads(alerts.read_text().splitlines()[0])
    assert written["rule"] == "reboot"


def test_load_config_validates_url(tmp_path: Path) -> None:
    bad = tmp_path / "a.json"
    bad.write_text(json.dumps({"ntfy_url": "ftp://x"}))
    import pytest
    with pytest.raises(ba.AlertError):
        ba.load_config(bad)
    empty = tmp_path / "b.json"
    empty.write_text("{}")
    assert ba.load_config(empty) == {}


def test_test_mode_writes_alert(tmp_path: Path, capsys) -> None:
    events = tmp_path / "events.jsonl"
    events.write_text("")
    rc = ba.main(["--events", str(events), "--config", str(tmp_path / "none.json"),
                  "--test"])
    assert rc == 0
    assert '"file": true' in capsys.readouterr().out


def test_poe_rss_growth_baselines_are_per_device(tmp_path: Path, monkeypatch) -> None:
    """An AP snapshot between two switch snaps must not suppress the leak
    alert — baselines are keyed per device, not a single shared slot."""
    fired: list = []

    def fake_fire(alerts_path, cfg, payload):
        fired.append(payload)
        return {"file": True, "ntfy": False, "mac": False}

    monkeypatch.setattr(ba, "fire_sinks", fake_fire)
    monkeypatch.setattr(ba.time, "sleep", lambda s: None)
    events = tmp_path / "events.jsonl"
    rows = [
        {"ts": "t0", "device": "bench-switch", "event": "snap", "ts_epoch": 1000.0,
         "rss_kb": 1000, "boot_id": "a", "uptime_s": 10, "mem_avail_kb": 1, "ports": ""},
        # generic OpenWrt DUT snap lands between the switch snaps
        {"ts": "t1", "device": "ap-lan4", "event": "snap", "ts_epoch": 2000.0,
         "rss_kb": 0, "boot_id": "b", "uptime_s": 10, "mem_avail_kb": 1, "ports": ""},
        # switch grew 200 kB in 1 h — far past the 8 kB/h leak threshold
        {"ts": "t2", "device": "bench-switch", "event": "snap", "ts_epoch": 4600.0,
         "rss_kb": 1200, "boot_id": "a", "uptime_s": 3610, "mem_avail_kb": 1, "ports": ""},
    ]
    events.write_text("".join(json.dumps(r) + "\n" for r in rows))
    rc = ba.main(["--events", str(events), "--config", str(tmp_path / "none.json")])
    assert rc == 0
    leaks = [p for p in fired if p.get("rule") == "poe_rss_growth"]
    assert leaks, "switch leak alert must fire despite an interleaved AP snapshot"
    assert leaks[0]["device"] == "bench-switch"
    assert leaks[0]["fields"]["rate_kb_per_h"] > 8
