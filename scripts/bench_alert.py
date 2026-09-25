#!/usr/bin/env python3
"""bench_alert — fan out bench_watch events to notification channels.

Consumes events.jsonl (bench_watch.py output) and routes matching events:

  * file audit sink (always): alerts.jsonl — the durable record
  * ntfy (if configured): HTTP POST, topic per severity, phone push
  * macOS (if enabled): osascript notification + `say` for critical

Built-in rules (event -> severity), with a per-device+event cool-down so a
flapping stream does not spam the phone:

  reboot (confirmed/likely)          critical
  disconnected                       warning   (only when repeated >= 3 in 10 min)
  spawn_error                        warning
  snap_unparsable                    info
  quota_warning                      warning
  poe_rss_growth                     warning   (switch: rss_kb growth > 8 kB/h)

The poe_rss_growth rule is synthesized here from consecutive switch snap
events — the leak instrument for the realtek-poe mcu_no_response() bug.

Usage:
  python3 scripts/bench_alert.py --events data/bench/watch/events.jsonl --once
  python3 scripts/bench_alert.py ... --watch        # follow mode
  python3 scripts/bench_alert.py ... --test         # synthetic alert through sinks

Config: data/bench/alert.json (gitignored; labgrid/alert.json.example pattern):
  {"ntfy_url": "https://ntfy.example.net", "topics": {"critical": "bench-critical",
   "warning": "bench-warnings", "info": "bench-info"}, "mac_notify": true,
   "cooldown_s": 300}
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

SEVERITY_RULES: dict[str, tuple[str, int, int]] = {
    # event -> (severity, flap_threshold_count, window_s) — count/window only
    # for flap-class rules; others fire on first sight after cooldown.
    "reboot": ("critical", 1, 0),
    "spawn_error": ("warning", 1, 0),
    "snap_unparsable": ("info", 1, 0),
    "quota_warning": ("warning", 1, 0),
    "disconnected": ("warning", 3, 600),
}

RSS_GROWTH_KB_PER_HOUR = 8.0


class AlertError(Exception):
    pass


def load_config(path: Path) -> dict:
    cfg = json.loads(path.read_text()) if path.exists() else {}
    for key in ("ntfy_url",):
        if key in cfg and not str(cfg[key]).startswith(("http://", "https://")):
            raise AlertError(f"config {key!r} must be an http(s) URL")
    return cfg


def rule_for(event: dict) -> tuple[str, str] | None:
    """event -> (rule_name, severity) or None when not alertable."""
    name = str(event.get("event", ""))
    if name in SEVERITY_RULES:
        sev = SEVERITY_RULES[name][0]
        return name, sev
    return None


def should_fire(rule: str, severity: str, event: dict,
                history: list[dict], cooldown_until: dict[tuple[str, str], float],
                now: float) -> bool:
    key = (str(event.get("device", "")), rule)
    if now < cooldown_until.get(key, 0.0):
        return False
    count, window = SEVERITY_RULES[rule][1], SEVERITY_RULES[rule][2]
    if window:
        recent = [e for e in history
                  if e.get("device") == event.get("device")
                  and e.get("event") == rule
                  and float(e.get("ts_epoch", now)) > now - window]
        if len(recent) + 1 < count:  # +1: the event being judged is not in history yet
            return False
    cooldown_until[key] = now + 300
    return True


def poe_rss_growth(prev: dict | None, cur: dict) -> dict | None:
    """Synthesize a leak-slope alert from consecutive switch snaps."""
    if not prev or prev.get("device") != cur.get("device"):
        return None
    try:
        dt = float(cur["ts_epoch"]) - float(prev["ts_epoch"])
        drss = float(cur.get("rss_kb", 0)) - float(prev.get("rss_kb", 0))
    except (KeyError, ValueError, TypeError):
        return None
    if dt <= 0:
        return None
    rate = drss * 3600.0 / dt
    if rate > RSS_GROWTH_KB_PER_HOUR:
        return {"device": cur.get("device", ""), "event": "poe_rss_growth",
                "rss_kb": cur.get("rss_kb"), "rate_kb_per_h": round(rate, 1)}
    return None


# ------------------------------------------------------------------- sinks


def sink_file(alerts_path: Path, payload: dict) -> bool:
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    with alerts_path.open("a") as f:
        f.write(json.dumps(payload, sort_keys=True) + "\n")
    return True


def sink_ntfy(cfg: dict, payload: dict) -> bool:
    url = str(cfg.get("ntfy_url", "")).rstrip("/")
    topics = cfg.get("topics", {})
    topic = topics.get(payload["severity"], "bench-warnings")
    if not url:
        return False
    title = f"[{payload['severity']}] {payload['device']}: {payload['rule']}"
    body = json.dumps(payload.get("fields", {}), sort_keys=True)[:400]
    try:
        proc = subprocess.run(
            ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
             "-H", f"Title: {title}", "-H", f"Priority: {payload['severity']}",
             "-H", "Tags: warning", "-d", body, f"{url}/{topic}"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.stdout.strip() == "200"


def sink_mac(cfg: dict, payload: dict) -> bool:
    if not cfg.get("mac_notify"):
        return False
    text = f"{payload['device']}: {payload['rule']} ({payload['severity']})"
    try:
        subprocess.run(["osascript", "-e",
                        f'display notification "{text}" with title "Bench alert"'],
                       capture_output=True, timeout=10)
        if payload["severity"] == "critical":
            subprocess.run(["say", f"Bench alert. {text}."],
                           capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return True


def fire_sinks(alerts_path: Path, cfg: dict, payload: dict) -> dict[str, bool]:
    return {"file": sink_file(alerts_path, payload),
            "ntfy": sink_ntfy(cfg, payload),
            "mac": sink_mac(cfg, payload)}


# --------------------------------------------------------------------- cli


def process_event(event: dict, history: list[dict],
                  cooldown_until: dict[tuple[str, str], float],
                  alerts_path: Path, cfg: dict) -> dict | None:
    matched = rule_for(event)
    now = float(event.get("ts_epoch", time.time()))
    if matched:
        rule, severity = matched
        if should_fire(rule, severity, event, history, cooldown_until, now):
            payload = {"ts": event.get("ts", ""), "device": event.get("device", ""),
                       "rule": rule, "severity": severity,
                       "fields": {k: v for k, v in event.items()
                                  if k not in ("ts", "device", "event", "ts_epoch")}}
            fire_sinks(alerts_path, cfg, payload)
            return payload
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--events", required=True, help="events.jsonl to consume")
    ap.add_argument("--config", default="data/bench/alert.json")
    ap.add_argument("--watch", action="store_true", help="follow the file")
    ap.add_argument("--test", action="store_true",
                    help="fire one synthetic alert through all sinks and exit")
    args = ap.parse_args(argv)

    try:
        cfg = load_config(Path(args.config))
    except (OSError, json.JSONDecodeError, AlertError) as e:
        print(f"FAIL: config: {e}")
        return 2

    events_path = Path(args.events)
    alerts_path = events_path.parent / "alerts.jsonl"
    cooldowns: dict[tuple[str, str], float] = {}
    history: list[dict] = []
    last_switch_snap: dict | None = None

    if args.test:
        payload = {"ts": "test", "device": "bench-alert", "rule": "synthetic",
                   "severity": "critical", "fields": {"kind": "sink test"}}
        results = fire_sinks(alerts_path, cfg, payload)
        print(json.dumps(results))
        return 0 if results["file"] else 1

    def _handle(event: dict) -> None:
        nonlocal last_switch_snap
        event.setdefault("ts_epoch", time.time())
        history.append(event)
        growth = poe_rss_growth(last_switch_snap if last_switch_snap and
                                str(last_switch_snap.get("event")) == "snap" else None,
                                event) if str(event.get("event")) == "snap" else None
        last_switch_snap = event if str(event.get("event")) == "snap" else last_switch_snap
        fired = process_event(event, history, cooldowns, alerts_path, cfg)
        if growth:
            growth["ts"] = event.get("ts", "")
            growth["ts_epoch"] = event.get("ts_epoch")
            payload = {"ts": growth["ts"], "device": growth["device"],
                       "rule": growth.pop("event"), "severity": "warning",
                       "fields": growth}
            key = (payload["device"], payload["rule"])
            if time.time() >= cooldowns.get(key, 0.0):
                cooldowns[key] = time.time() + 3600
                fire_sinks(alerts_path, cfg, payload)
        if fired:
            print(json.dumps(fired, sort_keys=True))

    if not events_path.exists():
        print(f"FAIL: {events_path} does not exist yet (start bench_watch first)")
        return 1
    with events_path.open() as f:
        for line in f:
            if line.strip():
                try:
                    _handle(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if not args.watch:
        return 0
    f = events_path.open()
    f.seek(0, 2)
    try:
        while True:
            line = f.readline()
            if line.strip():
                try:
                    _handle(json.loads(line))
                except json.JSONDecodeError:
                    continue
            else:
                time.sleep(2)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
