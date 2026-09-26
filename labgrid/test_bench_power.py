"""Bench power smoke test via labgrid — the tollgate rig seed.

Opt-in hardware test (power-cycles a real PoE port). Run explicitly:

    BENCH_POWER_TEST=1 LG_COORDINATOR=<host:port> BENCH_SWITCH_HOST=<ip> \
        BENCH_PLACE=ap-lan4 pytest labgrid/test_bench_power.py

Real coordinator/switch coordinates live in local bench records only
(data/sessions/) — they are never committed as defaults here.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

COORDINATOR = os.environ.get("LG_COORDINATOR", "")
PLACE = os.environ.get("BENCH_PLACE", "ap-lan4")
PORT = PLACE.removeprefix("ap-")
SWITCH = os.environ.get("BENCH_SWITCH_HOST", "")
REPO_ROOT = Path(__file__).resolve().parent.parent
PLACES_JSON = REPO_ROOT / "data" / "bench" / "places.json"

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("BENCH_POWER_TEST") != "1",
        reason="hardware test — opt in with BENCH_POWER_TEST=1 (needs a DUT on the port)",
    ),
    pytest.mark.skipif(
        not COORDINATOR or not SWITCH,
        reason="hardware test — set LG_COORDINATOR and BENCH_SWITCH_HOST "
               "(real coords live in local bench records, not in git)",
    ),
]


def _place_gate(place: str, places_path: Path) -> bool:
    """Power-cycling is gated on the registry, exactly like the serial smoke
    test (labgrid/test_bench_serial.py): the place must be recorded with
    reset_allowed=true AND power_export not disabled — a protected or
    one-way-trip DUT must never be power-cycled because an exporter stanza
    happened to exist."""
    if not places_path.exists():
        return False
    registry = json.loads(places_path.read_text(encoding="utf-8"))
    entry = next((e for e in registry.get("places", [])
                  if e.get("name") == place), None)
    return bool(entry
                and entry.get("reset_allowed") is True
                and entry.get("power_export", True) is True)


def _client(*args: str) -> str:
    out = subprocess.run(
        ["labgrid-client", "-x", COORDINATOR, "-p", PLACE, *args],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout


def _port_state() -> str:
    out = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", f"root@{SWITCH}",
         f"ubus call poe info | jsonfilter -e '@.ports.{PORT}.status'"],
        capture_output=True, text=True, timeout=30,
    )
    return out.stdout.strip()


def test_power_cycle_changes_port_state() -> None:
    if not _place_gate(PLACE, PLACES_JSON):
        pytest.skip(
            f"{PLACE} is not reset_allowed=true + power_export=true in "
            f"{PLACES_JSON} — refusing to power-cycle (registry gate)")
    _client("power", "off")
    assert "Delivering" not in _port_state()
    _client("power", "on")
    deadline = time.monotonic() + 90
    while "Delivering" not in _port_state() and time.monotonic() < deadline:
        time.sleep(5)
    assert "Delivering" in _port_state(), "port re-enabled but DUT did not resume draw"
