"""Bench serial boot smoke test via labgrid — power-cycle + console capture.

Opt-in hardware test (power-cycles a real PoE port and reads the DUT serial
console through the labgrid serial bridge). Run explicitly:

    BENCH_SERIAL_TEST=1 LG_COORDINATOR=<host:port> \
        BENCH_PLACE=ap-lan2 pytest labgrid/test_bench_serial.py

Asserts three boot markers that appear in every AP3915i boot (reference
capture: data/bench/ap-lan2/20260923-serial-via-lan4/lan2-boot.log):
`U-Boot 2012`, `Starting kernel`, `jffs2_build_xattr_subsystem`.
The full boot stream is archived to data/bench/<place>/<UTC-ts>/
labgrid-serial-boot.log — all paths are REPO_ROOT-relative, resolved from
this file's location (never CWD). The test must run from a checkout that
contains data/bench/places.json: the power-cycle gate reads it, so a bare
copy of this file in /tmp skips by design.

Safety: the place is power-cycled ONLY if data/bench/places.json records it
with reset_allowed=true; protected and unregistered places skip before any
hardware call (the ap-lan5 one-way-trip rule, machine-enforced).

Drives the bench exactly like test_bench_power.py — subprocess labgrid-client
(acquire / power / console / release). No labgrid imports: the module loads
on machines without labgrid installed, and `make ci` never collects it.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

COORDINATOR = os.environ.get("LG_COORDINATOR", "")
PLACE = os.environ.get("BENCH_PLACE", "ap-lan2")
REPO_ROOT = Path(__file__).resolve().parent.parent
PLACES_JSON = REPO_ROOT / "data" / "bench" / "places.json"

BOOT_MARKERS = ("U-Boot 2012", "Starting kernel", "jffs2_build_xattr_subsystem")
POWER_OFF_SETTLE = 10  # seconds PoE-off until the DUT is fully halted
CONSOLE_ATTACH = 5  # seconds for `labgrid-client console` to connect
BOOT_TIMEOUT = 180  # seconds power-on -> last marker (jffs2 xattr line)

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("BENCH_SERIAL_TEST") != "1",
        reason="hardware test — opt in with BENCH_SERIAL_TEST=1 (power-cycles the DUT)",
    ),
    pytest.mark.skipif(
        not COORDINATOR,
        reason="hardware test — set LG_COORDINATOR (real coords live in local bench records, not in git)",
    ),
]


def _client(*args: str) -> str:
    out = subprocess.run(
        ["labgrid-client", "-x", COORDINATOR, "-p", PLACE, *args],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout


def _reset_allowed(place: str, places_path: Path) -> bool:
    """True only for places recorded with reset_allowed=true in places.json.

    Unregistered places return False (no safety record -> no power-cycle).
    """
    registry = json.loads(places_path.read_text(encoding="utf-8"))
    return any(
        entry.get("name") == place and entry.get("reset_allowed") is True
        for entry in registry.get("places", [])
    )


def _read_until_markers(console: subprocess.Popen[bytes], capture_path: Path) -> bytes:
    """Stream the console to capture_path until all markers appear or timeout."""
    stream = bytearray()
    deadline = time.monotonic() + BOOT_TIMEOUT
    with capture_path.open("wb") as capture:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([console.stdout], [], [], 1.0)
            if not ready:
                continue
            chunk = os.read(console.stdout.fileno(), 4096)
            if not chunk:  # console process exited (EOF)
                break
            stream.extend(chunk)
            capture.write(chunk)
            capture.flush()
            if all(m in stream.decode("utf-8", errors="replace") for m in BOOT_MARKERS):
                break
    return bytes(stream)


def _terminate(console: subprocess.Popen[bytes]) -> None:
    console.terminate()
    try:
        console.wait(timeout=10)
    except subprocess.TimeoutExpired:
        console.kill()
        console.wait(timeout=10)


def test_power_cycle_boot_markers_on_serial_console() -> None:
    if not _reset_allowed(PLACE, PLACES_JSON):
        pytest.skip(f"{PLACE} is not reset_allowed=true in {PLACES_JSON} — refusing to power-cycle")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    capture_path = REPO_ROOT / "data" / "bench" / PLACE / stamp / "labgrid-serial-boot.log"
    capture_path.parent.mkdir(parents=True, exist_ok=True)

    _client("acquire")
    try:
        _client("power", "off")
        time.sleep(POWER_OFF_SETTLE)

        # labgrid-client console (rfc2217) execs `telnet`, which EXITS on stdin
        # EOF — stdin must be a PIPE with no writer closing it (DEVNULL gives
        # instant EOF and kills the console before power-on). Held open until
        # teardown closes it after _terminate.
        console = subprocess.Popen(
            ["labgrid-client", "-x", COORDINATOR, "-p", PLACE, "console"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            time.sleep(CONSOLE_ATTACH)
            _client("power", "on")
            stream = _read_until_markers(console, capture_path)
        finally:
            _terminate(console)
            if console.stdin:
                console.stdin.close()
            console_stderr = console.stderr.read().decode("utf-8", errors="replace").strip()

        text = stream.decode("utf-8", errors="replace")
        missing = [m for m in BOOT_MARKERS if m not in text]
        detail = f"; console stderr: {console_stderr}" if console_stderr else ""
        assert not missing, f"boot markers {missing} absent — capture: {capture_path}{detail}"
    finally:
        try:
            _client("power", "on")  # never leave the DUT dark on a failure path
        except AssertionError as exc:
            print(f"warning: best-effort power-on failed (DUT may be dark): {exc}")
        _client("release")
