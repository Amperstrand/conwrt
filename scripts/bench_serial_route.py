#!/usr/bin/env python3
"""bench_serial_route — point the ap-lan2 serial tunnel at a bench place.

The bench has ONE itinerant serial splice: the ap-lan2 listener unit's RJ45
null-modem, plugged into one DUT at a time by hand (see the "SERIAL ROUTING
MODEL" header of labgrid/exporter.yaml). Exactly one NetworkSerialPort
stanza is active there at any time, and exactly one
conwrt-serial-bridge@<place> systemd user instance runs on the exporter
host. Run this ON THE EXPORTER HOST (ai-legion) after moving the cable:

  1. stop + disable every conwrt-serial-bridge@ap-lan* instance except the
     target (two live instances would race for the listener's single UART)
  2. enable + start the target instance (per-instance drop-in holds the
     listener/jump/tty/port coordinates)
  3. in ~/conwrt-labgrid/exporter.yaml: uncomment the target place's
     pre-staged NetworkSerialPort stanza, comment every other one
  4. restart conwrt-exporter

It never touches places.json (repo side, updated by the operator session
that performs the move) and never issues power or DUT commands.

Usage:
  bench_serial_route.py <place>    route serial to <place> (e.g. ap-lan4)
  bench_serial_route.py --list     show instances, stanza states, ports
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

EXPORTER_YAML = Path.home() / "conwrt-labgrid" / "exporter.yaml"
DROPIN_GLOB = "conwrt-serial-bridge@*.service.d"
STANZA_BODY = ("host:", "port:", "speed:")

PLACE_LINE = re.compile(r"^([A-Za-z0-9._-]+):\s*$")


@dataclass(frozen=True)
class Route:
    place: str
    active: bool
    instance_state: str


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def bridge_places() -> list[str]:
    unit_root = Path.home() / ".config" / "systemd" / "user"
    places = []
    for dropin in sorted(unit_root.glob(DROPIN_GLOB)):
        match = re.fullmatch(r"conwrt-serial-bridge@(.+)\.service\.d", dropin.name)
        if match:
            places.append(match.group(1))
    return places


def instance_state(place: str) -> str:
    proc = run(["systemctl", "--user", "is-active", f"conwrt-serial-bridge@{place}"])
    return proc.stdout.strip() or proc.stderr.strip() or "unknown"


def read_stanza_states(text: str) -> dict[str, bool]:
    """Map place -> whether its NetworkSerialPort stanza is uncommented."""
    states: dict[str, bool] = {}
    place = None
    for line in text.splitlines():
        header = PLACE_LINE.match(line)
        if header:
            place = header.group(1)
            states.setdefault(place, False)
        elif place and line.strip() == "NetworkSerialPort:":
            states[place] = True
    return states


def rewrite_yaml(text: str, target: str) -> str:
    """Uncomment target's NetworkSerialPort stanza, comment all others.

    Stanza membership is tracked by a state machine entered at the
    'NetworkSerialPort:' line (commented or not) and left at the next
    non-comment line indented <= 2 (another resource or place header).
    NetworkPowerPort/NetworkService blocks never enter the stanza mode, so
    their own host:/index: lines are untouched. Prose '##' lines inside a
    stanza are preserved verbatim.
    """
    out: list[str] = []
    place: str | None = None
    in_stanza = False
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        header = PLACE_LINE.match(line)
        if header:
            place = header.group(1)
            in_stanza = False
            out.append(line)
            continue

        if in_stanza:
            if not stripped:
                out.append(line)
                continue
            commented = stripped.startswith("#")
            if not commented and indent <= 2:
                in_stanza = False
                out.append(line)
                continue
            body = stripped[3:] if stripped.startswith("## ") else None
            if place == target and body is not None and body.lstrip().startswith(STANZA_BODY):
                out.append(line[:indent] + body)
            elif place != target and not commented and stripped.startswith(STANZA_BODY):
                out.append(line[:indent] + "## " + stripped)
            else:
                out.append(line)
            continue

        if indent == 2 and stripped in ("NetworkSerialPort:", "## NetworkSerialPort:"):
            in_stanza = True
            if place != target and not stripped.startswith("#"):
                out.append(line[:indent] + "## " + stripped)
            elif place == target and stripped.startswith("## NetworkSerialPort:"):
                out.append(line[:indent] + "NetworkSerialPort:")
            else:
                out.append(line)
            continue

        out.append(line)
    return "\n".join(out) + "\n"


def flip_instances(target: str, places: list[str]) -> list[str]:
    log = []
    for place in places:
        unit = f"conwrt-serial-bridge@{place}"
        if place != target:
            run(["systemctl", "--user", "disable", "--now", unit])
            log.append(f"disabled {unit}")
    proc = run(["systemctl", "--user", "enable", "--now", f"conwrt-serial-bridge@{target}"])
    if proc.returncode != 0:
        raise SystemExit(f"ERROR: enable {target} failed: {proc.stderr.strip()}")
    log.append(f"enabled conwrt-serial-bridge@{target} ({instance_state(target)})")
    return log


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("place", nargs="?", help="target place, e.g. ap-lan4")
    parser.add_argument("--list", action="store_true", help="show route state")
    args = parser.parse_args()

    if not EXPORTER_YAML.is_file():
        raise SystemExit(f"ERROR: {EXPORTER_YAML} not found (run on the exporter host)")

    yaml_text = EXPORTER_YAML.read_text()
    stanza_states = read_stanza_states(yaml_text)
    places = bridge_places()

    if args.list or not args.place:
        print(f"{'place':<10} {'stanza':<8} {'instance':<10} port")
        for place in sorted(set(places) | set(stanza_states)):
            port = "?"
            match = re.search(
                rf"^{place}:\n(?:.*\n)*?  (?:# )?port: (\d+)", yaml_text, re.M)
            if match:
                port = match.group(1)
            stanza = "ACTIVE" if stanza_states.get(place) else "-"
            print(f"{place:<10} {stanza:<8} {instance_state(place):<10} {port}")
        active = [p for p, on in stanza_states.items() if on]
        print(f"\nlive route: {', '.join(active) or 'NONE'}")
        return 0

    target = args.place
    if target not in places:
        raise SystemExit(
            f"ERROR: no bridge instance for {target}. Create "
            f"~/.config/systemd/user/conwrt-serial-bridge@{target}.service.d/override.conf first.")
    live = [p for p, on in stanza_states.items() if on]
    if live == [target]:
        print(f"serial already routed to {target}; nothing to do")
        return 0

    backup = EXPORTER_YAML.with_suffix(f".yaml.bak-{date.today():%Y%m%d}")
    shutil.copy2(EXPORTER_YAML, backup)
    EXPORTER_YAML.write_text(rewrite_yaml(yaml_text, target))

    for line in flip_instances(target, places):
        print(line)
    proc = run(["systemctl", "--user", "restart", "conwrt-exporter"])
    if proc.returncode != 0:
        raise SystemExit(f"ERROR: exporter restart failed: {proc.stderr.strip()}")
    print(f"exporter restarted (yaml backup: {backup.name})")
    print(f"serial route now: {target} (was: {', '.join(live) or 'none'})")
    print(f"next: update serial_console for {target} in data/bench/places.json (repo side)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
