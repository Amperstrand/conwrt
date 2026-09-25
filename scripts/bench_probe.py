#!/usr/bin/env python3
"""bench_probe — classify a bench DUT's network-side health class.

The bench has no serial on most DUTs, so this maps how far a unit booted
using only network observables, and can apply the documented bounded cure
(one or two deliberate PoE cycles) for the auth-dead class.

Classes (evidence per class in data/bench/*/):
  alive      key-auth SSH works over the v6 link-local
  auth-dead  dropbear accepts TCP:22 and completes the banner exchange, then
             closes every session at auth ("Remote closed the connection").
             Box is up (neigh present). Signature of the jffs2 overlay
             replay race: /etc unwritable when dropbear wants host keys.
             Documented cure: 1-2 deliberate PoE cycles (ap-lan2 2026-09-22,
             ap-lan5 2026-09-24).
  net-dead   link up + PoE, but no TCP:22 answer within the probe window
             (kernel/network never came up, or dropbear never started)
  silent     no neigh entry at all; only PoE draw proves the port feeds it

Usage:
  bench_probe.py --place ap-lan5                classify + JSON verdict
  bench_probe.py --place ap-lan5 --recover      auth-dead -> <=2 PoE cycles
  bench_probe.py --place ap-lan5 --json         machine-readable output
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PLACES_JSON = REPO_ROOT / "data" / "bench" / "places.json"
SWITCH = "root@192.168.13.2"
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
PROBE_TIMEOUT = 20
AUTH_DEAD_MARKER = "Remote closed the connection"
BOOT_SETTLE_S = 150
MAX_CYCLES = 2


@dataclass
class Verdict:
    place: str
    verdict: str
    ssh_key_ok: bool
    banner_or_auth: str
    neigh: str
    evidence: str

    def text(self) -> str:
        lines = [f"{self.place}: {self.verdict}",
                 f"  key-auth SSH : {'OK' if self.ssh_key_ok else self.banner_or_auth}",
                 f"  v6 neighbor  : {self.neigh or 'absent'}",
                 f"  evidence     : {self.evidence}"]
        return "\n".join(lines)


def on_switch(script: str, timeout_s: int = PROBE_TIMEOUT) -> str:
    try:
        proc = subprocess.run(["ssh", *SSH_OPTS, SWITCH, script],
                              capture_output=True, text=True, timeout=timeout_s)
        return proc.stdout + proc.stderr
    except subprocess.TimeoutExpired as exc:
        # A hung probe is data: net-dead/silent units never answer. Return
        # whatever the channel produced before the guard killed it.
        out = exc.stdout or ""
        return (out if isinstance(out, str) else out.decode(errors="replace")) + \
            (exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")) + \
            "[probe timeout]"


def load_place(name: str) -> dict:
    places = json.loads(PLACES_JSON.read_text())["places"]
    for place in places:
        if place["name"] == name:
            return place
    raise SystemExit(f"ERROR: {name} not in {PLACES_JSON}")


def linklocal(mac: str) -> str:
    octets = mac.lower().split(":")
    octets.insert(3, "fe")
    octets.insert(3, "ff")
    first = int(octets[0], 16) ^ 0x02
    octets[0] = f"{first:02x}"
    hextets = ["".join(octets[i:i + 2]) for i in range(0, 8, 2)]
    return "fe80::" + ":".join(hextets)


def probe(place: dict, evidence_dir: Path | None = None) -> Verdict:
    ll = linklocal(place["mac"])
    zone = f"switch.{place.get('vlan') or 1000 + int(place['name'][-1])}"
    target = f"{ll}%{zone}"

    neigh = on_switch(f"ip neigh show dev {zone} | grep -i {place['mac'].lower()[:8]}")

    key = on_switch(f"dbclient -y -y -i /root/.ssh/id_ed25519 root@{target} "
                    "'echo SSH-KEY-OK' </dev/null")
    if "SSH-KEY-OK" in key:
        verdict = "alive"
    elif AUTH_DEAD_MARKER in key:
        verdict = "auth-dead"
    elif "refused" in key or "timed out" in key or "Connection timed" in key or not key.strip():
        verdict = "net-dead" if neigh.strip() else "silent"
    else:
        verdict = "net-dead" if neigh.strip() else "silent"

    result = Verdict(place=place["name"], verdict=verdict,
                     ssh_key_ok="SSH-KEY-OK" in key,
                     banner_or_auth=key.strip().splitlines()[-1] if key.strip() else "(no output)",
                     neigh="present" if neigh.strip() else "absent",
                     evidence="")
    if evidence_dir:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        (evidence_dir / f"{stamp}-probe.txt").write_text(
            f"{json.dumps(asdict(result), indent=1)}\n--- raw key probe ---\n{key}\n")
        result.evidence = str(evidence_dir / f"{stamp}-probe.txt")
    return result


def poe_cycle(place: dict) -> None:
    port = place["name"].removeprefix("ap-")
    script = (f'ubus call poe manage "{{\\"port\\":\\"{port}\\",\\"action\\":\\"disable\\"}}"; sleep 8; '
              f'ubus call poe manage "{{\\"port\\":\\"{port}\\",\\"action\\":\\"enable\\\"}}"')
    on_switch(script, 30)


def recover(place: dict, evidence_dir: Path) -> Verdict:
    result = probe(place, evidence_dir)
    cycles = 0
    while result.verdict == "auth-dead" and cycles < MAX_CYCLES:
        cycles += 1
        print(f"[HEAL] {place['name']}: auth-dead — deliberate PoE cycle {cycles}/{MAX_CYCLES}",
              file=sys.stderr)
        poe_cycle(place)
        time.sleep(BOOT_SETTLE_S)
        result = probe(place, evidence_dir)
    if result.verdict == "auth-dead":
        result.evidence += " | STILL AUTH-DEAD after bounded cycles — console required"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--place", required=True, help="place name, e.g. ap-lan5")
    parser.add_argument("--recover", action="store_true",
                        help="on auth-dead: up to 2 deliberate PoE cycles")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    place = load_place(args.place)
    if place.get("reset_allowed") is False:
        print(f"REFUSED: {args.place} is reset_allowed=false — PoE cycling not allowed", file=sys.stderr)
        return 2

    evidence_dir = REPO_ROOT / "data" / "bench" / args.place
    result = recover(place, evidence_dir) if args.recover else probe(place, evidence_dir)

    if args.as_json:
        print(json.dumps(asdict(result), indent=1))
    else:
        print(result.text())
    return 0 if result.verdict in ("alive", "auth-dead") else 1


if __name__ == "__main__":
    sys.exit(main())
