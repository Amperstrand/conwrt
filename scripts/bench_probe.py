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
  unprobed   negative verdict withheld: the same-path positive controls
             (switch shell, dbclient applet, VLAN interface) failed, so the
             bench network itself is not proven alive — the target's state
             is unknown, not dead (#286)

Usage:
  bench_probe.py --place ap-lan5                classify + JSON verdict
  bench_probe.py --place ap-lan5 --recover      auth-dead -> <=2 PoE cycles
  bench_probe.py --place ap-lan5 --json         machine-readable output
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PLACES_JSON = REPO_ROOT / "data" / "bench" / "places.json"
SWITCH = os.environ.get("CONWRT_SWITCH", "root@192.168.0.2")  # AGENTS.md: no bench IPs in-repo — operator supplies via env
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
    control: str = ""  # '' = controls passed/unused; else why the bench path is unproven

    def text(self) -> str:
        lines = [f"{self.place}: {self.verdict}",
                 f"  key-auth SSH : {'OK' if self.ssh_key_ok else self.banner_or_auth}",
                 f"  v6 neighbor  : {self.neigh or 'absent'}",
                 f"  evidence     : {self.evidence}"]
        if self.control:
            lines.append(f"  control      : {self.control}")
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


def positive_controls(zone: str) -> str:
    """Same-path positive controls: prove the bench network itself can
    carry this probe before any negative verdict is recorded (#286).

    A net-dead/silent classification means "the DUT did not answer" — that
    is only a valid statement if the switch SSH shell answers, dbclient
    exists on the switch, and the target VLAN interface is up. Without
    these controls a missing applet, broken VLAN, or failed switch SSH path
    is silently recorded as a DUT failure. Mirrors bench_inventory's
    `unprobed` treatment of a batch that could not run.

    Returns '' when every control passes, else a human-readable reason the
    bench path is unproven.
    """
    echo = on_switch("echo BENCH-CTRL-OK")
    if "BENCH-CTRL-OK" not in echo:
        return f"switch SSH/shell control failed: {echo.strip()[:160] or '(no output)'}"
    which = on_switch("command -v dbclient")
    if "dbclient" not in which:
        return f"dbclient applet missing on switch: {which.strip()[:160] or '(no output)'}"
    # Operational link-state control, not existence: `ip link show` exits 0
    # for admin-down/detached interfaces too (Codex P1 on #401 — an
    # existence check passes while the data path is dead). Require the
    # interface to actually report state UP. rc-marker form keeps the
    # missing-interface case loud ("Device switch.NNN does not exist."
    # contains the name, so substring checks would false-pass).
    link_out = on_switch(f"ip link show {zone} 2>&1; echo LINK-CTRL:$?")
    link_body = link_out.rsplit("LINK-CTRL:", 1)[0]
    if "LINK-CTRL:0" not in link_out:
        return (f"vlan interface {zone} missing on switch "
                f"({link_out.strip()[-60:] or 'no output'})")
    if "state UP" not in link_body:
        state = next((ln.strip() for ln in link_body.splitlines()
                      if "state" in ln), "")[:80]
        return (f"vlan interface {zone} not operational on switch "
                f"(want state UP; got: {state or link_body.strip()[:80]})")
    # Known-good data-path control (AGENTS.md rule 1: prove the probe
    # against a known-good host through the same interface). Opt-in via
    # CONWRT_VLAN_CONTROL_HOST — a host that must answer a ping THROUGH the
    # target VLAN. When unset, controls stop at operational link state and
    # every verdict's evidence says so (never silently claims path proof).
    host = os.environ.get("CONWRT_VLAN_CONTROL_HOST", "").strip()
    if host:
        ping_rc = on_switch(
            f"ping -I {zone} -c1 -W2 {host} >/dev/null 2>&1; "
            f"echo PING-CTRL:$?")
        if "PING-CTRL:0" not in ping_rc:
            return (f"known-good host {host} unreachable through {zone} "
                    f"({ping_rc.strip()[-40:] or 'no output'}) — bench data "
                    f"path unproven")
    return ""


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

    control = ""
    if verdict in ("net-dead", "silent"):
        # A negative verdict is only recorded when the same-path positive
        # controls prove the bench network is alive (#286).
        control = positive_controls(zone)
        if control:
            verdict = "unprobed"

    result = Verdict(place=place["name"], verdict=verdict,
                     ssh_key_ok="SSH-KEY-OK" in key,
                     banner_or_auth=key.strip().splitlines()[-1] if key.strip() else "(no output)",
                     neigh="present" if neigh.strip() else "absent",
                     evidence="", control=control)
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
