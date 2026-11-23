"""`conwrt adopt` — the post-flash adoption sequence as a gate ladder (#689).

Every flash lands the same way: default IP, rogue DHCP/RA armed (the house
has been poisoned by this class twice), no SSH key. The 2026-11-11 recovery
rebuilt that state by hand THREE times, hitting five separate v4 failure
modes before switching to the v6 door. This module is that sequence as
code, driven v6-first through :mod:`conwrt.v6door`.

The ladder (blankdl-trigger style: read back every value, name the
failure, DO NOT proceed on a failed gate):

1. alive     — the derived fe80:: answers (ping via the on-link switch)
2. shell     — the door runs a command and reports a board string
3. rogue     — dhcp.lan.ignore=1, ra=disabled, dhcpv6=disabled, each
               READ BACK (rogue-DHCP discipline)
4. mgmt-ip   — network.lan.ipaddr staged in CIDR form (<ip>/24, never a
               bare netmask — migrates to /32 across release upgrades),
               READ BACK before commit
5. key       — the management SSH key installed (idempotent), hostname set,
               READ BACK
6. v4        — best-effort ping/SSH via the new management IP; REPORTED,
               never fatal (v6 remains the management plane)

Output: a JSON adoption report (``--json``) for the executor, or the
human gate log. ``--dry-run`` prints the exact command ladder without
dialing.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from conwrt.v6door import Door, DoorResult, derive_linklocal, probe_alive


class AdoptError(Exception):
    """A gate refused to pass — the message names the gate and the values."""


@dataclass
class AdoptPlan:
    mac: str
    mgmt_ip: str                 # CIDR form, e.g. 192.168.104.51/24
    hostname: str
    ssh_key: str                 # the management pubkey line
    via_switch: Optional[str] = None
    vlan: int = 0
    iface: Optional[str] = None  # LocalDoor alternative


@dataclass
class GateReport:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class AdoptReport:
    plan_mac: str
    linklocal: str
    gates: list[GateReport] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(
            {
                "adopted": all(g.ok for g in self.gates),
                "mac": self.plan_mac,
                "linklocal": self.linklocal,
                "gates": [
                    {"gate": g.name, "ok": g.ok, "detail": g.detail}
                    for g in self.gates
                ],
            },
            indent=2,
        )


def _readback(door: Door, cmd: str) -> str:
    r: DoorResult = door.run(cmd)
    if r.rc != 0:
        raise AdoptError(f"door command failed (rc={r.rc}): {cmd}\n{r.out[-200:]}")
    return r.out


def gate_alive(plan: AdoptPlan) -> GateReport:
    addr = derive_linklocal(plan.mac)
    if not plan.via_switch:
        return GateReport("alive", True, "skipped: no switch vantage (LocalDoor)")
    if probe_alive(plan.via_switch, plan.vlan, plan.mac):
        return GateReport("alive", True, f"{addr} answers")
    raise AdoptError(f"alive: {addr} does not answer from {plan.via_switch}")


def gate_shell(door: Door) -> GateReport:
    out = _readback(door, "uname -a")
    if "Linux" not in out:
        raise AdoptError(f"shell: not a Linux shell: {out[:120]!r}")
    return GateReport("shell", True, out.split(",")[0][:80])


def gate_rogue(door: Door) -> GateReport:
    """Quiet the rogue DHCP/RA — every value READ BACK."""
    staged = (
        "uci set dhcp.lan.ignore='1'; uci set dhcp.lan.ra='disabled'; "
        "uci set dhcp.lan.dhcpv6='disabled'; "
        "echo ---READBACK---; "
        "uci get dhcp.lan.ignore; uci get dhcp.lan.ra; uci get dhcp.lan.dhcpv6"
    )
    out = _readback(door, staged)
    got = out.split("---READBACK---")[-1].split()
    want = ["1", "disabled", "disabled"]
    if got != want:
        raise AdoptError(f"rogue: readback {got} != {want} (raw: {out[-200:]})")
    return GateReport("rogue", True, "dhcp ignored, ra/dhcpv6 disabled (read back)")


def gate_mgmt_ip(door: Door, plan: AdoptPlan) -> GateReport:
    """Stage the management IP in CIDR form — READ BACK, then commit."""
    staged = (
        "uci revert network 2>/dev/null; "
        "uci set network.lan.proto='static'; "
        "uci delete network.lan.ipaddr 2>/dev/null; "
        f"uci add_list network.lan.ipaddr='{plan.mgmt_ip}'; "
        "echo ---READBACK---; "
        "uci get network.lan.proto; uci get network.lan.ipaddr"
    )
    out = _readback(door, staged)
    got = out.split("---READBACK---")[-1].split()
    if got != ["static", plan.mgmt_ip]:
        raise AdoptError(
            f"mgmt-ip: readback {got} != ['static', '{plan.mgmt_ip}'] "
            f"(raw: {out[-200:]})"
        )
    # CIDR form proven — commit. The network restart drops v4 defaults;
    # the v6 door keeps the session usable regardless.
    out = _readback(door, "uci commit network; echo COMMITTED")
    if "COMMITTED" not in out:
        raise AdoptError(f"mgmt-ip: commit failed: {out[-200:]}")
    return GateReport("mgmt-ip", True, f"{plan.mgmt_ip} staged, read back, committed")


def gate_key(door: Door, plan: AdoptPlan) -> GateReport:
    """Install the management key idempotently + hostname, READ BACK."""
    key = plan.ssh_key.replace("'", "'\\''")  # embed safely in the shell line
    cmd = (
        "mkdir -p /etc/dropbear; "
        f"grep -qF '{plan.ssh_key.split()[1]}' /etc/dropbear/authorized_keys 2>/dev/null "
        f"|| echo '{key}' >> /etc/dropbear/authorized_keys; "
        "chmod 600 /etc/dropbear/authorized_keys; "
        f"uci set system.@system[0].hostname='{plan.hostname}'; uci commit system; "
        "echo ---READBACK---; "
        "wc -l < /etc/dropbear/authorized_keys; uci get system.@system[0].hostname"
    )
    out = _readback(door, cmd)
    tail = out.split("---READBACK---")[-1].split()
    if len(tail) < 2 or not tail[0].isdigit() or tail[-1] != plan.hostname:
        raise AdoptError(f"key: readback unexpected: {tail} (raw: {out[-200:]})")
    return GateReport("key", True, f"key present ({tail[0]} line(s)), hostname={tail[-1]}")


def gate_v4(plan: AdoptPlan, timeout_s: int = 60) -> GateReport:
    """Best-effort v4 convenience check — reported, never fatal."""
    ip = plan.mgmt_ip.split("/")[0]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if subprocess.run(["ping", "-c1", "-W2", ip],
                              capture_output=True, timeout=5).returncode == 0:
                return GateReport("v4", True, f"{ip} answers (convenience path)")
        except subprocess.TimeoutExpired:
            pass
        time.sleep(5)
    return GateReport("v4", False, f"{ip} not answering yet (v6 remains the door)")


def run_adoption(plan: AdoptPlan, door: Door, v4_timeout: int = 60) -> AdoptReport:
    report = AdoptReport(plan.mac, derive_linklocal(plan.mac))
    ladder = [
        ("alive", lambda: gate_alive(plan)),
        ("shell", lambda: gate_shell(door)),
        ("rogue", lambda: gate_rogue(door)),
        ("mgmt-ip", lambda: gate_mgmt_ip(door, plan)),
        ("key", lambda: gate_key(door, plan)),
        ("v4", lambda: gate_v4(plan, v4_timeout)),
    ]
    for name, gate in ladder:
        try:
            report.gates.append(gate())
        except AdoptError as e:
            # The failing gate is this rung — a raw door error inside a
            # gate names the gate, not the transport boilerplate.
            report.gates.append(GateReport(name, False, str(e)))
            break
    return report


def _dry_run_ladder(plan: AdoptPlan) -> list[str]:
    return [
        f"# gate alive: ping {derive_linklocal(plan.mac)} from {plan.via_switch}",
        "uname -a",
        "uci set dhcp.lan.ignore='1'; uci set dhcp.lan.ra='disabled'; "
        "uci set dhcp.lan.dhcpv6='disabled'; uci get dhcp.lan.ignore; "
        "uci get dhcp.lan.ra; uci get dhcp.lan.dhcpv6",
        "uci revert network; uci set network.lan.proto='static'; "
        f"uci add_list network.lan.ipaddr='{plan.mgmt_ip}'; uci get network.lan.ipaddr; "
        "uci commit network",
        "mkdir -p /etc/dropbear; (grep key || echo key) >> authorized_keys; hostname",
        f"ping {plan.mgmt_ip.split('/')[0]}",
    ]


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "adopt", help="post-flash adoption as one command: v6 door, quiet the "
                      "rogue DHCP, CIDR mgmt IP, SSH key, JSON report (#689)")
    p.add_argument("--mac", required=True, help="unit MAC (registry dossier)")
    p.add_argument("--ip", required=True, help="management IP in CIDR form (e.g. 192.168.104.51/24)")
    p.add_argument("--hostname", required=True)
    p.add_argument("--key", required=True, help="management SSH public key line")
    p.add_argument("--via", help="on-link switch host (SwitchDoor vantage)")
    p.add_argument("--vlan", type=int, default=0)
    p.add_argument("--iface", help="local on-link interface (LocalDoor)")
    p.add_argument("--json", action="store_true", help="machine-readable report")
    p.add_argument("--dry-run", action="store_true",
                   help="print the exact ladder; dial nothing")
    p.set_defaults(func=_main)


def _main(args) -> int:
    plan = AdoptPlan(
        mac=args.mac, mgmt_ip=args.ip, hostname=args.hostname, ssh_key=args.key,
        via_switch=args.via, vlan=args.vlan, iface=args.iface,
    )
    if args.dry_run:
        for line in _dry_run_ladder(plan):
            print(line)
        return 0
    if args.via:
        from conwrt.v6door import SwitchDoor
        door: Door = SwitchDoor(args.via, args.vlan, args.mac)
    elif args.iface:
        from conwrt.v6door import LocalDoor
        door = LocalDoor(args.iface, args.mac)
    else:
        print("need --via/--vlan or --iface", file=sys.stderr)
        return 2
    report = run_adoption(plan, door)
    if args.json:
        print(report.to_json())
    else:
        for g in report.gates:
            print(f"[{'PASS' if g.ok else 'FAIL'}] {g.name}: {g.detail}")
    return 0 if all(g.ok for g in report.gates) else 1


cmd_adopt = _main
