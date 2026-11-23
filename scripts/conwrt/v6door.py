"""The v6 door — the universal dial-in helper for a freshly flashed unit.

Why v6-first (conwrt #689, session evidence 2026-11-11): the link-local
door survives everything a fresh flash throws at the management path —
PHY post-flash blindness, default-IP roulette, stale flash-rig routes on
the bench host, ARP staleness. v4 survived none of them. Zone-scoped v6
must be dialed from an ON-LINK host (the bench switch), never through a
router.

Two real doors and one test door:

- ``SwitchDoor``: ssh to an on-link OpenWrt switch, then ``dbclient``
  (empty-password dropbear accepts the factory state) to
  ``root@fe80::<EUI-64>%<vlan-iface>``. The bench vantage.
- ``LocalDoor``: direct ``ssh root@fe80::…%<iface>`` from this host —
  only valid when this host is on-link.
- Tests inject a fake door; nothing here dials in a dry run.

The EUI-64 derivation is pure and unit-pinned (known vectors).
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass


def derive_linklocal(mac: str) -> str:
    """fe80::<EUI-64> for a MAC — flip the U/L bit, insert ff:fe.

    >>> derive_linklocal("00:11:22:33:44:55")
    'fe80::211:22ff:fe33:4455'
    """
    octets = [int(p, 16) for p in mac.strip().lower().split(":")]
    if len(octets) != 6 or any(o > 0xFF for o in octets):
        raise ValueError(f"not a MAC: {mac!r}")
    octets[0] ^= 0x02  # universal/local bit
    eui = octets[:3] + [0xFF, 0xFE] + octets[3:]
    # Link-local: fe80 + seven zero words collapsed to "::", then the four
    # EUI-64 words (leading zeros stripped per word, lowercase).
    words = [eui[i] << 8 | eui[i + 1] for i in range(0, 8, 2)]
    return "fe80::" + ":".join(f"{w:x}" for w in words)


@dataclass
class DoorResult:
    rc: int
    out: str


class Door:
    """Run one shell command inside the unit through the v6 door."""

    def run(self, cmd: str, timeout: int = 30) -> DoorResult:  # pragma: no cover
        raise NotImplementedError


@dataclass
class SwitchDoor(Door):
    switch: str
    vlan: int
    mac: str

    def _target(self) -> str:
        return f"root@{derive_linklocal(self.mac)}%switch.{self.vlan}"

    def run(self, cmd: str, timeout: int = 30) -> DoorResult:
        remote = (
            f"DROPBEAR_PASSWORD='' dbclient -y -y {self._target()} "
            f"{_shquote(cmd)} </dev/null 2>&1 | grep -v Caution"
        )
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
             f"root@{self.switch}", remote],
            capture_output=True, text=True, timeout=timeout + 15,
        )
        return DoorResult(proc.returncode, (proc.stdout + proc.stderr).strip())


@dataclass
class LocalDoor(Door):
    iface: str
    mac: str

    def run(self, cmd: str, timeout: int = 30) -> DoorResult:
        target = f"root@{derive_linklocal(self.mac)}%{self.iface}"
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             target, cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return DoorResult(proc.returncode, (proc.stdout + proc.stderr).strip())


def _shquote(s: str) -> str:
    import shlex
    return shlex.quote(s)


def probe_alive(switch: str, vlan: int, mac: str, timeout: int = 10) -> bool:
    """Ping the derived link-local from the on-link switch."""
    target = derive_linklocal(mac)
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
         f"root@{switch}", f"ping -c 1 -W {timeout} {target}"],
        capture_output=True, text=True, timeout=timeout + 15,
    )
    return proc.returncode == 0


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "v6door", help="dial the v6 door: derive EUI-64, run one command "
                       "inside a fresh unit (or just print the address)")
    p.add_argument("--mac", required=True, help="unit MAC (registry dossier)")
    p.add_argument("--via", help="on-link switch host (SwitchDoor)")
    p.add_argument("--vlan", type=int, help="management VLAN on the switch")
    p.add_argument("--iface", help="local on-link interface (LocalDoor)")
    p.add_argument("--cmd", default="uname -a; uci get dhcp.lan.ignore",
                   help="command to run inside the unit")
    p.add_argument("--print-address", action="store_true",
                   help="just print the derived fe80:: address and exit")
    p.set_defaults(func=_main)


def _main(args) -> int:
    addr = derive_linklocal(args.mac)
    if args.print_address:
        print(addr)
        return 0
    if args.via:
        if args.vlan is None:
            print("--via requires --vlan", file=__import__("sys").stderr)
            return 2
        door: Door = SwitchDoor(args.via, args.vlan, args.mac)
    elif args.iface:
        door = LocalDoor(args.iface, args.mac)
    else:
        print("need --via/--vlan or --iface", file=__import__("sys").stderr)
        return 2
    r = door.run(args.cmd)
    print(r.out)
    return r.rc


cmd_v6door = _main
