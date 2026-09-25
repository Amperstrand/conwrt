#!/usr/bin/env python3
"""bench_scout — DHCP-client detection for silent L2-only bench devices.

The bench has NO DHCP (by policy — dnsmasq exists only for TFTP lifelines)
and the GS1900 build has no `bridge` applet, so a factory DHCP-client device
(Netgear ProSAFE switches, stock routers, anything unconfigured) is INVISIBLE
to bench_inventory: it emits only broadcast DHCP DISCOVERs, never unicast,
so neither `ip neigh` nor liveness probes ever see it.

This tool closes that gap, mirroring the proven TFTP-lifeline pattern
(runtime-only dnsmasq instance, nothing committed, dies on switch reboot):

  1. Preconditions (fail fast): SVI exists, DUT-port CARRIER is up
     (a NO-CARRIER port means no physics — today's lesson: nothing to
     scout), no dnsmasq already bound to that interface.
  2. Arm under the global amperstrand-bench flock (owner directive
     2026-09-22: switch-side mutations take the bench lock):
       - runtime fw4 accept for the VLAN (AGENTS AP3915i rule 6 — runtime
         VLAN SVIs drop unsolicited inbound UDP otherwise)
       - scoped dnsmasq: --port=0, one --interface=switch.10N,
         --bind-dynamic, tiny range (.50-.60), leasefile+log in /tmp
  3. Wait for DHCPDISCOVER/ACK; report MAC, offered IP, hostname.
  4. Optional --probe: fetch the device's HTTP title (BusyBox wget on the
     switch) for a management-surface hint (e.g. "NETGEAR").

Deliberately NOT rogue-DHCP: the instance binds exactly one SVI, serves a
bench-only range, and never touches uci/commit (AGENTS rule 9 class).

Usage:
  python3 scripts/bench_scout.py --host <switch> --vlan 1007 [--wait 90]
  python3 scripts/bench_scout.py --host <switch> --vlan 1007 --ip <addr> --probe
  python3 scripts/bench_scout.py --host <switch> --vlan 1007 --disarm
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from dataclasses import dataclass

SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
LEASE_RANGE = "192.168.10{v}.50,192.168.10{v}.60,255.255.255.0,2h"


class ScoutError(Exception):
    """Precondition failed or the switch was unreachable."""


@dataclass(frozen=True)
class Lease:
    mac: str
    ip: str
    hostname: str = ""


# ----------------------------------------------------------------- parsing


def port_of_vlan(vlan: int) -> str:
    if not 1001 <= vlan <= 1099:
        raise ScoutError(f"vlan {vlan} outside the bench pattern (100N)")
    return f"lan{vlan - 1000}"


def parse_carrier(ip_link_output: str) -> bool:
    """True if the port has an electrical link (no NO-CARRIER flag)."""
    return "NO-CARRIER" not in ip_link_output and "LOWERLAYERDOWN" not in ip_link_output


def parse_dhcp_events(log_lines: list[str]) -> list[str]:
    """Interesting dnsmasq DHCP log lines (DISCOVER/REQUEST/ACK/NAK), newest last."""
    keep = re.compile(r"DHCP(DISCOVER|REQUEST|ACK|NAK|RELEASE)")
    return [line for line in log_lines if keep.search(line)]


def parse_leases(raw: str) -> list[Lease]:
    """dnsmasq leasefile: '<expiry> <mac> <ip> <hostname> <client-id>'."""
    out: list[Lease] = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 3 and re.fullmatch(r"[0-9a-fA-F:]{17}", parts[1]):
            out.append(Lease(mac=parts[1].lower(), ip=parts[2],
                             hostname=parts[3] if len(parts) > 3 else ""))
    return out


def extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:80] if m else ""


# ------------------------------------------------------------------ remote


def ssh_run(host: str, cmd: str, timeout: int = 30) -> str:
    proc = subprocess.run(["ssh", *SSH_OPTS, f"root@{host}", cmd],
                          capture_output=True, text=True, timeout=timeout)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0 and not out.strip():
        raise ScoutError(f"switch ssh failed (rc={proc.returncode})")
    return out


def scout_paths(vlan: int) -> dict[str, str]:
    return {"pid": f"/tmp/scout-{vlan}.pid",
            "leases": f"/tmp/scout-{vlan}.leases",
            "log": f"/tmp/scout-{vlan}.log"}


def arm_script(vlan: int) -> str:
    p = scout_paths(vlan)
    ifname = f"switch.{vlan}"
    return (
        "flock /tmp/amperstrand-bench sh -c \""
        f"kill $(cat {p['pid']} 2>/dev/null) 2>/dev/null; "
        f"nft insert rule inet fw4 input iifname \\\"{ifname}\\\" accept 2>/dev/null; "
        f"dnsmasq --port=0 --dhcp-range={LEASE_RANGE.format(v=vlan - 1000)} "
        f"--interface={ifname} --bind-dynamic --pid-file={p['pid']} "
        f"--dhcp-leasefile={p['leases']} --log-facility={p['log']} "
        "--log-dhcp --no-resolv --dhcp-authoritative\" && echo SCOUT-ARMED"
    )


def check_preconditions(host: str, vlan: int) -> None:
    port = port_of_vlan(vlan)
    link = ssh_run(host, f"ip link show {port}")
    if not parse_carrier(link):
        raise ScoutError(
            f"{port} has NO CARRIER — no physical link. Fix power/cabling first; "
            "a DHCP scout cannot see a device that never transmits.")
    svi = ssh_run(host, f"ip link show switch.{vlan}")
    if f"switch.{vlan}@" not in svi:
        raise ScoutError(f"SVI switch.{vlan} does not exist on the switch")
    bound = ssh_run(host, "pgrep -af dnsmasq")
    if f"interface=switch.{vlan}" in bound:
        raise ScoutError(f"another dnsmasq is already bound to switch.{vlan}")


def cmd_scout(args: argparse.Namespace) -> int:
    p = scout_paths(args.vlan)
    if args.disarm:
        out = ssh_run(args.host, f"kill $(cat {p['pid']} 2>/dev/null) 2>/dev/null; "
                                 f"pgrep -af 'dnsmasq.*switch.{args.vlan}' || echo SCOUT-DISARMED")
        print(out.strip())
        return 0

    check_preconditions(args.host, args.vlan)
    out = ssh_run(args.host, arm_script(args.vlan))
    if "SCOUT-ARMED" not in out:
        print(f"FAIL: arming failed:\n{out[-300:]}")
        return 2
    print(f"[armed] dhcp scout on switch.{args.vlan} (range {LEASE_RANGE.format(v=args.vlan - 1000)})")

    if args.ip:
        leases = [Lease("", args.ip)]
    else:
        deadline = time.monotonic() + args.wait
        leases = []
        while time.monotonic() < deadline:
            time.sleep(5)
            raw = ssh_run(args.host, f"cat {p['leases']} 2>/dev/null")
            leases = parse_leases(raw)
            if leases:
                break
            events = parse_dhcp_events(ssh_run(
                args.host, f"cat {p['log']} 2>/dev/null").splitlines())
            if events:
                print(f"[listen] {events[-1].split('dnsmasq[-a-z0-9]*')[-1].strip()}")
        if not leases:
            events = parse_dhcp_events(ssh_run(
                args.host, f"cat {p['log']} 2>/dev/null").splitlines())
            print("[timeout] no DHCP lease. Raw activity:")
            for line in events[-5:] or ["(zero DHCP packets — device is not transmitting)"]:
                print(f"  {line}")
            print("Next: power-cycle the device (factory DHCP hunt) or report its "
                  "static IP with --ip <addr>. Scout stays armed (runtime-only, "
                  "dies on switch reboot).")
            return 1

    for lease in leases:
        print(f"[found] mac={lease.mac} ip={lease.ip}"
              + (f" hostname={lease.hostname}" if lease.hostname else ""))
        if args.probe:
            html = ssh_run(args.host,
                           f"wget -q -O - -T 5 http://{lease.ip}/ 2>/dev/null | head -c 4096")
            title = extract_title(html)
            print(f"[probe] http://{lease.ip}/ -> {title or '(no title / no http)'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", required=True, help="bench switch management IP")
    ap.add_argument("--vlan", type=int, required=True, help="bench VLAN (100N pattern)")
    ap.add_argument("--wait", type=int, default=90, help="seconds to listen for a lease")
    ap.add_argument("--probe", action="store_true", help="fetch HTTP title after detection")
    ap.add_argument("--ip", help="skip DHCP wait; probe this known address instead")
    ap.add_argument("--disarm", action="store_true", help="kill the scoped scout dnsmasq")
    args = ap.parse_args(argv)
    try:
        return cmd_scout(args)
    except ScoutError as e:
        print(f"FAIL: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
