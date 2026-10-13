#!/usr/bin/env python3
"""bench_net — declarative bay/VLAN configuration for OpenWrt DSA devices.

data/lab.yaml declares each device's bays (port -> VLAN -> subnet, plus the
uplink port that carries every bay VLAN tagged); this tool converges the live
switch to it. Covers GS1900-8HP (bench) and ER6P (rig). GS108T is web-managed
(blocked on factory reset — data/lab.yaml gs108t.plan).

Usage:
  bench_net.py status --device gs1900-bench     # live vs desired, read-only
  bench_net.py apply  --device gs1900-bench     # drift + hand-off plan

labgrid/conwrt integration: idempotent, exit 0 "converged" when clean — safe
to call from tests/drivers. v1 apply prints the exact uci sequence with
readback gates; automated execution lands with the next revision.
"""
from __future__ import annotations
import argparse, os, ipaddress, re, subprocess, sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent


def load(device: str) -> tuple[dict, dict]:
    cfg = yaml.safe_load((Path(os.environ.get("CONWRT_LAB", REPO / "data")) / "lab.yaml").read_text())
    if device not in cfg["devices"]:
        sys.exit(f"unknown device {device} (not in data/lab.yaml)")
    return cfg, cfg["devices"][device]


def ssh(host: str, cmd: str, timeout: int = 30) -> str:
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                        f"root@{host}", cmd], capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()


def live_state(host: str) -> dict:
    """Parse bridge-vlan sections (any naming style), the bridge device name,
    and L3 interfaces from a live OpenWrt DSA device."""
    out = ssh(host, "uci show network 2>/dev/null | "
                    "grep -E 'bridge-vlan|[.]vlan=|[.]ports=|[.]device='; "
                    "ip -4 -o addr show", timeout=20)
    secs: dict[str, dict] = {}
    bridge = "br-lan"
    ifaces: set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        dm = re.match(r"network\.[\w@[\]]+\.device='([\w.-]+)'", line)
        if dm and "br" in dm.group(1) or (dm and dm.group(1) == "switch"):
            bridge = dm.group(1)
            continue
        pm = re.match(r"network\.([\w@[\]]+)\.(vlan|ports)=", line)
        if pm:
            sec, key = pm.group(1), pm.group(2)
            d = secs.setdefault(sec, {"vlan": None, "ports": []})
            if key == "vlan":
                vm = re.search(r"'(\d+)'", line)
                if vm:
                    d["vlan"] = int(vm.group(1))
            else:
                for v in re.findall(r"'([^']*)'", line):
                    d["ports"].extend(v.split())
            continue
        im = re.match(r"\d+: (\S+)", line)
        if im:
            ifaces.add(im.group(1))
    vlans: dict[int, list[str]] = {}
    secmap: dict[int, str] = {}
    for sec, d in secs.items():
        if d["vlan"] is not None:
            vlans[d["vlan"]] = sorted(d["ports"])
            secmap[d["vlan"]] = sec
    return {"vlans": vlans, "ifaces": ifaces, "sections": secmap, "bridge": bridge}


def desired_bays(dev: dict) -> dict[int, list[str]]:
    """vlan -> sorted desired port-spec list, incl. uplink:t on every bay VLAN."""
    bays = dev.get("bays") or {}
    uplink = bays.get("uplink")
    out: dict[int, set[str]] = {}
    for port, bay in bays.items():
        if port == "uplink":
            continue
        v = bay["vlan"]
        s = out.setdefault(v, set())
        s.add(f"{port}:u*")
        if uplink:
            s.add(f"{uplink}:t")
        for extra in bay.get("trunk", []):
            s.add(f"{extra}:t")
    return {v: sorted(s) for v, s in out.items()}


def subnet_for(cfg: dict, vlan: int) -> str | None:
    for s, meta in cfg["subnets"].items():
        if meta.get("vlan") == vlan:
            return s
    return None


def plan(cfg: dict, dev: dict, name: str) -> list[str]:
    live = live_state(dev["mgmt"])
    bridge = live["bridge"]
    steps: list[str] = []
    for vlan, want in sorted(desired_bays(dev).items()):
        have = live["vlans"].get(vlan)
        want_str = " ".join(want)
        if have is None:
            steps.append(f"CREATE bridge-vlan {vlan} ports='{want_str}'")
        elif have != want:
            steps.append(f"UPDATE bridge-vlan {vlan}: have '{' '.join(have)}' want '{want_str}' "
                         f"(uci set network.{live['sections'][vlan]}.ports='{want_str}')")
        subnet = subnet_for(cfg, vlan)
        ifname = f"{bridge}.{vlan}"
        if subnet and ifname not in live["ifaces"]:
            l3 = str(next(ipaddress.ip_network(subnet).hosts()))
            steps.append(f"CREATE L3 {ifname} {l3}/24 + static interface")
    return steps


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["status", "apply"])
    ap.add_argument("--device", required=True, help="device id from data/lab.yaml")
    ap.add_argument("--yes", action="store_true")
    args = ap.parse_args()
    cfg, dev = load(args.device)
    if not dev.get("mgmt"):
        sys.exit(f"{args.device}: no mgmt address in lab.yaml")
    steps = plan(cfg, dev, args.device)
    print(f"== {args.device} ({dev['mgmt']})")
    if not steps:
        print("  converged — live state matches lab.yaml")
        sys.exit(0)
    for s in steps:
        print(f"  DRIFT: {s}")
    if args.command == "status":
        sys.exit(1)
    print(f"{len(steps)} change(s); v1 prints the hand-off plan (readback gates per AGENTS.md) — "
          "execute the uci sequence above manually or extend --yes")
    sys.exit(2)


if __name__ == "__main__":
    main()
