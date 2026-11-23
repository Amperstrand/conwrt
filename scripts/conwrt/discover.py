#!/usr/bin/env python3
"""discover — the dark-unit ladder as a conwrt subcommand (#323 item 1).

Thin promotion of scripts/bench_discover.py (the hypothesis-driven
discovery ladder generalized from the 2026-09-22 lan7/lan8 recovery):
this module wires its plan/run interface into `conwrt discover` and
adds NOTHING — the ladder's invariants (layer-0 positive control,
v6-first link-local, v4 archaeology, credentials PRINTED never
executed) live in one place. See docs/DETECTION-RECOVERY-TOOLING.md
choice C for why promotion beat rewriting.

Name choice: the existing `conwrt probe` (cmd_probe.py) is the older
active v4 model-IP prober; it keeps its name and behavior. The ladder
ships as `conwrt discover` — no collision, no behavior change for
existing probe users, and the doc's first-move chain reads
`conwrt listen` → `conwrt discover` → `conwrt v6door`/`conwrt adopt`.
"""
from __future__ import annotations

import argparse
import sys

import bench_discover


def cmd_discover(args: argparse.Namespace) -> int:
    argv = ["discover", args.mode, "--mac", args.mac, "--iface", args.iface,
            "--control-ip", args.control_ip]
    if args.probe_host:
        argv += ["--probe-host", args.probe_host]
    if args.probe_subnets:
        argv += ["--probe-subnets", args.probe_subnets]
    if args.inventory:
        argv += ["--inventory", str(args.inventory)]
    if args.json:
        argv += ["--json", str(args.json)]
    return bench_discover.main(argv[1:])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="conwrt discover",
        description="dark-unit discovery ladder (#323): positive control -> v6 "
                    "link-local -> v4 archaeology -> banner identify; "
                    "credentials are printed, NEVER executed")
    p.add_argument("mode", choices=("plan", "run"), nargs="?", default="plan",
                   help="plan: print the ladder (always hardware-safe); "
                        "run: execute the passive/v6/v4/banner layers via the probe host")
    p.add_argument("--mac", required=True, help="source MAC observed in any frame")
    p.add_argument("--iface", required=True,
                   help="on-link L3 iface on the probe host (e.g. switch.1007)")
    p.add_argument("--probe-host", help="SSH alias of an on-link probe host (required for run)")
    p.add_argument("--control-ip", required=True,
                   help="known-good host for the layer-0 positive control")
    p.add_argument("--probe-subnets", default="",
                   help="comma list of subnets the probe host itself lives in")
    p.add_argument("--inventory", type=str, default="",
                   help="inventory.jsonl for v4 archaeology (default: repo data/)")
    p.add_argument("--json", type=str, default="",
                   help="write ladder+results as JSON")
    return p


def main(argv: list[str] | None = None) -> int:
    return cmd_discover(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
