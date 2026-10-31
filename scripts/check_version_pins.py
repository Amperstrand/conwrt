#!/usr/bin/env python3
"""Within-repo OpenWrt version-pin audit (SSOT layering: docs/version-pins-ssot.md).

Checks (exit 1 on any failure):
  1. tests/integration pins are single-sourced — no `OPENWRT_VERSION =
     "…"` literal outside tests/integration/_pins.py.
  2. every models/*.json `openwrt.version` parses (major[.minor]); lists
     the 24.x models that now carry the plan-time deprecation warning.
  3. cross-repo agreement (informational when the peer checkouts exist;
     path overrides: CONWRT_BENCH_REGISTRY, PRTA_REPO):
       - prta lib/fresh_flash.py bench image family
       - conwrt-bench registry/inventory.jsonl specimen firmwares
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
failures: list[str] = []
notes: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)


def main() -> int:
    # 1. single-sourced harness pin
    strays = []
    for py in (REPO / "tests" / "integration").glob("*.py"):
        if py.name == "_pins.py":
            continue
        for i, line in enumerate(py.read_text().splitlines(), 1):
            if re.search(r'OPENWRT_VERSION\s*=\s*["\']', line):
                strays.append(f"{py.name}:{i}")
    if strays:
        fail(f"stray OPENWRT_VERSION literals (import from _pins.py): {', '.join(strays)}")
    else:
        notes.append("integration pin single-sourced in tests/integration/_pins.py ✓")

    # 2. model versions parse; count the warned family
    by_version: dict[str, int] = {}
    for mf in sorted((REPO / "models").glob("*.json")):
        try:
            version = json.loads(mf.read_text())["openwrt"]["version"]
        except (KeyError, json.JSONDecodeError) as exc:
            fail(f"{mf.name}: unreadable openwrt.version ({exc})")
            continue
        if not re.fullmatch(r"\d+(\.\d+)*|snapshot", version):
            fail(f"{mf.name}: unparseable version {version!r}")
        by_version[version] = by_version.get(version, 0) + 1
    warned = sum(n for v, n in by_version.items() if v.startswith("24"))
    notes.append(
        f"models: {dict(sorted(by_version.items()))} — {warned} species on 24.x "
        f"(carry the plan-time deprecation warning; #607)"
    )

    # 3. cross-repo (informational; skips silently when not checked out)
    prta = Path(os.environ.get("PRTA_REPO", str(Path.home() / "src" / "prta-scenario-poc")))
    ff = prta / "lib" / "fresh_flash.py"
    if ff.is_file():
        m = re.search(r'openwrt-(\d+\.\d+(?:\.\d+)?)-mediatek', ff.read_text())
        if m:
            notes.append(f"prta bench image family: {m.group(1)} ({ff})")
    bench = Path(os.environ.get("CONWRT_BENCH_REGISTRY", str(Path.home() / "conwrt-bench" / "registry")))
    inv = bench / "inventory.jsonl"
    if inv.is_file():
        fw: dict[str, int] = {}
        for line in inv.read_text().splitlines():
            try:
                v = json.loads(line).get("firmware_version", "?")
            except json.JSONDecodeError:
                continue
            fw[v] = fw.get(v, 0) + 1
        notes.append(f"bench specimens (ACTUAL, authoritative): {fw}")

    print("== conwrt version-pin audit ==")
    for n in notes:
        print(f"  · {n}")
    if failures:
        for f in failures:
            print(f"  ✗ {f}")
        return 1
    print("  PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
