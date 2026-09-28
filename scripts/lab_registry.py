#!/usr/bin/env python3
"""lab_registry — the single-source-of-truth registry tool for data/lab.yaml.

Commands:
  validate         schema + cross-reference checks (public-CI safe, reads lab.yaml)
  emit-exporter    print the labgrid exporter.yaml generated from lab.yaml
  deploy-exporter  emit + scp to the exporter host + restart (needs SSH)
  reconcile        read-only drift check: probe reality, diff vs lab.yaml
                   (fdb/neigh/leases/uptime via bench switch; labgrid places)

Design rules (see data/lab.yaml header + AGENTS.md):
  - lab.yaml is the ONLY writable state store (gitignored, contains MACs).
  - exporter.yaml and labgrid places are GENERATED — never hand-edit.
  - tools that change device state must finish by updating lab.yaml.
"""
from __future__ import annotations
import argparse, os, ipaddress, json, re, subprocess, sys, tempfile, os
from pathlib import Path

import yaml  # PyYAML (repo already depends on it via labgrid tooling)

REPO = Path(__file__).resolve().parent.parent
LAB = Path(os.environ.get("CONWRT_LAB", REPO / "data")) / "lab.yaml"
# CONWRT_LAB may point at a conwrt-lab checkout (private repo) or the in-tree fallback


def load() -> dict:
    return yaml.safe_load(LAB.read_text())


def cmd_validate(cfg: dict) -> int:
    errs, warns = [], []
    devs = cfg["devices"]
    subs = cfg["subnets"]

    # every device mgmt IP sits in a declared subnet
    def find_subnet(ip: str):
        net = ipaddress.ip_address(ip)
        for s in subs:
            if net in ipaddress.ip_network(s):
                return s
        return None

    seen_macs: dict[str, str] = {}
    for name, d in devs.items():
        mg = d.get("mgmt")
        if isinstance(mg, str):
            s = find_subnet(mg)
            if s is None:
                errs.append(f"{name}: mgmt {mg} not in any declared subnet")
            elif subs[s].get("owner") in ("planned", "reserved") and d.get("state") not in (None, "planned"):
                errs.append(f"{name}: mgmt {mg} lives in {subs[s]['owner']} subnet {s} but state is live")
        for mk, mv in (d.get("macs") or {}).items():
            if mv in ("unknown",) or mv is None:
                continue
            if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", str(mv)):
                errs.append(f"{name}: bad MAC {mk}={mv}")
            elif mv in seen_macs:
                errs.append(f"{name}: MAC {mv} ({mk}) duplicates {seen_macs[mv]}")
            else:
                seen_macs[mv] = f"{name}/{mk}"

    # topology endpoints exist; every cable has two device ends
    for t in cfg.get("topology", []):
        a, b = t[0], t[2]
        for endpoint in (a, b):
            base = endpoint.split("-or-")[0]
            if base not in devs and base not in ("house-chain",):
                errs.append(f"topology: endpoint '{endpoint}' not a device")

    # labgrid places reference real devices
    for place, p in cfg["labgrid"]["places"].items():
        dev = p.get("device")
        if dev and dev not in devs and dev != "-":
            errs.append(f"place {place}: unknown device {dev}")

    if not errs:
        print(f"OK: {len(devs)} devices, {len(subs)} subnets, "
              f"{len(cfg.get('topology', []))} links, {len(cfg['labgrid']['places'])} places, "
              f"{len(seen_macs)} unique MACs")
    for w in warns:
        print(f"WARN: {w}")
    for e in errs:
        print(f"ERROR: {e}")
    return 1 if errs else 0


def cmd_emit_exporter(cfg: dict) -> str:
    lines = ["## GENERATED from data/lab.yaml — DO NOT HAND-EDIT.",
             f"## regenerate: python3 scripts/lab_registry.py emit-exporter (updated {cfg['meta']['updated']})"]
    for place, p in cfg["labgrid"]["places"].items():
        dev = p.get("device")
        d = cfg["devices"].get(dev) if dev and dev != "-" else None
        lines.append(f"{place}:")
        power = p.get("power")
        if power and power != "none" and "/" in str(power):
            host, index = str(power).split("/")
            lines.append("  NetworkPowerPort:")
            lines.append("    model: conwrt_poe")
            lines.append(f"    host: {cfg['devices'][host]['mgmt']}")
            lines.append(f"    index: {index}")
        if d and d.get("mgmt"):
            lines.append("  NetworkService:")
            lines.append(f"    address: {d['mgmt']}")
            lines.append("    username: root")
    return "\n".join(lines) + "\n"


def sh(cmd: list[str], timeout=60) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()


def cmd_deploy_exporter(cfg: dict) -> int:
    host = cfg["labgrid"]["exporter"]["host"]
    remote_path = cfg["labgrid"]["exporter"]["config"].replace("~", "/root" if host == "ai-legion" else "~")
    # ai-legion exporter runs as root per pgrep evidence (/usr/local/bin/labgrid-exporter)
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(cmd_emit_exporter(cfg))
        tmp = f.name
    print(sh(["scp", "-q", tmp, f"{host}:{remote_path}.new"]))
    print(sh(["ssh", host, f"cp {remote_path} {remote_path}.bak && mv {remote_path}.new {remote_path} && "
                            "(systemctl --user restart conwrt-exporter 2>/dev/null || "
                            "systemctl restart conwrt-exporter 2>/dev/null || "
                            "pkill -f labgrid-exporter) && sleep 3 && pgrep -af labgrid-exporter | head -1"]))
    os.unlink(tmp)
    return 0


def cmd_reconcile(cfg: dict) -> int:
    """Read-only reality probe vs registry. Drift = exit 1."""
    drift = []
    switch = cfg["devices"]["gs1900-bench"]["mgmt"]
    # 1. bench switch uptime (self-reboot detection)
    up = sh(["ssh", "-o", "BatchMode=yes", f"root@{switch}", "uptime"])
    m = re.search(r"up (\d+) min", up)
    if m and int(m.group(1)) < 30:
        drift.append(f"gs1900-bench: uptime {m.group(1)}min — REBOOTED, failsafes likely DISARMED "
                     f"(re-run scripts/gs1900-bench-arm.sh)")
    # 2. per-device liveness: SSH banner or ARP on its mgmt subnet owner
    for name, d in cfg["devices"].items():
        mg = d.get("mgmt")
        if not isinstance(mg, str) or not mg:
            continue
        if d.get("state", "").startswith(("dark", "blocked", "rescue")):
            print(f"SKIP  {name}: state={d['state']} (blocked/dark by registry)")
            continue
        # probe from an L2/L3-adjacent host; never self-probe
        island = {"nr7101", "ap3915i-1", "ap3915i-2", "gangap", "gs1900-stock", "er6p"}
        via = cfg["devices"]["erx"]["mgmt"] if name in island else switch
        if mg == via:
            print(f"SKIP      {name}: {mg} (is the probe host)")
            continue
        r = sh(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", f"root@{via}",
                f"ip neigh show {mg} 2>/dev/null | head -1"], timeout=15)
        status = "REACHABLE" if ("lladdr" in r and "FAILED" not in r) else "STALE" if "STALE" in r else "NOT-SEEN"
        if status == "NOT-SEEN":
            drift.append(f"{name}: {mg} NOT-SEEN via root@{via}")
        print(f"{'DRIFT' if status == 'NOT-SEEN' else status:8} {name}: {mg}")
    # 3. labgrid places vs registry
    coord = cfg["labgrid"]["coordinator"]
    places_out = sh(["ssh", "-o", "BatchMode=yes", "ai-legion",
                     f"labgrid-client -x {coord} places 2>/dev/null"], timeout=20)
    live = {ln.split()[0] for ln in places_out.splitlines() if ln.strip() and ln.split()[0] not in ("Place", "Name", "—")}
    want = {p for p, pd in cfg["labgrid"]["places"].items() if not pd.get("disabled")}
    for p in sorted(want - live):
        drift.append(f"labgrid: place {p} in registry but NOT on coordinator")
    for p in sorted(live - want):
        print(f"WARN    labgrid: place {p} on coordinator but not in registry")
    print(("-- DRIFT --\n" + "\n".join(drift)) if drift else "NO DRIFT")
    return 1 if drift else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["validate", "emit-exporter", "deploy-exporter", "reconcile"])
    args = ap.parse_args()
    cfg = load()
    sys.exit({"validate": cmd_validate,
              "emit-exporter": lambda c: (print(cmd_emit_exporter(c)), 0)[1],
              "deploy-exporter": cmd_deploy_exporter,
              "reconcile": cmd_reconcile}[args.command](cfg))


if __name__ == "__main__":
    main()
