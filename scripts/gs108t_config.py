#!/usr/bin/env python3
"""gs108t_config — configure 802.1Q VLANs on the Netgear GS108T (S350 web UI).

Driven by data/lab.yaml (gs108t device entry: mgmt address + bays map).
Proven on GS108Tv2 firmware (factory default, admin/password) 2026-09-28.

Usage:
  gs108t_config.py inspect              # dump VLAN pages' DOM (selector discovery)
  gs108t_config.py plan                 # show what would be applied from lab.yaml
  gs108t_config.py apply                # create VLANs + set PVIDs (idempotent-ish)
  gs108t_config.py status               # read current VLAN table + PVIDs

Access: via SSH tunnel through the bench switch (default) or --tunnel-host.
Password from data/lab-secrets.yaml key gs108t_web (default "password").
"""
from __future__ import annotations
import argparse, os, re, subprocess, sys, time
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
BASE_LOCAL = 8095  # local tunnel port


def load_cfg():
    lab = Path(os.environ.get("CONWRT_LAB", REPO / "data")) / "lab.yaml"
    cfg = yaml.safe_load(lab.read_text())
    dev = cfg["devices"].get("gs108t")
    if not dev:
        sys.exit("gs108t not in lab.yaml")
    pw = "password"
    secrets = lab.parent / "lab-secrets.yaml"
    if secrets.exists():
        try:
            scfg = yaml.safe_load(secrets.read_text()) or {}
            pw = scfg.get("gs108t_web", pw)
        except Exception:
            pass
    return cfg, dev, pw


def tunnel(bench_mgmt: str):
    subprocess.run(["ssh", "-f", "-N", "-L", f"{BASE_LOCAL}:192.168.0.239:80",
                    "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
                    f"root@{bench_mgmt}"], check=False)
    time.sleep(1)


def with_browser(fn):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context()
        pg = ctx.new_page()
        out = fn(ctx, pg)
        b.close()
        return out


def login(ctx, pg, pw):
    base = f"http://127.0.0.1:{BASE_LOCAL}"
    pg.goto(base + "/", timeout=15000)
    time.sleep(1)
    pg.fill('input[name="pwd"]', pw)
    pg.click('input[name="login"]')
    time.sleep(3)
    return base


VLAN_CFG = "switching/dot1q/vlan_cfg.html"
VLAN_PORT = "switching/dot1q/vlan_port_cfg.html"  # PVID page


def desired(dev: dict) -> list[dict]:
    """[ {vlan: 82, untagged: [2], tagged: [1]}, ... ] from lab.yaml bays."""
    out = []
    for port, bay in (dev.get("bays") or {}).items():
        if port == "uplink":
            continue
        v = bay.get("vlan")
        if not v:
            continue
        out.append({"vlan": v, "untagged": [int(port.lstrip("p"))], "tagged": [1]})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["inspect", "plan", "apply", "status"])
    ap.add_argument("--no-tunnel", action="store_true", help="tunnel already up")
    args = ap.parse_args()
    cfg, dev, pw = load_cfg()
    want = desired(dev)
    print("desired VLANs:", want)
    if args.command == "plan":
        for w in want:
            print(f"  VLAN {w['vlan']}: port {w['untagged'][0]} untagged, uplink port 1 tagged "
                  f"(+ PVID {w['vlan']} on port {w['untagged'][0]})")
        return
    if not args.no_tunnel:
        tunnel(cfg["devices"]["gs1900-bench"]["mgmt"])
        print(f"tunnel up: 127.0.0.1:{BASE_LOCAL} -> gs108t:80")

    def run(ctx, pg):
        login(ctx, pg, pw)
        results = {}
        for name, path in [("vlan_cfg", VLAN_CFG), ("vlan_port", VLAN_PORT)]:
            pg.goto(f"http://127.0.0.1:{BASE_LOCAL}/{path}", timeout=15000)
            time.sleep(2)
            html = pg.content()
            results[name] = html
            open(f"/tmp/opencode/gs108t-{name}.html", "w").write(html)
            print(f"[{name}] {len(html)}b -> /tmp/opencode/gs108t-{name}.html")
            if args.command == "inspect":
                for m in re.findall(r"<(?:form|FORM)[^>]*>|<(?:input|INPUT|select|SELECT)[^>]{0,140}>|<td[^>]*>[^<]{0,30}</td>", html)[:40]:
                    print("   ", m.strip()[:150])
        return results

    with_browser(run)
    print("\nNOTE: apply mode is the next increment — after 'inspect' reveals the form "
          "shape, the selectors get baked in here (same pattern as configure-stock-switch.py).")


if __name__ == "__main__":
    main()
