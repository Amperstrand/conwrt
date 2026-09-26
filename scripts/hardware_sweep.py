#!/usr/bin/env python3
"""hardware_sweep — the jffs2 overlay-roulette A/B test on real AP3915i hardware.

Runs the same firstboot → timed-power-cut → classify cycle proven in QEMU
(overlay_roulette.py), but on real units via labgrid PoE control and the
v6 link-local channel. The QEMU rig proved ext4 absorbs all cuts; this is
where jffs2 gets tested.

Classification levels (from outside the unit):
  managed       — v6 alive, dropbear auth works, critical files present
  auth-dead     — v6 alive, TCP banner presents, every session closes at
                  auth (the UNIT2 killer: overlay lost the auth files)
  network-dead  — no v6, no ARP (unit not booting)
  partial       — auth works but critical files missing (new category)

Usage:
    python3 hardware_sweep.py --place ap-lan6 --cuts 8,25,45 --i-know
    python3 hardware_sweep.py --place ap-lan6 --cuts 8,25,45 --runs 2 --i-know

Safety: --i-know is mandatory (destructive: firstboot + timed power cuts),
reset_allowed=false places are refused, and the bench_adopt recovery
envelope (rom-audit, backup, overlay health) must pass before the first cut.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from bench_adopt import Place, load_places, load_labgrid_host  # noqa: E402

RESULTS = REPO_ROOT / "data" / "bench" / "hardware-sweep.jsonl"

SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]


def switch_ssh(switch_host: str, cmd: str, timeout: int = 60) -> tuple[int, str]:
    proc = subprocess.run(["ssh", *SSH_OPTS, f"root@{switch_host}", cmd],
                          capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout + proc.stderr


def switch_sh_script(switch_host: str, script: str, timeout: int = 90) -> str:
    """Feed a multi-line script to the switch via `ssh sh -s` (stdin)."""
    proc = subprocess.run(["ssh", *SSH_OPTS, f"root@{switch_host}", "sh -s"],
                          input=script, capture_output=True, text=True, timeout=timeout)
    return proc.stdout + proc.stderr


def labgrid_power(place: str, state: str, labgrid_host: str = "ai-legion") -> bool:
    cmd = (f'C=~/.local/bin/labgrid-client; X="-x 192.168.13.221:20408"; '
           f"$C $X -p {place} acquire >/dev/null 2>&1 && "
           f"$C $X -p {place} power {state} && "
           f"$C $X -p {place} release >/dev/null 2>&1 && echo POWER-{state.upper()}-OK")
    proc = subprocess.run(["ssh", *SSH_OPTS, labgrid_host, cmd],
                          capture_output=True, text=True, timeout=120)
    return f"POWER-{state.upper()}-OK" in proc.stdout


def classify_unit(place: "Place", switch_host: str) -> dict:
    """Classify from outside: v6 → TCP banner → auth → files.

    The verdict order matters: fleet members filter ICMPv6 (ping6 lies),
    so a dead ping6 alone is NEVER network-death — the TCP banner is an
    independent liveness channel that must run before the death verdict."""
    row: dict = {"place": place.name, "checked_at": time.strftime("%H:%M:%S")}

    # Layer 1: v6 aliveness (advisory — filtered echo is documented)
    rc, out = switch_ssh(switch_host,
                         f"ping6 -c2 -W2 -I switch.{place.vlan} {place.linklocal} "
                         ">/dev/null 2>&1 && echo V6-OK || echo V6-FAIL")
    v6_ok = "V6-OK" in out
    if v6_ok:
        row["v6"] = "alive"

    # Layer 2: TCP banner (dropbear listening) — independent channel
    rc, out = switch_ssh(switch_host,
                         f"nc {place.linklocal}%switch.{place.vlan} 22 </dev/null "
                         ">/tmp/hw-banner.out 2>&1 & N=$!; sleep 4; kill $N 2>/dev/null; "
                         "head -1 /tmp/hw-banner.out")
    if "SSH-2.0-dropbear" not in out:
        if not v6_ok:
            row["outcome"] = "network-dead"
            return row
        row["outcome"] = "no-dropbear"
        return row
    row["dropbear"] = "banner-present"

    # Layer 3: authentication (key auth from switch)
    rc, out = switch_ssh(switch_host,
                         f"dbclient -y -y -i /root/.ssh/id_ed25519 "
                         f"root@{place.linklocal}%switch.{place.vlan} "
                         "'echo AUTH-OK' </dev/null 2>&1 | grep -v Caution | head -2",
                         timeout=30)
    if "AUTH-OK" not in out:
        row["outcome"] = "auth-dead"
        row["detail"] = out.strip()[:200]
        return row
    row["auth"] = "key-works"

    # Layer 4: critical files present
    rc, out = switch_ssh(switch_host,
                         f"dbclient -y -y -i /root/.ssh/id_ed25519 "
                         f"root@{place.linklocal}%switch.{place.vlan} "
                         "'for f in /etc/shadow /etc/config/network /etc/config/dropbear "
                         "/etc/dropbear/authorized_keys; do [ -s \"$f\" ] && echo \"OK $f\" "
                         "|| echo \"MISSING $f\"; done; "
                         "dmesg | grep -iE \"jffs2.*orphan|jffs2.*unchecked|jffs2.*error\" | tail -3; "
                         "grep DISTRIB_RELEASE /etc/openwrt_release' </dev/null 2>&1 "
                         "| grep -v Caution",
                         timeout=30)
    missing = [l for l in out.splitlines() if "MISSING" in l]
    orphans = [l for l in out.splitlines() if "orphan" in l.lower() or "unchecked" in l.lower()]
    row["missing_files"] = missing if missing else []
    row["jffs2_debris"] = orphans[:3] if orphans else []
    row["release"] = next((l.split("=")[1].strip("'") for l in out.splitlines()
                           if "DISTRIB_RELEASE" in l), "?")

    if missing:
        row["outcome"] = "partial"
    else:
        row["outcome"] = "managed"
    return row


def run_cut_experiment(place: "Place", switch_host: str, t_cut: int,
                       run_n: int, labgrid_host: str) -> dict:
    """One experiment: firstboot → boot → cut at t_cut → boot → classify."""
    row: dict = {"t_cut": t_cut, "run": run_n,
                 "started_at": time.strftime("%H:%M:%S")}

    # Step 1: firstboot via v6 link-local (sync, RC-gated)
    rc, out = switch_ssh(switch_host,
                         f"DROPBEAR_PASSWORD='' dbclient -y -y "
                         f"root@{place.linklocal}%switch.{place.vlan} "
                         "'firstboot -y; echo FIRSTBOOT-RC=$?' </dev/null 2>&1 "
                         "| grep -v Caution | tail -2", timeout=30)
    if "FIRSTBOOT-RC=0" not in out:
        row["outcome"] = "firstboot-failed"
        row["detail"] = out.strip()[:200]
        return row

    # Every power transition is GATED: a dropped PoE manage or coordinator
    # hiccup that silently skips the cut would dress an ordinary boot up as
    # an overlay-corruption result and poison the sweep data.
    def powered(state: str, step: str) -> bool:
        if labgrid_power(place.name, state, labgrid_host):
            return True
        row["outcome"] = "power-control-failed"
        row["detail"] = f"labgrid power {state} failed at {step}"
        return False

    # Step 2: hard power cut (kills the session, expected)
    if not powered("off", "pre-boot cut"):
        return row
    time.sleep(3)

    # Step 3: power on, wait t_cut seconds, then hard cut
    if not powered("on", "timed-cut boot"):
        return row
    print(f"  booting... cutting at t={t_cut}s")
    time.sleep(t_cut)
    if not powered("off", f"t={t_cut}s cut"):
        return row
    time.sleep(3)

    # Step 4: power on, wait for boot to settle
    if not powered("on", "aftermath boot"):
        return row
    print(f"  aftermath boot, waiting 90s for settle...")
    time.sleep(90)

    # Step 5: classify
    row.update(classify_unit(place, switch_host))
    row["elapsed"] = time.strftime("%H:%M:%S")
    return row


def check_envelope(place: "Place", switch_host: str) -> None:
    """AGENTS reset-failsafe rule 1: this sweep firstboots units ON PURPOSE
    and then cuts power during overlay init — the exact auth-dead recipe —
    so the recovery envelope (ROM manageability proof, backup, overlay
    health) must be established BEFORE the first cut, not after."""
    from bench_adopt import (AdoptError, Runner, stage_backup, stage_overlay,
                             stage_rom_audit)
    evidence = REPO_ROOT / "data" / "bench" / place.name / \
        time.strftime("%Y%m%d-%H%M%S") / "sweep-envelope"
    r = Runner(lambda script: switch_sh_script(switch_host, script), place, evidence)
    stage_rom_audit(r)
    stage_backup(r)
    stage_overlay(r)
    print(f"[PASS] sweep envelope {place.name}: rom-audit + backup + overlay health")


def main(argv: list[str] | None = None) -> int:
    from bench_adopt import AdoptError, Place

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--place", required=True)
    ap.add_argument("--places", type=Path,
                    default=REPO_ROOT / "data/bench/places.json")
    ap.add_argument("--switch", default="192.168.13.2")
    ap.add_argument("--cuts", default="8,25,45", help="cut timings in seconds")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--i-know", action="store_true",
                    help="required: the sweep firstboots the DUT and cuts "
                         "power during overlay init (destructive experiment)")
    args = ap.parse_args(argv)

    if not args.i_know:
        print("refusing destructive sweep without --i-know "
              "(firstboot + timed power cuts)")
        return 2

    places = load_places(args.places)
    if args.place not in places:
        print(f"unknown place {args.place}; known: {sorted(places)}")
        return 2
    place = places[args.place]
    if not place.reset_allowed:
        print(f"refusing: {args.place} is reset_allowed=false "
              "(TFTP-dependent unit — the sweep would destroy its only door)")
        return 2
    labgrid_host = load_labgrid_host(args.places)

    try:
        check_envelope(place, args.switch)
    except AdoptError as err:
        print(f"[FAIL] recovery envelope not established — sweep refused:\n{err}")
        return 1

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    for t_cut in [int(x) for x in args.cuts.split(",")]:
        for run_n in range(args.runs):
            print(f"\n=== cut at {t_cut}s, run {run_n + 1}/{args.runs} ===")
            row = run_cut_experiment(place, args.switch, t_cut, run_n, labgrid_host)
            with RESULTS.open("a") as fh:
                fh.write(json.dumps(row) + "\n")
            print(f"  outcome: {row['outcome']}")
            if row["outcome"] == "auth-dead":
                print(f"  *** AUTH-DEAD reproduced — the UNIT2 killer ***")
                print(f"  detail: {row.get('detail', '')[:120]}")

    print(f"\nresults: {RESULTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
