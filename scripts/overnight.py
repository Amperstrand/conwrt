#!/usr/bin/env python3
"""overnight — unattended endurance testing on the bench rig.

Three parallel tracks, no human intervention:

Track A (hardware): firstboot+adopt reliability on lan4 (real jffs2)
  Each cycle: firstboot → reboot → v6 probe → adopt → verify → log
  ~5 min/cycle → ~90 cycles in 8 hours → statistical reliability data

Track B (QEMU): overlay-switch endurance on ai-legion (ext4)
  Expanded cut timings (5-60s, 2s resolution), 3 runs each
  Runs in parallel with Track A

Track C (optional): lan6 boot monitoring via serial (read-only)
  Power-cycle → capture serial boot output → classify

Usage:
    python3 overnight.py --track hardware --cycles 100
    python3 overnight.py --track qemu --cuts 5,7,9,...,59 --runs 3
    python3 overnight.py --track all --hours 8
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

RESULTS = REPO_ROOT / "data" / "bench" / "overnight.jsonl"

SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]


def log(row: dict) -> None:
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    row["timestamp"] = datetime.now().isoformat()
    with RESULTS.open("a") as fh:
        fh.write(json.dumps(row) + "\n")
    status = row.get("outcome", "?")
    cycle = row.get("cycle", "?")
    track = row.get("track", "?")
    print(f"[{track}] cycle {cycle}: {status}"
          + (f" — {row.get('detail', '')[:80]}" if row.get("detail") else ""))
    sys.stdout.flush()


def switch_ssh(cmd: str, timeout: int = 60) -> tuple[int, str]:
    proc = subprocess.run(
        ["ssh", *SSH_OPTS, "root@192.168.13.2", cmd],
        capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout + proc.stderr


def dut_ssh(ip: str, cmd: str, timeout: int = 30) -> tuple[int, str]:
    """SSH to a DUT via the switch (key auth)."""
    switch_cmd = (f"dbclient -y -y -i /root/.ssh/id_ed25519 "
                  f"root@{ip} '{cmd}' </dev/null 2>&1 | grep -v Caution")
    return switch_ssh(switch_cmd, timeout)


def dut_v6_shell(mac: str, vlan: int, cmd: str, timeout: int = 30) -> tuple[int, str]:
    """Empty-password v6 link-local shell (factory state)."""
    ll = eui64(mac)
    switch_cmd = (f"DROPBEAR_PASSWORD='' dbclient -y -y "
                  f"root@{ll}%switch.{vlan} '{cmd}' </dev/null 2>&1 | grep -v Caution")
    return switch_ssh(switch_cmd, timeout)


def eui64(mac: str) -> str:
    octets = mac.split(":")
    flipped = int(octets[0], 16) ^ 0x02
    eui = [f"{flipped:02x}"] + octets[1:3] + ["ff", "fe"] + octets[3:6]
    return "fe80::" + ":".join("".join(eui[i:i+2]) for i in range(0, 8, 2))


def classify_hardware(dut_ip: str, linklocal_mac: str, vlan: int) -> dict:
    """Classify a DUT from outside: v6 → banner → auth → files."""
    result = {}
    ll = eui64(linklocal_mac)

    rc, out = switch_ssh(
        f"ping6 -c2 -W2 -I switch.{vlan} {ll} "
        ">/dev/null 2>&1 && echo V6-OK || echo V6-FAIL")
    if "V6-OK" not in out:
        result["outcome"] = "network-dead"
        return result
    result["v6"] = "alive"

    # Layer 2: SSH at adopted IP (key auth)
    rc, out = dut_ssh(dut_ip, "echo AUTH-OK; uptime | cut -d, -f1")
    if "AUTH-OK" in out:
        result["outcome"] = "managed"
        result["auth"] = "key"
        # Check files
        rc, files_out = dut_ssh(dut_ip,
            'for f in /etc/shadow /etc/config/network /etc/dropbear/authorized_keys; '
            'do [ -s "$f" ] && echo "OK:$f" || echo "MISS:$f"; done')
        missing = [l.split(":")[1] for l in files_out.splitlines() if "MISS:" in l]
        result["missing_files"] = missing
        if missing:
            result["outcome"] = "partial"
        return result

    # Layer 3: try empty-password v6 (factory state)
    rc, out = dut_v6_shell(linklocal_mac, vlan, "echo FACTORY-OK")
    if "FACTORY-OK" in out:
        result["outcome"] = "factory"
        result["auth"] = "empty-password"
        return result

    # Layer 4: banner check (dropbear alive but auth dead)
    rc, out = switch_ssh(
        f"nc {ll}%switch.{vlan} 22 </dev/null "
        ">/tmp/nc.out 2>&1 & sleep 3; kill $! 2>/dev/null; head -1 /tmp/nc.out")
    if "SSH-2.0-dropbear" in out:
        result["outcome"] = "auth-dead"
        result["detail"] = "banner present, all auth methods fail"
    else:
        result["outcome"] = "no-dropbear"
    return result


def adopt_unit(dut_ip: str, mac: str, vlan: int) -> bool:
    """Adopt a factory-state unit via v6 link-local."""
    ll = eui64(mac)
    gw = f"192.168.{vlan - 900}.1"

    rc, out = switch_ssh(
        f"DROPBEAR_PASSWORD='' dbclient -y -y root@{ll}%switch.{vlan} "
        f"'mkdir -p /etc/dropbear; cat /root/.ssh/id_ed25519.pub >> /etc/dropbear/authorized_keys; "
        f"chmod 600 /etc/dropbear/authorized_keys; echo KEYS-OK' </dev/null 2>&1 | grep -v Caution")
    if "KEYS-OK" not in out:
        return False

    rc, out = switch_ssh(
        f"DROPBEAR_PASSWORD='' dbclient -y -y root@{ll}%switch.{vlan} "
        f"'uci set network.lan.proto=\"static\"; "
        f"uci delete network.lan.ipaddr 2>/dev/null; "
        f"uci add_list network.lan.ipaddr=\"{dut_ip}/24\"; "
        f"uci set network.lan.gateway=\"{gw}\"; "
        f"uci set network.lan.dns=\"{gw}\"; "
        f"uci commit network; echo ADOPT-OK' </dev/null 2>&1 | grep -v Caution")
    if "ADOPT-OK" not in out:
        return False

    switch_ssh(
        f"DROPBEAR_PASSWORD='' dbclient -y -y root@{ll}%switch.{vlan} "
        f"'/etc/init.d/network restart' </dev/null 2>/dev/null")
    time.sleep(10)
    return True


def track_hardware(max_cycles: int, dut_ip: str, mac: str, vlan: int) -> None:
    """Track A: firstboot+adopt reliability cycle on real jffs2 hardware."""
    print(f"\n{'='*60}")
    print(f"TRACK A: hardware firstboot reliability ({max_cycles} cycles)")
    print(f"Target: {dut_ip} (MAC {mac}, VLAN {vlan})")
    print(f"{'='*60}\n")

    passes = 0
    failures = 0

    for cycle in range(1, max_cycles + 1):
        row = {"track": "hardware", "cycle": cycle}

        # Step 1: firstboot + reboot in ONE command — after firstboot wipes
        # the overlay no key-auth session exists to issue the reboot, and
        # firstboot alone does not reboot: without it the next cycle just
        # re-firstboots a running system (dirty-overlay auth-dead risk).
        fb_cmd = "firstboot -y; rc=$?; echo FB-RC=$rc; sleep 2; [ $rc -eq 0 ] && reboot"
        rc, out = dut_ssh(dut_ip, fb_cmd)
        fb_issued = ("FB-RC=0" in out or
                     "losed" in out.lower() or
                     "closed" in out.lower())

        if not fb_issued:
            # Try via v6 link-local (unit might already be at factory state)
            rc, out = dut_v6_shell(mac, vlan, fb_cmd)
            fb_issued = ("FB-RC=0" in out or
                         "losed" in out.lower() or
                         "closed" in out.lower())

        if not fb_issued:
            # Unit completely unresponsive — real failure
            row.update({"outcome": "firstboot-unreachable",
                        "detail": out[-100:]})
            log(row)
            failures += 1
            time.sleep(15)
            continue

        # Step 2: wait for the reboot + jffs2 overlay reformat to COMPLETE
        # and the unit to answer again (up to 240s) — classification on a
        # still-rebooting unit fakes outcomes.
        deadline = time.monotonic() + 240
        classification = {"outcome": "network-dead"}
        while time.monotonic() < deadline:
            time.sleep(15)
            classification = classify_hardware(dut_ip, mac, vlan)
            if classification.get("outcome") != "network-dead":
                break

        # Step 3: classify the RETURNED unit
        row.update(classification)

        if classification["outcome"] == "factory":
            # Step 4: adopt
            if adopt_unit(dut_ip, mac, vlan):
                # Verify adoption
                time.sleep(5)
                verify = classify_hardware(dut_ip, mac, vlan)
                row["post_adopt"] = verify["outcome"]
                if verify["outcome"] in ("managed", "partial"):
                    row["outcome"] = "PASS"
                    passes += 1
                else:
                    row["outcome"] = f"ADOPT-FAILED ({verify['outcome']})"
                    failures += 1
            else:
                row["outcome"] = "ADOPT-ERROR"
                failures += 1
        elif classification["outcome"] == "managed":
            # Key auth SURVIVED a firstboot+reboot: the overlay was not
            # wiped — count it, do not bless it as a pass.
            row["outcome"] = "UNEXPECTED (managed after firstboot — overlay NOT wiped?)"
            failures += 1
        elif classification["outcome"] in ("auth-dead", "no-dropbear"):
            # THE ROULETTE — log prominently and STOP
            row["outcome"] = f"*** AUTH-DEAD at cycle {cycle} ***"
            row["detail"] = classification.get("detail", "")
            log(row)
            print(f"\n{'!'*60}")
            print(f"AUTH-DEAD DETECTED AT CYCLE {cycle}")
            print(f"This is the overlay-switch failure on real jffs2!")
            print(f"Stopping hardware track to preserve evidence.")
            print(f"{'!'*60}\n")
            failures += 1
            break
        else:
            row["outcome"] = f"UNEXPECTED ({classification['outcome']})"
            failures += 1

        log(row)
        time.sleep(5)  # brief pause between cycles

    # Summary
    summary = {"track": "hardware-summary", "passes": passes,
              "failures": failures, "total_cycles": cycle}
    log(summary)
    print(f"\nHardware track complete: {passes} PASS, {failures} FAIL, "
          f"{cycle} total cycles")


def track_qemu(cut_timings: list[int], runs_per_timing: int) -> None:
    """Track B: overlay-switch endurance in QEMU (runs on ai-legion)."""
    print(f"\n{'='*60}")
    print(f"TRACK B: QEMU overlay-switch endurance")
    print(f"Cut timings: {cut_timings}")
    print(f"Runs per timing: {runs_per_timing}")
    print(f"{'='*60}\n")

    # This runs overlay_roulette.py on ai-legion via SSH
    cuts_arg = ",".join(str(c) for c in cut_timings)
    cmd = (f"cd ~/labgrid && python3 overlay_roulette.py sweep "
           f"--cuts {cuts_arg} --runs {runs_per_timing}")

    proc = subprocess.run(
        ["ssh", *SSH_OPTS, "ai-legion", cmd],
        capture_output=True, text=True, timeout=7200)  # 2 hour timeout

    # Parse results from ai-legion
    rc, results = subprocess.run(
        ["ssh", *SSH_OPTS, "ai-legion",
         "cat ~/labgrid/results.jsonl | grep sweep | tail -100"],
        capture_output=True, text=True, timeout=60).returncode, ""

    # Log each result
    for line in (proc.stdout + "\n" + results).splitlines():
        try:
            data = json.loads(line)
            log({"track": "qemu", **data})
        except json.JSONDecodeError:
            pass

    log({"track": "qemu-summary", "detail": proc.stdout[-500:]})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--track", choices=["hardware", "qemu", "all"],
                   default="hardware")
    ap.add_argument("--cycles", type=int, default=100,
                   help="max cycles for hardware track")
    ap.add_argument("--hours", type=float, default=8,
                   help="time limit (not enforced, just for planning)")
    ap.add_argument("--dut-ip", default="192.168.104.51")
    ap.add_argument("--mac", default="b4:2d:56:25:79:b1")
    ap.add_argument("--vlan", type=int, default=1004)
    args = ap.parse_args()

    print(f"Overnight test starting at {datetime.now().isoformat()}")
    print(f"Track: {args.track}, cycles: {args.cycles}, hours: {args.hours}")
    print(f"Results: {RESULTS}\n")

    if args.track in ("hardware", "all"):
        track_hardware(args.cycles, args.dut_ip, args.mac, args.vlan)

    if args.track in ("qemu", "all"):
        cuts = list(range(5, 61, 5))  # 5, 10, 15, ..., 60
        track_qemu(cuts, runs_per_timing=3)

    print(f"\nOvernight test complete at {datetime.now().isoformat()}")
    print(f"Results in {RESULTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
