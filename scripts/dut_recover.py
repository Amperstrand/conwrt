#!/usr/bin/env python3
"""dut_recover.py — one-command recovery-mode flash of a wedged/dark DUT
through a bench rig router (ER6P bay pattern), with adoption.

Collapses the 2026-09-28 X1860 recovery arc (docs/gotchas.md, issue #28)
into a single command so an LLM or human session costs a few hundred tokens
instead of a full investigation.

Facts baked in (do NOT re-derive — they cost a session to learn):
  - Recovery-mode firmware does NOT answer ICMP. Probe TCP/HTTP only.
  - Steady red LED = wedged/bootloop (dead stack, zero frames). The operator
    must re-enter recovery: hold reset pin UNDER the device while powering
    on, ~10-12s until the LED blinks red.
  - Blinking red = recovery HTTP server is LIVE at recovery_ip.
  - A fresh OpenWrt DUT is an armed rogue (DHCP+RA on). We disarm before
    anything else can share its segment.
  - A reflash regenerates dropbear host keys: clear known_hosts before SSH.

Usage:
  # full flow: stage + watcher + wait for operator reset + flash + adopt
  python3 scripts/dut_recover.py \
      --model-id dlink-covr-x1860-a1 \
      --rig root@192.168.13.4 --bay br-lan.401 \
      --image data/openwrt-24.10.7-x1860-recovery.bin \
      --pubkey ~/.ssh/id_ed25519.pub

  # stage the watcher, return immediately (flash auto-fires when the
  # operator performs the reset dance; check later with --status)
  python3 scripts/dut_recover.py ... --stage-only
  python3 scripts/dut_recover.py --status --rig root@192.168.13.4

Recovery parameters (recovery_ip, upload endpoint/field, timings, reset
instructions) come from models/<model_id>.json — the single source of truth.
Never hardcode them here or re-derive them by probing.
"""
import argparse
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCHER = r"""#!/bin/sh
# pushed by dut_recover.py — polls recovery server, uploads once, logs, exits
RIP="__RIP__"
ENDPOINT="__ENDPOINT__"
FIELD="__FIELD__"
IMG=/tmp/dut-recovery.bin
LOG=/tmp/dut-flash.log
echo "$(date) watcher armed: polling http://$RIP/" >> $LOG
i=0
while [ $i -lt __LOOPS__ ]; do
  code=$(curl -m 2 -s -o /dev/null -w '%{http_code}' http://$RIP/ 2>/dev/null)
  if [ -n "$code" ] && [ "$code" != "000" ]; then
    echo "$(date) RECOVERY UP (HTTP $code) - uploading $IMG" >> $LOG
    curl -m 400 -s -F "$FIELD=@$IMG" -o /tmp/dut-upload-result \
         -w 'upload HTTP %{http_code}' http://$RIP$ENDPOINT >> $LOG 2>&1
    echo "" >> $LOG; echo "$(date) UPLOAD DONE" >> $LOG
    exit 0
  fi
  sleep 2
  i=$((i+1))
done
echo "$(date) watcher expired, recovery server never appeared" >> $LOG
"""


def run(cmd, timeout=60, check=True, quiet=False):
    if not quiet:
        print(f"  $ {' '.join(cmd)}", file=sys.stderr)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        print(f"FAILED: {' '.join(cmd)}\n{r.stderr.strip()[:400]}", file=sys.stderr)
        sys.exit(1)
    return r.stdout.strip()


def ssh(rig, cmd, timeout=60, check=True):
    return run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", rig, cmd],
               timeout=timeout, check=check, quiet=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--model-id", help="models/<id>.json for recovery parameters")
    ap.add_argument("--rig", default="root@192.168.12.4",
                    help="SSH target of the rig router (default: the ER6P at 192.168.12.4)")
    ap.add_argument("--bay", default="br-lan.401",
                    help="rig interface facing the DUT (default: ER6P port-2 bay)")
    ap.add_argument("--image", help="recovery image (recovery.bin variant, NOT factory.bin)")
    ap.add_argument("--pubkey", help="public key to install during adoption")
    ap.add_argument("--stage-only", action="store_true",
                    help="arm the watcher and exit; flash auto-fires on recovery")
    ap.add_argument("--status", action="store_true", help="show watcher/log state and exit")
    ap.add_argument("--from-lab", dest="from_lab", metavar="DEVICE_ID",
                    help="resolve --rig/--bay/image hints from the lab registry "
                         "(CONWRT_LAB env or data/lab.yaml)")
    args = ap.parse_args()

    if args.status:
        print(ssh(args.rig, "pgrep -f '[d]ut-autoflash' >/dev/null "
                            "&& echo WATCHER-RUNNING || echo WATCHER-DONE; "
                            "cat /tmp/dut-flash.log 2>/dev/null"))
        return

    if args.from_lab:
        import yaml, os
        lab = Path(os.environ.get("CONWRT_LAB", REPO / "data")) / "lab.yaml"
        cfg = yaml.safe_load(lab.read_text())
        d = cfg["devices"].get(args.from_lab) or sys.exit(f"--from-lab: unknown device {args.from_lab}")
        if not args.rig or args.rig == "root@192.168.12.4":
            rig_dev = d.get("wired", {})
            parent = next(iter(rig_dev), None) if rig_dev else None
            if parent and parent in cfg["devices"]:
                args.rig = "root@" + cfg["devices"][parent]["mgmt"]
                print(f"[from-lab] rig={args.rig} (parent {parent})")
        if args.model_id is None:
            args.model_id = d.get("model")
            print(f"[from-lab] model-id={args.model_id}")
    if not args.model_id or not args.image:
        ap.error("--model-id and --image are required (unless --status)")

    # 1. Model JSON is the source of truth for every recovery parameter.
    mpath = os.path.join(REPO, "models", f"{args.model_id}.json")
    m = json.load(open(mpath))
    r = m["flash_methods"]["recovery-http"]
    rip, cip = r["recovery_ip"], r["client_ip"]
    oip = r.get("openwrt_client_ip", "192.168.1.254")  # alias to reach post-boot DUT
    dut_ip = "192.168.1.1"  # fresh OpenWrt default; probe via $oip alias
    print(f"[1/6] model {args.model_id}: recovery={rip} upload={r['upload_endpoint']} "
          f"(field '{r['upload_field']}') flash~{r.get('flash_time_seconds', 300)}s")

    # 2. Rig + bay sanity: the bay needs a same-subnet alias so the DUT
    #    (no gateway) can answer. Use the model's client_ip.
    print(f"[2/6] rig {args.rig} bay {args.bay}")
    out = ssh(args.rig, f"ip -4 addr show {args.bay} | grep -q '{cip}/' "
                        f"&& echo alias-ok || echo alias-missing")
    if out == "alias-missing":
        print(f"  adding client alias {cip}{r.get('client_subnet','/255.255.255.0')} on {args.bay}")
        ssh(args.rig, f"ip addr add {cip}/24 dev {args.bay} 2>/dev/null; true")
    # Post-boot alias (fresh OpenWrt at 192.168.1.1 needs a 192.168.1.x source)
    ssh(args.rig, f"ip addr add {oip}/24 dev {args.bay} 2>/dev/null; true")

    # 3. Recovery server already live? (blinking red = someone already did the dance)
    live = ssh(args.rig, f"curl -m 2 -s -o /dev/null -w '%{{http_code}}' http://{rip}/")
    if live not in ("000", ""):
        print(f"[3/6] recovery server ALREADY LIVE (HTTP {live}) — flashing now")
    else:
        print("[3/6] recovery server not responding (normal while wedged)")
        print("\n  >>> OPERATOR ACTION — give the DUT the reset dance:\n")
        for line in (r.get("reset_instructions") or "").split(". "):
            if line.strip():
                print(f"      * {line.strip().rstrip('.')}")

    # 4. Stage image + watcher (idempotent).
    print(f"[4/6] staging image {args.image}")
    run(["scp", "-O", "-q", args.image, f"{args.rig}:/tmp/dut-recovery.bin"])
    script = (WATCHER.replace("__RIP__", rip)
                     .replace("__ENDPOINT__", r["upload_endpoint"])
                     .replace("__FIELD__", r["upload_field"])
                     .replace("__LOOPS__", "600"))  # 20 min
    run(["ssh", "-o", "BatchMode=yes", args.rig,
         f"cat > /tmp/dut-autoflash.sh <<'WEOF'\n{script}WEOF\n"
         "chmod +x /tmp/dut-autoflash.sh; "
         "pkill -f '[d]ut-autoflash' 2>/dev/null; "
         "rm -f /tmp/dut-flash.log; "
         "setsid /tmp/dut-autoflash.sh >/dev/null 2>&1 & sleep 1; "
         "pgrep -f '[d]ut-autoflash' >/dev/null && echo WATCHER-ARMED"])
    if args.stage_only:
        print("[5/6] --stage-only: watcher armed. The flash fires when recovery "
              "comes up. Re-run with --status later.")
        return

    # 5. Wait for upload + first boot. Do NOT busy-poll faster than this.
    print("[5/6] waiting for recovery + flash (watcher fires automatically)…")
    flash_s = int(r.get("flash_time_seconds", 300))
    deadline = time.time() + 25 * 60
    while time.time() < deadline:
        log = ssh(args.rig, "cat /tmp/dut-flash.log 2>/dev/null", check=False)
        if "UPLOAD DONE" in log:
            print(f"  upload complete: {log.strip().splitlines()[-2:]}")
            break
        if "expired" in log:
            print("  watcher expired — recovery never appeared"); sys.exit(1)
        time.sleep(10)
    else:
        print("  timeout waiting for flash"); sys.exit(1)
    print(f"  waiting {flash_s}s flash + first boot…")
    time.sleep(flash_s + 90)

    # 6. Verify + adopt. Clear stale host keys FIRST (reflash regenerates them).
    print(f"[6/6] verifying {dut_ip} and adopting")
    run(["ssh-keygen", "-f", os.path.expanduser("~/.ssh/known_hosts"), "-R", dut_ip],
        check=False)
    for _ in range(30):
        up = ssh(args.rig, f"curl -m 3 -s -o /dev/null -w '%{{http_code}}' http://{dut_ip}/",
                 check=False)
        if up == "200":
            break
        time.sleep(15)
    else:
        print(f"  WARNING: {dut_ip} not serving HTTP yet — check manually")
    adopt = run(["ssh", "-J", args.rig, "-o", "BatchMode=yes",
                 "-o", "StrictHostKeyChecking=accept-new",
                 f"root@{dut_ip}",
                 "ubus call system board | grep -E '\"model\"|\"version\"'; "
                 "uci set dhcp.lan.ignore='1'; uci set dhcp.lan.ra='disabled'; "
                 "uci set dhcp.lan.dhcpv6='disabled'; uci commit dhcp; "
                 f"echo \"readback ignore=$(uci get dhcp.lan.ignore) "
                 f"ra=$(uci get dhcp.lan.ra)\"; "
                 "/etc/init.d/dnsmasq restart 2>/dev/null; "
                 "/etc/init.d/odhcpd restart 2>/dev/null"], check=False)
    print("  " + adopt.replace("\n", "\n  "))
    if args.pubkey:
        pub = open(os.path.expanduser(args.pubkey)).read().strip()
        run(["ssh", "-J", args.rig, "-o", "BatchMode=yes", f"root@{dut_ip}",
             f"mkdir -p /etc/dropbear; echo '{pub}' >> /etc/dropbear/authorized_keys; "
             "chmod 600 /etc/dropbear/authorized_keys; echo KEY-INSTALLED"])
    mac = ssh(args.rig, f"ip neigh show dev {args.bay} | grep {dut_ip} "
                        f"| grep -oE '[0-9a-f:]{{17}}' | head -1", check=False)
    inv = {"model": m.get("model") or args.model_id, "mac_addresses": [mac] if mac else [],
           "firmware_version": "OpenWrt (recovery-reflashed via dut_recover.py)",
           "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "notes": f"Recovery-flashed via rig {args.rig} bay {args.bay}; "
                    f"rogue dhcp/ra disarmed; keyed" if args.pubkey else ""}
    print("\nINVENTORY-LINE:\n" + json.dumps(inv))


if __name__ == "__main__":
    main()
