#!/usr/bin/env python3
"""preflight-flash — executable pre-flight gate for flash/destructive-write campaigns.

Encodes the incident-derived assumptions from the MF286D campaign (and the
bench history behind AGENTS.md): every check below maps to a real failure
that cost hours or a device. A single FAIL blocks the operation (exit 2).
WARN does not block but must be dispositioned in the run log.

Usage:
  python3 scripts/preflight-flash.py --config preflight.json
  python3 scripts/preflight-flash.py --config preflight.json --json   # machine output

Config (JSON) — see scripts/preflight-flash.example.json:
{
  "nic": "enx00e04c3e7b58",
  "recovery_ip": "192.0.0.1",          # fence bind; must exist on exactly ONE host iface
  "device_ip": "192.168.32.1",         # device management address (verify-alive)
  "device_mac": "c8:ea:f8:00:07:8d",   # specimen gate (AGENTS.md MAC/serial rule)
  "payload": {"path": "...", "sha256": "...", "size": 393216,
               "expect_magic": {"offset": 0, "hex": "55424923", "what": "UBI# EC header"}},
  "rollback": {"path": "...", "sha256": "..."},
  "fence": {"port": 69, "rrq_probe": true},
  "exfil": {"url": "http://192.168.32.2:8080/log", "verb": "PUT", "test_payload": "preflight-probe"},
  "serial": {"attached": false, "waiver_reason": "RAM-boot path only; no boot-media write"},
  "watch_log": "/path/to/watch.log",    # must have a fresh heartbeat (mtime)
  "watch_max_age_s": 120
}

Incident → check mapping (2026-11 MF286D campaign unless noted):
  duplicate recovery IP on two ifaces ... session-4 recovery-window loss
  host firewall dropping udp/69 ......... session-4 "silent serving" root cause
  untested exfil verb (501 on PUT) ...... device-2 brick: script ran blind
  monitor logging errors only ........... the invisible 14-minute fix window
  zeros instead of trigger UBI .......... magic/invariant gate (payload)
  wrong unit on the cable ............... AGENTS.md specimen gate (MAC)
  fence not actually answering .......... bench fence wedge, session-4 #6
  no verify-alive before reboot ......... device-2 brick (rules 9/10)
"""
import argparse, hashlib, json, socket, struct, subprocess, sys, time, os, urllib.request

RESULTS = []
def check(name, status, detail=""):
    RESULTS.append({"check": name, "status": status, "detail": detail})
    mark = {"PASS": "✔", "FAIL": "✘", "WARN": "!", "SKIP": "-", "INFO": "·"}[status]
    print(f"  [{mark}] {name:42s} {detail}")
    return status == "PASS"

def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception as e:
        return ""

def ip_out(cmd):
    return sh(cmd)

def run(cfg, args):
    fails = warns = 0
    print("== interface & network ==")
    nic = cfg.get("nic", "")
    rip = cfg.get("recovery_ip", "")
    dip = cfg.get("device_ip", "")

    # 1. NIC exists and is up
    state = ip_out(f"ip link show {nic} 2>/dev/null | grep -o 'state [A-Z]*' | head -1")
    if not ip_out(f"ip link show {nic}"):
        check("nic exists", "FAIL", f"{nic} not present"); fails += 1
    else:
        check("nic exists", "PASS", nic)
        up = "state UP" in state
        if not up:
            check("nic state UP (carrier)", "WARN", f"{state or 'no state'} — nothing connected?"); warns += 1
        else:
            check("nic state UP (carrier)", "PASS")

    # 2. recovery IP bound EXACTLY once on the host (duplicate-IP = ARP ambiguity, session-4)
    holders = []
    cur = None
    for line in ip_out("ip -4 addr show").splitlines():
        ls = line.strip()
        if ls and ls[0].isdigit() and ":" in ls:
            cur = ls.split(":")[1].strip().split("@")[0].split(":")[0]
        if ls.startswith("inet ") and (f" {rip}/" in ls or ls.startswith(f"inet {rip}/")):
            holders.append(cur or ls.split()[-1])
    if len(holders) == 1 and holders[0] == nic:
        check("recovery IP unique + on campaign NIC", "PASS", f"{rip} only on {nic}")
    else:
        check("recovery IP unique + on campaign NIC", "FAIL",
              f"{rip} on {holders or 'NOTHING'} (need exactly [{nic}] — duplicate = ARP race)"); fails += 1

    # 3. device subnet reachable via campaign NIC only
    if dip:
        route = ip_out(f"ip route get {dip} 2>/dev/null").split()
        dev = route[route.index("dev")+1] if "dev" in route else "?"
        if dev == nic:
            check("device subnet routed via campaign NIC", "PASS", f"{dip} dev {dev}")
        else:
            check("device subnet routed via campaign NIC", "FAIL",
                  f"{dip} routes via {dev}, not {nic} — replies will leave the wrong interface"); fails += 1

    # 4. no FOREIGN tftp/dhcp listener stealing the fence (fence ownership)
    fence_port = cfg.get("fence", {}).get("port", 69)
    own, foreign = [], []
    for l in sh(f"ss -ulnp | grep ':{fence_port}\\b' || true").splitlines():
        import re as _re
        m = _re.search(r"pid=(\d+)", l)
        cmd = sh(f"tr '\\0' ' ' < /proc/{m.group(1)}/cmdline") if m else ""
        (own if ("flashd" in cmd or "tftp" in cmd.lower()) else foreign).append(cmd or l[:70])
    if own:
        check("fence :%d listener present" % fence_port, "PASS", own[0][:90])
    elif foreign:
        check("fence :%d listener present" % fence_port, "FAIL",
              f"foreign listener owns :{fence_port}: {foreign[0][:100]}"); fails += 1
    else:
        check("fence :%d listener present" % fence_port, "FAIL", "no fence listening"); fails += 1
    dhcp69 = sh(f"ss -ulnp | grep ':67\\b' | grep '{nic}' || true")
    check("DHCP authority on NIC (≤1)", "PASS" if dhcp69.count("dnsmasq") <= 1 else "FAIL",
          "one authority" if dhcp69 else "none (fine if not needed)"); fails += 0 if dhcp69.count("dnsmasq") <= 1 else 1

    # 5. host firewall must not eat fence traffic (session-4 root cause: ufw INPUT DROP)
    ufw = sh("ufw status 2>/dev/null | head -1")
    if "active" in ufw.lower():
        rule = sh(f"ufw status | grep -i '69/udp' | head -1")
        check("firewall allows udp/69 (ufw active!)", "PASS" if rule else "FAIL",
              rule or "ufw ACTIVE with no 69/udp allow — fence RRQs will be DROPPED")
        fails += 0 if rule else 1
    else:
        check("firewall (ufw)", "INFO", ufw or "inactive/absent")

    # 6. fence answers a REAL RRQ (probe) — proves serving, not just listening
    if cfg.get("fence", {}).get("rrq_probe"):
        import shutil
        if not shutil.which("tftp"):
            check("fence answers probe RRQ", "SKIP", "tftp client not installed (apt: tftp-hpa)")
        else:
            probe = sh(f"timeout 5 tftp {rip} -c get preflight-probe 2>&1 | tail -2")
            served = ("error" not in probe.lower() and "timed out" not in probe.lower())
            check("fence answers probe RRQ", "PASS" if served else "WARN", probe[:80]); warns += not served

    # 7. PHY sanity: partner advertisement (10baseT-only = uninitialized peer — informative)
    link = sh(f"ethtool {nic} 2>/dev/null | grep -E 'Speed|Link detected' | tr '\\n' ' '")
    if "10Mb/s" in link:
        check("PHY negotiation", "WARN", "partner advertises 10baseT-only (uninitialized device PHY — expected at U-Boot prompt)"); warns += 1
    else:
        check("PHY negotiation", "INFO", link or "n/a")

    print("== payload & rollback ==")
    p = cfg.get("payload", {})
    if p.get("path"):
        if not os.path.exists(p["path"]):
            check("payload exists", "FAIL", p["path"]); fails += 1
        else:
            data = open(p["path"], "rb").read()
            h = hashlib.sha256(data).hexdigest()
            check("payload sha256 pinned", "PASS" if h == p.get("sha256") else "FAIL",
                  f"{'match' if h == p.get('sha256') else 'MISMATCH'} {h[:16]}…")
            fails += h != p.get("sha256")
            if p.get("size"):
                check("payload size exact", "PASS" if len(data) == p["size"] else "FAIL",
                      f"{len(data)} vs pinned {p['size']}"); fails += len(data) != p["size"]
            m = p.get("expect_magic")
            if m:
                got = data[m["offset"]:m["offset"]+len(bytes.fromhex(m["hex"]))]
                ok = got == bytes.fromhex(m["hex"])
                check(f"payload magic @0x{m['offset']:x} ({m['what']})", "PASS" if ok else "FAIL",
                      f"got {got.hex()} want {m['hex']} — ZEROS/ERASED ARE NOT TRIGGERS")
                fails += not ok
    rb = cfg.get("rollback", {})
    if rb.get("path"):
        ok = os.path.exists(rb["path"])
        h = hashlib.sha256(open(rb["path"],"rb").read()).hexdigest() if ok else ""
        good = ok and (not rb.get("sha256") or h == rb["sha256"])
        check("rollback artifact staged+hashed (pair the corrective)", "PASS" if good else "FAIL",
              rb["path"] if good else f"missing/hash-mismatch {rb['path']}"); fails += not good
    else:
        check("rollback artifact staged", "WARN", "no rollback configured — rule 5 violated"); warns += 1

    print("== device identity & liveness ==")
    mac = cfg.get("device_mac", "")
    neigh = sh(f"ip neigh | grep -i '{mac}' | head -1")
    check("specimen MAC seen on wire (AGENTS.md gate)", "INFO" if neigh else "WARN",
          neigh or f"{mac} not in ARP table (device silent/unconnected — is that expected?)")
    if dip:
        alive = sh(f"ping -c1 -W2 -I {nic} {dip} >/dev/null 2>&1 && echo alive || echo dead")
        if alive == "alive":
            check("device verify-alive (pre-write)", "PASS", f"{dip} answers")
        else:
            check("device verify-alive (pre-write)", "WARN",
                  f"{dip} silent — if this is PRE-flash of a running stock unit, STOP here"); warns += 1

    print("== observation channels ==")
    e = cfg.get("exfil", {})
    if e.get("url"):
        try:
            req = urllib.request.Request(e["url"], method=e.get("verb", "PUT"),
                                         data=e.get("test_payload", "preflight").encode())
            resp = urllib.request.urlopen(req, timeout=5)
            check(f"exfil end-to-end (verb={e.get('verb','PUT')})", "PASS", f"HTTP {resp.status}")
        except Exception as ex:
            # python http.server 501-on-PUT class failure = the device-2 blind run
            check(f"exfil end-to-end (verb={e.get('verb','PUT')})", "FAIL", str(ex)[:100]); fails += 1
    wl = cfg.get("watch_log")
    wp = cfg.get("watch_proc", "")
    proc_alive = bool(wp) and bool(sh(f"pgrep -f '{wp}' | head -1"))
    if wl and os.path.exists(wl):
        age = time.time() - os.path.getmtime(wl)
        if wp:
            if not proc_alive:
                check("watcher process alive", "FAIL", f"'{wp}' not running"); fails += 1
            else:
                check("watcher process alive", "PASS", wp)
                if age < cfg.get("watch_max_age_s", 120):
                    check("watcher heartbeat (log fresh)", "PASS", f"last write {int(age)}s ago")
                else:
                    check("watcher heartbeat (log fresh)", "WARN",
                          f"alive but silent {int(age)}s — event-driven watcher on an idle link, or errors-only logging (rule 8)"); warns += 1
    elif wl:
        check("watcher heartbeat (log fresh)", "FAIL", f"{wl} missing"); fails += 1

    print("== console (boot-breaking ops) ==")
    s = cfg.get("serial", {})
    if s.get("attached"):
        check("serial console attached", "PASS", "rule 4 satisfied")
    elif s.get("waiver_reason"):
        check("serial console attached", "WARN", "WAIVED: " + s["waiver_reason"]); warns += 1
    else:
        check("serial console attached", "FAIL",
              "no console + boot-breaking op = single-path device (rule 4)"); fails += 1

    print()
    print(f"RESULT: {fails} FAIL, {warns} WARN, {len(RESULTS)} checks")
    if fails:
        print("BLOCKED — resolve FAILs before any write. A FAIL here once cost a device.")
        return 2
    print("PASS — proceed; disposition WARNs in the run log.")
    return 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    cfg = json.load(open(args.config))
    if args.json:
        # run quietly, emit JSON
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(cfg, args)
        print(json.dumps({"rc": rc, "checks": RESULTS}, indent=2))
        sys.exit(rc)
    sys.exit(run(cfg, args))

if __name__ == "__main__":
    main()
