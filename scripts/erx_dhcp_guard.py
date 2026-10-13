#!/usr/bin/env python3
"""erx_dhcp_guard — validate and monitor the ERX dnsmasq DHCP/DNS config.

The motivating incident (2026-09-28): anonymous `uci add dhcp host` sections
duplicated named sections, producing duplicate dhcp-host lines in the
generated dnsmasq config. dnsmasq treats duplicates as FATAL — it
crash-looped, taking down DNS + DHCP for the entire house (WiFi users lost
internet). This tool prevents that class.

Usage:
  erx_dhcp_guard.py validate    # pre-commit: check config for fatal issues
  erx_dhcp_guard.py check       # health check: is dnsmasq alive and working?
  erx_dhcp_guard.py audit       # both + list all host entries for review

Rules enforced:
  1. No duplicate MAC addresses across host sections (dnsmasq fatal)
  2. No duplicate IPs across host sections (dnsmasq fatal)
  3. No duplicate names (confusing, not fatal)
  4. dnsmasq generated config has no duplicate dhcp-host lines
  5. dnsmasq process is running (check mode)
  6. DNS resolves a known domain (check mode)
  7. DHCP lease file is non-empty (check mode)

Integration: run `validate` BEFORE any `uci commit dhcp` + dnsmasq restart.
Run `check` from cron every 5 minutes. Both exit non-zero on failure.
"""
from __future__ import annotations
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ERX = "root@192.168.13.1"


def ssh(cmd: str, timeout: int = 15) -> str:
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", ERX, cmd],
        capture_output=True, text=True, timeout=timeout
    )
    return r.stdout.strip()


def parse_host_entries() -> list[dict]:
    raw = ssh("uci show dhcp | grep '=host$\\|\\.mac=\\|\\.ip=\\|\\.name='")
    entries: dict[str, dict] = {}
    current = None
    for line in raw.splitlines():
        line = line.strip()
        if "=host$" in line or line.endswith("=host"):
            sec = line.split(".")[1].split("=")[0]
            current = sec
            entries.setdefault(current, {"section": sec, "mac": "", "ip": "", "name": ""})
        elif current and ".mac=" in line:
            entries[current]["mac"] = line.split("'")[1] if "'" in line else ""
        elif current and ".ip=" in line:
            entries[current]["ip"] = line.split("'")[1] if "'" in line else ""
        elif current and ".name=" in line:
            entries[current]["name"] = line.split("'")[1] if "'" in line else ""
    return [e for e in entries.values() if e["mac"] or e["ip"]]


def cmd_validate() -> int:
    print("== VALIDATE: dhcp config")
    hosts = parse_host_entries()
    errors: list[str] = []

    macs = [h["mac"] for h in hosts if h["mac"]]
    ips = [h["ip"] for h in hosts if h["ip"]]
    names = [h["name"] for h in hosts if h["name"]]

    for mac, count in Counter(macs).items():
        if count > 1:
            owners = [h["section"] for h in hosts if h["mac"] == mac]
            errors.append(f"DUPLICATE MAC {mac} in {owners} — dnsmasq will CRASH")

    for ip, count in Counter(ips).items():
        if count > 1:
            owners = [h["section"] for h in hosts if h["ip"] == ip]
            errors.append(f"DUPLICATE IP {ip} in {owners} — dnsmasq will CRASH")

    for name, count in Counter(names).items():
        if count > 1:
            owners = [h["section"] for h in hosts if h["name"] == name]
            errors.append(f"DUPLICATE NAME '{name}' in {owners} — confusing")

    gen = ssh("grep dhcp-host /var/etc/dnsmasq.conf.* 2>/dev/null || true")
    gen_lines = [l.strip() for l in gen.splitlines() if "dhcp-host" in l]
    for line, count in Counter(gen_lines).items():
        if count > 1:
            errors.append(f"GENERATED CONFIG duplicate: '{line}' appears {count}x — FATAL")

    for h in sorted(hosts, key=lambda x: x["ip"]):
        status = "✗" if any(h["section"] in e for e in errors) else "✓"
        print(f"  {status} {h['section']:24s} {h['mac']:20s} {h['ip']:16s} {h['name']}")

    if errors:
        print(f"\nFAIL: {len(errors)} error(s)")
        for e in errors:
            print(f"  ✗ {e}")
        return 1
    print(f"\nPASS: {len(hosts)} host entries, no duplicates, config is safe")
    return 0


def cmd_check() -> int:
    print("== CHECK: dnsmasq health")
    errors: list[str] = []

    proc = ssh("pgrep dnsmasq | head -1")
    if not proc:
        errors.append("dnsmasq NOT RUNNING")
    else:
        print(f"  ✓ dnsmasq running (PID {proc})")

    dns = ssh("nslookup google.com 127.0.0.1 2>&1 | head -5")
    if "Address" in dns and "SERVFAIL" not in dns and "NXDOMAIN" not in dns:
        addrs = [l.split(":")[1].strip() for l in dns.splitlines() if "Address" in l]
        resolved = addrs[1] if len(addrs) > 1 else (addrs[0] if addrs else "ok")
        print(f"  ✓ DNS resolving (google.com → {resolved})")
    else:
        errors.append(f"DNS NOT resolving: {dns[:100]}")

    leases = ssh("wc -l < /tmp/dhcp.leases 2>/dev/null || echo 0")
    count = int(leases.strip() or "0")
    if count > 0:
        print(f"  ✓ DHCP leases active ({count})")
    else:
        errors.append("DHCP lease file EMPTY — no clients have addresses")

    log = ssh("logread | grep -c 'dnsmasq.*FAILED\\|dnsmasq.*crash' 2>/dev/null || echo 0")
    crashes = int(log.strip() or "0")
    if crashes == 0:
        print(f"  ✓ No dnsmasq crash entries in log")
    else:
        errors.append(f"dnsmasq has {crashes} crash log entries")

    if errors:
        print(f"\nUNHEALTHY: {len(errors)} issue(s)")
        for e in errors:
            print(f"  ✗ {e}")
        return 1
    print(f"\nHEALTHY: dnsmasq fully operational")
    return 0


def cmd_audit() -> int:
    v = cmd_validate()
    c = cmd_check()
    return v if v != 0 else c


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "audit"
    fn = {"validate": cmd_validate, "check": cmd_check, "audit": cmd_audit}.get(mode)
    if not fn:
        print(f"unknown mode: {mode} (use validate|check|audit)")
        sys.exit(2)
    sys.exit(fn())
