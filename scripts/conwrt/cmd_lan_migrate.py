#!/usr/bin/env python3
# pyright: reportMissingImports=false, reportOptionalMemberAccess=false
"""Handler for `conwrt lan-migrate` — re-IP a running router's LAN, safely.

Moves the router LAN off one subnet to the model's ``lan_subnet`` gateway
(typically away from the OpenWrt default 192.168.1.1) WITHOUT reflashing.
The migration is:

  - **idempotent / repeatable** — if the router is already on the target IP,
    it exits successfully and touches nothing.
  - **self-verifying** — after applying, it polls the *new* IP for SSH.
  - **auto-rollback** — before applying, it stages a detached revert timer on
    the router; if the new IP doesn't come up in time, the router reverts to
    the old IP on its own. On success the rollback is canceled.

The host adds a temporary alias on the target subnet so it can reach the new IP
the moment the router restarts. Brick-safe: worst case the router reverts or
you reflash with conwrt.
"""
from __future__ import annotations

import ipaddress
import subprocess
import sys
import time
from types import SimpleNamespace

from model_loader import load_model
from profile.target import derive_target_profile


def _run(cmd: list[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _ssh(ip: str, cmd: str, key: str = "", timeout: int = 20) -> subprocess.CompletedProcess:
    args = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=8", "-o", "BatchMode=yes"]
    if key:
        args += ["-i", key]
    args += [f"root@{ip}", cmd]
    try:
        return _run(args, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "timeout")


def _port_open(ip: str, port: int = 22) -> bool:
    r = _run(["nc", "-z", "-G", "2", ip, str(port)], timeout=5)
    return r.returncode == 0


def _host_iface_to(ip: str) -> str:
    r = _run(["route", "-n", "get", ip], timeout=6)
    for line in r.stdout.splitlines():
        if "interface:" in line:
            return line.split("interface:")[1].strip()
    return ""


def cmd_lan_migrate(args: SimpleNamespace) -> int:
    model = load_model(args.model_id)
    target = derive_target_profile(model)["lan_gateway"]
    subnet = derive_target_profile(model)["lan_subnet"]
    if not target:
        print(f"model {args.model_id} has no lan_subnet — nothing to migrate to", file=sys.stderr)
        return 1

    current = args.ip or "192.168.1.1"
    rollback = int(args.rollback_secs)

    r = _ssh(current, "uci get network.lan.ipaddr", timeout=12)
    cur = r.stdout.strip()
    if cur == target:
        print(f"already on {target} ({subnet}) — nothing to do (idempotent)")
        return 0
    if not cur:
        print(f"could not read current LAN IP from {current} (SSH ok? is it OpenWrt?)", file=sys.stderr)
        return 1

    iface = args.interface or _host_iface_to(current)
    if not iface:
        print(f"could not detect host interface reaching {current}", file=sys.stderr)
        return 1

    net = ipaddress.ip_network(subnet, strict=False)
    host_alias = str(net.network_address + 50)
    print(f"migrating LAN: {cur} → {target} ({subnet})  [host iface {iface}, rollback {rollback}s]")

    _run(["sudo", "-n", "ifconfig", iface, "alias", f"{host_alias}/24"], timeout=8)
    print(f"  host alias {host_alias} on {iface} (so we can reach the new IP)")

    revert = (
        "#!/bin/sh\n"
        f"sleep {rollback}\n"
        "# cancel via flag, not pkill: `sh lanrevert.sh` execs `sleep`, so pkill -f lanrevert.sh misses it\n"
        "[ -e /tmp/lanrevert.cancel ] && { rm -f /tmp/lanrevert.cancel /tmp/lanrevert.sh; exit 0; }\n"
        f"uci set network.lan.ipaddr='{cur}'\n"
        "uci set network.lan.netmask='255.255.255.0'\n"
        "uci commit network\n"
        "/etc/init.d/network restart\n"
    )
    apply_cmd = (
        "rm -f /tmp/lanrevert.cancel; "
        "cat > /tmp/lanrevert.sh <<'CONWRT_REVERT'\n" + revert + "CONWRT_REVERT\n"
        "chmod +x /tmp/lanrevert.sh && setsid /tmp/lanrevert.sh >/dev/null 2>&1 < /dev/null &\n"
        f"uci set network.lan.ipaddr='{target}'\n"
        "uci set network.lan.netmask='255.255.255.0'\n"
        "uci commit network\n"
        "(/etc/init.d/network restart &)\n"
    )
    _ssh(current, apply_cmd, timeout=10)
    print("  applied; network restarting (rollback armed)")

    deadline = time.time() + max(rollback - 8, 20)
    up = False
    while time.time() < deadline:
        if _port_open(target):
            up = True
            break
        time.sleep(2)

    if up:
        _ssh(target, "touch /tmp/lanrevert.cancel; pkill -f lanrevert.sh 2>/dev/null; true", timeout=12)
        v = _ssh(target, "uci get network.lan.ipaddr", timeout=12).stdout.strip()
        print(f"  verified SSH on {target} (lan.ipaddr={v}); rollback canceled")
        print(f"migrated: {cur} → {target}")
        return 0

    print(f"  new IP {target} did not come up — waiting for auto-rollback to {cur}", file=sys.stderr)
    time.sleep(10)
    if _port_open(cur):
        print(f"  router reverted to {cur} — migration aborted, router reachable", file=sys.stderr)
    else:
        print(f"  router unreachable on both IPs — may need reflash", file=sys.stderr)
    return 1
