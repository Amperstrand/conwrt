"""conwrt_poe — labgrid power backend for the Amperstrand realtek-poe fork.

Backend for NetworkPowerDriver / NetworkPowerPort (model: conwrt_poe).
Controls PoE ports on an OpenWrt bench switch running the fork at
github.com/Amperstrand/realtek-poe (ai-experiments), whose ubus API is:

    ubus call poe manage {"port":"lanN","action":"enable"|"disable"}
    ubus call poe info          -> {"ports":{"lanN":{"status":"..."}}}

The stock labgrid `ubus` backend sends {"enable": bool} over HTTP-ubus —
incompatible with this fork and requires uhttpd-mod-ubus; this backend
speaks the fork's native action-form over SSH instead. Long-term fix
(pattern doc): patch the fork to accept enable-bools + uhttpd ACL, then
switch to the stock backend.

SSH sessions are multiplexed through a ControlMaster socket (30s persist)
so repeated power_get polls reuse one authenticated connection instead of
spawning a full SSH handshake each time.

Install: copy this file into the labgrid install on the driver host:
    ~/.local/lib/python3.12/site-packages/labgrid/driver/power/conwrt_poe.py
Source of truth: conwrt repo, labgrid/conwrt_poe.py
(reinstall after labgrid upgrades AND after editing this file)
"""

from __future__ import annotations

import json
import subprocess

SSH_OPTS = [
    "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ControlMaster=auto",
    "-o", "ControlPath=/tmp/conwrt-poe-%r@%h:%p",
    "-o", "ControlPersist=30s",
]
OFF_STATES = {"disabled", "off", "", "fault"}


def _ssh(host: str, command: str) -> str:
    proc = subprocess.run(
        ["ssh", *SSH_OPTS, f"root@{host}", command],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"switch ssh failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _reject_port_arg(port: str | None) -> None:
    if port is not None:
        raise RuntimeError(
            "conwrt_poe addresses ports by index only — remove the 'port:' "
            "key from the NetworkPowerPort exporter entry (the fork's "
            "action-string ubus API takes lan<index>)")


def power_set(host: str, port: str | None, index: int, value: int) -> None:
    _reject_port_arg(port)
    action = "enable" if value else "disable"
    _ssh(host, f"ubus call poe manage '{{\"port\":\"lan{index}\","
               f"\"action\":\"{action}\"}}'")


def power_get(host: str, port: str | None, index: int) -> bool:
    _reject_port_arg(port)
    raw = _ssh(host, "ubus call poe info")
    info = json.loads(raw)
    entry = info["ports"].get(f"lan{index}")
    if entry is None:
        raise RuntimeError(f"port lan{index} not in poe info")
    status = entry["status"] if isinstance(entry, dict) else entry
    return status.strip().lower() not in OFF_STATES
