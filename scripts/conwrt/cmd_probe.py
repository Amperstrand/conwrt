# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
"""Active network probing command — detect what device is connected to an interface.

Gathers probe target IPs from model JSONs, configures the host interface for each
/24 subnet, runs ping/HTTP/SSH probes, classifies findings, and reports results.
"""

import argparse
import importlib
import ipaddress
import json
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

from model_loader import list_models
from conwrt.device_inventory import auto_detect_interface

_router_probe = importlib.import_module("router-probe")
probe_http_get = _router_probe.probe_http_get
probe_ssh = _router_probe.probe_ssh
probe_ping = _router_probe.probe_ping
probe_link_state = _router_probe.probe_link_state

ProbeResult = tuple[str, str, str]

FALLBACK_IPS = ["192.168.1.1", "192.168.0.1", "192.168.8.1", "192.168.1.20"]


@dataclass
class ProbeTarget:
    ip: str
    state: str = "unknown"
    model_candidates: list[str] = field(default_factory=list)
    evidence: list[ProbeResult] = field(default_factory=list)


def _collect_probe_targets(models: Optional[list[dict]] = None) -> list[str]:
    """Collect unique probe target IPs from model JSONs plus fallback list."""
    if models is None:
        try:
            models = list_models()
        except (OSError, ValueError):
            models = []

    ips: set[str] = set()
    for model in models:
        default_ip = model.get("openwrt", {}).get("default_ip", "")
        if default_ip:
            ips.add(default_ip)
        for _method_name, method_cfg in model.get("flash_methods", {}).items():
            recovery_ip = method_cfg.get("recovery_ip", "")
            if recovery_ip:
                ips.add(recovery_ip)

    ips.update(FALLBACK_IPS)
    return sorted(ips)


def _subnet_for_ip(ip: str) -> str:
    """Return the /24 subnet prefix for a given IP (e.g. '192.168.0' for '192.168.0.1')."""
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}"


def _host_ip_for_subnet(subnet_prefix: str) -> str:
    """Return the .10 host IP for a /24 subnet (e.g. '192.168.0.10')."""
    return f"{subnet_prefix}.10"


def _configure_interface(
    interface: str,
    target_ip: str,
    current_subnet: str,
    added_aliases: list[str],
) -> str:
    """Configure the host interface IP alias for the target's /24 subnet.

    Returns the new current_subnet (may be unchanged if already configured).
    """
    target_subnet = _subnet_for_ip(target_ip)
    if target_subnet == current_subnet:
        return current_subnet

    # Remove previous alias if we had one
    if current_subnet:
        old_ip = _host_ip_for_subnet(current_subnet)
        subprocess.run(
            ["ifconfig", interface, "inet", old_ip, "-alias"],
            check=False,
            capture_output=True,
        )
        if old_ip in added_aliases:
            added_aliases.remove(old_ip)

    # Assign new alias
    host_ip = _host_ip_for_subnet(target_subnet)
    subprocess.run(
        ["ifconfig", interface, "inet", host_ip, "netmask", "255.255.255.0", "alias"],
        check=True,
        capture_output=True,
    )
    added_aliases.append(host_ip)
    return target_subnet


def _cleanup_aliases(interface: str, added_aliases: list[str]) -> None:
    """Remove all alias IPs we added to the interface."""
    for alias_ip in list(added_aliases):
        subprocess.run(
            ["ifconfig", interface, "inet", alias_ip, "-alias"],
            check=False,
            capture_output=True,
        )
    added_aliases.clear()


def _classify_http_state(http_result: ProbeResult) -> str:
    """Classify device state from an HTTP probe result."""
    _name, status, _detail = http_result
    if status in ("uboot",):
        return "uboot"
    if status in ("openwrt_luci",):
        return "openwrt"
    if status in ("glinet_stock", "linksys_stock"):
        return "stock"
    if status == "unknown_http":
        return "unknown"
    return "unknown"


def _classify_ssh_state(ssh_result: ProbeResult) -> str:
    """Classify device state from an SSH probe result."""
    _name, status, _detail = ssh_result
    if status in ("openwrt_ssh",):
        return "openwrt"
    if status == "ssh_ok":
        return "openwrt"
    return ""


def _probe_target(
    ip: str,
    timeout: float = 3.0,
) -> ProbeTarget:
    """Probe a single IP and return classified results."""
    target = ProbeTarget(ip=ip)

    # Ping first — if unreachable, skip further probes
    ping_result = probe_ping(ip)
    target.evidence.append(ping_result)
    if ping_result[1] != "reachable":
        target.state = "unreachable"
        return target

    # HTTP probe
    http_result = probe_http_get(ip)
    target.evidence.append(http_result)
    http_state = _classify_http_state(http_result)
    if http_state:
        target.state = http_state

    # SSH probe
    ssh_result = probe_ssh(ip)
    target.evidence.append(ssh_result)
    ssh_state = _classify_ssh_state(ssh_result)
    if ssh_state == "openwrt" and target.state != "uboot":
        target.state = "openwrt"

    return target


def _match_models_by_ip(ip: str, models: list[dict]) -> list[str]:
    """Return model IDs whose recovery_ip or default_ip matches the given IP."""
    matches = []
    for model in models:
        default_ip = model.get("openwrt", {}).get("default_ip", "")
        if default_ip == ip:
            matches.append(model["id"])
            continue
        for _method_name, method_cfg in model.get("flash_methods", {}).items():
            if method_cfg.get("recovery_ip", "") == ip:
                matches.append(model["id"])
                break
    return matches


def _format_results_table(targets: list[ProbeTarget]) -> str:
    """Format probe results as a human-readable table."""
    lines = []
    responded = [t for t in targets if t.state != "unreachable"]
    if not responded:
        lines.append("No devices found.")
        return "\n".join(lines)

    lines.append(f"{'IP':<18s} {'State':<12s} {'Model Candidates'}")
    lines.append("-" * 60)
    for t in responded:
        candidates = ", ".join(t.model_candidates) if t.model_candidates else "-"
        lines.append(f"{t.ip:<18s} {t.state:<12s} {candidates}")
        for name, status, detail in t.evidence:
            if status not in ("unreachable", "no_response", "no_link"):
                lines.append(f"  {name}: {status} — {detail}")
    return "\n".join(lines)


# Sort order: uboot first (most actionable), then openwrt, then stock, then unknown
_STATE_PRIORITY = {"uboot": 0, "openwrt": 1, "stock": 2, "unknown": 3, "unreachable": 4}


def cmd_probe(args: argparse.Namespace) -> int:
    """Probe an interface for connected routers."""
    interface = getattr(args, "interface", None) or auto_detect_interface()
    if not interface:
        print("ERROR: no active ethernet interface found. Use --interface.", file=sys.stderr)
        return 1

    timeout = getattr(args, "timeout", 3.0)
    json_output = getattr(args, "json_output", False)
    quiet = getattr(args, "quiet", False)

    try:
        models = list_models()
    except (OSError, ValueError):
        models = []

    target_ips = _collect_probe_targets(models)

    print(f"Probing {len(target_ips)} targets on {interface}...")
    results: list[ProbeTarget] = []
    current_subnet = ""
    added_aliases: list[str] = []

    try:
        for ip in target_ips:
            current_subnet = _configure_interface(interface, ip, current_subnet, added_aliases)
            target = _probe_target(ip, timeout=timeout)
            target.model_candidates = _match_models_by_ip(ip, models)
            results.append(target)
    finally:
        _cleanup_aliases(interface, added_aliases)

    # Sort by state priority
    results.sort(key=lambda t: _STATE_PRIORITY.get(t.state, 99))

    responded = [t for t in results if t.state != "unreachable"]

    if json_output:
        output = {
            "interface": interface,
            "targets_probed": len(target_ips),
            "devices_found": len(responded),
            "results": [
                {
                    "ip": t.ip,
                    "state": t.state,
                    "model_candidates": t.model_candidates,
                    "evidence": [
                        {"probe": name, "status": status, "detail": detail}
                        for name, status, detail in t.evidence
                    ],
                }
                for t in responded
            ],
        }
        print(json.dumps(output, indent=2))
    elif quiet:
        for t in responded:
            print(t.ip)
    else:
        print()
        print(_format_results_table(results))

    return 0 if responded else 1
