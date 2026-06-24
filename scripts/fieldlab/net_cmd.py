"""net-status and net-cleanup commands — host network diagnostics and cleanup.

conwrt operations (probe, lan-migrate, field-lab) add IP aliases to the host's
Ethernet interface as a side effect. If interrupted, these aliases leak and
cause routing/DNS conflicts. These commands diagnose and clean up.

net-status: shows all interfaces, IPs, routes, DNS — flags likely-stale aliases.
net-cleanup: removes conwrt-added IP aliases (--dry-run safe).
"""

from __future__ import annotations

import argparse
import platform
import re
import subprocess
import sys
from pathlib import Path

from fieldlab.network import detect_platform_local, MACOS, LINUX, OPENWRT


# Subnets conwrt commonly adds as aliases during operations
CONWRT_ALIAS_PATTERNS = [
    ("192.168.0.", "D-Link recovery subnet (conwrt probe)"),
    ("192.168.1.", "Common router subnet (conwrt probe / field-lab)"),
    ("192.168.8.", "GL.iNet default subnet (conwrt probe)"),
    ("192.168.10.", "conwrt probe target"),
    ("192.168.50.", "field-lab DHCP serve subnet"),
    ("10.89.4.", "x1860 br-lan (conwrt lan-migrate)"),
]

MAC_PATTERN = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


def _get_interfaces_macos() -> list[dict]:
    """Get interface info on macOS via ifconfig."""
    result = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True, check=False)
    interfaces = []
    current = None
    for line in result.stdout.split("\n"):
        if line and not line.startswith("\t") and not line.startswith(" "):
            parts = line.split(":")
            if len(parts) >= 2:
                current = {
                    "name": parts[0].strip(),
                    "flags": parts[1].strip() if len(parts) > 1 else "",
                    "inet": [],
                    "status": "",
                }
                interfaces.append(current)
        elif current and line.strip().startswith("inet "):
            inet_line = line.strip()
            current["inet"].append(inet_line)
        elif current and "status:" in line:
            current["status"] = line.split("status:")[1].strip()
    return interfaces


def _get_interfaces_linux() -> list[dict]:
    """Get interface info on Linux via ip addr."""
    result = subprocess.run(["ip", "-br", "addr"], capture_output=True, text=True, check=False)
    interfaces = []
    for line in result.stdout.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            interfaces.append({
                "name": parts[0],
                "status": parts[1],
                "inet": [p for p in parts[2:] if p.startswith("inet")],
                "flags": "",
            })
    return interfaces


def _get_routes() -> str:
    """Get default routes."""
    pf = detect_platform_local()
    if pf == MACOS:
        result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, check=False)
        return "\n".join(l for l in result.stdout.split("\n") if l.startswith("default"))
    result = subprocess.run(["ip", "route", "show"], capture_output=True, text=True, check=False)
    return result.stdout.strip()


def _get_dns() -> list[str]:
    """Get DNS resolvers."""
    pf = detect_platform_local()
    if pf == MACOS:
        result = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, check=False)
        resolvers = []
        for line in result.stdout.split("\n"):
            if "nameserver[" in line and ":" in line:
                ns = line.split(":", 1)[1].strip()
                if ns not in resolvers:
                    resolvers.append(ns)
        return resolvers
    try:
        content = Path("/etc/resolv.conf").read_text()
        return [l.split()[1] for l in content.split("\n") if l.startswith("nameserver ")]
    except OSError:
        return []


def _classify_alias(ip: str) -> str:
    """Classify an IP as likely conwrt-added or primary."""
    for pattern, desc in CONWRT_ALIAS_PATTERNS:
        if ip.startswith(pattern):
            return desc
    return ""


def cmd_net_status(args: argparse.Namespace, host=None) -> int:
    """Show host network diagnostics."""
    pf = detect_platform_local()
    print(f"[+] Platform: {pf}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    interfaces = _get_interfaces_macos() if pf == MACOS else _get_interfaces_linux()

    print(f"\nInterfaces:", file=sys.stderr)
    stale_found = []
    for iface in interfaces:
        name = iface["name"]
        if name in ("lo", "lo0") or not iface["inet"]:
            continue
        print(f"  {name} ({iface.get('status', 'unknown')}):", file=sys.stderr)
        has_multiple = len(iface["inet"]) > 1
        for idx, inet in enumerate(iface["inet"]):
            ip = ""
            if "inet " in inet:
                ip = inet.split("inet ")[1].split()[0]
            elif inet.startswith("inet"):
                ip = inet

            classification = _classify_alias(ip) if (has_multiple and idx > 0) else ""
            if classification:
                marker = f"  ← {classification}"
                stale_found.append((name, ip, classification))
            elif ip.startswith("127.") or not ip:
                marker = ""
            else:
                marker = "  ← primary"
            print(f"    {inet}{marker}", file=sys.stderr)

    print(f"\nDefault routes:", file=sys.stderr)
    routes = _get_routes()
    for line in routes.split("\n"):
        if line.strip():
            print(f"  {line.strip()}", file=sys.stderr)

    print(f"\nDNS resolvers:", file=sys.stderr)
    dns = _get_dns()
    for ns in dns:
        print(f"  {ns}", file=sys.stderr)

    if stale_found:
        print(f"\n[!] {len(stale_found)} likely-stale alias(es) detected:", file=sys.stderr)
        for name, ip, desc in stale_found:
            print(f"    {name}: {ip} — {desc}", file=sys.stderr)
        print(f"    Run 'fieldlab net-cleanup --dry-run' to review.", file=sys.stderr)
    else:
        print(f"\n[+] No stale aliases detected.", file=sys.stderr)

    return 0


def _remove_alias_macos(interface: str, ip: str) -> bool:
    """Remove an IP alias on macOS."""
    result = subprocess.run(
        ["sudo", "ifconfig", interface, "inet", ip, "-alias"],
        capture_output=True, text=True, check=False,
    )
    return result.returncode == 0


def _remove_alias_linux(interface: str, ip: str) -> bool:
    """Remove an IP on Linux."""
    result = subprocess.run(
        ["ip", "addr", "del", f"{ip}/32", "dev", interface],
        capture_output=True, text=True, check=False,
    )
    return result.returncode == 0


def cmd_net_cleanup(args: argparse.Namespace, host=None) -> int:
    """Remove stale IP aliases left by conwrt operations."""
    pf = detect_platform_local()
    dry_run = args.dry_run if hasattr(args, "dry_run") else True
    target_iface = args.interface if hasattr(args, "interface") else None

    interfaces = _get_interfaces_macos() if pf == MACOS else _get_interfaces_linux()

    to_remove = []
    for iface in interfaces:
        name = iface["name"]
        if target_iface and name != target_iface:
            continue
        if name in ("lo", "lo0"):
            continue
        has_multiple = len(iface["inet"]) > 1
        for idx, inet in enumerate(iface["inet"]):
            if idx == 0 or not has_multiple:
                continue
            ip = ""
            if "inet " in inet:
                ip = inet.split("inet ")[1].split()[0]
            elif inet.startswith("inet"):
                ip = inet
            if not ip or ip.startswith("127."):
                continue
            classification = _classify_alias(ip)
            if classification:
                to_remove.append((name, ip, classification))

    if not to_remove:
        print("[+] No stale aliases found. Network is clean.", file=sys.stderr)
        return 0

    print(f"[+] Found {len(to_remove)} stale alias(es):", file=sys.stderr)
    for name, ip, desc in to_remove:
        print(f"    {name}: {ip} — {desc}", file=sys.stderr)

    if dry_run:
        print(f"\n[DRY-RUN] No changes made. Re-run without --dry-run to remove.",
              file=sys.stderr)
        return 0

    removed = 0
    for name, ip, _desc in to_remove:
        if pf == MACOS:
            ok = _remove_alias_macos(name, ip)
        else:
            ok = _remove_alias_linux(name, ip)
        if ok:
            print(f"[+] Removed {ip} from {name}", file=sys.stderr)
            removed += 1
        else:
            print(f"[!] Failed to remove {ip} from {name}", file=sys.stderr)

    print(f"\n[+] Removed {removed}/{len(to_remove)} aliases.", file=sys.stderr)
    return 0
