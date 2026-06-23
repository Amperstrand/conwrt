"""discover command — probe the unknown device on the probe port.

Runs from the field router: reads ARP neighbors, pings common router IPs,
and scans common ports with busybox nc (which is pre-installed on OpenWrt).
No mutations to the unknown device — read-only discovery.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from datetime import datetime, timezone

from fieldlab.transport import Host, check_ssh, run_remote, check_tool
from fieldlab.rundir import FieldLabRun

COMMON_ROUTER_IPS = [
    "192.168.1.1", "192.168.0.1", "192.168.8.1", "192.168.10.1",
    "192.168.2.1", "192.168.3.1", "192.168.4.1", "10.0.0.1", "10.0.1.1",
]

MAC_PATTERN = re.compile(r"([a-fA-F0-9]{2}(?::[a-fA-F0-9]{2}){5})")
IP_PATTERN = re.compile(r"(\d+\.\d+\.\d+\.\d+)")


def _detect_probe_interface(host: Host) -> str | None:
    """Auto-detect the probe interface via UCI."""
    result = run_remote(host, "uci get network.wan.device 2>/dev/null", timeout=8)
    dev = result.stdout.strip()
    if dev and dev != "none" and result.returncode == 0:
        return dev
    return None


def _read_neighbors(host: Host, probe_if: str) -> list[dict]:
    """Read ARP/neighbor table entries on the probe interface."""
    result = run_remote(host, f"ip neigh show dev {shlex.quote(probe_if)} 2>/dev/null",
                        timeout=10)
    neighbors = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        ip_match = IP_PATTERN.search(line)
        mac_match = MAC_PATTERN.search(line)
        state = "unknown"
        for s in ("REACHABLE", "STALE", "DELAY", "FAILED", "INCOMPLETE"):
            if s in line:
                state = s.lower()
                break
        if ip_match:
            neighbors.append({
                "ip": ip_match.group(1),
                "mac": mac_match.group(1).lower() if mac_match else "",
                "state": state,
                "raw": line,
            })
    return neighbors


def _ping_target(host: Host, target_ip: str, probe_if: str | None = None) -> dict:
    """Ping a target from the field router."""
    if_cmd = f" -I {shlex.quote(probe_if)}" if probe_if else ""
    result = run_remote(
        host,
        f"ping -c 2 -W 2{if_cmd} {shlex.quote(target_ip)} 2>&1",
        timeout=10,
    )
    output = result.stdout.strip()
    reachable = result.returncode == 0 and "0% packet loss" in output
    rtt = ""
    for line in output.split("\n"):
        if "rtt min/avg/max" in line or "= " in line:
            rtt = line.strip()
            break
    return {
        "ip": target_ip,
        "reachable": reachable,
        "rtt": rtt,
    }


def _scan_ports(host: Host, target_ip: str, ports: list[int]) -> list[dict]:
    """Scan ports using Python socket (preferred) or busybox nc (fallback)."""
    has_python = check_tool(host, "python3")
    has_nc = check_tool(host, "nc")
    if not has_python and not has_nc:
        return [{"error": "neither python3 nor nc available on field router"}]

    results = []
    for port in ports:
        if has_python:
            probe = (
                f"python3 -c \""
                f"import socket; s=socket.socket(); s.settimeout(2); "
                f"print('open' if s.connect_ex(('{target_ip}', {port}))==0 else 'closed'); s.close()"
                f"\" 2>/dev/null"
            )
        else:
            probe = f"nc {shlex.quote(target_ip)} {port} </dev/null 2>/dev/null && echo open || echo closed"

        result = run_remote(host, probe, timeout=8)
        output = result.stdout.strip().split("\n")[-1].strip().lower() if result.stdout else ""
        is_open = "open" in output
        results.append({
            "port": port,
            "state": "open" if is_open else "closed",
        })
    return results


def _probe_http(host: Host, target_ip: str) -> dict:
    """Try to GET the target's HTTP interface using curl if available."""
    if not check_tool(host, "curl"):
        return {"available": False, "note": "curl not installed on field router"}

    result = run_remote(
        host,
        f"curl -sI -m 3 http://{shlex.quote(target_ip)}/ 2>&1 | head -10",
        timeout=8,
    )
    return {
        "available": True,
        "response": result.stdout.strip() if result.stdout else "",
        "reachable": bool(result.stdout and "HTTP" in result.stdout),
    }


def cmd_discover(args: argparse.Namespace, host: Host) -> int:
    """Discover the unknown device on the probe port."""
    print(f"[+] Discovering from field router {host}...", file=sys.stderr)

    if not check_ssh(host):
        print(f"[!] Cannot SSH to {host}.", file=sys.stderr)
        return 1

    # Resolve probe interface
    probe_if = args.probe_if
    if not probe_if:
        probe_if = _detect_probe_interface(host)
    if not probe_if:
        print("[!] Could not detect probe interface. Use --probe-if.", file=sys.stderr)
        return 1

    print(f"[+] Probe interface: {probe_if}", file=sys.stderr)

    # 1. Read ARP neighbors on the probe interface
    print(f"[+] Reading neighbors on {probe_if}...", file=sys.stderr)
    neighbors = _read_neighbors(host, probe_if)

    observed_macs = list({n["mac"] for n in neighbors if n["mac"]})
    observed_ips = list({n["ip"] for n in neighbors if n["ip"] and "." in n["ip"]})

    print(f"[+] Found {len(observed_macs)} MAC(s), {len(observed_ips)} IP(s) in ARP table",
          file=sys.stderr)

    # 2. Determine target IP
    target_ip = args.target
    if not target_ip:
        # Use the first reachable-looking neighbor, or try common IPs
        for n in neighbors:
            if n["state"] == "reachable" and "." in n["ip"]:
                target_ip = n["ip"]
                break
        if not target_ip:
            # Try pinging common router IPs through the probe interface
            for ip in COMMON_ROUTER_IPS:
                ping_result = run_remote(
                    host,
                    f"ping -c 1 -W 1 -I {shlex.quote(probe_if)} {ip} 2>&1",
                    timeout=5,
                )
                if "1 packets received" in ping_result.stdout or "0% packet loss" in ping_result.stdout:
                    target_ip = ip
                    break

    if not target_ip:
        print("[!] No device detected on probe port.", file=sys.stderr)
        print("    Connect a device and try again, or use --target to specify an IP.",
              file=sys.stderr)
    else:
        print(f"[+] Target device: {target_ip}", file=sys.stderr)

    # 3. Ping scan
    ping_results = []
    if target_ip:
        print(f"[+] Pinging {target_ip}...", file=sys.stderr)
        ping_results = [_ping_target(host, target_ip, probe_if)]

    # 4. Port scan
    port_results = []
    if target_ip:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
        print(f"[+] Scanning {len(ports)} ports on {target_ip}...", file=sys.stderr)
        port_results = _scan_ports(host, target_ip, ports)
        open_ports = [p for p in port_results if p.get("state") == "open"]
        if open_ports:
            print(f"[+] Open ports: {[p['port'] for p in open_ports]}", file=sys.stderr)
        else:
            print(f"[+] No open ports found.", file=sys.stderr)

    # 5. HTTP probe
    http_result = {}
    if target_ip:
        print(f"[+] Probing HTTP...", file=sys.stderr)
        http_result = _probe_http(host, target_ip)

    # Assemble findings
    findings = {
        "session_id": args.session or "(no session)",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "field_router": str(host),
        "probe_interface": probe_if,
        "observed_macs": observed_macs,
        "observed_ips": observed_ips,
        "neighbors": neighbors,
        "target": target_ip,
        "ping_results": ping_results,
        "port_scan": port_results,
        "http_probe": http_result,
        "artifacts": [],
    }

    output = json.dumps(findings, indent=2)

    # Write to run directory
    session = args.session
    if session:
        run = FieldLabRun(session)
    else:
        run = FieldLabRun.create()
    run.discover_dir.mkdir(parents=True, exist_ok=True)
    findings_path = run.discover_dir / "findings.json"
    findings_path.write_text(output + "\n")
    run.record_command("discover", probe_interface=probe_if, target=target_ip or "(none)")
    print(f"[+] Findings written to {findings_path}", file=sys.stderr)

    sys.stdout.write(output + "\n")
    return 0
