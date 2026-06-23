"""inspect command — read-only field router state collection.

Gathers identity, network config, interface state, tool availability,
and detects the probe interface. All read-only: no mutations.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

from fieldlab.transport import Host, run_remote, check_ssh
from fieldlab.rundir import FieldLabRun


# Shell commands run on the field router, separated by ===SECTION=== markers.
# All strictly read-only.
_INSPECT_SCRIPT = """\
echo '===BOARD==='; ubus call system board 2>/dev/null
echo '===OPENWRT_RELEASE==='; cat /etc/openwrt_release 2>/dev/null
echo '===UCI_NETWORK==='; uci show network 2>/dev/null
echo '===UCI_WIRELESS==='; uci show wireless 2>/dev/null
echo '===UCI_FIREWALL==='; uci show firewall 2>/dev/null
echo '===IP_BR_LINK==='; ip -br link 2>/dev/null
echo '===IP_BR_ADDR==='; ip -br addr 2>/dev/null
echo '===IP_ROUTE==='; ip route 2>/dev/null
echo '===NET_DEVICES==='; ls /sys/class/net 2>/dev/null
echo '===BRIDGE_LINK==='; bridge link 2>/dev/null
echo '===BRIDGE_VLAN==='; bridge vlan show 2>/dev/null
echo '===SWCONFIG==='; swconfig list 2>/dev/null || echo no-swconfig
echo '===DSA_CHECK==='; lsmod 2>/dev/null | grep -E '^(mtk_eth|dsa)|dsa_core' | head -5 || echo no-dsa-modules
echo '===TOOLS==='; for t in tcpdump nmap curl socat nc wg ifconfig; do printf '%s=' "$t"; which "$t" 2>/dev/null || echo missing; done
echo '===OPKG_RELEVANT==='; opkg list-installed 2>/dev/null | grep -iE 'tcpdump|nmap|socat|libpcap'
echo '===NEIGH==='; ip neigh 2>/dev/null
echo '===WAN_DEVICE==='; uci get network.wan.device 2>/dev/null || echo none
echo '===LOGREAD_TAIL==='; logread 2>/dev/null | tail -20
"""


def _parse_sections(raw: str) -> dict[str, str]:
    """Parse ===SECTION=== delimited output into a dict."""
    sections: dict[str, str] = {}
    current = None
    for line in raw.split("\n"):
        if line.startswith("===") and line.endswith("===") and len(line) > 6:
            current = line[3:-3]
            sections[current] = ""
        elif current is not None:
            sections[current] += line + "\n"
    return {k: v.strip() for k, v in sections.items()}


def _parse_tools(sections: dict[str, str]) -> dict[str, str]:
    """Parse the TOOLS section into {tool: path_or_missing}."""
    tools: dict[str, str] = {}
    for line in sections.get("TOOLS", "").split("\n"):
        line = line.strip()
        if "=" in line:
            name, path = line.split("=", 1)
            tools[name.strip()] = path.strip()
    return tools


def cmd_inspect(args: argparse.Namespace, host: Host) -> int:
    """Collect field router state and detect the probe interface."""
    print(f"[+] Inspecting field router {host}...", file=sys.stderr)

    if not check_ssh(host):
        print(f"[!] Cannot SSH to {host}. Check connectivity and keys.", file=sys.stderr)
        return 1

    result = run_remote(host, _INSPECT_SCRIPT, timeout=30)
    if result.returncode != 0:
        print(f"[!] SSH command failed: {result.stderr.strip()}", file=sys.stderr)
        return 1

    sections = _parse_sections(result.stdout)

    # Try to read carrier for the probe interface
    probe_if = args.probe_if
    uci_wan_dev = sections.get("WAN_DEVICE", "").strip()
    if not probe_if:
        probe_if = uci_wan_dev if uci_wan_dev and uci_wan_dev != "none" else None

    probe_state: dict = {}
    if probe_if:
        carrier_result = run_remote(
            host,
            f"cat /sys/class/net/{shlex.quote(probe_if)}/operstate 2>/dev/null || echo unknown; "
            f"cat /sys/class/net/{shlex.quote(probe_if)}/carrier 2>/dev/null || echo unknown; "
            f"cat /sys/class/net/{shlex.quote(probe_if)}/address 2>/dev/null || echo unknown",
            timeout=5,
        )
        parts = carrier_result.stdout.strip().split("\n")
        probe_state = {
            "device": probe_if,
            "operstate": parts[0] if len(parts) > 0 else "unknown",
            "carrier": parts[1] if len(parts) > 1 else "unknown",
            "mac": parts[2] if len(parts) > 2 else "unknown",
        }

    # Detect architecture
    dsa_line = sections.get("DSA_CHECK", "")
    swconfig_line = sections.get("SWCONFIG", "")
    if dsa_line and dsa_line != "no-dsa-modules":
        architecture = "dsa"
    elif swconfig_line and swconfig_line != "no-swconfig":
        architecture = "swconfig"
    else:
        architecture = "standalone"

    state = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": str(host),
        "board": sections.get("BOARD", ""),
        "openwrt_release": sections.get("OPENWRT_RELEASE", ""),
        "network_uci": sections.get("UCI_NETWORK", ""),
        "wireless_uci": sections.get("UCI_WIRELESS", ""),
        "firewall_uci": sections.get("UCI_FIREWALL", ""),
        "ip_link": sections.get("IP_BR_LINK", ""),
        "ip_addr": sections.get("IP_BR_ADDR", ""),
        "ip_route": sections.get("IP_ROUTE", ""),
        "net_devices": sections.get("NET_DEVICES", "").split(),
        "bridge_link": sections.get("BRIDGE_LINK", ""),
        "bridge_vlan": sections.get("BRIDGE_VLAN", ""),
        "switch_type": sections.get("SWCONFIG", ""),
        "architecture": architecture,
        "tools": _parse_tools(sections),
        "probe_interface": probe_state or {"device": "(not detected)"},
        "neighbors": sections.get("NEIGH", ""),
        "logread_tail": sections.get("LOGREAD_TAIL", ""),
    }

    output = json.dumps(state, indent=2)

    # Write to run directory
    session = args.session
    if session:
        run = FieldLabRun(session)
    else:
        run = FieldLabRun.create()
    run.inspect_dir.mkdir(parents=True, exist_ok=True)
    state_path = run.inspect_dir / "router-state.json"
    state_path.write_text(output + "\n")
    run.record_command("inspect", probe_interface=probe_if or "(auto)")
    print(f"[+] State written to {state_path}", file=sys.stderr)

    # Also write to --output if specified
    if args.output:
        Path(args.output).write_text(output + "\n")
        print(f"[+] Also written to {args.output}", file=sys.stderr)

    # Print summary to stderr, full JSON to stdout
    print(f"[+] Field router: {host}", file=sys.stderr)
    print(f"[+] Architecture: {architecture}", file=sys.stderr)
    print(f"[+] Probe interface: {probe_if or '(not detected)'}", file=sys.stderr)
    tools = state["tools"]
    has_tcpdump = tools.get("tcpdump", "missing") != "missing"
    print(f"[+] tcpdump: {'installed' if has_tcpdump else 'MISSING (needed for capture)'}",
          file=sys.stderr)

    sys.stdout.write(output + "\n")
    return 0
