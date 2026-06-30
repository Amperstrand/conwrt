"""prepare-probe command — inspect probe-port state, optionally clean up.

Since the field router's WAN port is typically free (WiFi is the uplink),
this command is mostly informational: it shows the current state of the
probe interface and whether a stale 'wan' UCI binding exists.

If --apply is given, it removes the probe interface from the 'wan' UCI
section at runtime (uci changes, no commit) so the field router stops
treating the unknown device as an ISP. Changes revert on reboot.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys

from fieldlab.transport import Host, check_ssh, run_remote
from fieldlab.rundir import FieldLabRun


def _detect_probe_interface(host: Host) -> str | None:
    result = run_remote(host, "uci get network.wan.device 2>/dev/null", timeout=8)
    dev = result.stdout.strip()
    if dev and dev != "none" and result.returncode == 0:
        return dev
    return None


def _interface_state(host: Host, iface: str) -> dict:
    """Collect runtime state for a specific interface."""
    result = run_remote(
        host,
        f"cat /sys/class/net/{shlex.quote(iface)}/operstate 2>/dev/null || echo unknown; "
        f"cat /sys/class/net/{shlex.quote(iface)}/carrier 2>/dev/null || echo unknown; "
        f"cat /sys/class/net/{shlex.quote(iface)}/address 2>/dev/null || echo unknown; "
        f"ip addr show dev {shlex.quote(iface)} 2>/dev/null | grep -E 'inet |inet6 '",
        timeout=8,
    )
    lines = result.stdout.strip().split("\n")
    return {
        "device": iface,
        "operstate": lines[0] if len(lines) > 0 else "unknown",
        "carrier": lines[1] if len(lines) > 1 else "unknown",
        "mac": lines[2] if len(lines) > 2 else "unknown",
        "addresses": lines[3:] if len(lines) > 3 else [],
    }


def _check_wan_binding(host: Host, probe_if: str) -> dict:
    """Check if the probe interface is bound to UCI wan/wan6."""
    result = run_remote(host, "uci show network 2>/dev/null | grep -E 'wan[0-9]*\\.device'",
                        timeout=8)
    bindings = {}
    for line in result.stdout.strip().split("\n"):
        if "=" in line and probe_if in line:
            key = line.split("=")[0].strip()
            bindings[key] = probe_if
    return {
        "is_wan_device": bool(bindings),
        "bindings": bindings,
        "uci_output": result.stdout.strip(),
    }


def cmd_prepare_probe(args: argparse.Namespace, host: Host) -> int:
    """Show probe-port state and optionally clean up stale WAN binding."""
    print(f"[+] Checking probe port on {host}...", file=sys.stderr)

    if not check_ssh(host):
        print(f"[!] Cannot SSH to {host}.", file=sys.stderr)
        return 1

    probe_if = args.probe_if
    if not probe_if:
        probe_if = _detect_probe_interface(host)
    if not probe_if:
        print("[!] Could not detect probe interface.", file=sys.stderr)
        return 1

    print(f"[+] Probe interface: {probe_if}", file=sys.stderr)

    iface_state = _interface_state(host, probe_if)
    wan_binding = _check_wan_binding(host, probe_if)

    # Check what the actual uplink is (WiFi STA vs Ethernet WAN)
    uplink_result = run_remote(
        host, "ip route show default 2>/dev/null", timeout=8)
    default_routes = uplink_result.stdout.strip().split("\n")
    wifi_check = run_remote(
        host, "uci show wireless 2>/dev/null | grep 'mode=.sta.'", timeout=8)
    has_wifi_sta = bool(wifi_check.stdout.strip())

    state = {
        "probe_interface": iface_state,
        "wan_binding": wan_binding,
        "default_routes": default_routes,
        "has_wifi_sta": has_wifi_sta,
        "probe_is_default_route": any(
            f"dev {probe_if}" in r for r in default_routes if "default" in r
        ),
    }

    print(f"\n{'='*60}", file=sys.stderr)
    print("  Probe Port State Report", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)
    print(f"  Interface:   {probe_if}", file=sys.stderr)
    print(f"  Operstate:   {iface_state['operstate']}", file=sys.stderr)
    print(f"  Carrier:     {iface_state['carrier']}", file=sys.stderr)
    print(f"  MAC:         {iface_state['mac']}", file=sys.stderr)
    print(f"  WAN-bound:   {'yes' if wan_binding['is_wan_device'] else 'no'}", file=sys.stderr)
    print(f"  WiFi STA:    {'yes' if has_wifi_sta else 'no'}", file=sys.stderr)
    print(f"  Is default:  {'yes' if state['probe_is_default_route'] else 'no'}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    if wan_binding["is_wan_device"]:
        print(f"[!] Probe interface '{probe_if}' is still bound to UCI wan.", file=sys.stderr)
        print("    The field router treats the unknown device as an ISP.", file=sys.stderr)

        if args.apply:
            print("\n[+] Applying cleanup (--apply)...", file=sys.stderr)
            print(f"    Removing {probe_if} from network.wan at runtime (no commit).",
                  file=sys.stderr)
            # Runtime change: uci set, but DON'T commit — reverts on reboot
            for section in wan_binding["bindings"]:
                section_name = section.split(".")[1]  # e.g. 'wan' from 'network.wan.device'
                result = run_remote(
                    host,
                    f"uci set network.{section_name}.device=''; "
                    f"ifdown {section_name} 2>/dev/null; echo done",
                    timeout=10,
                )
                print(f"    {section}: cleared ({result.stdout.strip()})", file=sys.stderr)
            print("\n[+] Cleanup applied. Changes are runtime-only (revert on reboot).",
                  file=sys.stderr)
            print(f"    To make permanent: ssh {host} 'uci commit network'", file=sys.stderr)
            print(f"    To revert now:     ssh {host} 'uci revert network; ifup wan'",
                  file=sys.stderr)
        else:
            print(f"\n[DRY-RUN] Would remove {probe_if} from network.wan UCI section.",
                  file=sys.stderr)
            print("          Re-run with --apply to clean up.", file=sys.stderr)
    else:
        print("[+] Probe interface is not WAN-bound — ready for field-lab use.", file=sys.stderr)

    if state["probe_is_default_route"] and not has_wifi_sta:
        print("\n[!] WARNING: probe port is the default route and no WiFi STA detected.",
              file=sys.stderr)
        print("    Cleaning up may cut internet access. Proceed with caution.", file=sys.stderr)

    # Record
    session = args.session
    if session:
        run = FieldLabRun(session)
    else:
        run = FieldLabRun.create()
    run.record_command("prepare-probe", probe_interface=probe_if, applied=args.apply)

    print(f"\n{json.dumps(state, indent=2)}", file=sys.stdout)
    return 0
