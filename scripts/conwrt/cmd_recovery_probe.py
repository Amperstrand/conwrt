"""recovery-probe — classify what answers at a recovery IP.

Born from the 2026-09-27 bench session: flashing from a routed fixture
(ER6P seat VLAN) needed three manual probes before every attempt — arm the
client alias, curl the recovery page, and read the neighbor table for the
device MAC. This command does all three and classifies the answer:

  recovery   U-Boot recovery HTTP server is live (flashable now)
  stock      vendor firmware web UI answered (not flashable via recovery)
  html       something answered but no known signature matched
  silent     nothing answered (device off, wrong seat, or link down)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from types import SimpleNamespace

DEFAULT_RECOVERY_IP = "192.168.0.1"


def classify_recovery_page(html: str) -> tuple[str, str]:
    """Classify an HTTP response body from the recovery IP."""
    if not html.strip():
        return "silent", "empty response body"
    low = html.lower()
    if "recovery mode" in low or "recovery" in low:
        if "d-link" in low and "recovery mode" not in low:
            return "stock", "D-Link page without recovery-mode marker"
        return "recovery", "recovery-mode page"
    if "hnap1" in low:
        return "stock", "HNAP API page (vendor firmware)"
    if "firmware" in low and "d-link" not in low and "dlink" not in low:
        return "recovery", "firmware-update page"
    if html.strip().startswith("<!DOCTYPE") or html.strip().startswith("<!doctype"):
        return "html", "unrecognized HTML"
    return "html", html[:80]


def _curl(url: str, timeout: int = 3) -> str:
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 2, check=False,
        )
        return r.stdout
    except (subprocess.SubprocessError, OSError):
        return ""


def _neighbor_mac(interface: str, ip: str) -> str:
    try:
        r = subprocess.run(
            ["ip", "neigh", "show", "dev", interface],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return ""
    for line in r.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == ip:
            for token in parts:
                if ":" in token and token.count(":") == 5:
                    return token
    return ""


def _carrier(interface: str) -> str:
    try:
        with open(f"/sys/class/net/{interface}/carrier", encoding="ascii") as fh:
            return fh.read().strip()
    except OSError:
        return "unknown"


def cmd_recovery_probe(args: argparse.Namespace) -> int:
    client_ip = args.client_ip
    if args.interface and client_ip:
        try:
            from platform_utils import configure_interface_ip
            configure_interface_ip(args.interface, client_ip, "24")
        except Exception as e:  # noqa: BLE001 — probe continues without alias
            print(f"warning: could not arm {client_ip} on {args.interface}: {e}",
                  file=sys.stderr)
        time.sleep(1)

    html = _curl(f"http://{args.recovery_ip}/")
    state, detail = classify_recovery_page(html)

    mac = _neighbor_mac(args.interface, args.recovery_ip) if args.interface else ""
    carrier = _carrier(args.interface) if args.interface else "unknown"

    result = {
        "recovery_ip": args.recovery_ip,
        "state": state,
        "detail": detail,
        "mac": mac,
        "interface": args.interface or "",
        "carrier": carrier,
    }
    if args.json_out:
        print(json.dumps(result, indent=2))
    else:
        print(f"recovery IP : {args.recovery_ip}")
        if args.interface:
            print(f"interface   : {args.interface} (carrier={carrier})")
        print(f"state       : {state} — {detail}")
        if mac:
            print(f"device MAC  : {mac}")
        if state == "recovery":
            print("verdict     : FLASHABLE — recovery server is live now")
        elif state == "stock":
            print("verdict     : vendor firmware — power-on reset dance needed for recovery mode")
        elif state == "silent":
            print("verdict     : nothing answering — check power, seat, and link")
    return 0 if state == "recovery" else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recovery-probe",
        description="Classify what answers at a recovery IP (arms the client alias first).")
    p.add_argument("--recovery-ip", default=DEFAULT_RECOVERY_IP,
                   help=f"recovery server IP (default {DEFAULT_RECOVERY_IP})")
    p.add_argument("--interface", default=None,
                   help="interface that shares L2 with the device (e.g. br-lan.401); "
                        "enables alias arming, MAC learning, and carrier readout")
    p.add_argument("--client-ip", default="192.168.0.10",
                   help="client alias to arm on the interface (default 192.168.0.10)")
    p.add_argument("--json", dest="json_out", action="store_true",
                   help="machine-readable output")
    return p


def main(argv: list[str] | None = None) -> int:
    return cmd_recovery_probe(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
