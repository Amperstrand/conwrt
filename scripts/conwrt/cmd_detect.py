# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import argparse
import sys

from flash.context import log
from flash.device_detect import (
    active_fingerprint as _active_fingerprint,
    match_models as _match_models,
)
from conwrt.device_inventory import auto_detect_interface


def cmd_fingerprint(args: argparse.Namespace) -> int:
    """Fingerprint a device to identify its model."""
    ip = args.ip
    log(f"Fingerprinting device at {ip}...")

    result = _active_fingerprint(ip, timeout=args.timeout)

    if not result.candidates:
        print(f"No device detected at {ip}.", file=sys.stderr)
        return 1

    matched = _match_models(result)

    if getattr(args, 'json_output', False):
        import json as _json
        output = {
            "ip": ip,
            "candidates": [
                {
                    "vendor": c.vendor,
                    "model_id": c.model_id,
                    "confidence": c.confidence,
                    "evidence": c.evidence,
                    "mac_oui": c.mac_oui,
                    "hostname": c.hostname,
                    "ssh_banner": c.ssh_banner,
                    "open_ports": c.open_ports,
                    "board_name": c.board_name,
                }
                for c in result.candidates
            ],
            "model_matches": [
                {
                    "model_id": c.model_id,
                    "vendor": c.vendor,
                    "confidence": c.confidence,
                    "evidence": c.evidence,
                }
                for c in matched
            ],
        }
        print(_json.dumps(output, indent=2))
    else:
        print()
        for c in result.candidates:
            print(f"  Vendor: {c.vendor}")
            if c.model_id:
                print(f"  Model:  {c.model_id}")
            print(f"  Confidence: {c.confidence}")
            print(f"  Evidence: {', '.join(c.evidence)}")
            if c.ssh_banner:
                print(f"  SSH Banner: {c.ssh_banner}")
            if c.open_ports:
                print(f"  Open Ports: {c.open_ports}")
            if c.board_name:
                print(f"  Board:      {c.board_name}")

        if matched:
            print()
            print("Model matches:")
            for m in matched:
                print(f"  {m.model_id} ({m.vendor}) — {m.confidence} confidence")
                print(f"    Evidence: {', '.join(m.evidence)}")
        else:
            print()
            print("No model matches found in models/ directory.")

    return 0


def cmd_auto(args: argparse.Namespace) -> int:
    from auto_detect import auto_detect, interactive_menu

    interface = args.interface or auto_detect_interface()
    if not interface:
        print("ERROR: no active ethernet interface found. Use --interface.", file=sys.stderr)
        return 1

    print(f"Auto-detecting routers on {interface}...")
    print()

    routers = auto_detect(interface, passive_timeout=args.passive_timeout)

    if not routers:
        print("No routers detected. Check that:")
        print("  - Ethernet cable is connected")
        print("  - Router is powered on")
        print("  - Interface is correct (use --interface)")
        return 1

    if args.no_menu:
        for r in routers:
            print(f"  IP: {r.ip}  MAC: {r.mac}  Vendor: {r.vendor}  "
                  f"Model: {r.model_name or '?'}  State: {r.firmware_state}  "
                  f"Confidence: {r.confidence}")
        return 0

    interactive_menu(routers)
    return 0
