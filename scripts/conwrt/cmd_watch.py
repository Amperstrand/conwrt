# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
"""`conwrt watch` — scan for routers in flashable states and prompt to flash.

The README entry point: plug a device in (recovery mode or running OpenWrt),
run `conwrt watch`, confirm the prompt, and conwrt flashes the latest OpenWrt.

Actively probes every model's recovery/default IPs (U-Boot recovery servers
answer ARP/HTTP even when silent) and classifies what it finds. MAC addresses
are matched against model OUIs and the local inventory for specimen identity
before any flash is offered.
"""

import argparse
import subprocess
import sys
import time

from conwrt.cmd_probe import (
    _cleanup_aliases,
    _configure_interface,
    _match_models_by_ip,
    _probe_target,
    _collect_probe_targets,
)
from conwrt.device_inventory import auto_detect_interface
from model_loader import list_models
from platform_utils import get_link_state

_FLASHABLE_STATES = ("uboot", "openwrt", "stock")

_PRIORITY_IPS = (
    "192.168.0.1",
    "192.168.1.1",
    "192.168.8.1",
    "10.0.0.1",
    "192.168.2.1",
)


def _prioritize(ips: list[str]) -> list[str]:
    head = [ip for ip in _PRIORITY_IPS if ip in ips]
    return head + [ip for ip in ips if ip not in head]


def _mac_for_ip(ip: str) -> str:
    """Return the neighbor MAC for ip (probes have already ARPed it)."""
    r = subprocess.run(
        ["ip", "neigh", "show", ip],
        capture_output=True, text=True, timeout=5, check=False,
    )
    for token in r.stdout.split():
        if token.count(":") == 5:
            return token.upper()
    return ""


def _oui_matches(mac: str, model: dict) -> bool:
    if not mac or mac == "UNKNOWN":
        return False
    prefix = mac[:8].upper()
    return prefix in {oui.upper() for oui in model.get("mac_oui", [])}


def _board_match(ip: str, models: list[dict]) -> dict | None:
    """Identify a running OpenWrt device by its /etc/board.json model id."""
    from model_match import match_model_by_board
    from ssh_utils import run_ssh

    r = run_ssh(ip, "cat /etc/board.json", connect_timeout=3, timeout=6)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    matched = match_model_by_board(r.stdout)
    if not matched:
        return None
    return next((m for m in models if m["id"] == matched["id"]), matched)


def _pick_model(ip: str, state: str, models: list[dict], mac: str):
    """Choose the most plausible model for a discovered device."""
    if state == "openwrt":
        board = _board_match(ip, models)
        if board:
            return board
    candidates = _match_models_by_ip(ip, models)
    if not candidates:
        return None
    if len(candidates) == 1:
        return next(m for m in models if m["id"] == candidates[0])
    for model_id in candidates:
        model = next(m for m in models if m["id"] == model_id)
        if _oui_matches(mac, model):
            return model
    return next(m for m in models if m["id"] == candidates[0])


def _print_card(ip: str, mac: str, state: str, model: dict | None) -> None:
    print()
    print("=" * 55)
    print(f"  Device found: {ip}  ({state})")
    if mac:
        print(f"  MAC:      {mac}")
    if model:
        print(f"  Model:    {model.get('description', model['id'])}")
        print(f"  Model ID: {model['id']}")
        methods = ", ".join(model.get("flash_methods", {}).keys())
        print(f"  Methods:  {methods}")
    else:
        print("  Model:    unknown (not in models/)")
    print("=" * 55)


def _flash_command(ip: str, state: str, model: dict | None, args: argparse.Namespace) -> list[str] | None:
    """Build the conwrt flash invocation for a discovered device."""
    cmd = [sys.executable, str(args._conwrt_py), "flash", "--interface", args.interface]
    if args.model_id:
        cmd += ["--model-id", args.model_id]
    elif model:
        cmd += ["--model-id", model["id"]]
    elif state != "openwrt":
        return None
    if args.image:
        cmd += ["--image", args.image]
    else:
        cmd += ["--request-image"]
    if args.no_upload:
        cmd += ["--no-upload"]
    if args.yes:
        cmd += ["--yes"]
    return cmd


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("(non-interactive terminal — skipping flash)")
        return False
    try:
        answer = input(f"{prompt} [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def cmd_watch(args: argparse.Namespace) -> int:
    interface = args.interface or auto_detect_interface()
    if not interface:
        print("ERROR: no active ethernet interface found. Use --interface.", file=sys.stderr)
        return 1
    args.interface = interface

    if not get_link_state(interface):
        print(f"WARNING: no link on {interface} — is the router plugged in and powered?")

    from pathlib import Path

    args._conwrt_py = Path(__file__).resolve().parent.parent / "conwrt.py"

    try:
        models = list_models()
    except (OSError, ValueError):
        models = []

    target_ips = _prioritize(_collect_probe_targets(models))
    flashed: set[str] = set()
    print(f"Watching {interface} — probing {len(target_ips)} addresses every "
          f"{args.interval}s (Ctrl-C to stop)", flush=True)

    try:
        while True:
            added_aliases: list[str] = []
            current_subnet = ""
            findings: list[tuple[str, str]] = []
            try:
                for ip in target_ips:
                    current_subnet = _configure_interface(
                        interface, ip, current_subnet, added_aliases,
                    )
                    target = _probe_target(ip, timeout=args.timeout)
                    if target.state in _FLASHABLE_STATES and ip not in flashed:
                        findings.append((ip, target.state))
                        print(f"  · {ip} — {target.state}", flush=True)
            finally:
                _cleanup_aliases(interface, added_aliases)

            for ip, state in findings:
                mac = _mac_for_ip(ip)
                model = _pick_model(ip, state, models, mac)
                _print_card(ip, mac, state, model)

                cmd = _flash_command(ip, state, model, args)
                if cmd is None:
                    print("  → no model match and device not running OpenWrt; "
                          "cannot flash automatically. Use `conwrt flash --model-id`.")
                    flashed.add(ip)
                    continue

                verb = "upgrade" if state == "openwrt" else "flash"
                image_desc = args.image or "a fresh ASU image (latest OpenWrt, your keys baked in)"
                if not _confirm(
                    f"  → {verb} this device with {image_desc}?", args.yes,
                ):
                    print("  (skipped)")
                    flashed.add(ip)
                    continue

                print(f"  $ {' '.join(cmd)}")
                rc = subprocess.run(cmd).returncode
                if rc == 0:
                    print(f"  ✓ flash flow completed for {ip}", flush=True)
                else:
                    print(f"  ✗ flash exited with code {rc}", flush=True)
                flashed.add(ip)
                if not args.loop:
                    return 0

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped watching.")
        return 0
