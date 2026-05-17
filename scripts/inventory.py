#!/usr/bin/env python3
"""Device inventory system for conwrt — append-only JSONL storage.

Each line in the inventory file is a JSON object with device metadata:
  timestamp, device_serial, model, vendor, firmware_version, openwrt_target,
  mac_addresses, ssh_key_fingerprint, password_set, sha256_firmware,
  flashed_by, notes

CLI usage:
    python3 scripts/inventory.py --add --model MT3000 --mac 94:83:c4:XX:XX:XX
    python3 scripts/inventory.py --list
    python3 scripts/inventory.py --find --serial XXXX

Module usage:
    from inventory import append_to_inventory, read_inventory, find_device
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

DEFAULT_INVENTORY_PATH = str(Path(__file__).resolve().parent.parent / "data" / "inventory.jsonl")


def append_to_inventory(entry: dict, path: str = DEFAULT_INVENTORY_PATH) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def read_inventory(path: str = DEFAULT_INVENTORY_PATH) -> list[dict]:
    if not os.path.isfile(path):
        return []
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def find_device(serial: str, path: str = DEFAULT_INVENTORY_PATH) -> Optional[dict]:
    for entry in read_inventory(path):
        if entry.get("device_serial") == serial:
            return entry
    return None


def _cli_add(args: argparse.Namespace) -> None:
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "device_serial": args.serial or "",
        "model": args.model or "",
        "vendor": args.vendor or "",
        "firmware_version": args.firmware or "",
        "openwrt_target": args.target or "",
        "mac_addresses": args.mac.split(",") if args.mac else [],
        "ssh_key_fingerprint": args.ssh_key or "",
        "password_set": args.password_set,
        "sha256_firmware": args.sha256 or "",
        "flashed_by": args.flashed_by or os.environ.get("USER", ""),
        "notes": args.notes or "",
    }
    append_to_inventory(entry, args.inventory)
    print(f"Added: {json.dumps(entry, indent=2)}")


def _cli_list(args: argparse.Namespace) -> None:
    entries = read_inventory(args.inventory)
    if not entries:
        print("No inventory entries.")
        return
    for i, entry in enumerate(entries, 1):
        serial = entry.get("device_serial", "?")
        model = entry.get("model", "?")
        ts = entry.get("timestamp", "?")
        macs = ", ".join(entry.get("mac_addresses", []))
        print(f"  [{i}] {ts} | {model} | serial={serial} | macs=[{macs}]")


def _cli_find(args: argparse.Namespace) -> None:
    entry = find_device(args.serial, args.inventory)
    if entry:
        print(json.dumps(entry, indent=2))
    else:
        print(f"Device with serial '{args.serial}' not found.")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Device inventory management")
    parser.add_argument("--inventory", default=DEFAULT_INVENTORY_PATH,
                        help="Path to inventory JSONL file")
    sub = parser.add_subparsers(dest="command")

    add_p = sub.add_parser("add", help="Add a device to inventory")
    add_p.add_argument("--serial", default="")
    add_p.add_argument("--model", default="")
    add_p.add_argument("--vendor", default="")
    add_p.add_argument("--firmware", default="")
    add_p.add_argument("--target", default="", help="OpenWrt target (e.g. mediatek/filogic)")
    add_p.add_argument("--mac", default="", help="Comma-separated MAC addresses")
    add_p.add_argument("--ssh-key", default="", help="SSH key fingerprint")
    add_p.add_argument("--password-set", action="store_true", default=False)
    add_p.add_argument("--sha256", default="", help="SHA-256 of firmware image")
    add_p.add_argument("--flashed-by", default="")
    add_p.add_argument("--notes", default="")
    add_p.set_defaults(func=_cli_add)

    list_p = sub.add_parser("list", help="List all inventory entries")
    list_p.set_defaults(func=_cli_list)

    find_p = sub.add_parser("find", help="Find device by serial")
    find_p.add_argument("--serial", required=True)
    find_p.set_defaults(func=_cli_find)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
