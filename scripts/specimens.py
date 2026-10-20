#!/usr/bin/env python3
"""Specimen ledger — the local record of known bench units (#296).

The MAC/serial specimen record for devices that cross this workstation's
bench. Two consumers:

- ``pi_image.py provision`` records every specimen whose live identity it
  verified (auto-population from AGENTS.md-mandated identity reads).
- ``pi_eeprom.py push`` refuses an ``--expect-mac`` that is NOT in the
  ledger: the armed dnsmasq allowlist and the operator's flag can share one
  mistake (wrong adjacent unit armed + same MAC passed), so the push gate
  gets this independent record as a second source (review of #294, issue
  #296).

Ledger file: ``$CONWRT_SPECIMENS`` or ``~/.conwrt/specimens.json``, written
0600 (unit MACs/serials/labels are operational metadata — local only).

Usage:
    python3 scripts/specimens.py list
    python3 scripts/specimens.py add --mac DC:A6:32:11:22:33 \
        [--serial 10000000abcd1234] [--label pi4-bench] [--host 192.168.4.52]
    python3 scripts/specimens.py read --host 192.168.4.52 [--label pi4-bench]
    python3 scripts/specimens.py remove --mac DC:A6:32:11:22:33
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

LEDGER_VERSION = 1


def default_ledger_path() -> Path:
    env = os.environ.get("CONWRT_SPECIMENS")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".conwrt" / "specimens.json"


def norm_mac(mac: str) -> str:
    return mac.strip().lower()


def norm_serial(serial: str) -> str:
    return serial.strip().lower()


def _resolve(path: Path | str | None) -> Path:
    return Path(path).expanduser() if path else default_ledger_path()


def load(path: Path | str | None = None) -> dict:
    """Read the ledger; missing file ⇒ empty ledger (never raises)."""
    p = _resolve(path)
    if not p.is_file():
        return {"version": LEDGER_VERSION, "specimens": []}
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(
            f"specimen ledger {p} is unreadable/corrupt: {exc} — fix or "
            "remove it (it will be rebuilt from live reads)") from exc
    if not isinstance(data.get("specimens"), list):
        raise SystemExit(f"specimen ledger {p} has no specimens list")
    return data


def save(data: dict, path: Path | str | None = None) -> None:
    p = _resolve(path)
    p.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)  # O_TRUNC keeps the old inode's mode — re-assert
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def record(mac: str | None = None, serial: str | None = None,
           label: str = "", host: str = "", source: str = "",
           path: Path | None = None) -> dict:
    """Upsert one specimen (matched by mac OR serial) into the ledger.

    Returns the stored entry. Recording never overrides a known MAC with
    a different serial (or vice versa) — that raises: a MAC and serial that
    disagree means two units are being conflated, which is exactly the
    specimen-gate failure this ledger exists to catch.
    """
    p = _resolve(path)
    data = load(p)
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    mac_n = norm_mac(mac) if mac else ""
    serial_n = norm_serial(serial) if serial else ""
    for entry in data["specimens"]:
        mac_hit = mac_n and entry.get("mac") == mac_n
        if not mac_hit:
            continue
        # A MAC whose serial CHANGES is two units being conflated — the
        # exact failure this ledger exists to catch. (The reverse — one
        # serial with several MACs — is a normal multi-interface unit and
        # appends as its own entry below.)
        if serial_n and entry.get("serial") and entry["serial"] != serial_n:
            raise SystemExit(
                f"refusing ledger update: MAC {mac_n} is recorded with "
                f"serial {entry['serial']} but this live read says "
                f"{serial_n} — two units are being conflated")
        if serial_n:
            entry["serial"] = serial_n
        if label:
            entry["label"] = label
        if host:
            entry["host"] = host
        if source:
            entry["source"] = source
        entry["last_seen"] = now
        save(data, p)
        return entry
    entry = {
        "mac": mac_n,
        "serial": serial_n,
        "label": label,
        "host": host,
        "source": source,
        "first_seen": now,
        "last_seen": now,
    }
    data["specimens"].append(entry)
    save(data, p)
    return entry


def known_macs(path: Path | None = None) -> set[str]:
    return {e["mac"] for e in load(path)["specimens"] if e.get("mac")}


def remove(mac: str, path: Path | str | None = None) -> bool:
    p = _resolve(path)
    data = load(p)
    mac_n = norm_mac(mac)
    before = len(data["specimens"])
    data["specimens"] = [e for e in data["specimens"]
                         if e.get("mac") != mac_n]
    if len(data["specimens"]) == before:
        return False
    save(data, p)
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_list(args: argparse.Namespace) -> int:
    data = load(args.ledger)
    rows = data["specimens"]
    if not rows:
        print("specimen ledger is empty "
              f"({args.ledger}) — bootstrap with `specimens read --host <pi>` "
              "or `specimens add --mac ...`")
        return 0
    print(f"{'MAC':18} {'SERIAL':18} {'LABEL':14} {'HOST':16} LAST_SEEN")
    for e in sorted(rows, key=lambda x: (x.get("label", ""), x.get("mac", ""))):
        print(f"{e.get('mac', '-') or '-':18} "
              f"{e.get('serial', '-') or '-':18} "
              f"{e.get('label', '-') or '-':14} "
              f"{e.get('host', '-') or '-':16} {e.get('last_seen', '-')}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    if not args.mac and not args.serial:
        print("specimens add: --mac and/or --serial required", file=sys.stderr)
        return 1
    entry = record(mac=args.mac, serial=args.serial, label=args.label or "",
                   host=args.host or "", source="manual", path=args.ledger)
    print(f"recorded: {entry}")
    return 0


def cmd_read(args: argparse.Namespace) -> int:
    from pi_image import remote_specimen
    serial, macs = remote_specimen(args.host)
    if not serial and not macs:
        print(f"no identity readable at {args.host} "
              "(is it up? root SSH?)", file=sys.stderr)
        return 1
    for mac in macs:
        record(mac=mac, serial=serial or "", label=args.label or "",
               host=args.host, source="specimens.read", path=args.ledger)
    print(f"recorded from {args.host}: serial={serial or 'n/a'} "
          f"macs={', '.join(macs) or 'n/a'}")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    if remove(args.mac, path=args.ledger):
        print(f"removed {norm_mac(args.mac)}")
        return 0
    print(f"{norm_mac(args.mac)} not in ledger", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ledger", default=None,
                   help="ledger path (default $CONWRT_SPECIMENS or "
                        "~/.conwrt/specimens.json)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list known specimens").set_defaults(
        func=cmd_list)

    sp = sub.add_parser("add", help="record a specimen manually")
    sp.add_argument("--mac", default=None)
    sp.add_argument("--serial", default=None)
    sp.add_argument("--label", default=None)
    sp.add_argument("--host", default=None)
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("read", help="record identity live from a host "
                                     "(same reads as the provision gate)")
    sp.add_argument("--host", required=True)
    sp.add_argument("--label", default=None)
    sp.set_defaults(func=cmd_read)

    sp = sub.add_parser("remove", help="remove a specimen by MAC")
    sp.add_argument("--mac", required=True)
    sp.set_defaults(func=cmd_remove)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
