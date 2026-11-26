#!/usr/bin/env python3
"""conwrt overlay — produce a post-flash identity overlay tarball (#828 item 3).

The `sysupgrade -n -f <overlay>` path (docs/zycast.md §1c) previously
required a hand-run `python -c` one-liner to build the tarball; the CLI
subcommand closes the reachability gap: identity resolution goes through
THE one decision place (`profile.overlay.resolve_overlay_identity` —
flag > config, mac-hash never baked), and the output is the exact
tarball `sysupgrade -f` accepts.

Usage:
    conwrt overlay --out /tmp/overlay.tar.gz \
        [--lan-ip 192.168.5.1] [--authorized-keys ~/.ssh/id_ed25519.pub] \
        [--keep-dhcp] [--print-command]
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from profile.overlay import (  # noqa: E402
    build_overlay_tarball,
    resolve_overlay_identity,
)


def _read_key_argument(value: str) -> str:
    """The --authorized-keys argument may be key text or a file path."""
    if value.startswith("ssh-"):
        return value.strip()
    path = os.path.expanduser(value)
    if os.path.isfile(path):
        return Path(path).read_text().strip()
    raise SystemExit(
        f"overlay: --authorized-keys is neither key text (ssh-…) nor a "
        f"readable file: {value!r}"
    )


def cmd_overlay(args: argparse.Namespace) -> int:
    keys: str | None = None
    if args.authorized_keys:
        keys = _read_key_argument(args.authorized_keys)

    lan_ip, keys = resolve_overlay_identity(args.lan_ip, keys)
    path = build_overlay_tarball(
        disable_dhcp=not args.keep_dhcp,
        authorized_keys=keys,
        lan_ip=lan_ip,
        out_path=getattr(args, "out", None),
    )

    print(path)
    if args.print_command:
        # The sysupgrade one-liner, exactly as the docs teach it — with
        # the real tarball path substituted, so the operator can paste it.
        print(f"scp -O {path} root@192.168.1.1:/tmp/", file=sys.stderr)
        print(
            f"ssh root@192.168.1.1 "
            f"\"sysupgrade -n -f /tmp/{Path(path).name} /tmp/<sysupgrade.bin>\"",
            file=sys.stderr,
        )
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "overlay",
        help="build the post-flash identity overlay tarball for sysupgrade -f (#828)",
        description=__doc__.split("\n")[0],
    )
    p.add_argument("--out", default=None, metavar="PATH",
                   help="write the tarball to PATH (default: a mkstemp path, printed)")
    p.add_argument("--lan-ip", default=None, metavar="IP",
                   help="pin the first-boot LAN IPv4 address (flag > config; "
                        "mac-hash derivation is never baked — device-side only)")
    p.add_argument("--authorized-keys", default=None, metavar="KEY_OR_PATH",
                   help="public key text or path to a .pub file "
                        "(flag > config [ssh].key)")
    p.add_argument("--keep-dhcp", action="store_true",
                   help="do NOT suppress the LAN DHCP server/RA (default: "
                        "suppressed — the rogue-DHCP discipline; only for "
                        "isolated DUT-bay tests that need a DHCP server)")
    p.add_argument("--print-command", action="store_true",
                   help="also print the scp+sysupgrade lines to paste")
    p.set_defaults(func=cmd_overlay)
