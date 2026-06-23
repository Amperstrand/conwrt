#!/usr/bin/env python3
"""fieldlab — conwrt Field Lab CLI.

Use a deployed OpenWrt router as a remote probe/flash appliance for
diagnosing unknown routers. Two conceptual modes:

  passthrough: the Mac observes/interacts with the unknown device through
    the field router (capture, forward). The field router is just a conduit.

  agent: the field router itself probes/flashes the unknown device
    (discover, future flash). The Mac supervises via artifacts.

Usage:
    python3 scripts/fieldlab.py inspect   --host root@192.168.1.1
    python3 scripts/fieldlab.py capture   --host root@192.168.1.1 --duration 30
    python3 scripts/fieldlab.py discover  --host root@192.168.1.1
    python3 scripts/fieldlab.py forward   --host root@192.168.1.1 --target 192.168.1.1:80
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure scripts/ is on sys.path so sibling modules (ssh_utils, etc.) are importable
_SCRIPTS_DIR = str(Path(__file__).resolve().parent.parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)


def main() -> int:
    from fieldlab.cli import build_parser
    from fieldlab.transport import Host

    parser = build_parser()
    args = parser.parse_args()

    command = getattr(args, "fieldlab_command", None)
    if not command:
        parser.print_help(sys.stderr)
        return 1

    # Validate SSH connectivity upfront (shared by all commands)
    host = Host.parse(args.host)

    if command == "inspect":
        from fieldlab.inspect_cmd import cmd_inspect
        return cmd_inspect(args, host)

    if command == "capture":
        from fieldlab.capture_cmd import cmd_capture
        return cmd_capture(args, host)

    if command == "discover":
        from fieldlab.discover_cmd import cmd_discover
        return cmd_discover(args, host)

    if command == "forward":
        from fieldlab.forward_cmd import cmd_forward
        return cmd_forward(args, host)

    if command == "prepare-probe":
        from fieldlab.prepare_cmd import cmd_prepare_probe
        return cmd_prepare_probe(args, host)

    if command == "serve":
        serve_cmd_type = getattr(args, "serve_command", None)
        if serve_cmd_type == "dhcp":
            from fieldlab.serve_cmd import cmd_serve_dhcp
            return cmd_serve_dhcp(args, host)
        if serve_cmd_type == "tftp":
            from fieldlab.serve_cmd import cmd_serve_tftp
            return cmd_serve_tftp(args, host)
        parser.print_help(sys.stderr)
        return 1

    if command == "fingerprint":
        from fieldlab.fingerprint_cmd import cmd_fingerprint
        return cmd_fingerprint(args, host)

    parser.print_help(sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
