"""forward command — SSH local port-forward to a service on the unknown device.

Builds an ssh -L command that tunnels a local port through the field router
to the unknown device on the probe network. This gives the Mac direct TCP
access to the unknown device's web UI, SSH, etc. without routing changes.

By default prints the command; use --exec to run it directly.
"""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

from fieldlab.transport import Host, check_ssh, _ssh_base
from fieldlab.rundir import FieldLabRun


def _parse_target(target: str) -> tuple[str, int]:
    """Parse '192.168.1.1:80' into ('192.168.1.1', 80)."""
    if ":" not in target:
        raise ValueError(f"Target must be IP:PORT, got '{target}'")
    ip, port_str = target.rsplit(":", 1)
    port = int(port_str)
    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of range: {port}")
    return ip.strip(), port


def _parse_local(local_spec: str | None, target_port: int) -> str:
    """Resolve local bind spec, auto-selecting if omitted."""
    if local_spec:
        return local_spec
    return f"127.0.0.1:{18000 + target_port}"


def build_forward_command(host: Host, target_ip: str, target_port: int,
                          local_spec: str) -> list[str]:
    """Build the ssh -L command list."""
    parts = _ssh_base(host)
    # Insert -L before the host
    forward = f"{local_spec}:{target_ip}:{target_port}"
    idx = parts.index(f"{host.user}@{host.ip}")
    parts[idx:idx] = ["-L", forward, "-N"]
    return parts


def cmd_forward(args: argparse.Namespace, host: Host) -> int:
    """Print or execute an SSH -L port-forward to the unknown device."""
    try:
        target_ip, target_port = _parse_target(args.target)
    except ValueError as e:
        print(f"[!] Invalid --target: {e}", file=sys.stderr)
        return 1

    local_spec = _parse_local(args.local, target_port)

    print(f"[+] Forward: {local_spec} → {host} → {target_ip}:{target_port}",
          file=sys.stderr)

    cmd = build_forward_command(host, target_ip, target_port, local_spec)
    cmd_str = " ".join(shlex.quote(c) for c in cmd)

    # Record in manifest
    session = args.session
    if session:
        run = FieldLabRun(session)
    else:
        run = FieldLabRun.create()
    run.record_command(
        "forward",
        local=local_spec,
        target=f"{target_ip}:{target_port}",
        exec=args.exec,
    )

    if args.exec:
        if not check_ssh(host):
            print(f"[!] Cannot SSH to {host}.", file=sys.stderr)
            return 1
        print(f"[+] Opening forward. Ctrl-C to close.", file=sys.stderr)
        print(f"    Access the service at: http://{local_spec}" if target_port in (80, 443)
              else f"    Connect to: {local_spec}", file=sys.stderr)
        # Exec replaces this process — the user gets a foreground SSH session
        import os
        os.execvp(cmd[0], cmd)
        return 1  # Only reached if exec fails
    else:
        # Print the command for the user to run manually
        print(f"\n  {cmd_str}\n", file=sys.stdout)
        print(f"  Then access: http://{local_spec}" if target_port in (80, 443, 8080)
              else f"  Then connect to: {local_spec}", file=sys.stdout)
        print(f"\n  Or use --exec to run it directly.", file=sys.stdout)
        return 0
