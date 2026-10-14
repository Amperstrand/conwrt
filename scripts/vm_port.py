"""Port claiming for VM fixtures on shared multi-agent hosts.

AGENTS.md "Multi-Agent Coordination": ports are claimed, not assumed —
fixtures take their host port from an env var so a colliding session can
shift, and fail fast (naming the holder) instead of cascading errors.
"""
from __future__ import annotations

import os
import shlex
import socket
import subprocess


def port_from_env(var: str, default: int) -> int:
    value = os.environ.get(var, "").strip()
    if not value:
        return default
    try:
        port = int(value)
    except ValueError as exc:
        raise RuntimeError(f"{var}={value!r} is not a port number") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError(f"{var}={value!r} is out of range")
    return port


def port_bound(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex((host, port)) == 0


def holder_hint(port: int) -> str:
    """Best-effort `ss -tlnp` line for whoever listens on *port*."""
    try:
        r = subprocess.run(
            ["ss", "-tlnp"], capture_output=True, text=True, timeout=5, check=False,
        )
    except (FileNotFoundError, OSError):
        return "(ss unavailable)"
    for line in r.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and f":{port}" in fields[3]:
            return line.strip()
    return "(no listener found in ss output — race?)"


def require_free(port: int, host: str, env_var: str, what: str) -> None:
    """Raise with an actionable message when *port* is already claimed.

    The message names the env var to shift this fixture to another port and
    points at the session ledger — on a multi-agent host the holder is very
    often a sibling session's VM.
    """
    if not port_bound(port, host):
        return
    raise RuntimeError(
        f"{what}: host port {port} is already in use.\n"
        f"  holder: {holder_hint(port)}\n"
        f"  On a shared host this is usually another session's VM — check "
        f"data/active-sessions.jsonl, or shift this fixture by setting "
        f"{env_var}={shlex.quote(str(port + 1))} (or any free port)."
    )
