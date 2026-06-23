"""SSH transport layer for field-lab commands.

Wraps ssh_utils with field-lab-specific needs. Designed to be swappable:
today SSH over LAN, future transports (FIPS mesh, WireGuard) can replace
the implementation without touching command code.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ssh_utils import ssh_cmd, run_ssh, DROPBEAR_SSH_OPTIONS

# ---------------------------------------------------------------------------
# Host parsing
# ---------------------------------------------------------------------------

@dataclass
class Host:
    """Parsed --host value: user@ip or just ip."""
    ip: str
    user: str = "root"

    @classmethod
    def parse(cls, host: str) -> "Host":
        """Parse 'root@192.168.1.1' or '192.168.1.1' into Host."""
        if "@" in host:
            user, ip = host.rsplit("@", 1)
            return cls(ip=ip.strip(), user=user.strip())
        return cls(ip=host.strip())

    def __str__(self) -> str:
        return f"{self.user}@{self.ip}"


# ---------------------------------------------------------------------------
# SSH options for field-lab (field router is OpenWrt Dropbear)

_FIELDLAB_SSH_OPTIONS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
    "-o", "PasswordAuthentication=no",
    "-o", "ConnectTimeout=10",
] + DROPBEAR_SSH_OPTIONS


def _ssh_base(host: Host, connect_timeout: int = 10) -> list[str]:
    """Build base SSH command list for field-lab."""
    return [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", f"ConnectTimeout={connect_timeout}",
    ] + DROPBEAR_SSH_OPTIONS + [f"{host.user}@{host.ip}"]


# ---------------------------------------------------------------------------
# Public transport API
# ---------------------------------------------------------------------------

def run_remote(
    host: Host | str,
    command: str,
    timeout: int = 30,
    connect_timeout: int = 10,
) -> subprocess.CompletedProcess:
    """Run a command on the remote field router, return CompletedProcess.

    This is the field-lab equivalent of ssh_utils.run_ssh, but uses
    Host objects and Dropbear-compatible options by default.
    """
    h = host if isinstance(host, Host) else Host.parse(host)
    cmd = _ssh_base(h, connect_timeout) + [command]
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False,
    )


def stream_remote(
    host: Host | str,
    command: str,
    connect_timeout: int = 10,
) -> subprocess.Popen[bytes]:
    """Start a remote command with stdout piped for binary streaming.

    Caller is responsible for reading proc.stdout and calling proc.terminate().
    Used by capture.py for `tcpdump -w -` streaming.
    """
    h = host if isinstance(host, Host) else Host.parse(host)
    cmd = _ssh_base(h, connect_timeout) + [command]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,  # Binary mode — pcap data
    )


def check_tool(host: Host | str, tool_name: str, timeout: int = 10) -> bool:
    """Check if a tool (tcpdump, curl, nc, etc.) exists on the remote router."""
    h = host if isinstance(host, Host) else Host.parse(host)
    result = run_remote(h, f"which {shlex.quote(tool_name)} 2>/dev/null", timeout=timeout)
    return result.returncode == 0 and bool(result.stdout.strip())


def check_ssh(host: Host | str, timeout: int = 8) -> bool:
    """Quick connectivity check — can we SSH to the field router?"""
    h = host if isinstance(host, Host) else Host.parse(host)
    try:
        result = run_remote(h, "echo SSH_OK", timeout=timeout)
        return result.returncode == 0 and "SSH_OK" in result.stdout
    except (subprocess.SubprocessError, OSError):
        return False
