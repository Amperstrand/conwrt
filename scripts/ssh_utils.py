from __future__ import annotations

import subprocess
from collections.abc import Sequence


def ssh_cmd(
    ip: str,
    command: str | Sequence[str],
    key: str | None = None,
    connect_timeout: int = 10,
) -> list[str]:
    cmd: list[str] = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", "PasswordAuthentication=no",
    ]
    if key:
        cmd += ["-i", key]
    cmd.append(f"root@{ip}")
    if isinstance(command, str):
        cmd.append(command)
    else:
        cmd.extend(command)
    return cmd


def scp_cmd(
    ip: str,
    src: str,
    dst: str,
    key: str | None = None,
    connect_timeout: int = 10,
) -> list[str]:
    cmd: list[str] = [
        "scp",
        "-O",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={connect_timeout}",
    ]
    if key:
        cmd += ["-i", key]
    cmd += [src, dst]
    return cmd


def run_ssh(ip, command, key=None, connect_timeout=10, timeout=30, **kwargs):
    """Run SSH command and return subprocess.CompletedProcess."""
    ssh_options = kwargs.pop("ssh_options", None)
    cmd = ssh_cmd(ip, command, key=key, connect_timeout=connect_timeout)
    if ssh_options:
        cmd[1:1] = list(ssh_options)
    return subprocess.run(
        cmd,
        capture_output=True, text=True, timeout=timeout, check=False, **kwargs,
    )
