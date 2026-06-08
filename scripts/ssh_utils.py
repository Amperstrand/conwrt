from __future__ import annotations

import socket
import subprocess
from collections.abc import Sequence

# OpenWrt Dropbear reads authorized_keys from this path, NOT ~/.ssh/authorized_keys.
# conwrt must use this path for all post-flash SSH key installation on OpenWrt.
DROPBEAR_AUTH_KEYS_PATH = "/etc/dropbear/authorized_keys"

# SSH options needed when connecting from openssh-client to a Dropbear server
# that may lack modern host key algorithms (Dropbear 2025.89 on some targets).
# See: docs/gotchas.md "OpenWrt Dropbear SSH Quirks — Algorithm Negotiation"
DROPBEAR_SSH_OPTIONS: list[str] = [
    "-o", "HostKeyAlgorithms=+ssh-rsa,ssh-ed25519",
    "-o", "KexAlgorithms=+curve25519-sha256,diffie-hellman-group14-sha256",
    "-o", "Ciphers=+aes128-ctr,aes256-ctr",
]


def ssh_cmd(
    ip: str,
    command: str | Sequence[str],
    key: str | None = None,
    connect_timeout: int = 10,
    dropbear_target: bool = False,
) -> list[str]:
    cmd: list[str] = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", "PasswordAuthentication=no",
    ]
    if dropbear_target:
        cmd.extend(DROPBEAR_SSH_OPTIONS)
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
    dropbear_target: bool = False,
) -> list[str]:
    cmd: list[str] = [
        "scp",
        "-O",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={connect_timeout}",
    ]
    if dropbear_target:
        cmd.extend(DROPBEAR_SSH_OPTIONS)
    if key:
        cmd += ["-i", key]
    cmd += [src, dst]
    return cmd


def run_ssh(ip, command, key=None, connect_timeout=10, timeout=30, **kwargs):
    """Run SSH command and return subprocess.CompletedProcess."""
    ssh_options = kwargs.pop("ssh_options", None)
    dropbear_target = kwargs.pop("dropbear_target", False)
    cmd = ssh_cmd(ip, command, key=key, connect_timeout=connect_timeout,
                  dropbear_target=dropbear_target)
    if ssh_options:
        cmd[1:1] = list(ssh_options)
    return subprocess.run(
        cmd,
        capture_output=True, text=True, timeout=timeout, check=False, **kwargs,
    )


def check_ssh(ip: str, connect_timeout: int = 3, sentinel: str = "SSH_OK") -> bool:
    try:
        r = run_ssh(ip, f"echo {sentinel}", connect_timeout=connect_timeout,
                     timeout=connect_timeout + 5)
        return r.returncode == 0 and sentinel in r.stdout
    except (subprocess.SubprocessError, OSError):
        return False
