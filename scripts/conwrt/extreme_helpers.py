# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
"""Pure utility helpers extracted from extreme.py — no conwrt dependencies.

These functions use only stdlib modules (subprocess, re, shutil, typing)
and are safe to import from any module without circular-import risk.
"""

import re
import shutil
import subprocess
from typing import Optional


def _generate_zyxel_password(serial: str) -> Optional[str]:
    pwgen = shutil.which("zyxel_pwgen")
    if not pwgen:
        return None
    try:
        result = subprocess.run(
            [pwgen, serial],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")[-1].strip()
    except OSError:
        pass
    return None


def _ssh_with_password(ip: str, user: str, password: str, command: str,
                        timeout: int = 30, *, extra_ssh_options: list[str] | None = None) -> subprocess.CompletedProcess:
    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.CompletedProcess(
            args=[], returncode=127,
            stdout="", stderr="sshpass not found. Install with: brew install hudochenkov/sshpass/sshpass",
        )
    cmd = [
        sshpass, "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout=10",
        *(extra_ssh_options or []),
        f"{user}@{ip}",
        command,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _scp_with_password(ip: str, user: str, password: str,
                       remote_src: str, local_dst: str,
                       timeout: int = 120, *, extra_ssh_options: list[str] | None = None) -> subprocess.CompletedProcess:
    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.CompletedProcess(
            args=[], returncode=127,
            stdout="", stderr="sshpass not found.",
        )
    cmd = [
        sshpass, "-p", password,
        "scp", "-O",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        *(extra_ssh_options or []),
        f"{user}@{ip}:{remote_src}",
        local_dst,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _parse_key_value_lines(output: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _sanitize_filename_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return cleaned.strip("-._") or "unknown"
