"""E2E test helpers."""
from __future__ import annotations

import subprocess

from ssh_utils import run_ssh


def device_ssh(device: dict, command: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return run_ssh(device["ip"], command, key=device.get("key"), timeout=timeout)
