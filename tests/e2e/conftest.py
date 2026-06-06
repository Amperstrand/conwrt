"""E2E test fixtures for physical OpenWrt routers.

Hardware tests require environment variables:
  CONWRT_DEVICE_IP   — router IP (e.g. 192.168.1.1)
  CONWRT_SSH_KEY     — path to SSH private key (optional, uses default if unset)

Tests skip automatically when CONWRT_DEVICE_IP is not set.
"""
from __future__ import annotations

import os
import subprocess
from typing import Generator

import pytest

from ssh_utils import run_ssh, check_ssh


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _device_available(ip: str, key: str | None = None) -> bool:
    return check_ssh(ip, connect_timeout=5, sentinel="SSH_OK") if ip else False


@pytest.fixture(scope="session")
def device_ip() -> str:
    ip = _env("CONWRT_DEVICE_IP")
    if not ip:
        pytest.skip("CONWRT_DEVICE_IP not set — hardware tests require a connected router")
    return ip


@pytest.fixture(scope="session")
def device_key() -> str | None:
    return _env("CONWRT_SSH_KEY") or None


@pytest.fixture(scope="session")
def device(device_ip: str, device_key: str | None) -> Generator[dict[str, str | None], None, None]:
    if not _device_available(device_ip, device_key):
        pytest.skip(f"Device at {device_ip} not reachable via SSH")
    r = run_ssh(device_ip, "cat /etc/openwrt_release", key=device_key, timeout=10)
    if r.returncode != 0:
        pytest.skip(f"Cannot read /etc/openwrt_release from {device_ip}")
    info: dict[str, str] = {}
    for line in r.stdout.strip().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip().strip("'\"")
    yield {"ip": device_ip, "key": device_key, **info}
