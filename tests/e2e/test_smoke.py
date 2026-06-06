"""E2E smoke tests — basic SSH connectivity and device identity.

Run: CONWRT_DEVICE_IP=192.168.1.1 pytest tests/e2e/ -m smoke -v
"""
from __future__ import annotations

import pytest

from .helpers import device_ssh


@pytest.mark.smoke
def test_ssh_connectivity(device: dict) -> None:
    r = device_ssh(device, "echo SSH_OK")
    assert r.returncode == 0
    assert "SSH_OK" in r.stdout


@pytest.mark.smoke
def test_running_openwrt(device: dict) -> None:
    assert device.get("OPENWRT_RELEASE") or device.get("OPENWRT_ARCH")


@pytest.mark.smoke
def test_hostname_readable(device: dict) -> None:
    r = device_ssh(device, "uci get system.@system[0].hostname")
    assert r.returncode == 0
    assert r.stdout.strip()


@pytest.mark.smoke
def test_uptime_readable(device: dict) -> None:
    r = device_ssh(device, "cat /proc/uptime")
    assert r.returncode == 0
    parts = r.stdout.strip().split()
    assert len(parts) >= 1
    uptime_seconds = float(parts[0])
    assert uptime_seconds > 0


@pytest.mark.smoke
def test_lan_ip_matches(device: dict) -> None:
    r = device_ssh(device, "uci get network.lan.ipaddr")
    assert r.returncode == 0
    assert r.stdout.strip() == device["ip"]
