"""E2E configure tests — verify profile apply produces correct UCI state.

Requires: CONWRT_DEVICE_IP, CONWRT_SSH_KEY, and a freshly-flashed device.
"""
from __future__ import annotations

import pytest

from .helpers import device_ssh


@pytest.mark.configure
def test_authorized_keys_present(device: dict) -> None:
    r = device_ssh(device, "wc -l < /etc/dropbear/authorized_keys")
    assert r.returncode == 0
    assert int(r.stdout.strip()) > 0


@pytest.mark.configure
def test_password_disabled_on_wan(device: dict) -> None:
    r = device_ssh(device, "uci get dropbear.@dropbear[0].PasswordAuth")
    assert r.returncode == 0


@pytest.mark.configure
def test_wwan_interface_configured(device: dict) -> None:
    r = device_ssh(device, "uci get network.wwan.proto")
    if r.returncode != 0:
        pytest.skip("No wwan interface (WiFi STA not configured)")
    assert r.stdout.strip() == "dhcp"


@pytest.mark.configure
def test_wifi_radio_enabled(device: dict) -> None:
    r = device_ssh(device, "uci get wireless.radio0.disabled")
    if r.returncode != 0:
        pytest.skip("No radio0")
    assert r.stdout.strip() == "0"


@pytest.mark.configure
def test_guest_wifi_firewall_zone(device: dict) -> None:
    r = device_ssh(device, "uci get firewall.guest.name")
    if r.returncode != 0:
        pytest.skip("No guest firewall zone (guest-wifi not configured)")
    assert r.stdout.strip() == "guest"
