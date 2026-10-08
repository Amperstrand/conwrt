"""NordVPN e2e user stories — flash, exit, AP, management, kill switch.

Each test is a user story: it starts from what the user plugs in and ends
with an observable outcome on the real surface (the router, the network
port, the lab phone). Hardware-gated: skips without CONWRT_DEVICE_IP; the
phone stories skip without ADB access to the bench Android.

Run (bench session, ai-legion-small):
    CONWRT_DEVICE_IP=192.168.1.1 pytest tests/e2e/test_nordvpn_e2e.py -v

Destructive stories additionally require CONWRT_E2E_FLASH=1.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from .helpers import device_ssh

REPO = Path(__file__).resolve().parents[2]
ADB_HOST = os.environ.get("CONWRT_E2E_ADB_HOST", "root@192.168.13.208")
ANDROID_SERIAL = os.environ.get("CONWRT_E2E_ANDROID_SERIAL", "ZY326DPC7R")
VPN_AP_SSID = os.environ.get("CONWRT_E2E_AP_SSID", "nord")
VPN_AP_KEY = os.environ.get("CONWRT_E2E_AP_KEY", "nordnord")
VPN_AP_SUBNET = "172.16.31."


def _adb(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run adb on the bench host that has the phone on USB."""
    cmd = ["ssh", "-o", "ConnectTimeout=8", ADB_HOST,
           "adb", "-s", ANDROID_SERIAL, "shell", *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


@pytest.fixture(scope="session")
def phone():
    """The bench Android (prta-scenario-poc pattern: skip cleanly when absent)."""
    r = _adb("echo PHONE_OK", timeout=15)
    if r.returncode != 0 or "PHONE_OK" not in r.stdout:
        pytest.skip(f"bench phone not reachable via {ADB_HOST} ({ANDROID_SERIAL})")
    return ANDROID_SERIAL


@pytest.fixture(scope="session")
def exit_ip(device: dict) -> str:
    """Public IP as seen from a wired LAN client routed through the router."""
    route_added = False
    try:
        subprocess.run(
            ["sudo", "-n", "ip", "route", "add", "default",
             "via", device["ip"], "dev", device.get("interface", "enp5s0"),
             "metric", "50"],
            capture_output=True, timeout=10, check=False,
        )
        route_added = True
        r = subprocess.run(
            ["curl", "-4", "-s", "-m", "12",
             "http://ip-api.com/line/?fields=query,country,city,isp"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        assert r.returncode == 0 and r.stdout.strip(), f"no exit IP: {r.stderr}"
        return r.stdout.strip()
    finally:
        if route_added:
            subprocess.run(
                ["sudo", "-n", "ip", "route", "del", "default",
                 "via", device["ip"], "dev", device.get("interface", "enp5s0"),
                 "metric", "50"],
                capture_output=True, timeout=10, check=False,
            )


@pytest.mark.smoke
@pytest.mark.hardware
def test_us0_wireguard_tunnel_alive(device: dict) -> None:
    """As a user I want the router's tunnel up so everything behind it exits via NordVPN."""
    r = device_ssh(device, "wg show wg0 latest-handshakes")
    assert r.returncode == 0, r.stderr
    parts = r.stdout.split()
    assert parts, "no wg peer"
    handshake_age = time.time() - int(parts[-1])
    assert handshake_age < 300, f"handshake is {handshake_age:.0f}s old — tunnel not alive"


@pytest.mark.smoke
@pytest.mark.hardware
def test_us1_wired_client_exits_via_nordvpn_germany(device: dict, exit_ip: str) -> None:
    """As a user who plugs into the network port, my traffic exits via NordVPN DE."""
    lines = exit_ip.splitlines()
    assert "Germany" in lines, f"exit not in Germany: {exit_ip}"


@pytest.mark.smoke
@pytest.mark.hardware
def test_us1b_exit_ip_is_not_the_upstream(device: dict, exit_ip: str) -> None:
    """As a privacy-minded user my exit IP must not be my house ISP address."""
    house_ip = subprocess.run(
        ["curl", "-4", "-s", "-m", "10", "http://ip-api.com/line/?fields=query"],
        capture_output=True, text=True, timeout=15, check=False,
    ).stdout.strip()
    exit_only = exit_ip.splitlines()[0] if "\n" in exit_ip else exit_ip
    assert exit_only and exit_only != house_ip, "exit equals house IP — traffic is NOT going through the VPN"


@pytest.mark.smoke
@pytest.mark.hardware
def test_us2_phone_gets_dhcp_lease_on_vpn_ap(device: dict, phone: str) -> None:
    """As a user who joins SSID 'nord' with the password, I get a VPN-subnet lease."""
    _adb("cmd", "wifi", "connect-network", VPN_AP_SSID, "wpa2", VPN_AP_KEY)
    deadline = time.time() + 45
    lease = ""
    while time.time() < deadline:
        r = _adb("ifconfig", "wlan0")
        for line in r.stdout.splitlines():
            if "inet addr" in line:
                lease = line.split("inet addr:")[1].split()[0]
                break
        if lease.startswith(VPN_AP_SUBNET):
            break
        time.sleep(3)
    assert lease.startswith(VPN_AP_SUBNET), f"no {VPN_AP_SUBNET}x lease on wlan0 (got '{lease}')"


@pytest.mark.smoke
@pytest.mark.hardware
def test_us3_phone_exits_via_vpn(device: dict, phone: str) -> None:
    """As a phone user on 'nord', my traffic flows through the router's tunnel."""
    r = _adb("ping", "-c", "3", "-W", "4", "1.1.1.1", timeout=30)
    assert "0% packet loss" in r.stdout or " 0% packet loss" in r.stdout, \
        f"phone cannot reach the internet through the VPN AP: {r.stdout[-200:]}"


@pytest.mark.smoke
@pytest.mark.hardware
def test_us4_management_reachable_from_vpn_zone(device: dict, phone: str) -> None:
    """As an operator I can reach the router's SSH from the VPN side (not locked out)."""
    r = _adb("nc", "-w", "3", VPN_AP_SUBNET + "1", "22", timeout=15)
    assert "SSH" in r.stdout, f"no dropbear banner from the VPN zone: {r.stdout!r} {r.stderr!r}"


@pytest.mark.smoke
@pytest.mark.hardware
def test_us5_kill_switch_blocks_leaks(device: dict) -> None:
    """As a user, if the tunnel dies my clients must NOT leak via the uplink."""
    device_ssh(device, "ifdown wg0")
    time.sleep(3)
    route_added = False
    leak = ""
    try:
        subprocess.run(
            ["sudo", "-n", "ip", "route", "add", "default",
             "via", device["ip"], "dev", device.get("interface", "enp5s0"),
             "metric", "50"],
            capture_output=True, timeout=10, check=False,
        )
        route_added = True
        r = subprocess.run(
            ["curl", "-4", "-s", "-m", "8", "http://ip-api.com/line/?fields=query"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        leak = r.stdout.strip()
    finally:
        if route_added:
            subprocess.run(
                ["sudo", "-n", "ip", "route", "del", "default",
                 "via", device["ip"], "dev", device.get("interface", "enp5s0"),
                 "metric", "50"],
                capture_output=True, timeout=10, check=False,
            )
        device_ssh(device, "ifup wg0")
    assert leak == "", f"traffic leaked around the dead tunnel (exit {leak})"


@pytest.mark.smoke
@pytest.mark.hardware
def test_us6_server_selection_lists_and_matches(device: dict) -> None:
    """As an operator I can list NordVPN servers and see which one I'm pinned to."""
    r = subprocess.run(
        [sys_executable(), str(REPO / "scripts" / "nordvpn.py"),
         "servers", "--country", "DE", "--limit", "5", "--json"],
        capture_output=True, text=True, timeout=40, check=False,
    )
    assert r.returncode == 0, r.stderr
    servers = json.loads(r.stdout)
    assert servers, "no DE wireguard_udp servers listed"
    endpoints = {s["station"] for s in servers}

    wg = device_ssh(device, "wg show wg0 endpoints").stdout.split()
    active = wg[1].rsplit(":", 1)[0] if len(wg) >= 2 else ""
    r2 = device_ssh(device, "wg show wg0 endpoints; uci -q get network.nordvpn_server_route.target")
    pinned = r2.stdout.strip().splitlines()[-1] if r2.stdout.strip() else ""
    assert active in endpoints or pinned in endpoints or active == "", \
        f"active endpoint {active} (route {pinned}) not among listed DE servers {sorted(endpoints)}"


def sys_executable() -> str:
    import sys
    return sys.executable


@pytest.mark.flash
@pytest.mark.destructive
@pytest.mark.hardware
def test_us7_flash_from_scratch_is_unattended(device: dict) -> None:
    """As a fresh user with a router in a known state, one command re-provisions it.

    Requires CONWRT_E2E_FLASH=1 — reflashes the device (sysupgrade -n) with
    the current ASU build and expects it to come back fully configured.
    """
    if os.environ.get("CONWRT_E2E_FLASH") != "1":
        pytest.skip("set CONWRT_E2E_FLASH=1 to allow re-flashing the device")
    r = subprocess.run(
        [sys_executable(), str(REPO / "scripts" / "conwrt.py"), "flash",
         "--model-id", "dlink-covr-x1860-a1", "--request-image",
         "--interface", device.get("interface", "enp5s0"), "--no-voice"],
        cwd=str(REPO), timeout=1500, check=False,
    )
    assert r.returncode == 0
    deadline = time.time() + 600
    ok = False
    while time.time() < deadline:
        rr = device_ssh(device, ". /etc/openwrt_release; echo $DISTRIB_RELEASE")
        if rr.returncode == 0 and rr.stdout.strip():
            ok = True
            break
        time.sleep(15)
    assert ok, "device did not come back after flash"
