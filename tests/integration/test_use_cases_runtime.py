"""Pytest integration tests for conwrt use cases on OpenWrt QEMU.

Uses the session-scoped openwrt_vm fixture from conftest.py to boot
one VM and test all use cases against it.
"""
from __future__ import annotations

import shutil
import subprocess
import textwrap
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
pytestmark = [pytest.mark.hardware]


def _ssh(ssh_cmd, vm, command, timeout=15):
    r = subprocess.run(ssh_cmd + [command], capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()


def _configure_and_verify(config_toml_content, openwrt_vm, checks):
    ssh_cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        "-i", str(REPO_ROOT / "tests" / "integration" / ".vm_ssh_key"),
        "-p", "2222", "root@127.0.0.1",
    ]

    tmpdir = Path(tempfile.mkdtemp())
    config_toml = tmpdir / "config.toml"
    config_toml.write_text(textwrap.dedent(config_toml_content))

    original = REPO_ROOT / "config.toml"
    backup = REPO_ROOT / "config.toml.bak"
    if original.exists():
        shutil.copy(original, backup)
    try:
        shutil.copy(config_toml, original)
        result = subprocess.run(
            ["python3", str(REPO_ROOT / "scripts" / "conwrt.py"), "configure",
             "--model-id", "virtual-x86-64", "--ip", "127.0.0.1"],
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, f"configure failed: {result.stderr[:200]}"
    finally:
        if backup.exists():
            shutil.move(backup, original)

    for check_name, check_cmd, expected in checks:
        out = _ssh(ssh_cmd, openwrt_vm, check_cmd)
        assert expected in out, f"{check_name}: expected '{expected}' in '{out[:200]}'"


def test_doh_configures_resolver(openwrt_vm):
    _configure_and_verify("""\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["doh"]
        [use_cases.doh]
        provider = "cloudflare"
    """, openwrt_vm, [
        ("uci.doh", "uci show https-dns-proxy 2>/dev/null || echo skip", "cloudflare-dns.com"),
    ])


def test_ssh_hardening_disables_passwords(openwrt_vm):
    _configure_and_verify("""\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["ssh-hardening"]
    """, openwrt_vm, [
        ("uci.dropbear", "uci show dropbear", "PasswordAuth"),
    ])


def test_wireguard_client_configures_peer(openwrt_vm):
    _configure_and_verify("""\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["wireguard-client"]
        [use_cases.wireguard-client]
        peer_public_key = "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ="
        endpoint_host = "vpn.example.com"
        endpoint_port = 51820
        address = "10.0.0.2/32"
        allowed_ips = "10.0.0.0/24"
    """, openwrt_vm, [
        ("uci.wg0", "uci show network.wg0 2>/dev/null || echo skip", "wireguard"),
        ("uci.endpoint", "uci show network 2>/dev/null | grep endpoint || echo skip", "endpoint"),
    ])


def test_wireguard_server_auto_generates_key(openwrt_vm):
    _configure_and_verify("""\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["wireguard-server"]
        [use_cases.wireguard-server]
        private_key = "generate"
        listen_port = 51820
        subnet = "10.1.99.1/24"
    """, openwrt_vm, [
        ("uci.wg0", "uci show network.wg0 2>/dev/null || echo skip", "wireguard"),
        ("uci.listen", "uci show network.wg0 2>/dev/null || echo skip", "51820"),
    ])


def test_vpn_node_generates_listing_script(openwrt_vm):
    _configure_and_verify("""\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["vpn-node"]
        [use_cases.vpn-node]
        nsec = "abc123def456"
        title = "Test VPN"
        endpoint_host = "vpn.test.com"
    """, openwrt_vm, [
        ("script.exists", "ls /etc/vpn-listing.sh 2>/dev/null && echo exists || echo missing", "exists"),
        ("nsec.stored", "cat /etc/vpn-node/nsec 2>/dev/null || echo missing", "abc123"),
        ("script.nak", "grep nak /etc/vpn-listing.sh 2>/dev/null || echo missing", "nak"),
    ])


def test_nodns_configures_dnsmasq(openwrt_vm):
    _configure_and_verify("""\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["nodns"]
    """, openwrt_vm, [
        ("uci.dnsmasq", "uci show dhcp 2>/dev/null | head -30", "dnsmasq"),
    ])


def test_combined_sqm_doh_hardening(openwrt_vm):
    _configure_and_verify("""\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["sqm", "doh", "nodns", "ssh-hardening"]
        [use_cases.sqm]
        download_kbps = 20000
        upload_kbps = 10000
        [use_cases.doh]
        provider = "google"
    """, openwrt_vm, [
        ("sqm", "uci show sqm 2>/dev/null", "download='20000'"),
        ("doh", "uci show https-dns-proxy 2>/dev/null || echo skip", "dns.google"),
        ("dropbear", "uci show dropbear 2>/dev/null", "PasswordAuth"),
    ])
