"""Dry-run conwrt configure tests — verify UCI output without SSH or QEMU.

These tests run in <1 second (no VM, no network) by using conwrt's --dry-run
flag which prints the UCI commands that would be applied.

This complements the QEMU integration tests (test_sqm.py) which verify the
commands actually work on a real OpenWrt instance.
"""
from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_configure_dry_run(config_toml_content: str, tmp_path: Path) -> str:
    config_toml = tmp_path / "config.toml"
    config_toml.write_text(textwrap.dedent(config_toml_content))

    original = REPO_ROOT / "config.toml"
    backup = REPO_ROOT / "config.toml.bak"
    if original.exists():
        shutil.copy(original, backup)
    try:
        shutil.copy(config_toml, original)
        result = subprocess.run(
            ["python3", str(REPO_ROOT / "scripts" / "conwrt.py"), "configure",
             "--model-id", "virtual-x86-64",
             "--ip", "192.168.1.1",
             "--dry-run"],
            capture_output=True, text=True, timeout=30,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0, f"conwrt configure --dry-run failed:\n{result.stderr}"
        return result.stdout
    finally:
        if backup.exists():
            shutil.move(backup, original)


def test_sqm_dry_run_generates_cake_qdisc(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["sqm"]

        [use_cases.sqm]
        download_kbps = 10000
        upload_kbps = 5000
    """, tmp_path)

    assert "uci set sqm.wan.enabled='1'" in output
    assert "uci set sqm.wan.qdisc='cake'" in output
    assert "uci set sqm.wan.script='piece_of_cake.qos'" in output
    assert "uci set sqm.wan.download='10000'" in output
    assert "uci set sqm.wan.upload='5000'" in output
    assert "uci commit sqm" in output
    assert "/etc/init.d/sqm enable" in output
    assert "/etc/init.d/sqm restart" in output


def test_sqm_dry_run_custom_speeds(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["sqm"]

        [use_cases.sqm]
        download_kbps = 340000
        upload_kbps = 19000
    """, tmp_path)

    assert "uci set sqm.wan.download='340000'" in output
    assert "uci set sqm.wan.upload='19000'" in output


def test_sqm_dry_run_includes_packages(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["sqm"]

        [use_cases.sqm]
        download_kbps = 10000
        upload_kbps = 5000
    """, tmp_path)

    assert "sqm-scripts" in output
    assert "luci-app-sqm" in output


def test_doh_dry_run_generates_resolver_config(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["doh"]

        [use_cases.doh]
        provider = "cloudflare"
    """, tmp_path)

    assert "cloudflare-dns.com" in output or "dns-query" in output


def test_doh_dry_run_google_provider(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["doh"]

        [use_cases.doh]
        provider = "google"
    """, tmp_path)

    assert "dns.google" in output


def test_combined_sqm_doh_dry_run(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["sqm", "doh"]

        [use_cases.sqm]
        download_kbps = 10000
        upload_kbps = 5000

        [use_cases.doh]
        provider = "cloudflare"
    """, tmp_path)

    assert "uci set sqm.wan.qdisc='cake'" in output
    assert "cloudflare-dns.com" in output or "dns-query" in output


def test_nodns_dry_run_generates_dnsmasq_config(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["nodns"]
    """, tmp_path)

    assert "dnsmasq" in output.lower()


def test_ssh_hardening_dry_run_disables_password_auth(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["ssh-hardening"]
    """, tmp_path)

    assert "dropbear" in output.lower()
    assert "PasswordAuth" in output or "passwordauth" in output.lower()


def test_wireguard_client_dry_run_generates_wg0_config(tmp_path):
    output = _run_configure_dry_run("""\
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
    """, tmp_path)

    assert "wg0" in output or "wireguard" in output.lower()
    assert "vpn.example.com" in output or "51820" in output


def test_adguard_dry_run_includes_packages(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["adguard"]
    """, tmp_path)

    assert "adguard" in output.lower()


def test_mwan3_dry_run_generates_interfaces(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["mwan3"]
    """, tmp_path)

    assert "mwan3" in output.lower()


def test_ssl_dry_run_includes_packages(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["ssl"]
    """, tmp_path)

    assert "ssl" in output.lower() or "acme" in output.lower()


def test_all_non_hardware_use_cases_combined(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["sqm", "doh", "nodns", "ssh-hardening"]

        [use_cases.sqm]
        download_kbps = 10000
        upload_kbps = 5000

        [use_cases.doh]
        provider = "cloudflare"
    """, tmp_path)

    assert "uci set sqm.wan.qdisc='cake'" in output
    assert "cloudflare-dns.com" in output or "dns-query" in output
    assert "dnsmasq" in output.lower()
    assert "dropbear" in output.lower()


def test_wireguard_server_dry_run_auto_generates_key(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["wireguard-server"]

        [use_cases.wireguard-server]
        listen_port = 51820
        subnet = "10.0.0.1/24"
    """, tmp_path)

    assert "uci set network.wg0=interface" in output
    assert "wireguard" in output
    assert "51820" in output
    assert "10.0.0.1/24" in output
    assert "private_key" in output
    assert "generate" in output or "private_key='generate'" in output
    assert "firewall" in output.lower()
    assert "vpn" in output.lower()


def test_wireguard_server_dry_run_with_peer(tmp_path):
    output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["wireguard-server"]

        [use_cases.wireguard-server]
        listen_port = 51820
        subnet = "10.0.0.1/24"
        peer1_public_key = "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ="
        peer1_allowed_ips = "10.0.0.2/32"
    """, tmp_path)

    assert "wg0_peer1" in output or "wireguard_wg0" in output
    assert "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ=" in output
    assert "10.0.0.2/32" in output


def test_wireguard_client_server_loop(tmp_path):
    """Verify server and client configs are compatible — same port, compatible subnets."""
    server_output = _run_configure_dry_run("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["wireguard-server"]

        [use_cases.wireguard-server]
        listen_port = 51820
        subnet = "10.0.0.1/24"
    """, tmp_path)

    client_output = _run_configure_dry_run("""\
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
    """, tmp_path)

    assert "51820" in server_output
    assert "51820" in client_output
    assert "10.0.0.1/24" in server_output
    assert "10.0.0.2/32" in client_output
    assert "wg0" in server_output
    assert "wg0" in client_output
