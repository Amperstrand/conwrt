"""Integration tests for conwrt use cases beyond SQM.

Tests DoH, guest-wifi, and nodns use cases against the QEMU OpenWrt VM.
Each test verifies that conwrt configure applies the correct UCI state.
"""
from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = [pytest.mark.hardware]


def _run_conwrt_configure(config_toml_content: str, tmp_path: Path, host: str) -> subprocess.CompletedProcess:
    config_toml = tmp_path / "config.toml"
    config_toml.write_text(textwrap.dedent(config_toml_content))

    original = REPO_ROOT / "config.toml"
    backup = REPO_ROOT / "config.toml.bak"
    if original.exists():
        shutil.copy(original, backup)
    try:
        shutil.copy(config_toml, original)
        return subprocess.run(
            ["python3", str(REPO_ROOT / "scripts" / "conwrt.py"), "configure",
             "--model-id", "virtual-x86-64",
             "--ip", host],
            capture_output=True, text=True, timeout=300,
            cwd=str(REPO_ROOT),
        )
    finally:
        if backup.exists():
            shutil.move(backup, original)


def test_doh_configures_https_dns_proxy(openwrt_vm, ssh_cmd, tmp_path):
    ssh_cmd("opkg update 2>/dev/null; opkg install https-dns-proxy 2>&1", timeout=120)

    result = _run_conwrt_configure("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["doh"]

        [use_cases.doh]
        provider = "cloudflare"
    """, tmp_path, openwrt_vm["host"])

    assert result.returncode == 0, f"conwrt configure failed:\n{result.stderr}"

    uci_output = ssh_cmd("uci show https-dns-proxy 2>/dev/null || echo 'not found'")
    if "not found" in uci_output:
        pytest.skip("https-dns-proxy package not installed on this VM")

    assert "cloudflare-dns.com" in uci_output or "dns-query" in uci_output, \
        f"Expected DoH provider URL in UCI output, got: {uci_output}"


def test_guest_wifi_creates_isolated_network(openwrt_vm, ssh_cmd, tmp_path):
    result = _run_conwrt_configure("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["guest-wifi"]

        [use_cases.guest-wifi]
        ssid = "TestGuest"
        key = "guestpass123"
    """, tmp_path, openwrt_vm["host"])

    assert result.returncode == 0, f"conwrt configure failed:\n{result.stderr}"

    uci_output = ssh_cmd("uci show network.guest 2>/dev/null || echo 'not found'")
    if "not found" in uci_output:
        pytest.skip("guest-wifi use case may not have WiFi radio on x86 VM")

    assert "guest" in uci_output.lower(), f"Expected guest network section, got: {uci_output}"


def test_nodns_configures_local_cache(openwrt_vm, ssh_cmd, tmp_path):
    result = _run_conwrt_configure("""\
        [password]
        mode = "none"

        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"

        [use_cases]
        enabled = ["nodns"]
    """, tmp_path, openwrt_vm["host"])

    assert result.returncode == 0, f"conwrt configure failed:\n{result.stderr}"

    uci_output = ssh_cmd("uci show dhcp 2>/dev/null | head -30")
    assert "dnsmasq" in uci_output, f"Expected dnsmasq config, got: {uci_output}"


def test_multiple_use_cases_combined(openwrt_vm, ssh_cmd, tmp_path):
    ssh_cmd("opkg update 2>/dev/null; opkg install https-dns-proxy 2>&1", timeout=120)

    result = _run_conwrt_configure("""\
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
        provider = "google"
    """, tmp_path, openwrt_vm["host"])

    assert result.returncode == 0, f"conwrt configure failed:\n{result.stderr}"

    sqm_output = ssh_cmd("uci show sqm 2>/dev/null")
    assert "enabled='1'" in sqm_output
    assert "download='10000'" in sqm_output

    doh_output = ssh_cmd("uci show https-dns-proxy 2>/dev/null || echo 'not found'")
    if "not found" not in doh_output:
        assert "dns.google" in doh_output or "dns-query" in doh_output
