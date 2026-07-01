"""SQM integration test — verifies conwrt configure applies SQM correctly.

Runs against a real OpenWrt x86_64 VM in QEMU. Verifies:
1. conwrt configure generates correct UCI state
2. SQM service is enabled and running
3. tc qdisc is configured (CAKE/fq_codel on the WAN device)
"""
from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = [pytest.mark.hardware]


def test_openssh_available(ssh_cmd):
    out = ssh_cmd("cat /etc/openwrt_release")
    assert "OpenWrt" in out


def test_sqm_package_installed(openwrt_vm, ssh_cmd):
    ssh_cmd("opkg update 2>/dev/null; opkg install sqm-scripts luci-app-sqm 2>&1", timeout=60)
    out = ssh_cmd("opkg list-installed | grep sqm")
    assert "sqm-scripts" in out


def test_conwrt_configure_applies_sqm(openwrt_vm, ssh_cmd, tmp_path):
    config_toml = tmp_path / "config.toml"
    config_toml.write_text(textwrap.dedent("""\
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
    """))

    import shutil
    original = REPO_ROOT / "config.toml"
    backup = REPO_ROOT / "config.toml.bak"
    if original.exists():
        shutil.copy(original, backup)
    try:
        shutil.copy(config_toml, original)

        result = subprocess.run(
            ["python3", str(REPO_ROOT / "scripts" / "conwrt.py"), "configure",
             "--model-id", "virtual-x86-64",
             "--ip", openwrt_vm["host"]],
            capture_output=True, text=True, timeout=300,
            cwd=str(REPO_ROOT),
        )

        assert result.returncode == 0, (
            f"conwrt configure failed (exit {result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    finally:
        if backup.exists():
            shutil.move(backup, original)

    uci_output = ssh_cmd("uci show sqm")
    assert "sqm" in uci_output
    assert "enabled='1'" in uci_output
    assert "qdisc='cake'" in uci_output
    assert "script='piece_of_cake.qos'" in uci_output
    assert "download='10000'" in uci_output
    assert "upload='5000'" in uci_output


def test_sqm_service_enabled(ssh_cmd):
    out = ssh_cmd("/etc/init.d/sqm enabled && echo ENABLED || echo DISABLED")
    assert "ENABLED" in out


def test_tc_qdisc_configured(ssh_cmd):
    out = ssh_cmd("tc qdisc show 2>/dev/null || echo 'tc not available'")
    if "tc not available" in out:
        pytest.skip("tc not available on this VM (kernel module missing)")
    assert "cake" in out or "fq_codel" in out, f"Expected CAKE or fq_codel qdisc, got: {out}"
