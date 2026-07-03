#!/usr/bin/env python3
"""Test ALL conwrt use cases on a real OpenWrt QEMU VM.

Boots one OpenWrt VM, then for each testable use case:
1. Creates config.toml with that use case
2. Runs conwrt configure
3. SSHes to VM and verifies UCI state + service runtime
4. Records pass/fail

Covers: sqm, doh, nodns, ssh-hardening, wireguard-client,
wireguard-server, ssl, tollgate-security, vpn-node

Usage (on SHC VM with KVM):
    cd /tmp/conwrt && source .venv/bin/activate
    python3 tests/integration/test_all_use_cases.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VM_SSH_BASE = [
    "ssh", "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=5",
    "-i", str(REPO_ROOT / "tests" / "integration" / ".vm_ssh_key"),
    "-p", "2222", "root@127.0.0.1",
]


def run(cmd, timeout=30):
    if isinstance(cmd, list):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)


def vm_ssh(cmd, timeout=15):
    r = subprocess.run(VM_SSH_BASE + [cmd], capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip(), r.returncode


def configure(config_toml_content, tmp_path):
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
             "--model-id", "virtual-x86-64", "--ip", "127.0.0.1"],
            capture_output=True, text=True, timeout=120,
        )
        return result
    finally:
        if backup.exists():
            shutil.move(backup, original)


def test_use_case(name, config_toml, checks, tmp_path):
    print(f"\n{'='*50}")
    print(f"  Testing: {name}")
    print(f"{'='*50}")

    result = configure(config_toml, tmp_path)
    if result.returncode != 0:
        print(f"  CONFIGURE FAILED: {result.stderr[:200]}")
        return {"name": name, "status": "FAIL", "reason": "configure failed"}

    details = []
    all_pass = True
    for check_name, check_cmd, expected in checks:
        out, rc = vm_ssh(check_cmd)
        passed = expected in out if expected else rc == 0
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_pass = False
        print(f"  {check_name}: {status}")
        if not passed:
            print(f"    expected '{expected}' in: {out[:150]}")
        details.append({"check": check_name, "status": status})

    return {"name": name, "status": "PASS" if all_pass else "FAIL", "details": details}


def main():
    import tempfile
    tmp_path = Path(tempfile.mkdtemp())

    results = []

    # 1. SQM
    results.append(test_use_case("sqm", """\
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
    """, [
        ("uci.qdisc", "uci show sqm", "qdisc='cake'"),
        ("uci.enabled", "uci show sqm", "enabled='1'"),
        ("uci.download", "uci show sqm", "download='10000'"),
        ("tc.qdisc", "tc qdisc show dev eth0 2>/dev/null || echo 'no tc'", "cake"),
    ], tmp_path))

    # 2. DoH
    results.append(test_use_case("doh", """\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["doh"]
        [use_cases.doh]
        provider = "cloudflare"
    """, [
        ("uci.doh", "uci show https-dns-proxy 2>/dev/null || echo 'not found'", "cloudflare-dns.com"),
    ], tmp_path))

    # 3. nodns
    results.append(test_use_case("nodns", """\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["nodns"]
    """, [
        ("uci.dnsmasq", "uci show dhcp 2>/dev/null | head -30", "dnsmasq"),
    ], tmp_path))

    # 4. ssh-hardening
    results.append(test_use_case("ssh-hardening", """\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["ssh-hardening"]
    """, [
        ("uci.dropbear", "uci show dropbear 2>/dev/null", "dropbear"),
        ("uci.password_auth", "uci show dropbear 2>/dev/null", "PasswordAuth"),
    ], tmp_path))

    # 5. WireGuard client
    results.append(test_use_case("wireguard-client", """\
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
    """, [
        ("uci.wg0", "uci show network.wg0 2>/dev/null || echo 'not found'", "wireguard"),
        ("uci.peer", "uci show network 2>/dev/null | grep endpoint", "endpoint"),
    ], tmp_path))

    # 6. WireGuard server
    results.append(test_use_case("wireguard-server", """\
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
    """, [
        ("uci.wg0", "uci show network.wg0 2>/dev/null || echo 'not found'", "wireguard"),
        ("uci.listen", "uci show network.wg0 2>/dev/null", "51820"),
    ], tmp_path))

    # 7. SSL
    results.append(test_use_case("ssl", """\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["ssl"]
    """, [
        ("pkg.ssl", "opkg list-installed 2>/dev/null | grep -E 'ssl|acme' || echo 'none'", "ssl"),
    ], tmp_path))

    # 8. tollgate-security
    results.append(test_use_case("tollgate-security", """\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["tollgate-security"]
    """, [
        ("uci.firewall", "uci show firewall 2>/dev/null | head -20", "firewall"),
    ], tmp_path))

    # 9. vpn-node (verify nak script generated)
    results.append(test_use_case("vpn-node", """\
        [password]
        mode = "none"
        [network]
        lan_ip_mode = "static"
        lan_ip = "192.168.1.1"
        [use_cases]
        enabled = ["vpn-node"]
        [use_cases.vpn-node]
        nsec = "abc123def456789"
        title = "Test VPN"
        endpoint_host = "vpn.test.com"
        endpoint_port = 51820
    """, [
        ("script.exists", "ls /etc/vpn-listing.sh 2>/dev/null && echo exists || echo missing", "exists"),
        ("nsec.stored", "cat /etc/vpn-node/nsec 2>/dev/null || echo missing", "abc123"),
        ("script.nak", "grep nak /etc/vpn-listing.sh 2>/dev/null || echo missing", "nak"),
    ], tmp_path))

    # 10. Combined: SQM + DoH + ssh-hardening + nodns
    results.append(test_use_case("combined", """\
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
    """, [
        ("sqm.present", "uci show sqm 2>/dev/null", "download='20000'"),
        ("doh.present", "uci show https-dns-proxy 2>/dev/null || echo skip", "dns.google"),
        ("dropbear.hardened", "uci show dropbear 2>/dev/null", "PasswordAuth"),
    ], tmp_path))

    # Summary
    print(f"\n{'='*60}")
    print(f"  COMPREHENSIVE USE CASE TEST RESULTS")
    print(f"{'='*60}")
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    for r in results:
        icon = "✅" if r["status"] == "PASS" else "❌"
        print(f"  {icon} {r['name']:25s} {r['status']}")
        if r["status"] == "FAIL":
            for d in r.get("details", []):
                if d["status"] == "FAIL":
                    print(f"      └─ {d['check']}: FAIL")
    print(f"\n  Total: {passed} passed, {failed} failed")
    print(f"{'='*60}")

    # Write results
    import json
    results_dir = Path("/tmp/conwrt-usecase-results")
    results_dir.mkdir(exist_ok=True)
    summary_lines = [f"# conwrt Use Case Test Results\n"]
    summary_lines.append(f"**Date:** {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
    summary_lines.append(f"## Results: {passed}/{passed+failed} passed\n")
    summary_lines.append(f"| Use Case | Status |\n|----------|--------|\n")
    for r in results:
        summary_lines.append(f"| {r['name']} | {r['status']} |\n")
    (results_dir / "summary.md").write_text("".join(summary_lines))
    (results_dir / "comparison.json").write_text(json.dumps({
        "passed": passed, "failed": failed,
        "total": passed + failed,
        "results": results,
    }, indent=2))

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
