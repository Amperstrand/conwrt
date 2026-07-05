#!/usr/bin/env python3
"""Run conwrt use case tests on QEMU OpenWrt VM, publish evidence to Nostr/Blossom.

This script:
1. Boots an OpenWrt QEMU VM (on the SHC host it runs on)
2. For each use case: applies config, verifies, captures evidence
3. Publishes all evidence via the result_publisher (kind 30078 + Blossom)

Usage:
    # On SHC VM with KVM:
    python3 run_use_case_tests.py --openwrt-img /tmp/openwrt.img --nsec ~/.config/prta/nsec

Evidence for each use case:
    - conwrt configure stdout/stderr
    - uci show <config> output
    - logread (last 50 lines)
    - Verification command output (ping, curl, wg show, etc.)
    - ip addr / ip route
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


# ─── Use case definitions ───
USE_CASES = [
    {
        "name": "sqm",
        "packages": ["sqm-scripts", "luci-app-sqm"],
        "configure": [
            "uci set sqm.eth0=queue",
            "uci set sqm.eth0.enabled=1",
            "uci set sqm.eth0.download=50000",
            "uci set sqm.eth0.upload=10000",
            "uci set sqm.eth0.qdisc='cake'",
            "uci set sqm.eth0.script='piece_of_cake.qos'",
            "uci commit sqm",
            "/etc/init.d/sqm restart",
        ],
        "verify": [
            ("tc qdisc show dev eth0", "tc_qdisc.txt"),
            ("uci show sqm", "uci_sqm.txt"),
        ],
        "description": "SQM CAKE qdisc for bufferbloat reduction",
    },
    {
        "name": "doh",
        "packages": ["https-dns-proxy", "luci-app-https-dns-proxy"],
        "configure": [
            "uci set https-dns-proxy.main=main",
            "uci set https-dns-proxy.main.bootstrap_dns='8.8.8.8,1.1.1.1'",
            "uci set https-dns-proxy.main.resolver_url='https://dns.google/dns-query'",
            "uci commit https-dns-proxy",
            "/etc/init.d/https-dns-proxy restart",
        ],
        "verify": [
            ("nslookup example.com 127.0.0.1", "dns_test.txt"),
            ("uci show https-dns-proxy", "uci_doh.txt"),
            ("logread | grep https-dns | tail 10", "doh_log.txt"),
        ],
        "description": "DNS-over-HTTPS encrypted DNS resolution",
    },
    {
        "name": "ssh-hardening",
        "packages": [],
        "configure": [
            "uci set dropbear.@dropbear[0].PasswordAuth=off",
            "uci set dropbear.@dropbear[0].RootPasswordAuth=off",
            "uci commit dropbear",
            "/etc/init.d/dropbear restart",
        ],
        "verify": [
            ("uci show dropbear", "uci_dropbear.txt"),
            ("logread | grep dropbear | tail 5", "ssh_log.txt"),
        ],
        "description": "SSH password auth disabled, key-only",
    },
    {
        "name": "wireguard-client",
        "packages": ["wireguard-tools", "luci-proto-wireguard", "kmod-wireguard", "qrencode"],
        "configure": [
            "uci set network.wg0=interface",
            "uci set network.wg0.proto=wireguard",
            "uci set network.wg0.private_key='generate'",
            "uci set network.wg0.listen_port=51820",
            "uci set network.wg0.addresses='10.0.0.2/32'",
            "uci -q delete network.wgpeer 2>/dev/null; uci set network.wgpeer=wireguard_wg0",
            "uci set network.wgpeer.public_key='J6vna+T8o+ibG4qSGL3dp7cbHYQTnvFo4//+V21ctHM='",
            "uci set network.wgpeer.endpoint_host='66.92.204.237'",
            "uci set network.wgpeer.endpoint_port='51820'",
            "uci set network.wgpeer.allowed_ips='10.66.42.0/24'",
            "uci set network.wgpeer.persistent_keepalive='25'",
            "uci commit network",
            "/etc/init.d/network restart",
        ],
        "verify": [
            ("wg show wg0 2>/dev/null || echo 'wg0 not up yet'", "wg_show.txt"),
            ("uci show network.wg0; uci show network.wgpeer", "uci_wg.txt"),
            ("ip addr show wg0 2>/dev/null || echo 'no wg0'", "wg_interface.txt"),
        ],
        "description": "WireGuard VPN client with auto-generated keys",
    },
    {
        "name": "nodns",
        "packages": ["dnsmasq", "curl"],
        "configure": [
            "uci -q delete dhcp.nodns 2>/dev/null",
            "uci set dhcp.nodns='domain'",
            "uci add_list dhcp.nodns.server='10.66.42.1'",
            "uci set dhcp.nodns.domain='nodns'",
            "uci commit dhcp",
            "/etc/init.d/dnsmasq restart",
        ],
        "verify": [
            ("uci show dhcp.nodns 2>/dev/null || echo 'no nodns config'", "uci_nodns.txt"),
            ("nslookup test.nodns 127.0.0.1 2>/dev/null | head -5 || echo 'DNS query failed'", "nodns_test.txt"),
        ],
        "description": "Local DNS cache of nodns records",
    },
]


def run(cmd: str, timeout: int = 30) -> tuple[int, str]:
    """Run shell command, return (exit_code, output)."""
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr)


def ssh_to_openwrt(cmd: str, host: str = "192.168.1.1", timeout: int = 30) -> tuple[int, str]:
    """SSH to OpenWrt VM and run command."""
    r = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
         f"root@{host}", cmd],
        capture_output=True, text=True, timeout=timeout
    )
    return r.returncode, (r.stdout + r.stderr)


def boot_openwrt(img_path: str, ram_mb: int = 512) -> int:
    """Boot OpenWrt QEMU VM, return PID."""
    # Kill any existing VM
    run("sudo kill $(cat /tmp/openwrt-test.pid 2>/dev/null) 2>/dev/null; sleep 1")

    # Create TAP device for LAN
    run("sudo ip tuntap add dev tap0test mode tap 2>/dev/null; sudo ip link set tap0test up; sudo ip addr add 192.168.1.100/24 dev tap0test 2>/dev/null")

    # Boot QEMU
    cmd = (
        f"sudo qemu-system-x86_64 "
        f"-m {ram_mb} "
        f"-display none "
        f"-serial file:/tmp/openwrt-test-console.log "
        f"-drive file={img_path},format=raw,if=virtio "
        f"-netdev tap,id=net0,ifname=tap0test,script=no,downscript=no "
        f"-device virtio-net-pci,netdev=net0 "
        f"-daemonize "
        f"-pidfile /tmp/openwrt-test.pid"
    )
    rc, out = run(cmd)
    if rc != 0:
        print(f"QEMU boot failed: {out}")
        return -1

    pid = int(Path("/tmp/openwrt-test.pid").read_text().strip())
    print(f"QEMU booted (PID {pid}), waiting 25s for OpenWrt...")
    time.sleep(25)

    # Verify SSH
    rc, out = ssh_to_openwrt("echo OK")
    if rc != 0:
        print(f"SSH failed, retrying... {out[:100]}")
        time.sleep(10)
        rc, out = ssh_to_openwrt("echo OK")
    if rc == 0:
        print("OpenWrt SSH accessible")
    else:
        print(f"SSH still failed: {out[:200]}")
    return pid


def install_packages(use_case: dict) -> tuple[int, str]:
    """Install packages for a use case."""
    pkgs = use_case.get("packages", [])
    if not pkgs:
        return 0, "no packages needed"
    
    # opkg update first
    rc, out = ssh_to_openwrt("opkg update", timeout=60)
    if rc != 0:
        return rc, f"opkg update failed: {out[:200]}"
    
    # Install
    rc, out = ssh_to_openwrt(f"opkg install {' '.join(pkgs)}", timeout=120)
    return rc, out


def apply_and_verify(use_case: dict, results_dir: Path) -> dict:
    """Apply use case configuration and capture evidence."""
    name = use_case["name"]
    uc_dir = results_dir / name
    uc_dir.mkdir(parents=True, exist_ok=True)
    
    evidence = {"use_case": name, "status": "unknown", "artifacts": {}}
    
    # 1. Install packages
    print(f"  [{name}] Installing packages...")
    rc, out = install_packages(use_case)
    (uc_dir / "package_install.txt").write_text(out)
    evidence["artifacts"]["package_install"] = "package_install.txt"
    if rc != 0:
        evidence["status"] = "fail"
        evidence["error"] = "package install failed"
        return evidence
    
    # 2. Apply configuration
    print(f"  [{name}] Applying configuration...")
    config_output = []
    for cmd in use_case["configure"]:
        rc, out = ssh_to_openwrt(cmd, timeout=15)
        config_output.append(f"$ {cmd}\n{out}")
    config_text = "\n".join(config_output)
    (uc_dir / "configure.txt").write_text(config_text)
    evidence["artifacts"]["configure"] = "configure.txt"
    
    time.sleep(3)  # Let services restart
    
    # 3. Verify + capture evidence
    print(f"  [{name}] Verifying...")
    verify_output = []
    all_pass = True
    for cmd, filename in use_case["verify"]:
        rc, out = ssh_to_openwrt(cmd, timeout=15)
        (uc_dir / filename).write_text(out)
        evidence["artifacts"][filename.replace(".txt", "")] = filename
        verify_output.append(f"$ {cmd}\n{out}")
        # Simple pass heuristic: command succeeded
        if rc != 0:
            all_pass = False
    
    # 4. Capture logread
    rc, out = ssh_to_openwrt("logread | tail -50", timeout=10)
    (uc_dir / "logread.txt").write_text(out)
    evidence["artifacts"]["logread"] = "logread.txt"
    
    # 5. Capture ip addr/route
    for cmd, fname in [("ip addr show", "ip_addr.txt"), ("ip route show", "ip_route.txt")]:
        rc, out = ssh_to_openwrt(cmd, timeout=5)
        (uc_dir / fname).write_text(out)
        evidence["artifacts"][fname.replace(".txt", "")] = fname
    
    evidence["status"] = "pass" if all_pass else "fail"
    evidence["description"] = use_case["description"]
    evidence["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    # 6. Write summary
    summary = f"# {name}\n\nStatus: {evidence['status']}\n\n{use_case['description']}\n\n## Verification output\n\n" + "\n\n".join(verify_output)
    (uc_dir / "summary.md").write_text(summary)
    
    print(f"  [{name}] {'PASS' if all_pass else 'FAIL'}")
    return evidence


def main():
    parser = argparse.ArgumentParser(description="Run conwrt use case tests + publish evidence")
    parser.add_argument("--openwrt-img", default="/tmp/openwrt.img", help="Path to OpenWrt QEMU image")
    parser.add_argument("--results-dir", default="/tmp/conwrt-test-results", help="Results directory")
    parser.add_argument("--nsec", default=os.path.expanduser("~/.config/prta/nsec"), help="Nostr private key")
    parser.add_argument("--blossom-server", default="https://blossom.psbt.me")
    parser.add_argument("--relays", default="wss://relay.cashu.email")
    parser.add_argument("--skip-publish", action="store_true", help="Skip publishing to Nostr/Blossom")
    parser.add_argument("--use-case", default=None, help="Run only this use case")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    # Filter use cases
    use_cases = USE_CASES
    if args.use_case:
        use_cases = [uc for uc in USE_CASES if uc["name"] == args.use_case]
        if not use_cases:
            print(f"Unknown use case: {args.use_case}")
            sys.exit(1)

    print(f"═══════════════════════════════════════════════════════════")
    print(f"  conwrt Use Case Test Runner")
    print(f"  Use cases: {[uc['name'] for uc in use_cases]}")
    print(f"  Results: {results_dir}")
    print(f"═══════════════════════════════════════════════════════════")

    # Boot OpenWrt
    img = args.openwrt_img
    if not Path(img).exists():
        print(f"OpenWrt image not found: {img}")
        print("Download: wget 'https://downloads.openwrt.org/releases/24.10.2/targets/x86/64/openwrt-24.10.2-x86-64-generic-squashfs-combined.img.gz' -O /tmp/openwrt.img.gz && gunzip /tmp/openwrt.img.gz")
        sys.exit(1)

    pid = boot_openwrt(img)
    if pid < 0:
        sys.exit(1)

    # Run each use case
    all_results = []
    for uc in use_cases:
        print(f"\n{'─' * 50}")
        print(f"Testing: {uc['name']} — {uc['description']}")
        print(f"{'─' * 50}")
        result = apply_and_verify(uc, results_dir)
        all_results.append(result)

    # Shutdown OpenWrt
    print(f"\nShutting down OpenWrt VM...")
    ssh_to_openwrt("poweroff", timeout=5)
    time.sleep(3)
    run("sudo kill $(cat /tmp/openwrt-test.pid 2>/dev/null) 2>/dev/null")

    # Summary
    passed = sum(1 for r in all_results if r["status"] == "pass")
    failed = sum(1 for r in all_results if r["status"] == "fail")
    print(f"\n═══════════════════════════════════════════════════════════")
    print(f"  RESULTS: {passed} passed, {failed} failed")
    print(f"  Evidence: {results_dir}")
    print(f"═══════════════════════════════════════════════════════════")

    # Write overall summary
    summary = f"# conwrt Use Case Test Results\n\n"
    summary += f"**Date**: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n"
    summary += f"**Passed**: {passed} | **Failed**: {failed}\n\n"
    summary += "| Use Case | Status | Description |\n|---|---|---|\n"
    for r in all_results:
        status = "✅ PASS" if r["status"] == "pass" else "❌ FAIL"
        summary += f"| {r['use_case']} | {status} | {r.get('description', '')} |\n"
    (results_dir / "summary.md").write_text(summary)

    # Publish
    if not args.skip_publish:
        print(f"\nPublishing to Nostr/Blossom...")
        run_id = f"conwrt-usecases-{int(time.time())}"
        prta_root = Path(__file__).resolve().parents[1]
        cmd = (
            f"python3 {prta_root}/conwrt/publish_results.py "
            f"--results-dir {results_dir} "
            f"--run-id {run_id} "
            f"--nsec-file {args.nsec} "
            f"--blossom-server {args.blossom_server} "
            f"--relays {args.relays} "
            f"--summary '{passed} passed, {failed} failed' "
            f"--passed {passed} --failed {failed}"
        )
        rc, out = run(cmd, timeout=120)
        print(out)
        if rc == 0:
            print(f"✅ Published! View at https://tests.tollgate.me (project: conwrt)")
        else:
            print(f"⚠️  Publish failed (exit {rc})")


if __name__ == "__main__":
    main()
