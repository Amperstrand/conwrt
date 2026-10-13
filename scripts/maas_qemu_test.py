#!/usr/bin/env python3
"""QEMU PXE enlistment test for MAAS.

Boots a VM that network-boots from the MAAS bench network,
verifying the full PXE chain: DHCP → TFTP → iPXE → ephemeral kernel →
cloud-init enlistment.

Requirements:
    - QEMU with KVM support (for reasonable speed)
    - A bridge interface on the bench subnet
    - The bridge must have STP disabled (instant forwarding)

Usage:
    maas_qemu_test.py --bridge br-bench [--timeout 300]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path


def check_kvm() -> bool:
    """Check if KVM acceleration is available."""
    return Path("/dev/kvm").exists()


def check_bridge(bridge: str) -> tuple[bool, str]:
    """Verify the bridge exists and has STP disabled."""
    link = Path(f"/sys/class/net/{bridge}")
    if not link.exists():
        return False, f"bridge {bridge} does not exist"

    stp_file = link / "bridge" / "stp_state"
    if stp_file.exists():
        stp = stp_file.read_text().strip()
        if stp != "0":
            return False, f"bridge {bridge} has STP enabled (stp_state={stp}) — fix with: ip link set {bridge} type bridge stp_state 0"

    # Check for at least one enslaved port
    ports = list((link / "brif").iterdir()) if (link / "brif").exists() else []
    if not ports:
        return False, f"bridge {bridge} has no ports enslaved"

    return True, f"bridge {bridge} ready (stp=off, {len(ports)} ports)"


def build_qemu_cmd(bridge: str, kvm: bool, memory_mb: int, cpus: int) -> list[str]:
    """Build the QEMU command for PXE boot."""
    cmd = ["qemu-system-x86_64"]

    if kvm:
        cmd += ["-enable-kvm", "-cpu", "host"]
    else:
        print("WARNING: running without KVM — ephemeral boot will be very slow")

    cmd += [
        "-smp", str(cpus),
        "-m", str(memory_mb),
        "-netdev", f"bridge,br={bridge},id=net0",
        "-device", "e1000,netdev=net0",
        "-boot", "n",
        "-machine", "graphics=off",
        "-display", "none",
        "-monitor", "none",
        "-no-reboot",
    ]
    return cmd


def check_ssh_to_maas(maas_ip: str = "10.50.0.5") -> bool:
    """Quick SSH check to the MAAS host."""
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
         f"ubuntu@{maas_ip}", "echo ok"],
        capture_output=True, text=True, timeout=10
    )
    return r.returncode == 0


def query_maas_machines(maas_ip: str = "10.50.0.5") -> int:
    """Query MAAS for machine count via the API."""
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
         f"ubuntu@{maas_ip}",
         "sudo maas apikey --username admin 2>/dev/null | xargs -I{} "
         "maas login admin http://localhost:5240/MAAS {} >/dev/null 2>&1; "
         "maas admin machines read 2>/dev/null | grep -c fqdn || echo 0"],
        capture_output=True, text=True, timeout=30
    )
    try:
        return int(r.stdout.strip().split("\n")[-1])
    except (ValueError, IndexError):
        return 0


def run_test(args: argparse.Namespace) -> int:
    """Main test runner."""
    print("=== MAAS QEMU PXE Enlistment Test ===\n")

    # Pre-flight checks
    kvm = check_kvm()
    print(f"KVM: {'available' if kvm else 'NOT AVAILABLE (slow!)'}")

    ok, msg = check_bridge(args.bridge)
    print(f"Bridge: {msg}")
    if not ok:
        return 1

    if not check_ssh_to_maas(args.maas_ip):
        print(f"ERROR: cannot SSH to MAAS at {args.maas_ip}")
        return 1
    print(f"MAAS: reachable at {args.maas_ip}")

    initial_machines = query_maas_machines(args.maas_ip)
    print(f"Initial machines: {initial_machines}")

    # Build and launch QEMU
    cmd = build_qemu_cmd(args.bridge, kvm, args.memory, args.cpus)
    print(f"\nLaunching VM: {' '.join(cmd[:8])}...")
    print(f"Timeout: {args.timeout}s\n")

    proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    # Poll for enlistment
    start = time.time()
    enlisted = False
    try:
        while time.time() - start < args.timeout:
            time.sleep(args.poll_interval)
            elapsed = int(time.time() - start)
            machines = query_maas_machines(args.maas_ip)
            if machines > initial_machines:
                print(f"\n[{elapsed}s] ENLISTMENT DETECTED! Machines: {machines}")
                enlisted = True
                break
            if elapsed % 30 == 0:
                print(f"[{elapsed}s] waiting... (machines: {machines}, VM alive: {proc.poll() is None})")
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    if enlisted:
        print("\n=== TEST PASSED ===")
        print("The VM successfully PXE-booted from MAAS and self-enlisted.")
        print("Full chain verified: DHCP → TFTP → iPXE → kernel → cloud-init → enlistment")
        return 0
    else:
        print("\n=== TEST INCOMPLETE ===")
        print(f"No new machine after {args.timeout}s.")
        print("Check: VM console (add -serial stdio), MAAS events, dhcpd.leases")
        return 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bridge", default="br-bench",
                   help="bridge interface on the bench subnet")
    p.add_argument("--maas-ip", default="10.50.0.5",
                   help="MAAS controller IP")
    p.add_argument("--timeout", type=int, default=300,
                   help="seconds to wait for enlistment (default: 300)")
    p.add_argument("--poll-interval", type=int, default=15,
                   help="seconds between MAAS queries (default: 15)")
    p.add_argument("--memory", type=int, default=1024,
                   help="VM memory in MB (default: 1024)")
    p.add_argument("--cpus", type=int, default=2,
                   help="VM CPU count (default: 2)")
    args = p.parse_args()
    return run_test(args)


if __name__ == "__main__":
    sys.exit(main())
