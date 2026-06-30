"""serve command — run temporary DHCP/TFTP servers on the probe port.

On OpenWrt: adds a temporary DHCP scope to the existing dnsmasq via UCI
(runtime only, no uci commit — reverts on reboot). On Linux: runs a
standalone dnsmasq. Kill with Ctrl-C; cleanup removes all temporary state.

Platform abstraction lives in fieldlab/network.py.
"""

from __future__ import annotations

import argparse
import re
import signal
import sys

from fieldlab.transport import Host, check_ssh, run_remote, stream_remote
from fieldlab.rundir import FieldLabRun
from fieldlab.network import OPENWRT, LINUX


def _parse_subnet(subnet: str) -> tuple[str, int]:
    if "/" in subnet:
        ip, cidr_str = subnet.rsplit("/", 1)
        return ip.strip(), int(cidr_str)
    return subnet.strip(), 24


def _pool_range(server_ip: str) -> tuple[str, str]:
    parts = server_ip.split(".")
    base = f"{parts[0]}.{parts[1]}.{parts[2]}"
    return f"{base}.100", f"{base}.200"


def _detect_probe_interface(host: Host) -> str | None:
    result = run_remote(host, "uci get network.wan.device 2>/dev/null", timeout=8)
    dev = result.stdout.strip()
    if dev and dev != "none" and result.returncode == 0:
        return dev
    return None


def _detect_remote_platform(host: Host) -> str:
    result = run_remote(host, "cat /etc/openwrt_release 2>/dev/null", timeout=5)
    if "OpenWrt" in result.stdout:
        return OPENWRT
    return LINUX


def _uci_setup_dhcp(host: Host, probe_if: str, server_ip: str,
                    pool_start: str, pool_end: str, lease_time: str,
                    tftp_root: str | None) -> bool:
    """Configure a temporary DHCP scope via UCI on OpenWrt (no commit)."""
    cmds = [
        "uci set network.fieldlab=interface",
        "uci set network.fieldlab.proto='static'",
        f"uci set network.fieldlab.ipaddr='{server_ip}'",
        "uci set network.fieldlab.netmask='255.255.255.0'",
        f"uci set network.fieldlab.device='{probe_if}'",
        "uci set dhcp.fieldlab=dhcp",
        "uci set dhcp.fieldlab.interface='fieldlab'",
        f"uci set dhcp.fieldlab.start='{pool_start.split('.')[-1]}'",
        "uci set dhcp.fieldlab.limit='50'",
        f"uci set dhcp.fieldlab.leasetime='{lease_time}'",
    ]
    if tftp_root:
        cmds.append("uci set dhcp.fieldlab.enable_tftp='1'")
        cmds.append(f"uci set dhcp.fieldlab.tftp_root='{tftp_root}'")

    for cmd in cmds:
        run_remote(host, cmd, timeout=5)

    run_remote(host, "ifup fieldlab 2>/dev/null; /etc/init.d/dnsmasq reload 2>/dev/null", timeout=10)
    return True


def _uci_cleanup_dhcp(host: Host) -> None:
    """Remove the temporary DHCP scope (runtime revert, no commit needed)."""
    run_remote(host, "ifdown fieldlab 2>/dev/null", timeout=5)
    run_remote(host, "uci delete network.fieldlab 2>/dev/null", timeout=5)
    run_remote(host, "uci delete dhcp.fieldlab 2>/dev/null", timeout=5)
    run_remote(host, "/etc/init.d/dnsmasq reload 2>/dev/null", timeout=10)


def cmd_serve_dhcp(args: argparse.Namespace, host: Host) -> int:
    """Start a temporary DHCP server on the probe interface."""
    probe_if = args.probe_if or _detect_probe_interface(host)
    if not probe_if:
        print("[!] Could not detect probe interface. Use --probe-if.", file=sys.stderr)
        return 1

    server_ip, cidr = _parse_subnet(args.subnet)
    pool_start = args.pool_start or _pool_range(server_ip)[0]
    pool_end = args.pool_end or _pool_range(server_ip)[1]

    if not check_ssh(host):
        print(f"[!] Cannot SSH to {host}.", file=sys.stderr)
        return 1

    remote_platform = _detect_remote_platform(host)
    print(f"[+] Field router: {host} ({remote_platform})", file=sys.stderr)
    print(f"[+] Probe interface: {probe_if}", file=sys.stderr)
    print(f"[+] DHCP server: {server_ip}, pool {pool_start} – {pool_end}",
          file=sys.stderr)
    if args.tftp_root:
        print(f"[+] TFTP root: {args.tftp_root}", file=sys.stderr)

    session = args.session
    run = FieldLabRun(session) if session else FieldLabRun.create()
    run.record_command("serve-dhcp", probe_interface=probe_if,
                       server_ip=server_ip, pool=f"{pool_start}-{pool_end}")

    if remote_platform == OPENWRT:
        print("[+] Configuring dnsmasq via UCI (runtime, no commit)...", file=sys.stderr)
        _uci_setup_dhcp(host, probe_if, server_ip, pool_start, pool_end,
                        args.lease_time, args.tftp_root)
        print("[+] DHCP server active. Press Ctrl-C to stop.", file=sys.stderr)
        print("[+] Watching for DHCP leases...", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)

        watch_proc = stream_remote(host, "logread -f 2>&1")
    else:
        print(f"[!] DHCP serve not yet implemented for {remote_platform}", file=sys.stderr)
        print("    Use OpenWrt field router, or run dnsmasq manually.", file=sys.stderr)
        return 1

    def _cleanup(_signum, _frame):
        print("\n[+] Cleaning up...", file=sys.stderr)
        if watch_proc.poll() is None:
            watch_proc.terminate()
        if remote_platform == OPENWRT:
            _uci_cleanup_dhcp(host)
        print("[+] Cleanup complete. All temporary config removed.", file=sys.stderr)

    old_int = signal.signal(signal.SIGINT, _cleanup)
    old_term = signal.signal(signal.SIGTERM, _cleanup)

    try:
        while True:
            chunk = watch_proc.stdout.read(4096)
            if not chunk:
                break
            for raw_line in chunk.decode("utf-8", errors="replace").split("\n"):
                line = raw_line.strip()
                if not line:
                    continue
                sys.stderr.write(line + "\n")
                sys.stderr.flush()
                if "DHCPACK" in line or "DHCPREQUEST" in line or "DHCPOFFER" in line:
                    mac_match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if mac_match and ip_match and "DHCPACK" in line:
                        print(f"\n[+] LEASE: {ip_match.group(1)} → {mac_match.group(1)}",
                              file=sys.stderr)
                        print(f"    Reach via: ssh -J {host} root@{ip_match.group(1)}",
                              file=sys.stderr)
    except BrokenPipeError:
        pass
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        if watch_proc.poll() is None:
            watch_proc.terminate()
        if remote_platform == OPENWRT:
            _uci_cleanup_dhcp(host)

    return 0


def cmd_serve_tftp(args: argparse.Namespace, host: Host) -> int:
    """Start a temporary TFTP server on the probe interface."""
    probe_if = args.probe_if or _detect_probe_interface(host)
    if not probe_if:
        print("[!] Could not detect probe interface.", file=sys.stderr)
        return 1

    if not args.tftp_root:
        print("[!] --tftp-root required for TFTP serve.", file=sys.stderr)
        return 1

    if not check_ssh(host):
        print(f"[!] Cannot SSH to {host}.", file=sys.stderr)
        return 1

    _detect_remote_platform(host)
    server_ip = args.server_ip or "192.168.1.2"

    print(f"[+] TFTP serve via UCI: scope fieldlab on {probe_if}", file=sys.stderr)
    print(f"[+] TFTP root: {args.tftp_root}", file=sys.stderr)
    print(f"[+] Server IP: {server_ip}", file=sys.stderr)

    pool_start, pool_end = _pool_range(server_ip)
    _uci_setup_dhcp(host, probe_if, server_ip, pool_start, pool_end, "1h", args.tftp_root)

    session = args.session
    run = FieldLabRun(session) if session else FieldLabRun.create()
    run.record_command("serve-tftp", probe_interface=probe_if, tftp_root=args.tftp_root)

    print("[+] TFTP active. Press Ctrl-C to stop.", file=sys.stderr)
    watch_proc = stream_remote(host, "logread -f 2>&1")

    def _cleanup(_signum, _frame):
        if watch_proc.poll() is None:
            watch_proc.terminate()
        _uci_cleanup_dhcp(host)

    old_int = signal.signal(signal.SIGINT, _cleanup)
    old_term = signal.signal(signal.SIGTERM, _cleanup)

    try:
        while True:
            chunk = watch_proc.stdout.read(4096)
            if not chunk:
                break
            line = chunk.decode("utf-8", errors="replace").strip()
            if line:
                sys.stderr.write(line + "\n")
                sys.stderr.flush()
    except BrokenPipeError:
        pass
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        if watch_proc.poll() is None:
            watch_proc.terminate()
        _uci_cleanup_dhcp(host)

    return 0
