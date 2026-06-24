"""argparse definitions for the field-lab CLI."""

from __future__ import annotations

import argparse


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    """Add --host and --probe-if flags shared by all subcommands."""
    parser.add_argument(
        "--host", required=True,
        help="Field router SSH target (e.g. root@192.168.1.1)",
    )
    parser.add_argument(
        "--probe-if", default=None,
        help="Probe interface name (auto-detected from 'uci get network.wan.device' if omitted)",
    )
    parser.add_argument(
        "--session", default=None,
        help="Run session ID (auto-generated as YYYYMMDD-HHMMSS-fieldlab if omitted)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fieldlab",
        description="conwrt Field Lab — use a deployed OpenWrt router as a remote probe/flash appliance",
    )
    subparsers = parser.add_subparsers(dest="fieldlab_command")

    # --- inspect ---
    inspect_p = subparsers.add_parser(
        "inspect",
        help="Collect read-only state from the field router (identity, network, tools)",
    )
    _add_common_args(inspect_p)
    inspect_p.add_argument(
        "--output", "-o", default=None,
        help="Write JSON to file (default: stdout + run artifact)",
    )

    # --- capture ---
    capture_p = subparsers.add_parser(
        "capture",
        help="Stream remote tcpdump from the probe port to a local pcap file or stdout",
    )
    _add_common_args(capture_p)
    capture_p.add_argument(
        "--duration", type=int, default=0,
        help="Capture duration in seconds (0 = until Ctrl-C)",
    )
    capture_p.add_argument(
        "--out", default=None,
        help="Output pcap path, or '-' for stdout (default: runs/<session>/captures/probe.pcap)",
    )
    capture_p.add_argument(
        "--filter", default=None,
        help="tcpdump capture filter expression (e.g. 'not port 22')",
    )

    # --- discover ---
    discover_p = subparsers.add_parser(
        "discover",
        help="Probe the unknown device on the probe port from the field router (ARP, ping, ports)",
    )
    _add_common_args(discover_p)
    discover_p.add_argument(
        "--target", default=None,
        help="Specific target IP to probe (auto-detected from ARP table if omitted)",
    )
    discover_p.add_argument(
        "--ports", default="22,23,53,80,443,4919,5000,7547",
        help="Comma-separated ports to scan (default: common router ports)",
    )

    # --- forward ---
    forward_p = subparsers.add_parser(
        "forward",
        help="Open a local SSH port-forward to a service on the unknown device",
    )
    _add_common_args(forward_p)
    forward_p.add_argument(
        "--target", required=True,
        help="Target service on the probe network (e.g. 192.168.1.1:80)",
    )
    forward_p.add_argument(
        "--local", default=None,
        help="Local bind address (e.g. 127.0.0.1:18080). Auto-selected if omitted.",
    )
    forward_p.add_argument(
        "--exec", action="store_true",
        help="Execute the SSH -L command directly instead of printing it",
    )

    # --- prepare-probe (light cleanup) ---
    prep_p = subparsers.add_parser(
        "prepare-probe",
        help="Inspect probe-port state and optionally clean up stale WAN binding (dry-run safe)",
    )
    _add_common_args(prep_p)
    prep_p.add_argument(
        "--apply", action="store_true",
        help="Apply cleanup changes (default: dry-run, print plan only)",
    )

    serve_p = subparsers.add_parser(
        "serve",
        help="Run temporary DHCP/TFTP servers on the probe port",
    )
    serve_sub = serve_p.add_subparsers(dest="serve_command")

    serve_dhcp = serve_sub.add_parser(
        "dhcp",
        help="Start a DHCP server on the probe interface",
    )
    _add_common_args(serve_dhcp)
    serve_dhcp.add_argument(
        "--subnet", default="192.168.50.1/24",
        help="Server IP and CIDR for the probe subnet (default: 192.168.50.1/24)",
    )
    serve_dhcp.add_argument(
        "--pool-start", default=None,
        help="DHCP pool start (default: server_ip .100)",
    )
    serve_dhcp.add_argument(
        "--pool-end", default=None,
        help="DHCP pool end (default: server_ip .200)",
    )
    serve_dhcp.add_argument(
        "--lease-time", default="1h",
        help="DHCP lease time (default: 1h)",
    )
    serve_dhcp.add_argument(
        "--tftp-root", default=None,
        help="Also serve TFTP from this directory (for U-Boot netboot)",
    )

    serve_tftp = serve_sub.add_parser(
        "tftp",
        help="Start a TFTP server on the probe interface",
    )
    _add_common_args(serve_tftp)
    serve_tftp.add_argument(
        "--tftp-root", required=True,
        help="TFTP root directory",
    )
    serve_tftp.add_argument(
        "--server-ip", default=None,
        help="IP to assign to the probe interface (default: 192.168.1.2)",
    )

    fp_p = subparsers.add_parser(
        "fingerprint",
        help="Identify the target device via SSH ProxyJump through the field router",
    )
    fp_p.add_argument(
        "--host", required=True,
        help="Field router SSH target (the jump host, e.g. root@10.89.4.1)",
    )
    fp_p.add_argument(
        "--target", required=True,
        help="Target device IP to fingerprint (e.g. 192.168.1.1)",
    )
    fp_p.add_argument(
        "--session", default=None,
        help="Run session ID",
    )

    net_status_p = subparsers.add_parser(
        "net-status",
        help="Show host network diagnostics (interfaces, routes, DNS, stale aliases)",
    )

    net_cleanup_p = subparsers.add_parser(
        "net-cleanup",
        help="Remove stale IP aliases left by conwrt operations",
    )
    net_cleanup_p.add_argument(
        "--dry-run", action="store_true", default=True,
        help="Preview only, don't remove (default: dry-run)",
    )
    net_cleanup_p.add_argument(
        "--interface", default=None,
        help="Only clean this interface (default: all)",
    )
    net_cleanup_p.add_argument(
        "--apply", action="store_true",
        help="Actually remove aliases (default is dry-run for safety)",
    )

    forensics_p = subparsers.add_parser(
        "forensics",
        help="Pre-flash backup: /etc backup, TollGate detection, ecash extraction",
    )
    forensics_p.add_argument(
        "--target", required=True,
        help="Target device IP (e.g. 192.168.1.1)",
    )
    forensics_p.add_argument(
        "--password", required=True,
        help="SSH password for the target device",
    )
    forensics_p.add_argument(
        "--bind", default=None,
        help="Source IP to bind (for subnet collision cases)",
    )

    return parser
