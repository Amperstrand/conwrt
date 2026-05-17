#!/usr/bin/env python3
"""WireGuard management VPN setup for freshly-flashed OpenWrt routers.

Retrieves peer config from a WireGuard server and applies it to a target
router via SSH + UCI.

The server connection details come from CLI flags.  Peer config files
are expected at ``/etc/wireguard/clients/peer-N.conf`` on the server.

Usage:
    python3 scripts/wg-setup.py --peer 3 --server my-vpn
    python3 scripts/wg-setup.py --peer 4 --ip 192.168.1.1 --key ~/.ssh/id_rsa --server my-vpn
    python3 scripts/wg-setup.py --peer 5 --server my-vpn --dry-run
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ssh_utils import ssh_cmd

PEER_CONFIGS_PATH = "/etc/wireguard/clients"


@dataclass
class PeerConfig:
    private_key: str
    address: str
    preshared_key: str
    server_public_key: str
    endpoint_host: str
    endpoint_port: int
    allowed_ips: str
    keepalive: int


def fetch_peer_config(server_host: str, peer_num: int) -> PeerConfig:
    conf_path = f"{PEER_CONFIGS_PATH}/peer-{peer_num}.conf"
    r = subprocess.run(
        ["ssh", server_host, f"cat {conf_path}"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if r.returncode != 0:
        print(f"ERROR: Failed to fetch peer-{peer_num}.conf from {server_host}")
        print(f"  {r.stderr.strip()}")
        sys.exit(1)

    values: dict[str, str] = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, _, val = line.partition("=")
            values[key.strip().lower()] = val.strip()

    endpoint_raw = values.get("endpoint", "")
    host, _, port_str = endpoint_raw.partition(":")
    return PeerConfig(
        private_key=values.get("privatekey", ""),
        address=values.get("address", ""),
        preshared_key=values.get("presharedkey", ""),
        server_public_key=values.get("publickey", ""),
        endpoint_host=host,
        endpoint_port=int(port_str) if port_str else int(values.get("endpoint_port", "51820")),
        allowed_ips=values.get("allowedips", ""),
        keepalive=int(values.get("persistentkeepalive", "25")),
    )


def build_uci_commands(pc: PeerConfig) -> list[str]:
    addr = pc.address.replace("/32", "")
    return [
        "uci set network.wg0=interface",
        "uci set network.wg0.proto='wireguard'",
        f"uci set network.wg0.private_key='{pc.private_key}'",
        f"uci set network.wg0.addresses='{addr}'",
        "uci set network.wg0.listen_port='51820'",
        "uci set network.wg0.mtu='1420'",
        "",
        "uci add network wireguard_wg0",
        f"uci set network.@wireguard_wg0[-1].public_key='{pc.server_public_key}'",
        f"uci set network.@wireguard_wg0[-1].preshared_key='{pc.preshared_key}'",
        f"uci set network.@wireguard_wg0[-1].endpoint_host='{pc.endpoint_host}'",
        f"uci set network.@wireguard_wg0[-1].endpoint_port='{pc.endpoint_port}'",
        f"uci add_list network.@wireguard_wg0[-1].allowed_ips='{pc.allowed_ips}'",
        f"uci set network.@wireguard_wg0[-1].persistent_keepalive='{pc.keepalive}'",
        f"uci set network.@wireguard_wg0[-1].route_allowed_ips='1'",
        "",
        "uci add_list firewall.@zone[1].network='wg0'",
        "",
        "uci commit network",
        "uci commit firewall",
        "/etc/init.d/network restart 2>/dev/null || true",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Configure WireGuard VPN on an OpenWrt router from a server peer config",
    )
    parser.add_argument("--peer", type=int, required=True,
                        help="Peer number (matching peer-N.conf on the server)")
    parser.add_argument("--server", required=True,
                        help="SSH host alias for the WireGuard server (from ~/.ssh/config)")
    parser.add_argument("--ip", default="192.168.1.1",
                        help="Router IP address (default: 192.168.1.1)")
    parser.add_argument("--key", default=None,
                        help="SSH private key path (auto-detected if omitted)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print UCI commands without executing")
    args = parser.parse_args()

    print(f"Fetching peer-{args.peer} config from {args.server}...")
    pc = fetch_peer_config(args.server, args.peer)
    if not pc.private_key:
        print("ERROR: No private key found in peer config")
        return 1
    print(f"  Address: {pc.address}")
    print(f"  Endpoint: {pc.endpoint_host}:{pc.endpoint_port}")

    uci_cmds = build_uci_commands(pc)
    uci_chain = " && ".join(c for c in uci_cmds if c)

    if args.dry_run:
        print(f"\nDry run — UCI commands for {args.ip}:")
        for cmd in uci_cmds:
            print(f"  {cmd}" if cmd else "")
        return 0

    print(f"\nApplying WireGuard config to {args.ip}...")
    r = subprocess.run(
        ssh_cmd(args.ip, uci_chain, key=args.key, connect_timeout=10),
        capture_output=True, text=True, timeout=60, check=False,
    )
    if r.returncode != 0:
        print(f"ERROR: UCI commands failed (rc={r.returncode})")
        if r.stderr:
            print(f"  {r.stderr.strip()[:300]}")
        return 1
    print("  Done. UCI config applied, network restarted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
