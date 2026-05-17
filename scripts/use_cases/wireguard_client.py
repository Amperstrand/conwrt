"""wireguard-client — WireGuard VPN client for routing traffic through a VPN tunnel."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register


def _build_wireguard_client(params: dict[str, Any]) -> str:
    private_key = params.get("private_key", "generate")
    peer_public_key = params.get("peer_public_key", "")
    endpoint_host = params.get("endpoint_host", "")
    endpoint_port = params.get("endpoint_port", 51820)
    peer_psk = params.get("peer_psk", "")
    address = params.get("address", "10.67.0.2/32")
    dns = params.get("dns", "")
    kill_switch = params.get("kill_switch", True)
    allowed_ips = params.get("allowed_ips", "0.0.0.0/0, ::/0")

    lines = [
        "# --- WireGuard VPN client ---",
        f"uci set network.wg0=interface",
        f"uci set network.wg0.proto='wireguard'",
        f"uci set network.wg0.private_key='{private_key}'",
        f"uci set network.wg0.addresses='{address}'",
    ]

    if dns:
        lines.append(f"uci add_list network.wg0.dns='{dns}'")

    lines.extend([
        f"uci set network.wg0_peer=wireguard_wg0",
        f"uci set network.wg0_peer.public_key='{peer_public_key}'",
        f"uci set network.wg0_peer.endpoint_host='{endpoint_host}'",
        f"uci set network.wg0_peer.endpoint_port='{endpoint_port}'",
        f"uci set network.wg0_peer.allowed_ips='{allowed_ips}'",
        f"uci set network.wg0_peer.route_allowed_ips='1'",
        f"uci set network.wg0_peer.persistent_keepalive='25'",
    ])

    if peer_psk:
        lines.append(f"uci set network.wg0_peer.preshared_key='{peer_psk}'")

    lines.extend([
        "",
        "uci add firewall zone",
        "uci set firewall.@zone[-1].name='vpn'",
        "uci set firewall.@zone[-1].input='REJECT'",
        "uci set firewall.@zone[-1].output='ACCEPT'",
        "uci set firewall.@zone[-1].forward='REJECT'",
        "uci set firewall.@zone[-1].masq='1'",
        "uci set firewall.@zone[-1].mtu_fix='1'",
        "uci set firewall.@zone[-1].network='wg0'",
        "",
        "uci add firewall forwarding",
        "uci set firewall.@forwarding[-1].src='lan'",
        "uci set firewall.@forwarding[-1].dest='vpn'",
    ])

    if kill_switch:
        lines.extend([
            "",
            "uci add firewall rule",
            "uci set firewall.@rule[-1].name='KillSwitch-Reject-NonVPN'",
            "uci set firewall.@rule[-1].src='lan'",
            "uci set firewall.@rule[-1].dest='wan'",
            "uci set firewall.@rule[-1].proto='all'",
            "uci set firewall.@rule[-1].target='REJECT'",
        ])

    lines.extend([
        "",
        "uci commit network",
        "uci commit firewall",
        "/etc/init.d/network restart 2>/dev/null || true",
        f"echo 'WireGuard client configured: {endpoint_host}:{endpoint_port}'",
    ])

    return textwrap.dedent("\n".join(lines))


register(UseCase(
    name="wireguard-client",
    description="WireGuard VPN client — route traffic through a VPN tunnel",
    packages=[
        "wireguard-tools",
        "luci-proto-wireguard",
    ],
    packages_remove=[],
    params={
        "private_key": ParamDef(type=str, default="generate",
                                description="WireGuard private key ('generate' = auto-generate on first boot)"),
        "peer_public_key": ParamDef(type=str, required=True,
                                     description="VPN server public key"),
        "endpoint_host": ParamDef(type=str, required=True,
                                   description="VPN server hostname or IP"),
        "endpoint_port": ParamDef(type=int, default=51820,
                                   description="VPN server UDP port"),
        "peer_psk": ParamDef(type=str, default="",
                             description="Optional pre-shared key"),
        "address": ParamDef(type=str, default="10.67.0.2/32",
                            description="Tunnel IP address with CIDR"),
        "dns": ParamDef(type=str, default="",
                        description="DNS server through tunnel (empty = use peer's)"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block all traffic if VPN drops"),
        "allowed_ips": ParamDef(type=str, default="0.0.0.0/0, ::/0",
                                description="IPs to route through tunnel"),
    },
    build_defaults=_build_wireguard_client,
    requires_capabilities=[],
    requires_post_flash=False,
))
