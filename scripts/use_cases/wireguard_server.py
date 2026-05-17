"""wireguard-server — WireGuard VPN server for remote access to the local network."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register


def _build_wireguard_server(params: dict[str, Any]) -> str:
    private_key = params.get("private_key", "")
    listen_port = params.get("listen_port", 51820)
    subnet = params.get("subnet", "10.1.99.1/24")
    peer1_public_key = params.get("peer1_public_key", "")
    peer1_allowed_ips = params.get("peer1_allowed_ips", "10.1.99.2/32")
    peer1_psk = params.get("peer1_psk", "")

    peer_lines = []
    if peer1_public_key:
        peer_lines.append(
            f"uci set network.wg0_peer1=wireguard_wg0"
        )
        peer_lines.append(
            f"uci set network.wg0_peer1.public_key='{peer1_public_key}'"
        )
        peer_lines.append(
            f"uci set network.wg0_peer1.allowed_ips='{peer1_allowed_ips}'"
        )
        peer_lines.append(
            f"uci set network.wg0_peer1.route_allowed_ips='1'"
        )
        if peer1_psk:
            peer_lines.append(
                f"uci set network.wg0_peer1.preshared_key='{peer1_psk}'"
            )

    return textwrap.dedent(f"""\
        # --- WireGuard VPN server ---
        uci set network.wg0=interface
        uci set network.wg0.proto='wireguard'
        uci set network.wg0.private_key='{private_key}'
        uci set network.wg0.listen_port='{listen_port}'
        uci add_list network.wg0.addresses='{subnet}'
        {('\n'.join(peer_lines) if peer_lines else '')}

        uci add firewall zone
        uci set firewall.@zone[-1].name='vpn'
        uci set firewall.@zone[-1].input='ACCEPT'
        uci set firewall.@zone[-1].output='ACCEPT'
        uci set firewall.@zone[-1].forward='REJECT'
        uci set firewall.@zone[-1].masq='1'
        uci set firewall.@zone[-1].mtu_fix='1'
        uci set firewall.@zone[-1].network='wg0'

        uci add firewall forwarding
        uci set firewall.@forwarding[-1].src='vpn'
        uci set firewall.@forwarding[-1].dest='lan'

        uci add firewall forwarding
        uci set firewall.@forwarding[-1].src='vpn'
        uci set firewall.@forwarding[-1].dest='wan'

        uci add firewall rule
        uci set firewall.@rule[-1].name='Allow-WireGuard'
        uci set firewall.@rule[-1].src='wan'
        uci set firewall.@rule[-1].dest_port='{listen_port}'
        uci set firewall.@rule[-1].proto='udp'
        uci set firewall.@rule[-1].target='ACCEPT'

        uci commit network
        uci commit firewall
        /etc/init.d/network restart 2>/dev/null || true
        echo "WireGuard server configured: port {listen_port}, subnet {subnet}"
    """)


register(UseCase(
    name="wireguard-server",
    description="WireGuard VPN server — remote access to home network",
    packages=[
        "wireguard-tools",
        "luci-proto-wireguard",
        "qrencode",
    ],
    params={
        "private_key": ParamDef(type=str, required=True,
                                description="WireGuard private key for the server"),
        "listen_port": ParamDef(type=int, default=51820,
                                description="UDP listen port"),
        "subnet": ParamDef(type=str, default="10.1.99.1/24",
                           description="VPN client subnet (server IP + CIDR)"),
        "peer1_public_key": ParamDef(type=str, default="",
                                     description="First peer's public key"),
        "peer1_allowed_ips": ParamDef(type=str, default="10.1.99.2/32",
                                      description="First peer's allowed IPs"),
        "peer1_psk": ParamDef(type=str, default="",
                              description="First peer's pre-shared key (optional)"),
    },
    build_defaults=_build_wireguard_server,
    requires_capabilities=[],
    requires_post_flash=True,
))
