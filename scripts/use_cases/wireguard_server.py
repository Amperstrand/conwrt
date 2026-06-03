"""wireguard-server — WireGuard VPN server for remote access to the local network."""
from __future__ import annotations

import textwrap
from typing import Any

from profile.ops import Op, ShellCommand, UciAddList, UciCommit, UciSet

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    return {
        "private_key": str(params.get("private_key", "")),
        "listen_port": int(params.get("listen_port", 51820)),
        "subnet": str(params.get("subnet", "10.1.99.1/24")),
        "peer1_public_key": str(params.get("peer1_public_key", "")),
        "peer1_allowed_ips": str(params.get("peer1_allowed_ips", "10.1.99.2/32")),
        "peer1_psk": str(params.get("peer1_psk", "")),
    }


def _build_wireguard_server_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    private_key = r["private_key"]
    listen_port = str(r["listen_port"])
    subnet = r["subnet"]
    peer1_public_key = r["peer1_public_key"]
    peer1_allowed_ips = r["peer1_allowed_ips"]
    peer1_psk = r["peer1_psk"]

    ops: list[Op] = [
        ShellCommand(command="uci set network.wg0=interface"),
        UciSet(config="network", section="wg0", values={
            "proto": "wireguard",
            "private_key": private_key,
            "listen_port": listen_port,
        }),
        UciAddList(config="network", section="wg0", option="addresses", value=subnet),
    ]

    if peer1_public_key:
        ops.append(ShellCommand(command="uci set network.wg0_peer1=wireguard_wg0"))
        peer_values = {
            "public_key": peer1_public_key,
            "allowed_ips": peer1_allowed_ips,
            "route_allowed_ips": "1",
        }
        if peer1_psk:
            peer_values["preshared_key"] = peer1_psk
        ops.append(UciSet(config="network", section="wg0_peer1", values=peer_values))

    ops.extend([
        ShellCommand(command="uci add firewall zone"),
        UciSet(config="firewall", section="@zone[-1]", values={
            "name": "vpn",
            "input": "ACCEPT",
            "output": "ACCEPT",
            "forward": "REJECT",
            "masq": "1",
            "mtu_fix": "1",
            "network": "wg0",
        }),
        ShellCommand(command="uci add firewall forwarding"),
        UciSet(config="firewall", section="@forwarding[-1]", values={
            "src": "vpn",
            "dest": "lan",
        }),
        ShellCommand(command="uci add firewall forwarding"),
        UciSet(config="firewall", section="@forwarding[-1]", values={
            "src": "vpn",
            "dest": "wan",
        }),
        ShellCommand(command="uci add firewall rule"),
        UciSet(config="firewall", section="@rule[-1]", values={
            "name": "Allow-WireGuard",
            "src": "wan",
            "dest_port": listen_port,
            "proto": "udp",
            "target": "ACCEPT",
        }),
        UciCommit(config="network"),
        UciCommit(config="firewall"),
        ShellCommand(command="/etc/init.d/network restart 2>/dev/null || true"),
    ])

    return ops


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

    peer_block = "\n".join(peer_lines) if peer_lines else ""

    return textwrap.dedent(f"""\
        # --- WireGuard VPN server ---
        uci set network.wg0=interface
        uci set network.wg0.proto='wireguard'
        uci set network.wg0.private_key='{private_key}'
        uci set network.wg0.listen_port='{listen_port}'
        uci add_list network.wg0.addresses='{subnet}'
        {peer_block}

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
    build_configure=_build_wireguard_server,
    build_configure_ops=_build_wireguard_server_ops,
    requires_capabilities=[],
    test_status="untested",
    tested_notes="post-install peer setup",
    configure_via="ssh",
))
