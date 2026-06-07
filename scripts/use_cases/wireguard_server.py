"""wireguard-server — WireGuard VPN server for remote access to the local network."""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciAddList, UciCommit, UciSet, render_shell
from profile.uci_helpers import uci_cleanup_sections

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
        Comment(text="--- WireGuard VPN server ---"),
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

    # Named firewall sections + while-loop cleanup of stale anonymous sections
    ops.extend([
        BlankLine(),
        uci_cleanup_sections("firewall", "name='vpn'"),
        uci_cleanup_sections("firewall", "name='Allow-WireGuard'"),
        BlankLine(),
        ShellCommand(command="uci set firewall.wg_server_vpn=zone"),
        UciSet(config="firewall", section="wg_server_vpn", values={
            "name": "vpn",
            "input": "ACCEPT",
            "output": "ACCEPT",
            "forward": "REJECT",
            "masq": "1",
            "mtu_fix": "1",
            "network": "wg0",
        }),
        BlankLine(),
        ShellCommand(command="uci set firewall.wg_server_fwd_lan=forwarding"),
        UciSet(config="firewall", section="wg_server_fwd_lan", values={
            "src": "vpn",
            "dest": "lan",
        }),
        BlankLine(),
        ShellCommand(command="uci set firewall.wg_server_fwd_wan=forwarding"),
        UciSet(config="firewall", section="wg_server_fwd_wan", values={
            "src": "vpn",
            "dest": "wan",
        }),
        BlankLine(),
        ShellCommand(command="uci set firewall.wg_server_allow=rule"),
        UciSet(config="firewall", section="wg_server_allow", values={
            "name": "Allow-WireGuard",
            "src": "wan",
            "dest_port": listen_port,
            "proto": "udp",
            "target": "ACCEPT",
        }),
        BlankLine(),
        UciCommit(config="network"),
        UciCommit(config="firewall"),
        ServiceAction(name="network", action="restart"),
        ShellCommand(command=f'echo "WireGuard server configured: port {listen_port}, subnet {subnet}"'),
    ])

    return ops


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
    build_configure=lambda p: render_shell(_build_wireguard_server_ops(p)),
    build_configure_ops=_build_wireguard_server_ops,
    requires_capabilities=[],
    test_status="tested",
    tested_notes="ops characterization + transport parity",
    configure_via="ssh",
))
