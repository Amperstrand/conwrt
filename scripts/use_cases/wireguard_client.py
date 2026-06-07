"""wireguard-client — WireGuard VPN client for routing traffic through a VPN tunnel."""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciAddList, UciCommit, UciSet, render_shell
from profile.uci_helpers import uci_cleanup_sections
from shell_safe import validate_host, validate_port

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    endpoint_host = str(params.get("endpoint_host", ""))
    if endpoint_host:
        endpoint_host = validate_host(endpoint_host, "endpoint_host")
    endpoint_port = params.get("endpoint_port", 51820)
    if isinstance(endpoint_port, int):
        endpoint_port = validate_port(endpoint_port, "endpoint_port")
    return {
        "private_key": params.get("private_key", "generate"),
        "peer_public_key": params.get("peer_public_key", ""),
        "endpoint_host": endpoint_host,
        "endpoint_port": endpoint_port,
        "peer_psk": params.get("peer_psk", ""),
        "address": params.get("address", "10.67.0.2/32"),
        "dns": params.get("dns", ""),
        "kill_switch": params.get("kill_switch", True),
        "allowed_ips": params.get("allowed_ips", "0.0.0.0/0, ::/0"),
    }


def _build_wireguard_client_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    private_key = r["private_key"]
    peer_public_key = r["peer_public_key"]
    endpoint_host = r["endpoint_host"]
    endpoint_port = r["endpoint_port"]
    peer_psk = r["peer_psk"]
    address = r["address"]
    dns = r["dns"]
    kill_switch = r["kill_switch"]
    allowed_ips = r["allowed_ips"]

    ops: list[Op] = [
        Comment(text="--- WireGuard VPN client ---"),
        ShellCommand(command="uci set network.wg0=interface"),
        UciSet(config="network", section="wg0", values={
            "proto": "wireguard",
            "private_key": private_key,
            "addresses": address,
        }),
    ]

    if dns:
        ops.append(UciAddList(config="network", section="wg0", option="dns", value=dns))

    ops.extend([
        ShellCommand(command="uci set network.wg0_peer=wireguard_wg0"),
        UciSet(config="network", section="wg0_peer", values={
            "public_key": peer_public_key,
            "endpoint_host": endpoint_host,
            "endpoint_port": str(endpoint_port),
            "allowed_ips": allowed_ips,
            "route_allowed_ips": "1",
            "persistent_keepalive": "25",
        }),
    ])

    if peer_psk:
        ops.append(UciSet(config="network", section="wg0_peer", values={"preshared_key": peer_psk}))

    # Named firewall sections + while-loop cleanup of stale anonymous sections
    # to prevent accumulation across reconfigure runs (same pattern as guest-wifi).
    ops.extend([
        BlankLine(),
        Comment(text="--- Cleanup stale anonymous WireGuard firewall sections ---"),
        uci_cleanup_sections("firewall", "name='vpn'"),
        uci_cleanup_sections("firewall", "dest='vpn'"),
        uci_cleanup_sections("firewall", "name='KillSwitch-Reject-NonVPN'"),
        BlankLine(),
        Comment(text="--- WireGuard firewall zone + forwarding ---"),
        ShellCommand(command="uci set firewall.wg_client_vpn=zone"),
        UciSet(config="firewall", section="wg_client_vpn", values={
            "name": "vpn",
            "input": "REJECT",
            "output": "ACCEPT",
            "forward": "REJECT",
            "masq": "1",
            "mtu_fix": "1",
            "network": "wg0",
        }),
        BlankLine(),
        ShellCommand(command="uci set firewall.wg_client_fwd=forwarding"),
        UciSet(config="firewall", section="wg_client_fwd", values={
            "src": "lan",
            "dest": "vpn",
        }),
    ])

    if kill_switch:
        ops.extend([
            BlankLine(),
            ShellCommand(command="uci set firewall.wg_client_killswitch=rule"),
            UciSet(config="firewall", section="wg_client_killswitch", values={
                "name": "KillSwitch-Reject-NonVPN",
                "src": "lan",
                "dest": "wan",
                "proto": "all",
                "target": "REJECT",
            }),
        ])

    ops.extend([
        BlankLine(),
        UciCommit(config="network"),
        UciCommit(config="firewall"),
        ServiceAction(name="network", action="restart"),
        ShellCommand(command=f"echo 'WireGuard client configured: {endpoint_host}:{endpoint_port}'"),
    ])

    return ops


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
    build_configure=lambda p: render_shell(_build_wireguard_client_ops(p)),
    build_configure_ops=_build_wireguard_client_ops,
    test_status="tested",
    tested_notes="D-Link COVR-X1860 A1",
    requires_capabilities=[],
))
