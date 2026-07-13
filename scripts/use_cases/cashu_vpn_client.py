"""cashu-vpn-client — WireGuard client for the vps-on-demand Cashu VPN exit.

Pre-paid WireGuard tunnel: the operator pays the vps-on-demand peer service
(Cashu token in the X-Cashu header of POST /peer) out-of-band, receives
{peer_ip, public_key, endpoint, allowed_ips} from the API, and pastes those
values into this use case. The router then brings up wg0 as a full-tunnel
client to 66.92.204.237:51820 with the assigned peer IP.

This preset only configures the router side. Cashu payment, peer creation,
and X-Cashu header handling happen on the host before flashing — no Cashu
tokens or WireGuard private keys are baked into the firmware image. Each
router auto-generates its own Curve25519 private key on first boot.
"""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciAddList, UciCommit, UciSet, render_shell
from profile.uci_helpers import uci_cleanup_sections
from shell_safe import validate_host, validate_port

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    # Mirrors wireguard_client.py: validate host/port formats, leave CIDR/key
    # strings to ParamDef type-checking at the apply_defaults() boundary.
    server_host = str(params.get("server_host", ""))
    if server_host:
        server_host = validate_host(server_host, "server_host")
    server_port = params.get("server_port", 51820)
    if isinstance(server_port, int):
        server_port = validate_port(server_port, "server_port")

    return {
        "private_key": params.get("private_key", "generate"),
        "peer_public_key": str(params.get("peer_public_key", "")),
        "server_host": server_host,
        "server_port": server_port,
        "peer_ip": str(params.get("peer_ip", "")),
        "allowed_ips": str(params.get("allowed_ips", "0.0.0.0/0")),
        "kill_switch": params.get("kill_switch", True),
        "dns": str(params.get("dns", "1.1.1.1")),
    }


def _build_cashu_vpn_client_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    private_key = r["private_key"]
    peer_public_key = r["peer_public_key"]
    server_host = r["server_host"]
    server_port = r["server_port"]
    peer_ip = r["peer_ip"]
    allowed_ips = r["allowed_ips"]
    kill_switch = r["kill_switch"]
    dns = r["dns"]

    ops: list[Op] = [
        Comment(text="--- Cashu VPN client (vps-on-demand WireGuard exit) ---"),
        Comment(text="Tunnel address and peer key come from POST /peer on the vps-on-demand service."),
        ShellCommand(command="uci set network.wg0=interface"),
        UciSet(config="network", section="wg0", values={
            "proto": "wireguard",
            "private_key": private_key,
            "addresses": peer_ip,
        }),
    ]

    if dns:
        for token in (t.strip() for t in dns.split(",") if t.strip()):
            ops.append(UciAddList(config="network", section="wg0", option="dns", value=token))

    ops.extend([
        ShellCommand(command="uci set network.wg0_peer=wireguard_wg0"),
        UciSet(config="network", section="wg0_peer", values={
            "public_key": peer_public_key,
            "endpoint_host": server_host,
            "endpoint_port": str(server_port),
            "allowed_ips": allowed_ips,
            "route_allowed_ips": "1",
            "persistent_keepalive": "25",
        }),
    ])

    # Named firewall sections + while-loop cleanup of stale anonymous sections
    # to prevent accumulation across reconfigure runs (same pattern as guest-wifi).
    ops.extend([
        BlankLine(),
        Comment(text="--- Cleanup stale anonymous WireGuard firewall sections ---"),
        uci_cleanup_sections("firewall", "name='vpn'"),
        uci_cleanup_sections("firewall", "dest='vpn'"),
        uci_cleanup_sections("firewall", "name='KillSwitch-Reject-NonVPN'"),
        BlankLine(),
        Comment(text="--- WireGuard firewall zone + LAN forwarding ---"),
        ShellCommand(command="uci set firewall.cashu_vpn_zone=zone"),
        UciSet(config="firewall", section="cashu_vpn_zone", values={
            "name": "vpn",
            "input": "REJECT",
            "output": "ACCEPT",
            "forward": "REJECT",
            "masq": "1",
            "mtu_fix": "1",
            "network": "wg0",
        }),
        BlankLine(),
        ShellCommand(command="uci set firewall.cashu_vpn_fwd=forwarding"),
        UciSet(config="firewall", section="cashu_vpn_fwd", values={
            "src": "lan",
            "dest": "vpn",
        }),
    ])

    if kill_switch:
        ops.extend([
            BlankLine(),
            Comment(text="--- Kill switch: drop LAN→WAN when the tunnel is down ---"),
            ShellCommand(command="uci set firewall.cashu_vpn_killswitch=rule"),
            UciSet(config="firewall", section="cashu_vpn_killswitch", values={
                "name": "KillSwitch-Reject-NonVPN",
                "src": "lan",
                "dest": "wan",
                "proto": "all",
                "target": "REJECT",
            }),
        ])

    ops.extend([
        BlankLine(),
        Comment(text="--- Commit + restart ---"),
        UciCommit(config="network"),
        UciCommit(config="firewall"),
        ServiceAction(name="network", action="restart"),
        ShellCommand(command=f"echo 'Cashu VPN client configured: {server_host}:{server_port} (peer_ip={peer_ip})'"),
    ])

    if kill_switch:
        ops.append(ShellCommand(
            command=(
                "i=0; while [ $i -lt 30 ]; do"
                " if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then"
                " echo 'Cashu VPN kill-switch: tunnel verified'; exit 0;"
                " fi; sleep 1; i=$((i+1));"
                " done;"
                " echo 'Cashu VPN kill-switch: tunnel failed — removing kill switch to restore WAN';"
                " uci delete firewall.cashu_vpn_killswitch;"
                " uci commit firewall;"
                " fw4 restart"
            ),
        ))

    return ops


register(UseCase(
    name="cashu-vpn-client",
    description="Cashu VPN client — full-tunnel WireGuard client for the vps-on-demand exit",
    packages=[
        "wireguard-tools",
        "wireguard-kmod",
        "luci-proto-wireguard",
    ],
    packages_remove=[],
    params={
        "private_key": ParamDef(type=str, default="generate",
                                description="WireGuard private key ('generate' = auto-generate on first boot)"),
        "peer_public_key": ParamDef(type=str, required=True, allow_empty=False,
                                     description="vps-on-demand VPN exit public key (from POST /peer 'public_key')"),
        "peer_ip": ParamDef(type=str, required=True, allow_empty=False,
                             description="Tunnel IP assigned by the VPN exit, with CIDR (from POST /peer 'peer_ip')"),
        "server_host": ParamDef(type=str, default="66.92.204.237",
                                 description="vps-on-demand VPN exit hostname or IP"),
        "server_port": ParamDef(type=int, default=51820,
                                 description="vps-on-demand VPN exit UDP port"),
        "allowed_ips": ParamDef(type=str, default="0.0.0.0/0",
                                 description="IPs routed through the tunnel (0.0.0.0/0 = full tunnel)"),
        "dns": ParamDef(type=str, default="1.1.1.1",
                         description="DNS server reached through the tunnel (empty = use peer's)"),
        "kill_switch": ParamDef(type=bool, default=True,
                                 description="Block all traffic if the VPN tunnel drops"),
    },
    build_configure=lambda p: render_shell(_build_cashu_vpn_client_ops(p)),
    build_configure_ops=_build_cashu_vpn_client_ops,
    test_status="experimental",
    tested_notes="",
    requires_capabilities=["ethernet"],
))
