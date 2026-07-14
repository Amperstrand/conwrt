"""vpn-pia — Private Internet Access WireGuard VPN.

Full API integration: generates WG keypair, authenticates with PIA API
(token generation + key registration), configures WireGuard with server
response values, sets up firewall kill switch and DNS.

PIA tokens expire ~7 days. For reboot persistence, install the
pia-wg-autostart init script (see skill: openwrt-pia-wireguard, Step 9).
"""
from __future__ import annotations

from typing import Any

from profile.ops import Comment, Op, ShellCommand, render_shell

from .. import ParamDef, UseCase, register
from .base import (
    JSON_HELPER_SH,
    build_dns_ops,
    build_firewall_ops,
    build_verify_ops,
    keypair_sh,
    static_route_sh,
    wg_cleanup_sh,
)


def _build_pia_ops(params: dict[str, Any]) -> list[Op]:
    username = params["username"]
    password = params["password"]
    region = params.get("region", "netherlands")
    gateway = params["upstream_gateway"]
    upstream_iface = params.get("upstream_iface", "wwan")
    kill_switch = params.get("kill_switch", True)

    pia_script = f"""{JSON_HELPER_SH}
{keypair_sh()}

# Authenticate with PIA — get auth token
curl -s -m 15 -u "{username}:{password}" \\
    "https://www.privateinternetaccess.com/gtoken/generateToken" \\
    -o /tmp/vpn_token.json
PIA_TOKEN=$(cat /tmp/vpn_token.json | json_get token)

# URL-encode token: PIA tokens contain +, /, = that break curl
ENC_TOKEN=$(echo "$PIA_TOKEN" | sed 's/+/%2B/g; s/=/%3D/g; s|/|%2F|g')

WG_PUB=$(cat /tmp/vpn_public.key)

# Register WG key with regional server
curl -s -m 15 -k \\
    "https://{region}.privacy.network:1337/addKey?pt=${{ENC_TOKEN}}&pubkey=${{WG_PUB}}" \\
    -o /tmp/vpn_addkey.json

# Parse server response
SERVER_KEY=$(cat /tmp/vpn_addkey.json | json_get server_key)
SERVER_IP=$(cat /tmp/vpn_addkey.json | json_get server_ip)
SERVER_PORT=$(cat /tmp/vpn_addkey.json | json_get server_port)
PEER_IP=$(cat /tmp/vpn_addkey.json | json_get peer_ip)

{wg_cleanup_sh()}

PIA_PRIV=$(cat /tmp/vpn_private.key)

# Configure WireGuard interface
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key="$PIA_PRIV"
uci set network.wg0.listen_port='51820'
uci add_list network.wg0.addresses="${{PEER_IP}}/32"
uci set network.wg0.mtu='1280'
uci set network.wg0.auto='1'

# Add PIA peer
uci add network wireguard_wg0
uci set network.@wireguard_wg0[0].public_key="$SERVER_KEY"
uci set network.@wireguard_wg0[0].endpoint_host="$SERVER_IP"
uci set network.@wireguard_wg0[0].endpoint_port="$SERVER_PORT"
uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'
uci set network.@wireguard_wg0[0].route_allowed_ips='1'
uci set network.@wireguard_wg0[0].persistent_keepalive='25'

{static_route_sh("SERVER_IP", gateway, upstream_iface, "pia_server_route")}
"""

    ops: list[Op] = [
        Comment(text=f"--- PIA WireGuard VPN ({region}) ---"),
        ShellCommand(command=pia_script),
    ]
    ops.extend(build_firewall_ops(kill_switch=kill_switch))
    ops.extend(build_dns_ops(["10.0.0.243", "10.0.0.242"]))
    ops.extend(build_verify_ops(kill_switch=kill_switch))
    return ops


register(UseCase(
    name="vpn-pia",
    description="Private Internet Access WireGuard VPN — full API integration "
                "(token gen + key registration + kill switch + DNS)",
    packages=["wireguard-tools", "luci-proto-wireguard"],
    packages_remove=[],
    params={
        "username": ParamDef(type=str, required=True, allow_empty=False,
                             description="PIA account username (e.g. p1234567)"),
        "password": ParamDef(type=str, required=True, allow_empty=False,
                             description="PIA account password"),
        "region": ParamDef(type=str, default="netherlands",
                           description="PIA region (e.g. netherlands, czech, frankfurt, swiss)"),
        "upstream_gateway": ParamDef(type=str, required=True, allow_empty=False,
                                     description="Upstream gateway IP (prevents circular routing)"),
        "upstream_iface": ParamDef(type=str, default="wwan",
                                   description="Upstream interface name (wwan, wan, etc.)"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block all non-VPN traffic if tunnel drops"),
    },
    build_configure=lambda p: render_shell(_build_pia_ops(p)),
    build_configure_ops=_build_pia_ops,
    test_status="tested",
    tested_notes="OpenWrt 24.10.4, MediaTek Filogic — PIA Czechia region",
))
