"""vpn-ivpn — IVPN WireGuard VPN.

Authenticates with IVPN account ID, registers WG public key, fetches
server config, configures WireGuard interface.
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


def _build_ivpn_ops(params: dict[str, Any]) -> list[Op]:
    account_id = params["account_id"]
    gateway = params["upstream_gateway"]
    upstream_iface = params.get("upstream_iface", "wwan")
    kill_switch = params.get("kill_switch", True)

    ivpn_script = f"""{JSON_HELPER_SH}
{keypair_sh()}

WG_PUB=$(cat /tmp/vpn_public.key)

# Register WG public key with IVPN API
KEY_RESP=$(curl -s -m 15 -X POST \\
    "https://api.ivpn.net/v4/account/wireguard/key?account_id={account_id}" \\
    -H "Content-Type: application/json" \\
    -d '{{"public_key":"${{WG_PUB}}"}}')
PEER_IP=$(echo "$KEY_RESP" | json_get ip_address)
# Strip CIDR if present
PEER_IP=${{PEER_IP%%/*}}

# Fetch server list and pick first
SERVERS=$(curl -s -m 15 "https://api.ivpn.net/v4/servers")
# Get first WireGuard-capable server
SERVER_ENTRY=$(echo "$SERVERS" | jq -r '[.servers[] | .hosts[] | select(has("public_key"))] | .[0]')
SERVER_IP=$(echo "$SERVER_ENTRY" | json_get host)
SERVER_KEY=$(echo "$SERVER_ENTRY" | json_get public_key)
SERVER_PORT=$(echo "$SERVER_ENTRY" | json_get wg_port)
[ -z "$SERVER_PORT" ] && SERVER_PORT=51820

{wg_cleanup_sh()}

IVPN_PRIV=$(cat /tmp/vpn_private.key)

# Configure WireGuard interface
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key="$IVPN_PRIV"
uci set network.wg0.listen_port='51820'
uci add_list network.wg0.addresses="${{PEER_IP}}/32"
uci set network.wg0.mtu='1280'
uci set network.wg0.auto='1'

# Add IVPN peer
uci add network wireguard_wg0
uci set network.@wireguard_wg0[0].public_key="$SERVER_KEY"
uci set network.@wireguard_wg0[0].endpoint_host="$SERVER_IP"
uci set network.@wireguard_wg0[0].endpoint_port="$SERVER_PORT"
uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'
uci set network.@wireguard_wg0[0].route_allowed_ips='1'
uci set network.@wireguard_wg0[0].persistent_keepalive='25'

{static_route_sh("SERVER_IP", gateway, upstream_iface, "ivpn_server_route")}
"""

    ops: list[Op] = [
        Comment(text="--- IVPN WireGuard VPN ---"),
        ShellCommand(command=ivpn_script),
    ]
    ops.extend(build_firewall_ops(kill_switch=kill_switch))
    ops.extend(build_dns_ops(["10.0.0.53"]))
    ops.extend(build_verify_ops(kill_switch=kill_switch))
    return ops


register(UseCase(
    name="vpn-ivpn",
    description="IVPN WireGuard VPN — account ID auth + key registration",
    packages=["wireguard-tools", "luci-proto-wireguard"],
    packages_remove=[],
    params={
        "account_id": ParamDef(type=str, required=True, allow_empty=False,
                               description="IVPN account ID (e.g. 'ivpn-xxxxx')"),
        "upstream_gateway": ParamDef(type=str, required=True, allow_empty=False,
                                     description="Upstream gateway IP (prevents circular routing)"),
        "upstream_iface": ParamDef(type=str, default="wwan",
                                   description="Upstream interface name (wwan, wan, etc.)"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block all non-VPN traffic if tunnel drops"),
    },
    build_configure=lambda p: render_shell(_build_ivpn_ops(p)),
    build_configure_ops=_build_ivpn_ops,
    test_status="untested",
    tested_notes="",
))
