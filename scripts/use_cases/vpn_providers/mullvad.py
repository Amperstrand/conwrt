"""vpn-mullvad — Mullvad WireGuard VPN.

Full API integration: generates WG keypair, registers public key with
Mullvad API using account token, fetches server config, configures
WireGuard interface with response values.
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


def _build_mullvad_ops(params: dict[str, Any]) -> list[Op]:
    account_token = params["account_token"]
    country = params.get("country", "")
    gateway = params["upstream_gateway"]
    upstream_iface = params.get("upstream_iface", "wwan")
    kill_switch = params.get("kill_switch", True)

    country_filter = f'"country_code":"{country}"' if country else ""

    mullvad_script = f"""{JSON_HELPER_SH}
{keypair_sh()}

WG_PUB=$(cat /tmp/vpn_public.key)

# Register WG public key with Mullvad API
RESPONSE=$(curl -s -m 15 -X POST \\
    "https://api.mullvad.net/www/accounts/me/wg-peers/" \\
    -H "Authorization: Token {account_token}" \\
    -H "Content-Type: application/json" \\
    -d '{{"public_key":"${{WG_PUB}}"}}')

PEER_IP=$(echo "$RESPONSE" | json_get ipv4_address)
# Strip CIDR if present (Mullvad returns 10.xx.xx.xx/32)
PEER_IP=${{PEER_IP%%/*}}

# Fetch server list and pick best server
SERVERS=$(curl -s -m 15 "https://api.mullvad.net/public/relays/wireguard/")
if [ -n "{country_filter}" ]; then
    SERVER_ENTRY=$(echo "$SERVERS" | jq -r '[.[] | select(.country_code=="{country}")] | .[0]')
else
    SERVER_ENTRY=$(echo "$SERVERS" | jq -r '.[0]')
fi
SERVER_IP=$(echo "$SERVER_ENTRY" | json_get ipv4_addr_in)
SERVER_KEY=$(echo "$SERVER_ENTRY" | json_get public_key)
SERVER_HOST=$(echo "$SERVER_ENTRY" | json_get hostname)
SERVER_PORT=51820

{wg_cleanup_sh()}

MULLVAD_PRIV=$(cat /tmp/vpn_private.key)

# Configure WireGuard interface
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key="$MULLVAD_PRIV"
uci set network.wg0.listen_port='51820'
uci add_list network.wg0.addresses="${{PEER_IP}}/32"
uci set network.wg0.mtu='1280'
uci set network.wg0.auto='1'

# Add Mullvad peer
uci add network wireguard_wg0
uci set network.@wireguard_wg0[0].public_key="$SERVER_KEY"
uci set network.@wireguard_wg0[0].endpoint_host="$SERVER_IP"
uci set network.@wireguard_wg0[0].endpoint_port="$SERVER_PORT"
uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'
uci set network.@wireguard_wg0[0].route_allowed_ips='1'
uci set network.@wireguard_wg0[0].persistent_keepalive='25'

{static_route_sh("SERVER_IP", gateway, upstream_iface, "mullvad_server_route")}
"""

    ops: list[Op] = [
        Comment(text=f"--- Mullvad WireGuard VPN{f' ({country})' if country else ''} ---"),
        ShellCommand(command=mullvad_script),
    ]
    ops.extend(build_firewall_ops(kill_switch=kill_switch))
    ops.extend(build_dns_ops(["10.64.0.1"]))
    ops.extend(build_verify_ops(kill_switch=kill_switch))
    return ops


register(UseCase(
    name="vpn-mullvad",
    description="Mullvad WireGuard VPN — API key registration + server auto-selection",
    packages=["wireguard-tools", "luci-proto-wireguard"],
    packages_remove=[],
    params={
        "account_token": ParamDef(type=str, required=True, allow_empty=False,
                                  description="Mullvad account token (10-digit number from account page)"),
        "country": ParamDef(type=str, default="",
                            description="ISO country code to filter servers (e.g. 'se' for Sweden, empty = auto)"),
        "upstream_gateway": ParamDef(type=str, required=True, allow_empty=False,
                                     description="Upstream gateway IP (prevents circular routing)"),
        "upstream_iface": ParamDef(type=str, default="wwan",
                                   description="Upstream interface name (wwan, wan, etc.)"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block all non-VPN traffic if tunnel drops"),
    },
    build_configure=lambda p: render_shell(_build_mullvad_ops(p)),
    build_configure_ops=_build_mullvad_ops,
    test_status="untested",
    tested_notes="",
))
