"""vpn-surfshark — Surfshark WireGuard VPN.

Authenticates with Surfshark service credentials, obtains auth token,
registers WG key, fetches server config, configures WireGuard interface.
"""
from __future__ import annotations

from typing import Any

from profile.ops import Comment, Op, ShellCommand

from .. import ParamDef, UseCase, register
from .base import (
    JSON_HELPER_SH,
    build_dns_ops,
    build_firewall_ops,
    build_verify_ops,
    keypair_sh,
    static_route_sh,
    transport_sh,
    wg_cleanup_sh,
)


def _build_surfshark_ops(params: dict[str, Any]) -> list[Op]:
    username = params["username"]
    password = params["password"]
    country = params.get("country", "")
    gateway = params["upstream_gateway"]
    upstream_iface = params.get("upstream_iface", "wwan")
    kill_switch = params.get("kill_switch", True)

    country_filter = f"country/{country}/" if country else ""

    surfshark_script = f"""{JSON_HELPER_SH}
{keypair_sh()}

WG_PUB=$(cat /tmp/vpn_public.key)

# Authenticate with Surfshark — get auth token
AUTH_RESP=$(curl -s -m 15 -X POST \\
    "https://api.surfshark.com/v1/auth/login" \\
    -H "Content-Type: application/json" \\
    -d '{{"username":"{username}","password":"{password}"}}')
AUTH_TOKEN=$(echo "$AUTH_RESP" | json_get token)

# Generate WireGuard configuration
WG_RESP=$(curl -s -m 15 -X POST \\
    "https://api.surfshark.com/v1/account/wireguard/new" \\
    -H "Authorization: Bearer ${{AUTH_TOKEN}}" \\
    -H "Content-Type: application/json" \\
    -d '{{"publicKey":"${{WG_PUB}}"}}')
PEER_IP=$(echo "$WG_RESP" | json_get ipAddress)
# Strip CIDR if present
PEER_IP=${{PEER_IP%%/*}}

# Fetch server list and pick best (v4 clusters: public endpoint, hostname-only
# entries — connectionName/pubKey; no IP field, so the endpoint is a DNS name)
SERVERS=$(curl -s -m 15 \\
    "https://api.surfshark.com/v4/server/clusters/generic?countryCode=" \\
    -H "Content-Type: application/json")
if [ -n "{country_filter}" ]; then
    SERVER_ENTRY=$(echo "$SERVERS" | jq -r '[.[] | select(.country | test("{country}";"i"))] | .[0]')
else
    SERVER_ENTRY=$(echo "$SERVERS" | jq -r '.[0]')
fi
SERVER_HOST=$(echo "$SERVER_ENTRY" | json_get connectionName)
SERVER_KEY=$(echo "$SERVER_ENTRY" | json_get pubKey)
SERVER_PORT=51820
# Resolve the endpoint hostname for the static /32 route; skip the route
# (netifd's wireguard proto installs its own endpoint route) when DNS fails.
SERVER_IP=$(nslookup "$SERVER_HOST" 2>/dev/null | awk '/^Address [0-9]*:/ {{print $NF}}' | tail -1)
[ -n "$SERVER_KEY" ] && [ -n "$SERVER_HOST" ] \\
    || {{ echo 'Surfshark: server list incomplete — aborting before wg0 cleanup'; exit 1; }}

{wg_cleanup_sh()}

SS_PRIV=$(cat /tmp/vpn_private.key)

# Configure WireGuard interface
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key="$SS_PRIV"
uci set network.wg0.listen_port='51820'
uci add_list network.wg0.addresses="${{PEER_IP}}/32"
uci set network.wg0.mtu='1280'
uci set network.wg0.auto='1'

# Add Surfshark peer
uci add network wireguard_wg0
uci set network.@wireguard_wg0[0].public_key="$SERVER_KEY"
uci set network.@wireguard_wg0[0].endpoint_host="$SERVER_HOST"
uci set network.@wireguard_wg0[0].endpoint_port="$SERVER_PORT"
uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'
uci set network.@wireguard_wg0[0].route_allowed_ips='1'
uci set network.@wireguard_wg0[0].persistent_keepalive='25'

if [ -n "$SERVER_IP" ]; then
{static_route_sh("SERVER_IP", gateway, upstream_iface, "surfshark_server_route")}else
    echo "Surfshark: endpoint DNS unresolved — skipping static route (netifd installs its own)"
fi
"""

    ops: list[Op] = [
        Comment(text=f"--- Surfshark WireGuard VPN ---"),
        ShellCommand(command=transport_sh(surfshark_script)),
    ]
    ops.extend(build_firewall_ops(kill_switch=kill_switch))
    ops.extend(build_dns_ops(["162.252.172.57", "149.154.159.92"]))
    ops.extend(build_verify_ops(kill_switch=kill_switch))
    return ops


register(UseCase(
    name="vpn-surfshark",
    description="Surfshark WireGuard VPN — token auth + key registration + server auto-selection",
    packages=["wireguard-tools", "luci-proto-wireguard"],
    packages_remove=[],
    params={
        "username": ParamDef(type=str, required=True, allow_empty=False,
                             description="Surfshark service username (from dashboard > VPN > Manual setup)"),
        "password": ParamDef(type=str, required=True, allow_empty=False,
                             description="Surfshark service password"),
        "country": ParamDef(type=str, default="",
                            description="Country name filter (optional, e.g. 'Germany')"),
        "upstream_gateway": ParamDef(type=str, required=True, allow_empty=False,
                                     description="Upstream gateway IP (prevents circular routing)"),
        "upstream_iface": ParamDef(type=str, default="wwan",
                                   description="Upstream interface name (wwan, wan, etc.)"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block all non-VPN traffic if tunnel drops"),
    },
    build_configure_ops=_build_surfshark_ops,
    test_status="untested",
    tested_notes="",
))
