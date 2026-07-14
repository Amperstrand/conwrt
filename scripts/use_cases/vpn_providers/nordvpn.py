"""vpn-nordvpn — NordVPN WireGuard VPN (NordLynx).

Authenticates with NordVPN service credentials, obtains NordLynx token,
fetches recommended server, configures WireGuard. Requires service
credentials from the NordVPN dashboard (not account email/password).
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


def _build_nordvpn_ops(params: dict[str, Any]) -> list[Op]:
    service_username = params["service_username"]
    service_password = params["service_password"]
    country = params.get("country", "")
    gateway = params["upstream_gateway"]
    upstream_iface = params.get("upstream_iface", "wwan")
    kill_switch = params.get("kill_switch", True)

    country_param = f'&filters{{"country_id":[{country}]}}' if country else ""

    nordvpn_script = f"""{JSON_HELPER_SH}
{keypair_sh()}

# Authenticate with NordVPN — get access token
TOKEN_RESP=$(curl -s -m 15 -X POST \\
    "https://api.nordvpn.com/v2/users/tokens" \\
    -H "Content-Type: application/json" \\
    -u "{service_username}:{service_password}" \\
    -d '{{}}')
ACCESS_TOKEN=$(echo "$TOKEN_RESP" | json_get token)

# Get NordLynx credentials (private key)
LYNX_RESP=$(curl -s -m 15 \\
    "https://api.nordvpn.com/v1/users/services/credentials" \\
    -H "Authorization: Bearer ${{ACCESS_TOKEN}}")
NORDLYNX_KEY=$(echo "$LYNX_RESP" | json_get nordlynx_private_key)

# Get recommended server
RECO=$(curl -s -m 15 \\
    "https://api.nordvpn.com/v1/servers/recommendations?limit=1{country_param}" \\
    -H "Authorization: Bearer ${{ACCESS_TOKEN}}")
SERVER_IP=$(echo "$RECO" | jq -r '.[0].station')
SERVER_HOST=$(echo "$RECO" | jq -r '.[0].hostname')
# NordVPN server public key (from server tech spec)
SERVER_KEY=$(echo "$RECO" | jq -r '.[0].technologies[] | select(.identifier=="wireguard_udp") | .metadata[] | select(.name=="public_key") | .value')
SERVER_PORT=51820

# NordVPN assigns a virtual IP via NordLynx
PEER_IP="10.5.0.2"

{wg_cleanup_sh()}

# Use NordLynx-generated private key if available, else our generated one
if [ -n "$NORDLYNX_KEY" ]; then
    WG_PRIV="$NORDLYNX_KEY"
else
    WG_PRIV=$(cat /tmp/vpn_private.key)
fi

# Configure WireGuard interface
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key="$WG_PRIV"
uci set network.wg0.listen_port='51820'
uci add_list network.wg0.addresses="${{PEER_IP}}/32"
uci set network.wg0.mtu='1280'
uci set network.wg0.auto='1'

# Add NordVPN peer
uci add network wireguard_wg0
uci set network.@wireguard_wg0[0].public_key="$SERVER_KEY"
uci set network.@wireguard_wg0[0].endpoint_host="$SERVER_IP"
uci set network.@wireguard_wg0[0].endpoint_port="$SERVER_PORT"
uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'
uci set network.@wireguard_wg0[0].route_allowed_ips='1'
uci set network.@wireguard_wg0[0].persistent_keepalive='25'

{static_route_sh("SERVER_IP", gateway, upstream_iface, "nordvpn_server_route")}
"""

    ops: list[Op] = [
        Comment(text=f"--- NordVPN NordLynx WireGuard VPN ---"),
        ShellCommand(command=nordvpn_script),
    ]
    ops.extend(build_firewall_ops(kill_switch=kill_switch))
    ops.extend(build_dns_ops(["103.86.96.100", "103.86.99.100"]))
    ops.extend(build_verify_ops(kill_switch=kill_switch))
    return ops


register(UseCase(
    name="vpn-nordvpn",
    description="NordVPN WireGuard VPN (NordLynx) — service credential auth + server recommendation",
    packages=["wireguard-tools", "luci-proto-wireguard"],
    packages_remove=[],
    params={
        "service_username": ParamDef(type=str, required=True, allow_empty=False,
                                     description="NordVPN service username (from dashboard > VPN > Manual setup)"),
        "service_password": ParamDef(type=str, required=True, allow_empty=False,
                                     description="NordVPN service password (from dashboard)"),
        "country": ParamDef(type=str, default="",
                            description="Country ID filter (optional, e.g. '228' for Germany)"),
        "upstream_gateway": ParamDef(type=str, required=True, allow_empty=False,
                                     description="Upstream gateway IP (prevents circular routing)"),
        "upstream_iface": ParamDef(type=str, default="wwan",
                                   description="Upstream interface name (wwan, wan, etc.)"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block all non-VPN traffic if tunnel drops"),
    },
    build_configure=lambda p: render_shell(_build_nordvpn_ops(p)),
    build_configure_ops=_build_nordvpn_ops,
    test_status="untested",
    tested_notes="",
))
