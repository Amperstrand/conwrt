"""vpn-mullvad — Mullvad WireGuard VPN.

Full API integration: generates WG keypair, registers public key with
Mullvad API using account token, fetches server config, configures
WireGuard interface with response values.
"""
from __future__ import annotations

import re
from typing import Any

from profile.ops import Comment, Op, ShellCommand
from shell_safe import interface_name

from .. import ParamDef, UseCase, register
from .base import (
    JSON_HELPER_SH,
    build_dns_ops,
    build_firewall_ops,
    build_verify_ops,
    keypair_sh,
    wg0_uci_sh,
    static_route_sh,
    transport_sh,
    wg_cleanup_sh,
)

# values are baked into the transport-script TEXT (Authorization header,
# jq select pattern, quoted uci values) — quotes/metacharacters inject
# shell or break the header (surfshark #604 class; plan.rs
# VpnMullvadProfile::validate mirrors these gates).
_TOKEN_SAFE = re.compile(r"^[A-Za-z0-9_.-]+$")
_COUNTRY_SAFE = re.compile(r"^[A-Za-z]{2}$")


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    account_token = str(params["account_token"])
    country = str(params.get("country", ""))
    gateway = str(params["upstream_gateway"])
    upstream_iface = str(params.get("upstream_iface", "wwan"))
    kill_switch = bool(params.get("kill_switch", True))

    if not _TOKEN_SAFE.fullmatch(account_token):
        raise ValueError(
            f"account_token must be letters/digits/dots/hyphens, got {account_token!r}"
        )
    if country and not _COUNTRY_SAFE.fullmatch(country):
        raise ValueError(f"country must be a 2-letter code, got {country!r}")
    if not re.fullmatch(r"[0-9.]+", gateway):
        raise ValueError(f"upstream_gateway must be an IPv4 address, got {gateway!r}")
    upstream_iface = interface_name(upstream_iface, "upstream_iface")
    return {
        "account_token": account_token,
        "country": country,
        "upstream_gateway": gateway,
        "upstream_iface": upstream_iface,
        "kill_switch": kill_switch,
    }


def _build_mullvad_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    account_token = r["account_token"]
    country = r["country"]
    gateway = r["upstream_gateway"]
    upstream_iface = r["upstream_iface"]
    kill_switch = r["kill_switch"]

    country_filter = f'"country_code":"{country}"' if country else ""

    mullvad_script = f"""{JSON_HELPER_SH}
{keypair_sh()}

WG_PUB=$(cat /tmp/vpn_public.key)

# Register WG public key with Mullvad API
RESPONSE=$(curl -s -m 15 -X POST \\
    "https://api.mullvad.net/www/accounts/me/wg-peers/" \\
    -H "Authorization: Token {account_token}" \\
    -H "Content-Type: application/json" \\
    -d '{{"public_key":"'"${{WG_PUB}}"'"}}')

PEER_IP=$(echo "$RESPONSE" | json_get ipv4_address)
# Strip CIDR if present (Mullvad returns 10.xx.xx.xx/32)
PEER_IP=${{PEER_IP%%/*}}

# Fetch server list and pick best server
SERVERS=$(curl -s -m 15 -H "Accept: application/json" "https://api.mullvad.net/www/relays/wireguard/")
if [ -n "{country_filter}" ]; then
    SERVER_ENTRY=$(echo "$SERVERS" | jq -r '[.[] | select(.country_code=="{country}")] | .[0]')
else
    SERVER_ENTRY=$(echo "$SERVERS" | jq -r '.[0]')
fi
SERVER_IP=$(echo "$SERVER_ENTRY" | json_get ipv4_addr_in)
SERVER_KEY=$(echo "$SERVER_ENTRY" | json_get pubkey)
SERVER_HOST=$(echo "$SERVER_ENTRY" | json_get hostname)
SERVER_PORT=51820

# Abort BEFORE the destructive wg0 cleanup unless the response is
# complete (surfshark #604-P2 class)
[ -n "$SERVER_KEY" ] && [ -n "$SERVER_IP" ] \\
    || {{ echo 'Mullvad: server list incomplete — aborting before wg0 cleanup'; exit 1; }}
if [ -z "$PEER_IP" ]; then echo 'Mullvad: key registration failed (no peer IP) — aborting before wg0 cleanup'; exit 1; fi

{wg_cleanup_sh()}

MULLVAD_PRIV=$(cat /tmp/vpn_private.key)

{wg0_uci_sh('"$MULLVAD_PRIV"', '"${PEER_IP}/32"', '"$SERVER_KEY"', '"$SERVER_IP"', '"$SERVER_PORT"')}
{static_route_sh("SERVER_IP", gateway, upstream_iface, "mullvad_server_route")}

# Pre-commit IP readback (AGENTS.md; surfshark #604-P1 class)
WG_ADDR=$(uci -q get network.wg0.addresses)
case "$WG_ADDR" in
    */32) ;;
    *) echo "Mullvad: wg0 address '$WG_ADDR' not a sane /32 — aborting before commit"; exit 1 ;;
esac
"""

    ops: list[Op] = [
        Comment(text=f"--- Mullvad WireGuard VPN{f' ({country})' if country else ''} ---"),
        # Clean baseline (AGENTS.md): revert staged debris before staging
        ShellCommand(command="uci -q revert network 2>/dev/null || true"),
        ShellCommand(command="uci -q revert firewall 2>/dev/null || true"),
        ShellCommand(command="uci -q revert dhcp 2>/dev/null || true"),
        ShellCommand(command=transport_sh(mullvad_script)),
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
    build_configure_ops=_build_mullvad_ops,
    test_status="untested",
    tested_notes="",
))
