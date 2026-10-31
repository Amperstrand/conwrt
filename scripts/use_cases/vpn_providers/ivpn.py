"""vpn-ivpn — IVPN WireGuard VPN.

Authenticates with IVPN account ID, registers WG public key, fetches
server config, configures WireGuard interface.
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

# values are baked into the transport-script TEXT (URL query, jq
# pattern, quoted uci values) — quotes/metacharacters in the account
# ID inject shell or break the URL (the surfshark #604 class; plan.rs
# VpnIvpnProfile::validate mirrors these gates).
_ACCOUNT_SAFE = re.compile(r"^[A-Za-z0-9_-]+$")


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    account_id = str(params["account_id"])
    gateway = str(params["upstream_gateway"])
    upstream_iface = str(params.get("upstream_iface", "wwan"))
    kill_switch = bool(params.get("kill_switch", True))

    if not _ACCOUNT_SAFE.fullmatch(account_id):
        raise ValueError(
            f"account_id must be letters/digits/underscores/hyphens, got {account_id!r}"
        )
    if not re.fullmatch(r"[0-9.]+", gateway):
        raise ValueError(f"upstream_gateway must be an IPv4 address, got {gateway!r}")
    upstream_iface = interface_name(upstream_iface, "upstream_iface")
    return {
        "account_id": account_id,
        "upstream_gateway": gateway,
        "upstream_iface": upstream_iface,
        "kill_switch": kill_switch,
    }


def _build_ivpn_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    account_id = r["account_id"]
    gateway = r["upstream_gateway"]
    upstream_iface = r["upstream_iface"]
    kill_switch = r["kill_switch"]

    ivpn_script = f"""{JSON_HELPER_SH}
{keypair_sh()}

WG_PUB=$(cat /tmp/vpn_public.key)

# Register WG public key with IVPN API
KEY_RESP=$(curl -s -m 15 -X POST \\
    "https://api.ivpn.net/v4/account/wireguard/key?account_id={account_id}" \\
    -H "Content-Type: application/json" \\
    -d '{{"public_key":"'"${{WG_PUB}}"'"}}')
PEER_IP=$(echo "$KEY_RESP" | json_get ip_address)
# Strip CIDR if present
PEER_IP=${{PEER_IP%%/*}}

# Fetch server list and pick first (.json variant — the extensionless path 404s)
SERVERS=$(curl -s -m 15 "https://api.ivpn.net/v4/servers.json")
SERVER_ENTRY=$(echo "$SERVERS" | jq -r '[.wireguard[].hosts[] | select(has("public_key"))] | .[0]')
SERVER_IP=$(echo "$SERVER_ENTRY" | json_get host)
SERVER_KEY=$(echo "$SERVER_ENTRY" | json_get public_key)
SERVER_PORT=$(echo "$SERVER_ENTRY" | json_get wg_port)
[ -z "$SERVER_PORT" ] && SERVER_PORT=51820

# Abort BEFORE the destructive wg0 cleanup unless the response is complete
# (the surfshark #604-P2 class: a failed key registration leaves PEER_IP
# empty — without this guard the script below deletes a working tunnel)
[ -n "$SERVER_KEY" ] && [ -n "$SERVER_IP" ] \\
    || {{ echo 'IVPN: server list incomplete — aborting before wg0 cleanup'; exit 1; }}
if [ -z "$PEER_IP" ]; then echo 'IVPN: key registration failed (no peer IP) — aborting before wg0 cleanup'; exit 1; fi

{wg_cleanup_sh()}

IVPN_PRIV=$(cat /tmp/vpn_private.key)

{wg0_uci_sh('"$IVPN_PRIV"', '"${PEER_IP}/32"', '"$SERVER_KEY"', '"$SERVER_IP"', '"$SERVER_PORT"')}
{static_route_sh("SERVER_IP", gateway, upstream_iface, "ivpn_server_route")}

# Pre-commit IP readback (AGENTS.md): refuse to reach commit with a
# tunnel address that is not a sane /32 (the surfshark #604-P1 class)
WG_ADDR=$(uci -q get network.wg0.addresses)
case "$WG_ADDR" in
    */32) ;;
    *) echo "IVPN: wg0 address '$WG_ADDR' not a sane /32 — aborting before commit"; exit 1 ;;
esac
"""

    ops: list[Op] = [
        Comment(text="--- IVPN WireGuard VPN ---"),
        # Clean baseline (AGENTS.md): aborted runs leave /tmp/.uci staging
        # debris — revert before staging so the later commits cannot make
        # unrelated changes permanent
        ShellCommand(command="uci -q revert network 2>/dev/null || true"),
        ShellCommand(command="uci -q revert firewall 2>/dev/null || true"),
        ShellCommand(command="uci -q revert dhcp 2>/dev/null || true"),
        ShellCommand(command=transport_sh(ivpn_script)),
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
    build_configure_ops=_build_ivpn_ops,
    test_status="untested",
    tested_notes="",
))
