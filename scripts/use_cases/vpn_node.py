"""vpn-node — WireGuard VPN server that announces itself on Nostr.

Configures WireGuard server + publishes a kind 30402 Europa listing on
first boot. Uses nak CLI for Nostr event signing (available on OpenWrt
as a static binary).

Combined with the wireguard-server use case, this creates a self-
announcing VPN node that appears on europa.westernbtc.com/operators.

For payment collection, deploy alongside tollgate-auth (RADIUS + Cashu).
"""
from __future__ import annotations

from typing import Any

from profile.ops import Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register


def _build_vpn_node_ops(params: dict[str, Any]) -> list[Op]:
    nsec = params.get("nsec", "")
    d_tag = params.get("d_tag", f"vpn-{__import__('time').time():.0f}")
    title = params.get("title", "VPN Node")
    endpoint_host = params.get("endpoint_host", "")
    endpoint_port = str(params.get("endpoint_port", 51820))
    region_country = params.get("country", "US")
    price_amount = str(params.get("price_amount", 50))
    price_unit = params.get("price_unit", "hour")
    relays = params.get("relays", "wss://relay.damus.io,wss://relay.cashu.email")
    content = params.get("content", "VPN node. WireGuard. No logs.")
    nak_bin = params.get("nak_path", "/usr/bin/nak")

    relay_args = " ".join(relays.split(","))

    listing_json = (
        '{"type":"vpn-service",'
        f'"name":"{title}",'
        f'"endpoint":"{endpoint_host}:{endpoint_port}",'
        f'"protocols":["wireguard"],'
        f'"prices":[{{"amount":{price_amount},"currency":"sat","unit":"{price_unit}"}}],'
        f'"policies":["no-logs"],'
        f'"content":"{content}"}}'
    )

    first_boot = f"""cat > /etc/vpn-listing.sh << 'SCRIPT'
#!/bin/sh
# Publish Europa listing on first boot
NSEC_FILE="/etc/vpn-node/nsec"
WG_PUBKEY=$(wg show wg0 public-key 2>/dev/null)
if [ -z "$WG_PUBKEY" ] || [ ! -f "$NSEC_FILE" ]; then
    echo "vpn-listing: missing wg0 pubkey or nsec, skipping" >&2
    exit 0
fi
NSEC=$(cat "$NSEC_FILE")
{nak_bin} event \\
    -k 30402 \\
    --sec "$NSEC" \\
    -d "{d_tag}" \\
    -t "t=vpn-service" \\
    -t "t=wireguard" \\
    -t "protocol=wireguard" \\
    -t "region={region_country}" \\
    -t "price={price_amount}sat/{price_unit}" \\
    -c '{listing_json}' \\
    {relay_args} 2>&1
echo "vpn-listing: published"
SCRIPT
chmod +x /etc/vpn-listing.sh

mkdir -p /etc/vpn-node
echo '{nsec}' > /etc/vpn-node/nsec
chmod 600 /etc/vpn-node/nsec

( sleep 30 && /etc/vpn-listing.sh > /tmp/vpn-listing.log 2>&1 ) &
"""

    return [
        Comment(text="--- VPN Node: Nostr listing publisher ---"),
        ShellCommand(command=first_boot),
    ]


register(UseCase(
    name="vpn-node",
    description="Self-announcing WireGuard VPN server (publishes Europa listing on Nostr)",
    packages=["wireguard-tools", "luci-proto-wireguard"],
    params={
        "nsec": ParamDef(type=str, required=True,
                         description="Operator Nostr nsec (hex) for listing + wallet"),
        "d_tag": ParamDef(type=str, default="vpn-node",
                          description="Nostr listing d-tag identifier"),
        "title": ParamDef(type=str, default="VPN Node",
                          description="Listing title shown to clients"),
        "endpoint_host": ParamDef(type=str, required=True,
                                  description="Public hostname or IP clients connect to"),
        "endpoint_port": ParamDef(type=int, default=51820,
                                  description="WireGuard UDP port"),
        "country": ParamDef(type=str, default="US",
                            description="ISO country code for region tag"),
        "price_amount": ParamDef(type=int, default=50,
                                  description="Price in sats"),
        "price_unit": ParamDef(type=str, default="hour",
                               description="Price unit: hour, day, week, month"),
        "content": ParamDef(type=str, default="VPN node. WireGuard. No logs.",
                            description="Listing description"),
        "relays": ParamDef(type=str, default="wss://relay.damus.io,wss://relay.cashu.email",
                           description="Comma-separated Nostr relay URLs"),
        "nak_path": ParamDef(type=str, default="/usr/bin/nak",
                             description="Path to nak binary"),
    },
    build_configure=lambda p: render_shell(_build_vpn_node_ops(p)),
    build_configure_ops=_build_vpn_node_ops,
    requires_capabilities=[],
    configure_via="ssh",
))
