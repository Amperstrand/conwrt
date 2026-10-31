"""vpn-node — WireGuard VPN server that announces itself on Nostr.

Configures WireGuard server + publishes a kind 30402 Europa listing on
first boot. Uses nak CLI for Nostr event signing (available on OpenWrt
as a static binary).

Combined with the wireguard-server use case, this creates a self-
announcing VPN node that appears on europa.westernbtc.com/operators.

For payment collection, deploy alongside tollgate-auth (RADIUS + Cashu).
"""
from __future__ import annotations

import re
from typing import Any

from profile.ops import Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell
from shell_safe import validate_host, validate_port

from . import ParamDef, UseCase, register

# Everything is baked into the transport-script TEXT at build time:
# nsec into `echo '{nsec}'` (single-quoted), title/content into BOTH a
# single-quoted shell arg and a JSON string, d_tag/region/price into
# double-quoted -t args, relays as BARE shell words, nak_path as an
# unquoted command. A quote/metacharacter in any of them injects shell
# at first-boot run time (surfshark #604 class; plan.rs
# VpnNodeProfile::validate mirrors these gates).
_NSEC_RE = re.compile(r"^[A-Za-z0-9]+$")  # hex or nsec1… bech32
_TAG_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_TEXT_RE = re.compile(r"^[^'\"\\\x00-\x1f]+$")  # display strings: no quotes/backslash/ctrl
_COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")
_RELAY_RE = re.compile(r"^wss://[A-Za-z0-9./:_-]+$")
_PATH_RE = re.compile(r"^[A-Za-z0-9./_()-]+$")
_PRICE_UNITS = ("hour", "day", "week", "month")


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    nsec = str(params["nsec"])
    d_tag = str(params.get("d_tag", "vpn-node"))
    title = str(params.get("title", "VPN Node"))
    endpoint_host = str(params.get("endpoint_host", ""))
    endpoint_port = int(params.get("endpoint_port", 51820))
    country = str(params.get("country", "US"))
    price_amount = int(params.get("price_amount", 50))
    price_unit = str(params.get("price_unit", "hour"))
    relays = str(params.get("relays", "wss://relay.damus.io,wss://relay.cashu.email"))
    content = str(params.get("content", "VPN node. WireGuard. No logs."))
    nak_bin = str(params.get("nak_path", "/usr/bin/nak"))

    if not _NSEC_RE.fullmatch(nsec):
        raise ValueError("nsec must be hex (or nsec1… bech32) — no quotes or metacharacters")
    if not _TAG_RE.fullmatch(d_tag):
        raise ValueError(f"d_tag must be letters/digits/dots/hyphens, got {d_tag!r}")
    for field, value in (("title", title), ("content", content)):
        if not _TEXT_RE.fullmatch(value):
            raise ValueError(
                f"{field} must not contain quotes, backslashes, or control characters "
                f"(it lands inside a single-quoted shell arg and a JSON string)"
            )
    if not endpoint_host:
        raise ValueError("endpoint_host is required (public hostname or IP)")
    endpoint_host = validate_host(endpoint_host, "endpoint_host")
    endpoint_port = validate_port(endpoint_port, "endpoint_port")
    if not _COUNTRY_RE.fullmatch(country):
        raise ValueError(f"country must be a 2-letter code, got {country!r}")
    if price_amount <= 0:
        raise ValueError("price_amount must be a positive integer (sats)")
    if price_unit not in _PRICE_UNITS:
        raise ValueError(f"price_unit must be one of {', '.join(_PRICE_UNITS)}, got {price_unit!r}")
    for relay in relays.split(","):
        if not _RELAY_RE.fullmatch(relay):
            raise ValueError(f"relay {relay!r} must be a wss:// URL without quotes/spaces/metacharacters")
    if not _PATH_RE.fullmatch(nak_bin):
        raise ValueError(f"nak_path contains unsafe characters, got {nak_bin!r}")
    return {
        "nsec": nsec,
        "d_tag": d_tag,
        "title": title,
        "endpoint_host": endpoint_host,
        "endpoint_port": endpoint_port,
        "country": country,
        "price_amount": price_amount,
        "price_unit": price_unit,
        "relays": relays,
        "content": content,
        "nak_bin": nak_bin,
    }


def _build_vpn_node_ops(params: dict[str, Any]) -> list[Op]:
    # 1.x defect fixed with this port: the d_tag fallback was a
    # TIMESTAMP (f"vpn-{time():.0f}") — contradicting the ParamDef
    # default `vpn-node` and making direct-call output
    # non-deterministic (golden regeneration differs every run).
    # _resolve_params applies the declared default.
    r = _resolve_params(params)
    nsec = r["nsec"]
    d_tag = r["d_tag"]
    title = r["title"]
    endpoint_host = r["endpoint_host"]
    endpoint_port = str(r["endpoint_port"])
    region_country = r["country"]
    price_amount = str(r["price_amount"])
    price_unit = r["price_unit"]
    relays = r["relays"]
    content = r["content"]
    nak_bin = r["nak_bin"]

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
