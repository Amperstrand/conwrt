#!/usr/bin/env python3
"""nordvpn.py — select NordVPN WireGuard servers and render client configs.

Host-side companion to the vpn-nordvpn use case: list servers per country
with load and WireGuard public keys, or render a ready-to-use WireGuard
.conf from an access token.

Examples:
    nordvpn.py servers --country DE --limit 10
    nordvpn.py servers --country DE --json | jq '.[0].hostname'
    nordvpn.py config --token TOKEN --country DE --out nordvpn.conf
    nordvpn.py config --token TOKEN --server de1507.nordvpn.com --out de1507.conf

stdlib only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from use_cases.vpn_providers.nordvpn import (  # noqa: E402
    _fetch_credentials,
    _is_ip,
    _resolve_endpoint,
    _server_public_key,
)

import base64  # noqa: E402
import urllib.request  # noqa: E402

COUNTRY_ALIASES = {"germany": "DE", "de": "DE"}


def _get_json(url: str, token: str = "") -> object:
    req = urllib.request.Request(url, headers={"User-Agent": "conwrt-nordvpn/1.0"})
    if token:
        req.add_header(
            "Authorization",
            "Basic " + base64.b64encode(f"token:{token}".encode()).decode(),
        )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())


def _country_id(country: str) -> str:
    c = COUNTRY_ALIASES.get(country.strip().lower(), country.strip().lower()).lower()
    if c.isdigit():
        return c
    countries = _get_json("https://api.nordvpn.com/v1/servers/countries")
    for entry in countries:
        if entry.get("code", "").lower() == c or entry.get("name", "").lower() == c:
            return str(entry["id"])
    raise ValueError(f"unknown NordVPN country: {country}")


def _servers(country: str, limit: int, token: str = "") -> list[dict]:
    url = (
        "https://api.nordvpn.com/v1/servers/recommendations"
        f"?limit={limit}&filters%5Bservers_technologies%5D%5Bidentifier%5D=wireguard_udp"
    )
    if country:
        url += f"&filters%5Bcountry_id%5D={_country_id(country)}"
    return _get_json(url, token)


def _wg_key(server: dict) -> str:
    key = _server_public_key(server)
    if not key:
        key = "<no wireguard_udp key>"
    return key


def cmd_servers(args: argparse.Namespace) -> int:
    country = args.country or ""
    try:
        servers = _servers(country, args.limit, args.token)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if args.json:
        out = [
            {
                "hostname": s.get("hostname", ""),
                "station": s.get("station", ""),
                "load": s.get("load"),
                "country": (s.get("locations") or [{}])[0].get("country", {}).get("code", ""),
                "wg_public_key": _wg_key(s),
            }
            for s in servers
        ]
        print(json.dumps(out, indent=2))
        return 0

    if not servers:
        print(f"No wireguard_udp servers found for country '{country or 'any'}'.")
        return 1
    print(f"{'HOSTNAME':<28} {'STATION':<17} {'LOAD':>4}  CC")
    print("-" * 60)
    for s in servers:
        cc = (s.get("locations") or [{}])[0].get("country", {}).get("code", "")
        print(f"{s.get('hostname', '?'):<28} {s.get('station', '?'):<17} {s.get('load', '?'):>3}%  {cc}")
    print()
    print("Pin one via config.toml:  [use_cases.vpn-nordvpn]  server = \"de1507.nordvpn.com\"")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    basic = base64.b64encode(f"token:{args.token}".encode()).decode()
    priv_key = _fetch_credentials(basic)["nordlynx_private_key"]
    endpoint_ip, port, peer_key = _resolve_endpoint(args.server or "DE", args.token)
    host = endpoint_ip if _is_ip(endpoint_ip) else endpoint_ip
    conf = (
        "[Interface]\n"
        f"PrivateKey = {priv_key}\n"
        "Address = 10.5.0.2/32\n"
        "DNS = 103.86.96.100\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {peer_key}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        f"Endpoint = {host}:{port}\n"
        "PersistentKeepalive = 25\n"
    )
    if args.out:
        Path(args.out).write_text(conf)
        print(f"wrote {args.out} (endpoint {host}:{port})")
    else:
        print(conf, end="")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_servers = sub.add_parser("servers", help="List NordVPN wireguard_udp servers")
    p_servers.add_argument("--country", default="", help="Country code or name (e.g. DE, germany). Empty = worldwide")
    p_servers.add_argument("--limit", type=int, default=10, help="Max servers to list (default 10)")
    p_servers.add_argument("--token", default="", help="Access token (improves result freshness; not required)")
    p_servers.add_argument("--json", action="store_true", help="Machine-readable output")

    p_conf = sub.add_parser("config", help="Render a WireGuard .conf from an access token")
    p_conf.add_argument("--token", required=True, help="NordVPN access token (Nord Account dashboard)")
    p_conf.add_argument("--server", default="DE", help="Country code/id, hostname, or IP (default: DE)")
    p_conf.add_argument("--country", default="", help="Alias for --server (accepted for discoverability)")
    p_conf.add_argument("--out", default="", help="Write to file instead of stdout")

    args = parser.parse_args()
    if getattr(args, "country", ""):
        args.server = args.country
    try:
        if args.command == "servers":
            return cmd_servers(args)
        return cmd_config(args)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
