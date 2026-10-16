"""vpn-nordvpn — NordVPN WireGuard VPN (NordLynx).

Two configuration modes:

1. ``config_file`` — path to a host-side WireGuard .conf (e.g. exported from
   the NordVPN dashboard). Resolved at BUILD time on the host and rendered as
   a fully static first-boot script: no API calls, no jq, no curl on the
   device. The most robust mode for ASU-baked images.

2. ``access_token`` — a NordVPN access token (Nord Account dashboard →
   NordVPN → Manual setup). The device fetches its NordLynx private key via
   ``GET /v1/users/services/credentials`` (HTTP Basic ``token:<access_token>``)
   and picks a server via ``/v1/servers/recommendations``. Tunnel address is
   static 10.5.0.2/32 for all accounts.

The legacy service-username/password token exchange (POST /v2/users/tokens)
was removed by NordVPN in April 2023 and is not supported.

Sources: NordSecurity/nordvpn-linux core/urls.go; live API verification
2026-10-08 (DE country_id=81, filters[servers_technologies][identifier]=
wireguard_udp, per-server WG public key in technologies metadata).
"""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from profile.ops import BlankLine, Comment, Op, ShellCommand

from .. import ParamDef, UseCase, register
from .base import (
    JSON_HELPER_SH,
    build_dns_ops,
    build_firewall_ops,
    build_verify_ops,
    wg0_uci_sh,
    wg_cleanup_sh,
    transport_sh,
)

NORDVPN_DNS = ["103.86.96.100", "103.86.99.100"]

# NordVPN technology ids (api.nordvpn.com/v1/technologies, live 2026-10-08)
NORDVPN_TECH_IDS = {
    "nordlynx": "wireguard_udp",
    "openvpn-udp": "openvpn_udp",
    "openvpn-tcp": "openvpn_tcp",
    "openvpn-udp-tls-crypt": "openvpn_udp_tls_crypt",
    "openvpn-tcp-tls-crypt": "openvpn_tcp_tls_crypt",
    "ikev2": "ikev2",
}

# Public, NordVPN-wide constants identical across every server .ovpn
# (downloads.nordcdn.com config archive, verified across servers 2026-10-08).
NORDVPN_OPENVPN_PORTS = "1231 1232 1233 1234"


NORDVPN_CA = """\
-----BEGIN CERTIFICATE-----
MIIFCjCCAvKgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA5MQswCQYDVQQGEwJQQTEQ
MA4GA1UEChMHTm9yZFZQTjEYMBYGA1UEAxMPTm9yZFZQTiBSb290IENBMB4XDTE2
MDEwMTAwMDAwMFoXDTM1MTIzMTIzNTk1OVowOTELMAkGA1UEBhMCUEExEDAOBgNV
BAoTB05vcmRWUE4xGDAWBgNVBAMTD05vcmRWUE4gUm9vdCBDQTCCAiIwDQYJKoZI
hvcNAQEBBQADggIPADCCAgoCggIBAMkr/BYhyo0F2upsIMXwC6QvkZps3NN2/eQF
kfQIS1gql0aejsKsEnmY0Kaon8uZCTXPsRH1gQNgg5D2gixdd1mJUvV3dE3y9FJr
XMoDkXdCGBodvKJyU6lcfEVF6/UxHcbBguZK9UtRHS9eJYm3rpL/5huQMCppX7kU
eQ8dpCwd3iKITqwd1ZudDqsWaU0vqzC2H55IyaZ/5/TnCk31Q1UP6BksbbuRcwOV
skEDsm6YoWDnn/IIzGOYnFJRzQH5jTz3j1QBvRIuQuBuvUkfhx1FEwhwZigrcxXu
MP+QgM54kezgziJUaZcOM2zF3lvrwMvXDMfNeIoJABv9ljw969xQ8czQCU5lMVmA
37ltv5Ec9U5hZuwk/9QO1Z+d/r6Jx0mlurS8gnCAKJgwa3kyZw6e4FZ8mYL4vpRR
hPdvRTWCMJkeB4yBHyhxUmTRgJHm6YR3D6hcFAc9cQcTEl/I60tMdz33G6m0O42s
Qt/+AR3YCY/RusWVBJB/qNS94EtNtj8iaebCQW1jHAhvGmFILVR9lzD0EzWKHkvy
WEjmUVRgCDd6Ne3eFRNS73gdv/C3l5boYySeu4exkEYVxVRn8DhCxs0MnkMHWFK6
MyzXCCn+JnWFDYPfDKHvpff/kLDobtPBf+Lbch5wQy9quY27xaj0XwLyjOltpiST
LWae/Q4vAgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqG
SIb3DQEBDQUAA4ICAQC9fUL2sZPxIN2mD32VeNySTgZlCEdVmlq471o/bDMP4B8g
nQesFRtXY2ZCjs50Jm73B2LViL9qlREmI6vE5IC8IsRBJSV4ce1WYxyXro5rmVg/
k6a10rlsbK/eg//GHoJxDdXDOokLUSnxt7gk3QKpX6eCdh67p0PuWm/7WUJQxH2S
DxsT9vB/iZriTIEe/ILoOQF0Aqp7AgNCcLcLAmbxXQkXYCCSB35Vp06u+eTWjG0/
pyS5V14stGtw+fA0DJp5ZJV4eqJ5LqxMlYvEZ/qKTEdoCeaXv2QEmN6dVqjDoTAo
k0t5u4YRXzEVCfXAC3ocplNdtCA72wjFJcSbfif4BSC8bDACTXtnPC7nD0VndZLp
+RiNLeiENhk0oTC+UVdSc+n2nJOzkCK0vYu0Ads4JGIB7g8IB3z2t9ICmsWrgnhd
NdcOe15BincrGA8avQ1cWXsfIKEjbrnEuEk9b5jel6NfHtPKoHc9mDpRdNPISeVa
wDBM1mJChneHt59Nh8Gah74+TM1jBsw4fhJPvoc7Atcg740JErb904mZfkIEmojC
VPhBHVQ9LHBAdM8qFI2kRK0IynOmAZhexlP/aT/kpEsEPyaZQlnBn3An1CRz8h0S
PApL8PytggYKeQmRhl499+6jLxcZ2IegLfqq41dzIjwHwTMplg+1pKIOVojpWA==
-----END CERTIFICATE-----
"""

NORDVPN_TLS_AUTH = """\
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
e685bdaf659a25a200e2b9e39e51ff03
0fc72cf1ce07232bd8b2be5e6c670143
f51e937e670eee09d4f2ea5a6e4e6996
5db852c275351b86fc4ca892d78ae002
d6f70d029bd79c4d1c26cf14e9588033
cf639f8a74809f29f72b9d58f9b8f5fe
fc7938eade40e9fed6cb92184abb2cc1
0eb1a296df243b251df0643d53724cdb
5a92a1d6cb817804c4a9319b57d53be5
80815bcfcb2df55018cc83fc43bc7ff8
2d51f9b88364776ee9d12fc85cc7ea5b
9741c4f598c485316db066d52db4540e
212e1518a9bd4828219e24b20d88f598
a196c9de96012090e333519ae18d3509
9427e7b372d348d352dc4c85e18cd4b9
3f8a56ddb2e64eb67adfc9b337157ff4
-----END OpenVPN Static key V1-----
"""


# Shell: discover the upstream gateway at runtime (WiFi STA leases arrive
# after boot starts, so it cannot be baked at build time).
_GATEWAY_DISCOVER_SH = """
VPN_GW=""
_i=0
# netifd's wireguard proto normally installs the endpoint /32 route itself on
# ifup; this is a fallback for paths where it does not. Capped short because
# uci-defaults block the boot sequence (dropbear starts only after).
while [ $_i -lt 20 ]; do
    VPN_GW=$(ip -4 route show default dev {iface} 2>/dev/null | head -n1 | sed -n 's/.*via \\([0-9.]\\+\\).*/\\1/p')
    [ -z "$VPN_GW" ] && VPN_GW=$(ip -4 route show default 2>/dev/null | head -n1 | sed -n 's/.*via \\([0-9.]\\+\\).*/\\1/p')
    [ -n "$VPN_GW" ] && break
    sleep 2; _i=$((_i+2))
done
if [ -n "$VPN_GW" ]; then
    uci -q delete network.nordvpn_server_route
    uci set network.nordvpn_server_route=route
    uci set network.nordvpn_server_route.interface='{iface}'
    uci set network.nordvpn_server_route.target='{route_ip}'
    uci set network.nordvpn_server_route.netmask='255.255.255.255'
    uci set network.nordvpn_server_route.gateway="$VPN_GW"
    uci commit network
    /etc/init.d/network reload >/dev/null 2>&1 || true
    echo "VPN: endpoint route {route_ip}/32 via $VPN_GW on {iface}"
else
    echo "VPN: WARNING no upstream gateway found — endpoint route skipped"
fi
"""


def _parse_wg_conf(text: str) -> dict[str, str]:
    """Parse the [Interface]/[Peer] keys of a WireGuard .conf into a flat dict."""
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in ("PrivateKey", "Address", "DNS", "PublicKey",
                   "AllowedIPs", "Endpoint", "PersistentKeepalive", "MTU"):
            values[key] = value.strip()
    for required in ("PrivateKey", "Address", "PublicKey", "Endpoint"):
        if not values.get(required):
            raise ValueError(f"config_file missing required WireGuard key: {required}")
    return values


def _split_endpoint(endpoint: str) -> tuple[str, str]:
    if endpoint.startswith("["):  # [IPv6]:port
        host, _, port = endpoint.rpartition("]:")
        return host.lstrip("["), port or "51820"
    if ":" in endpoint:
        host, _, port = endpoint.rpartition(":")
        return host, port or "51820"
    return endpoint, "51820"


def _country_id_from_list(countries: list[dict[str, Any]], code: str) -> str:
    """Resolve a 2-letter code or country name to a NordVPN country id.

    ``countries`` is the /v1/servers/countries payload. Returns "" when the
    country is unknown (the recommendations query then runs unfiltered).
    """
    needle = code.strip().lower()
    for entry in countries:
        if entry.get("code", "").lower() == needle or entry.get("name", "").lower() == needle:
            return str(entry["id"])
    return ""


def _select_server(
    servers: list[Any], *, station: str = "", hostname: str = "",
) -> dict[str, Any] | None:
    """Pick the pinned server out of an API response, client-side.

    NordVPN's /v1/servers ignores unknown filters (e.g. stations[ip]) and
    returns an arbitrary 100-server page — the pin must never trust
    server-side filtering.
    """
    for server in servers:
        if station and server.get("station") == station:
            return server
        if hostname and server.get("hostname") == hostname:
            return server
    return None


def _resolve_endpoint(value: str, token: str, tech: str = "wireguard_udp") -> tuple[str, str, str]:
    """Return (endpoint_ip_or_host, port, server_public_key) for a target.

    ``value`` is a hostname, a "Country" name, or a country code. Hostnames
    are resolved via the servers API to a full server object (the WireGuard
    public key lives in its technologies metadata); anything else goes
    through the recommendations API with a country filter. A bare IP is
    refused: the API no longer supports station-IP lookup, and guessing
    would configure a random server.
    """
    basic = base64.b64encode(f"token:{token}".encode()).decode()
    parts = value.rsplit(":", 1)
    looks_like_host = len(parts) == 2 and parts[1].isdigit()
    host_value = parts[0] if looks_like_host else value

    if _is_ip(host_value):
        raise ValueError(
            f"cannot resolve pinned NordVPN server IP {host_value}: the API no "
            f"longer supports station-IP lookup — pin by hostname (e.g. "
            f"de1507.nordvpn.com) or country instead"
        )
    if host_value.endswith(".nordvpn.com"):
        server_list = _api_get(
            "https://api.nordvpn.com/v1/servers"
            f"?filters%5Bhostname%5D={host_value.split('.')[0]}", basic,
        )
        server = _select_server(server_list, hostname=host_value)
        if server is None:
            raise ValueError(
                f"could not verify hostname pin {host_value}: NordVPN's servers "
                f"API currently ignores filters (returns an arbitrary page) — "
                f"pin by country ('DE', 'germany', or a country id) instead"
            )
        key = _server_public_key(server)
        if tech == "wireguard_udp" and not key:
            raise ValueError(f"server {server.get('hostname', host_value)} has no "
                             f"wireguard_udp public key")
        ip, port = _split_endpoint(value if looks_like_host else f"{host_value}:51820")
        return server.get("station", "") or host_value, port, key

    code = host_value.strip().lower()
    country_id = code if code.isdigit() else _country_id_from_list(
        _api_get("https://api.nordvpn.com/v1/servers/countries", basic), code,
    )
    server = _recommend_server(country_id, tech, basic)
    key = ""
    if tech == "wireguard_udp":
        key = _server_public_key(server)
        if not key:
            raise ValueError(f"server {server.get('hostname')} has no wireguard_udp public key")
    default_port = {"wireguard_udp": "51820"}.get(tech, "1231")
    return server["station"], default_port, key


def _api_get(url: str, basic: str) -> Any:
    import json as _json
    import urllib.request

    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Basic {basic}")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return _json.loads(resp.read().decode())


def _recommend_server(country_id: str, tech: str, basic: str) -> dict[str, Any]:
    """Full server object from the (country-filtered) recommendations API."""
    url = (
        "https://api.nordvpn.com/v1/servers/recommendations?limit=1"
        f"&filters%5Bservers_technologies%5D%5Bidentifier%5D={tech}"
    )
    if country_id:
        url += f"&filters%5Bcountry_id%5D={country_id}"
    servers = _api_get(url, basic)
    if not servers:
        raise ValueError(f"no NordVPN {tech} server found for the requested country")
    return servers[0]


def _resolve_server(value: str, token: str, tech: str) -> dict[str, Any]:
    """Full server object (hostname + station) for a hostname/country pick.

    The OpenVPN flavor pins verify-x509-name to the hostname, so hostname and
    station must come from the same server object. A bare IP is refused (see
    _resolve_endpoint).
    """
    basic = base64.b64encode(f"token:{token}".encode()).decode()
    host = value.rsplit(":", 1)[0] if value.count(":") == 1 and value.rsplit(":", 1)[1].isdigit() else value

    if _is_ip(host):
        raise ValueError(
            f"cannot resolve pinned NordVPN server IP {host}: the API no "
            f"longer supports station-IP lookup — pin by hostname (e.g. "
            f"de1507.nordvpn.com) or country instead"
        )
    if host.endswith(".nordvpn.com"):
        server_list = _api_get(
            "https://api.nordvpn.com/v1/servers"
            f"?filters%5Bhostname%5D={host.split('.')[0]}", basic,
        )
        server = _select_server(server_list, hostname=host)
        if server is None:
            raise ValueError(
                f"could not verify hostname pin {host}: NordVPN's servers API "
                f"currently ignores filters — pin by country instead"
            )
        return server

    code = host.strip().lower()
    country_id = code if code.isdigit() else _country_id_from_list(
        _api_get("https://api.nordvpn.com/v1/servers/countries", basic), code,
    )
    return _recommend_server(country_id, tech, basic)


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _server_public_key(server: dict[str, Any]) -> str:
    for tech in server.get("technologies", []):
        if tech.get("identifier") != "wireguard_udp":
            continue
        for meta in tech.get("metadata", []):
            if meta.get("name") == "public_key":
                return meta.get("value", "")
    return ""


def _route_target(host: str, token: str) -> str:
    """Resolve an endpoint host to an IP for the static /32 route.

    uci route targets must be IPs; wg endpoint_host may stay a hostname.
    Falls back to the raw host (route add becomes a no-op) on failure.
    """
    if _is_ip(host):
        return host
    try:
        import socket
        return socket.gethostbyname(host)
    except OSError:
        if token:
            try:
                station, _, _ = _resolve_endpoint(host, token)
                if _is_ip(station):
                    return station
            except ValueError:
                pass
    return host


def _build_nordvpn_ops(params: dict[str, Any]) -> list[Op]:
    access_token = params.get("access_token", "")
    config_file = params.get("config_file", "")
    gateway = params.get("upstream_gateway", "")
    upstream_iface = params.get("upstream_iface", "wwan")
    kill_switch = params.get("kill_switch", True)
    server = params.get("server") or "DE"
    mtu = params.get("mtu", "1420")
    ap_ssid = params.get("ap_ssid", "")
    ap_key = params.get("ap_key", "")
    allow_management = params.get("allow_management", True)
    technology = params.get("technology") or "nordlynx"

    if technology.startswith("openvpn"):
        if not access_token:
            return [Comment(
                text="vpn-nordvpn: openvpn technologies require access_token "
                     "(service credentials are fetched from it at build time)",
            )]
        return _build_nordvpn_openvpn_ops(params)

    if config_file:
        conf_path = Path(config_file).expanduser()
        if not conf_path.is_file():
            raise ValueError(f"config_file not found: {config_file}")
        conf = _parse_wg_conf(conf_path.read_text())
        endpoint_ip, endpoint_port = _split_endpoint(conf["Endpoint"])
        priv_key = conf["PrivateKey"]
        peer_key = conf["PublicKey"]
        address = conf["Address"]
        allowed_ips = conf.get("AllowedIPs", "0.0.0.0/0")
        keepalive = conf.get("PersistentKeepalive", "25")
        mtu = conf.get("MTU", mtu)
        route_ip = _route_target(endpoint_ip, "")
        mode_desc = f"static config from {conf_path.name} (endpoint {endpoint_ip}:{endpoint_port})"
    elif access_token:
        # Token mode resolves EVERYTHING at build time on the host: the
        # NordLynx key from the credentials endpoint and the server from the
        # recommendations API. The device gets a fully static config — no
        # curl, no jq, no API dependency at first boot.
        basic = base64.b64encode(f"token:{access_token}".encode()).decode()
        creds = _fetch_credentials(basic)
        priv_key = creds["nordlynx_private_key"]
        endpoint_ip, endpoint_port, peer_key = _resolve_endpoint(server, access_token)
        route_ip = endpoint_ip if _is_ip(endpoint_ip) else _route_target(endpoint_ip, access_token)
        address = "10.5.0.2/32"
        allowed_ips = "0.0.0.0/0"
        keepalive = "25"
        mode_desc = f"access token, server '{server}' (endpoint {endpoint_ip}:{endpoint_port})"
    else:
        return [Comment(
            text="vpn-nordvpn: NOT CONFIGURED — set [use_cases.vpn-nordvpn] "
                 "config_file (path to a WireGuard .conf) or access_token in config.toml",
        )]

    if gateway:
        route_block = (
            "uci set network.nordvpn_server_route=route\n"
            f"uci set network.nordvpn_server_route.interface='{upstream_iface}'\n"
            f"uci set network.nordvpn_server_route.target='{route_ip}'\n"
            "uci set network.nordvpn_server_route.netmask='255.255.255.255'\n"
            f"uci set network.nordvpn_server_route.gateway='{gateway}'\n"
        )
    else:
        route_block = _GATEWAY_DISCOVER_SH.format(iface=upstream_iface, route_ip=route_ip)

    address_lit = "'" + address + "'"
    port_lit = "'" + endpoint_port + "'"
    nordvpn_script = f"""{JSON_HELPER_SH}
WG_PRIV="{priv_key}"
SERVER_KEY="{peer_key}"
SERVER_IP="{endpoint_ip}"

{wg_cleanup_sh()}

uci -q delete openvpn.nordvpn
/etc/init.d/openvpn stop >/dev/null 2>&1 || true

# WireGuard tunnel (NordLynx)
{wg0_uci_sh('"$WG_PRIV"', address_lit, '"$SERVER_KEY"', '"$SERVER_IP"', port_lit, mtu=mtu, keepalive=keepalive, listen_port=False)}

uci -q delete network.nordvpn_server_route
{route_block}
"""

    ops: list[Op] = [
        Comment(text=f"--- NordVPN NordLynx WireGuard VPN ({mode_desc}) ---"),
        ShellCommand(command=transport_sh(nordvpn_script)),
    ]
    ops.extend(build_firewall_ops(kill_switch=kill_switch, allow_management=allow_management))
    ops.extend(build_dns_ops(NORDVPN_DNS))
    if ap_ssid:
        ops.extend(_build_vpn_ap_ops(ap_ssid, ap_key))
    ops.extend(build_verify_ops(kill_switch=kill_switch))
    return ops


# Client subnet for the 2.4GHz VPN-exit AP. Distinct from mgmt (172.16.0.0/24)
# and the model lan_subnet; the AP network joins the vpn firewall zone.
VPN_AP_SUBNET_IP = "172.16.31.1"
VPN_AP_SUBNET_MASK = "255.255.255.0"


def _sq(value: str) -> str:
    """Single-quote a value for safe embedding in a uci shell command."""
    return "'" + value.replace("'", "'\\''") + "'"


def _build_vpn_ap_ops(ap_ssid: str, ap_key: str) -> list[Op]:
    """2.4GHz AP whose WiFi clients exit through the VPN tunnel.

    Hardware-verified design (2026-10-08, x1860 + Android client):
    - A dedicated bridge device (br-vpnlan) — a standalone unbridged AP
      iface never delivered DHCP to clients; the bridge is the pattern that
      works (same as br-mgmt).
    - A dedicated `vpnap` firewall zone with vpnap→vpn forwarding. Putting
      vpnlan in the vpn zone breaks clients twice: the zone input policy
      drops DHCP/DNS, and its forward policy drops vpnlan→wg0 traffic.
    - Input rules for DHCP (67-68), DNS (53, subnet-scoped so the router is
      not an open resolver at the VPN exit IP), and management (22/80/443).
    - txpower is radio-wide: raise it to the DE legal max (20 dBm) — a
      low-power mgmt AP on the same radio otherwise throttles this AP into
      unusable range.
    - dnsmasq only registers dhcp ranges for interfaces that are up when it
      (re)starts, so wait for vpnlan ifup and restart dnsmasq once more.
    """
    ap_script = f"""# --- VPN-exit AP ({_sq(ap_ssid)} on 2.4GHz) ---
VPN_AP_RADIO=""
for radio in $(uci show wireless 2>/dev/null | grep "=wifi-device" | cut -d. -f2 | cut -d= -f1); do
    band=$(uci -q get wireless.$radio.band || true)
    hwmode=$(uci -q get wireless.$radio.hwmode || true)
    case "$band" in
        2g|2.4g|2ghz|2.4ghz) VPN_AP_RADIO="$radio"; break ;;
    esac
    case "$hwmode" in
        11g|11ng|11axg|11bg|11b) VPN_AP_RADIO="$radio"; break ;;
    esac
done
if [ -z "$VPN_AP_RADIO" ]; then
    echo "VPN AP: no 2.4GHz radio found — AP skipped"
else
    uci set network.vpnlan_dev=device
    uci set network.vpnlan_dev.type='bridge'
    uci set network.vpnlan_dev.name='br-vpnlan'

    uci set network.vpnlan=interface
    uci set network.vpnlan.device='br-vpnlan'
    uci set network.vpnlan.proto='static'
    uci set network.vpnlan.ipaddr='{VPN_AP_SUBNET_IP}'
    uci set network.vpnlan.netmask='{VPN_AP_SUBNET_MASK}'

    uci set dhcp.vpnlan=dhcp
    uci set dhcp.vpnlan.interface='vpnlan'
    uci set dhcp.vpnlan.start='100'
    uci set dhcp.vpnlan.limit='150'
    uci set dhcp.vpnlan.leasetime='12h'

    uci set wireless.wifinet_vpn_ap=wifi-iface
    uci set wireless.wifinet_vpn_ap.device="$VPN_AP_RADIO"
    uci set wireless.wifinet_vpn_ap.mode='ap'
    uci set wireless.wifinet_vpn_ap.ssid={_sq(ap_ssid)}
    uci set wireless.wifinet_vpn_ap.encryption='psk2'
    uci set wireless.wifinet_vpn_ap.key={_sq(ap_key)}
    uci set wireless.wifinet_vpn_ap.network='vpnlan'

    uci set wireless.$VPN_AP_RADIO.txpower='20'
    uci set wireless.$VPN_AP_RADIO.country='DE'

    uci set firewall.vpn_ap_zone=zone
    uci set firewall.vpn_ap_zone.name='vpnap'
    uci set firewall.vpn_ap_zone.input='REJECT'
    uci set firewall.vpn_ap_zone.output='ACCEPT'
    uci set firewall.vpn_ap_zone.forward='REJECT'
    uci add_list firewall.vpn_ap_zone.network='vpnlan'

    uci set firewall.vpn_ap_fwd=forwarding
    uci set firewall.vpn_ap_fwd.src='vpnap'
    uci set firewall.vpn_ap_fwd.dest='vpn'

    uci set firewall.vpn_ap_dhcp=rule
    uci set firewall.vpn_ap_dhcp.name='Allow-VPNAP-DHCP'
    uci set firewall.vpn_ap_dhcp.src='vpnap'
    uci set firewall.vpn_ap_dhcp.proto='udp'
    uci set firewall.vpn_ap_dhcp.dest_port='67 68'
    uci set firewall.vpn_ap_dhcp.target='ACCEPT'

    uci set firewall.vpn_ap_dns=rule
    uci set firewall.vpn_ap_dns.name='Allow-VPNAP-DNS'
    uci set firewall.vpn_ap_dns.src='vpnap'
    uci del_list firewall.vpn_ap_dns.src_ip='172.16.31.0/24' 2>/dev/null
    uci add_list firewall.vpn_ap_dns.src_ip='172.16.31.0/24'
    uci set firewall.vpn_ap_dns.proto='tcp udp'
    uci set firewall.vpn_ap_dns.dest_port='53'
    uci set firewall.vpn_ap_dns.target='ACCEPT'

    uci set firewall.vpn_ap_mgmt=rule
    uci set firewall.vpn_ap_mgmt.name='Allow-VPNAP-Management'
    uci set firewall.vpn_ap_mgmt.src='vpnap'
    uci set firewall.vpn_ap_mgmt.proto='tcp'
    uci set firewall.vpn_ap_mgmt.dest_port='22 80 443'
    uci set firewall.vpn_ap_mgmt.target='ACCEPT'

    uci -q del_list firewall.vpn_zone.network='vpnlan'

    uci commit network
    uci commit wireless
    uci commit dhcp
    uci commit firewall
    /etc/init.d/network reload >/dev/null 2>&1 || true
    wifi >/dev/null 2>&1 || true

    # dnsmasq only registers dhcp-ranges for interfaces that are up at
    # (re)start. Run re-arm in the background: uci-defaults block the boot
    # sequence, and dropbear only starts after they finish.
    ( _i=0
      while [ $_i -lt 60 ]; do
          ip -4 addr show dev br-vpnlan 2>/dev/null | grep -q "{VPN_AP_SUBNET_IP}" && break
          sleep 2; _i=$((_i+2))
      done
      /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
    ) &
    echo "VPN AP: {ap_ssid} up on $VPN_AP_RADIO (br-vpnlan {VPN_AP_SUBNET_IP}, DHCP 172.16.31.100+)"
fi
"""
    return [
        BlankLine(),
        Comment(text="--- 2.4GHz VPN-exit AP ---"),
        ShellCommand(command=transport_sh(ap_script, "/tmp/vpn_ap_setup.sh")),
    ]


def _build_nordvpn_openvpn_ops(params: dict[str, Any]) -> list[Op]:
    """NordVPN via OpenVPN (tun0) — service-credential auth, template-faithful.

    Configuration mirrors the official per-server .ovpn templates
    (downloads.nordcdn.com config archive): multi-port remotes (1231-1234),
    tls-auth with the NordVPN-wide static key, verify-x509-name CN pinning,
    AES-256-CBC + SHA512 (GCM negotiable via openvpn_cipher). Credentials and
    server are resolved at BUILD time from the access token — the device gets
    static files, no API dependency.
    """
    access_token = params["access_token"]
    server = params.get("server") or "DE"
    technology = params.get("technology") or "openvpn-udp"
    kill_switch = params.get("kill_switch", True)
    allow_management = params.get("allow_management", True)
    ap_ssid = params.get("ap_ssid", "")
    ap_key = params.get("ap_key", "")
    cipher = params.get("openvpn_cipher", "AES-256-CBC")

    proto = "tcp" if technology.endswith("tcp") else "udp"
    tech_id = NORDVPN_TECH_IDS[technology]

    basic = base64.b64encode(f"token:{access_token}".encode()).decode()
    creds = _fetch_credentials(basic)
    srv = _resolve_server(server, access_token, tech_id)
    endpoint_ip = srv["station"]
    # The x509 CN pins the hostname; station and hostname must come from the
    # same server object or the TLS handshake rejects the peer.
    hostname = srv["hostname"]

    remotes = "\n".join(
        f"uci add_list openvpn.nordvpn.remote='{endpoint_ip} {port}'"
        for port in NORDVPN_OPENVPN_PORTS.split()
    )

    openvpn_script = f"""{wg_cleanup_sh()}

# Tear down any previous OpenVPN instance
uci -q delete openvpn.nordvpn

mkdir -p /etc/openvpn
cat > /etc/openvpn/nordvpn.ca << 'NORD_CA_EOF'
{NORDVPN_CA}
NORD_CA_EOF
cat > /etc/openvpn/nordvpn.ta << 'NORD_TA_EOF'
{NORDVPN_TLS_AUTH}
NORD_TA_EOF
cat > /etc/openvpn/nordvpn.auth << 'NORD_AUTH_EOF'
{creds["username"]}
{creds["password"]}
NORD_AUTH_EOF
chmod 600 /etc/openvpn/nordvpn.auth

uci -q delete openvpn.nordvpn
uci set openvpn.nordvpn=openvpn
uci set openvpn.nordvpn.enabled='1'
uci set openvpn.nordvpn.client='1'
uci set openvpn.nordvpn.dev='tun'
uci set openvpn.nordvpn.proto='{proto}'
{remotes}
uci set openvpn.nordvpn.resolv_retry='infinite'
uci set openvpn.nordvpn.nobind='1'
uci set openvpn.nordvpn.persist_key='1'
uci set openvpn.nordvpn.persist_tun='1'
uci set openvpn.nordvpn.ca='/etc/openvpn/nordvpn.ca'
uci set openvpn.nordvpn.auth_user_pass='/etc/openvpn/nordvpn.auth'
uci set openvpn.nordvpn.tls_auth='/etc/openvpn/nordvpn.ta'
uci set openvpn.nordvpn.key_direction='1'
uci set openvpn.nordvpn.verify_x509_name='{hostname} name'
uci set openvpn.nordvpn.remote_cert_tls='server'
uci set openvpn.nordvpn.cipher='{cipher}'
uci set openvpn.nordvpn.data_ciphers='AES-256-GCM:AES-256-CBC'
uci set openvpn.nordvpn.auth='SHA512'
uci set openvpn.nordvpn.comp_lzo='no'
uci set openvpn.nordvpn.mssfix='1450'
uci set openvpn.nordvpn.ping='15'
uci set openvpn.nordvpn.ping_restart='0'
uci set openvpn.nordvpn.verb='3'
uci set openvpn.nordvpn.pull='1'
uci commit openvpn

# Bring tun0 up and attach the vpn zone to it
uci -q del_list firewall.vpn_zone.network='wg0'
uci -q add_list firewall.vpn_zone.network='tun0'
/etc/init.d/openvpn restart || /etc/init.d/openvpn start
"""

    ops: list[Op] = [
        Comment(text=f"--- NordVPN OpenVPN ({technology}, {proto}, endpoint {endpoint_ip}, cipher {cipher}) ---"),
        ShellCommand(command=transport_sh(openvpn_script, "/tmp/nordvpn_openvpn_setup.sh")),
    ]
    ops.extend(build_firewall_ops(iface="tun0", kill_switch=kill_switch,
                                  allow_management=allow_management))
    ops.extend(build_dns_ops(NORDVPN_DNS))
    if ap_ssid:
        ops.extend(_build_vpn_ap_ops(ap_ssid, ap_key))
    ops.extend(build_verify_ops(iface="tun0", kill_switch=kill_switch, kind="openvpn"))
    return ops


def _fetch_credentials(basic: str) -> dict[str, str]:
    """Exchange an access token for service credentials.

    Returns nordlynx_private_key (WireGuard) and username/password (OpenVPN
    and IKEv2) — one token covers every NordVPN technology.
    """
    import json as _json
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        "https://api.nordvpn.com/v1/users/services/credentials",
    )
    req.add_header("Authorization", f"Basic {basic}")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = _json.loads(resp.read().decode())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ValueError(f"NordVPN credentials fetch failed: {exc}") from exc
    if not isinstance(data, dict) or not data.get("nordlynx_private_key"):
        raise ValueError("NordVPN credentials response missing nordlynx_private_key "
                         "(check that the access token is valid)")
    return data


register(UseCase(
    name="vpn-nordvpn",
    description="NordVPN WireGuard VPN (NordLynx) — access token or static config, optional VPN-exit AP",
    packages=["wireguard-tools", "luci-proto-wireguard"],
    packages_remove=[],
    params={
        "access_token": ParamDef(type=str, required=False, allow_empty=True,
                                 description="NordVPN access token (Nord Account dashboard). Preferred mode: key + server are resolved at build time"),
        "config_file": ParamDef(type=str, required=False, allow_empty=True,
                                description="Path to a WireGuard .conf — overrides access_token if set"),
        "server": ParamDef(type=str, default="DE",
                           description="Country selection: 'DE', 'germany', or a NordVPN country id (hostname/IP pins are refused — the API currently ignores server filters)"),
        "technology": ParamDef(type=str, default="nordlynx",
                               description="NordVPN technology: nordlynx (WireGuard, default), openvpn-udp, openvpn-tcp"),
        "openvpn_cipher": ParamDef(type=str, default="AES-256-CBC",
                                   description="OpenVPN cipher override (e.g. AES-256-GCM); data-ciphers always allows both"),
        "ap_ssid": ParamDef(type=str, required=False, allow_empty=True,
                            description="2.4GHz AP SSID whose clients exit via the VPN (empty = disabled)"),
        "ap_key": ParamDef(type=str, required=False, allow_empty=True,
                           description="WiFi password for the VPN-exit AP"),
        "allow_management": ParamDef(type=bool, default=True,
                                     description="Allow SSH/LuCI to the router from the VPN zone (disable = lockout risk)"),
        "upstream_gateway": ParamDef(type=str, required=False, allow_empty=True,
                                     description="Upstream gateway IP (empty = discover at runtime from default route)"),
        "upstream_iface": ParamDef(type=str, default="wwan",
                                   description="Upstream interface name (wwan for WiFi STA, wan for ethernet)"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block LAN→WAN traffic if tunnel drops"),
        "mtu": ParamDef(type=str, default="1420",
                        description="WireGuard interface MTU"),
    },
    build_configure_ops=_build_nordvpn_ops,
    test_status="tested",
    tested_notes="Tested on hardware 2026-10-08 (D-Link COVR-X1860 A1, OpenWrt 25.12.5): "
                 "config_file mode with 5GHz STA uplink, full-tunnel WireGuard to NordVPN "
                 "DE exit verified from LAN client (handshake, NAT, DNS via tunnel, kill switch). "
                 "Token mode + 2.4GHz VPN-exit AP tested same day after reflash.",
))


def _build_openvpn_uc_ops(params: dict[str, Any]) -> list[Op]:
    return _build_nordvpn_ops({**params, "technology": params.get("technology") or "openvpn-udp"})


register(UseCase(
    name="vpn-nordvpn-openvpn",
    description="NordVPN OpenVPN (udp/tcp) — service credentials resolved from access token",
    packages=["openvpn-openssl"],
    packages_remove=[],
    params={
        "access_token": ParamDef(type=str, required=False, allow_empty=True,
                                 description="NordVPN access token (Nord Account dashboard)"),
        "technology": ParamDef(type=str, default="openvpn-udp",
                               description="openvpn-udp or openvpn-tcp"),
        "server": ParamDef(type=str, default="DE",
                           description="Country selection: 'DE', 'germany', or a country id (hostname/IP pins are refused)"),
        "openvpn_cipher": ParamDef(type=str, default="AES-256-CBC",
                                   description="OpenVPN cipher override (e.g. AES-256-GCM); data-ciphers always allows both"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block LAN→WAN traffic if tunnel drops"),
        "allow_management": ParamDef(type=bool, default=True,
                                     description="Allow SSH/LuCI to the router from the VPN zone (disable = lockout risk)"),
        "ap_ssid": ParamDef(type=str, required=False, allow_empty=True,
                            description="2.4GHz AP SSID whose clients exit via the VPN (empty = disabled)"),
        "ap_key": ParamDef(type=str, required=False, allow_empty=True,
                           description="WiFi password for the VPN-exit AP"),
    },
    build_configure_ops=_build_openvpn_uc_ops,
    test_status="tested",
    tested_notes="Tested on hardware 2026-10-08 (COVR-X1860 A1, OpenWrt 25.12.5): OpenVPN UDP "
                 "to a DE server with service credentials from the access token, exit verified.",
))


def _build_ikev2_ops(params: dict[str, Any]) -> list[Op]:
    """NordVPN IKEv2/IPsec via strongSwan — EAP-MSCHAPv2, kernel ESP.

    Hardware-bring-up lessons baked in (2026-10-08, COVR-X1860 / MT7621):

    - socket-default is mandatory: with socket-dynamic, charon logs
      "sending packet" while nothing ever leaves (never binds UDP :500).
    - eap-identity answers the server's EAP_IDENTITY request; without it the
      inline NAK stalls the exchange.
    - ESP proposals must NOT include modp (no PFS) — NordVPN rejects it.
    - local_ts=dynamic (the acquired virtual IP), remote_ts 0/0.
    - The stock mt7621 kernel ships without XFRM: the kmod-ipsec* packages
      must be in the image (they are, via this use case's package list).
    - hw_accel=false removes the EIP-93 crypto engine before any SA exists
      (rmmod at usage 0 is safe; with live references it wedges the kernel —
      see AGENTS.md) and blacklists it for subsequent boots. hw_accel=true
      forces the module in: ESP AES-CBC/SHA then negotiates onto EIP-93
      transforms — note SAD install has failed with EINVAL in that
      configuration on kernel 6.12.94; the bench records the outcome either
      way.
    """
    access_token = params.get("access_token", "")
    if not access_token:
        return [Comment(
            text="vpn-nordvpn-ikev2: NOT CONFIGURED — set access_token in "
                 "config.toml [use_cases.vpn-nordvpn-ikev2] (EAP credentials "
                 "are derived from it at build time)",
        )]
    server = params.get("server") or "DE"
    hw_accel = params.get("hw_accel", True)
    kill_switch = params.get("kill_switch", True)
    allow_management = params.get("allow_management", True)
    ap_ssid = params.get("ap_ssid", "")
    ap_key = params.get("ap_key", "")

    basic = base64.b64encode(f"token:{access_token}".encode()).decode()
    creds = _fetch_credentials(basic)
    srv = _resolve_server(server, access_token, "ikev2")

    hw_block = (
        "modprobe crypto_hw_eip93 2>/dev/null || true\n"
        if hw_accel else
        "rmmod crypto_hw_eip93 2>/dev/null || true\n"
        "mkdir -p /etc/modprobe.d\n"
        "echo 'blacklist crypto_hw_eip93' > /etc/modprobe.d/no-eip93.conf\n"
    )

    ikev2_script = f"""# --- NordVPN IKEv2 (strongSwan, EAP-MSCHAPv2) ---
{hw_block}
mkdir -p /var/ipsec /etc/swanctl/conf.d /etc/swanctl/x509ca

printf 'charon {{\\n  install_routes = yes\\n}}\\n' > /var/ipsec/strongswan.conf

cat > /etc/swanctl/x509ca/nordvpn.pem << 'NORD_CA_EOF'
{NORDVPN_CA}
NORD_CA_EOF

cat > /etc/swanctl/conf.d/nordvpn-ikev2.conf << 'NORD_SWAN_EOF'
connections {{
  nordvpn {{
    version = 2
    send_cert = never
    local_addrs = %defaultroute
    remote_addrs = {srv["station"]}
    proposals = aes256-sha256-modp2048, aes256-sha1-modp2048, aes128-sha256-modp2048
    reauth_time = 0s
    fragmentation = yes
    mobike = yes
    local {{
      auth = eap
      eap_id = "{creds["username"]}"
    }}
    remote {{
      auth = pubkey
      id = %any
    }}
    vips = 0.0.0.0
    dpd_delay = 60s
    children {{
      nord {{
        remote_ts = 0.0.0.0/0
        local_ts = dynamic
        start_action = start
        close_action = restart
        esp_proposals = aes256-sha256, aes256-sha1, aes128-sha256
        rekey_time = 3600s
      }}
    }}
  }}
}}
secrets {{
  eap-nord {{
    secret = "{creds["password"]}"
  }}
}}
NORD_SWAN_EOF

chmod 600 /etc/swanctl/conf.d/nordvpn-ikev2.conf

# charon is not under procd here: start it from rc.local after the network
grep -q 'nordvpn-ikev2-charon' /etc/rc.local 2>/dev/null || cat >> /etc/rc.local << 'NORD_RC_EOF'
# nordvpn-ikev2-charon
( sleep 8; /usr/lib/ipsec/charon >/dev/null 2>&1; ) &
( sleep 20; swanctl --load-all >/dev/null 2>&1; swanctl --initiate --child nord >/dev/null 2>&1; ) &
NORD_RC_EOF

# also bring it up right now (first boot)
( sleep 8; /usr/lib/ipsec/charon >/dev/null 2>&1; ) &
( sleep 20; swanctl --load-all >/dev/null 2>&1; swanctl --initiate --child nord >/dev/null 2>&1; ) &
echo "NordVPN IKEv2 staged: server {srv['hostname']} ({srv['station']}), hw_accel={'on' if hw_accel else 'off'}"
"""

    ops: list[Op] = [
        Comment(text=f"--- NordVPN IKEv2/IPsec (server {srv['hostname']}, hw_accel={hw_accel}) ---"),
        ShellCommand(command=transport_sh(ikev2_script, "/tmp/nordvpn_ikev2_setup.sh")),
    ]
    ops.extend(build_firewall_ops(iface="ipsec0", kill_switch=kill_switch,
                                  allow_management=allow_management))
    ops.append(ShellCommand(command=(
        "nft add rule inet fw4 input_wan udp dport { 500, 4500 } accept comment 'IKE/NAT-T' 2>/dev/null; "
        "nft add rule inet fw4 input_wan meta l4proto esp accept comment 'ESP' 2>/dev/null; true"
    )))
    ops.extend(build_dns_ops(NORDVPN_DNS))
    if ap_ssid:
        ops.extend(_build_vpn_ap_ops(ap_ssid, ap_key))
    return ops


register(UseCase(
    name="vpn-nordvpn-ikev2",
    description="NordVPN IKEv2/IPsec (strongSwan, EAP-MSCHAPv2) — optional EIP-93 hw accel",
    packages=[
        "strongswan", "strongswan-charon", "strongswan-swanctl",
        "strongswan-mod-aes", "strongswan-mod-sha1", "strongswan-mod-sha2",
        "strongswan-mod-gmp", "strongswan-mod-hmac", "strongswan-mod-pubkey",
        "strongswan-mod-x509", "strongswan-mod-pem", "strongswan-mod-random",
        "strongswan-mod-nonce", "strongswan-mod-eap-identity",
        "strongswan-mod-eap-mschapv2", "strongswan-mod-md4",
        "strongswan-mod-kernel-netlink", "strongswan-mod-updown",
        "strongswan-mod-attr", "strongswan-mod-openssl",
        "strongswan-mod-socket-default",
        "kmod-ipsec4", "kmod-xfrm-interface", "kmod-nft-xfrm",
    ],
    packages_remove=[],
    params={
        "access_token": ParamDef(type=str, required=False, allow_empty=True,
                                 description="NordVPN access token (Nord Account dashboard)"),
        "server": ParamDef(type=str, default="DE",
                           description="Country selection: 'DE', 'germany', or a country id (hostname/IP pins are refused)"),
        "hw_accel": ParamDef(type=bool, default=True,
                             description="EIP-93 hardware crypto on (false = rmmod+blacklist before any SA)"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block LAN→WAN traffic if tunnel drops"),
        "allow_management": ParamDef(type=bool, default=True,
                                     description="Allow SSH/LuCI to the router from the VPN zone"),
        "ap_ssid": ParamDef(type=str, required=False, allow_empty=True,
                            description="2.4GHz AP SSID whose clients exit via the VPN (empty = disabled)"),
        "ap_key": ParamDef(type=str, required=False, allow_empty=True,
                           description="WiFi password for the VPN-exit AP"),
    },
    build_configure_ops=_build_ikev2_ops,
    test_status="untested",
    tested_notes="IKE_SA proven manually 2026-10-08 (EAP-MSCHAPv2, AES-CBC-256/SHA256); "
                 "CHILD_SA blocked by SAD EINVAL with eip93 loaded — hw_accel=false is the "
                 "supported path pending the driver verdict.",
))
