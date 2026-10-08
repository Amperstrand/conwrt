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
    wg_cleanup_sh,
    transport_sh,
)

NORDVPN_DNS = ["103.86.96.100", "103.86.99.100"]

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


def _resolve_endpoint(value: str, token: str) -> tuple[str, str, str]:
    """Return (endpoint_ip_or_host, port, server_public_key) for a target.

    ``value`` is an IP, a hostname, a "Country" name, or a country code. IPs
    and hostnames are resolved via filters[hostname]/direct use; anything else
    goes through the recommendations API with a country filter.
    """
    import json as _json
    import urllib.request

    def _get(url: str, basic: str = "") -> Any:
        req = urllib.request.Request(url)
        if basic:
            req.add_header("Authorization", f"Basic {basic}")
        with urllib.request.urlopen(req, timeout=20) as resp:
            return _json.loads(resp.read().decode())

    basic = base64.b64encode(f"token:{token}".encode()).decode()
    parts = value.rsplit(":", 1)
    looks_like_host = len(parts) == 2 and parts[1].isdigit()
    host_value = parts[0] if looks_like_host else value

    if _is_ip(host_value) or host_value.endswith(".nordvpn.com"):
        server = {
            "station": host_value if _is_ip(host_value) else "",
            "hostname": host_value,
        }
        if not server["station"]:
            hit = _get(
                "https://api.nordvpn.com/v1/servers"
                f"?filters%5Bhostname%5D={host_value.split('.')[0]}",
                basic,
            )
            if not hit:
                raise ValueError(f"no NordVPN server found for hostname {host_value}")
            server["station"] = hit[0].get("station", "")
        key = _server_public_key(server) or ""
        ip, port = _split_endpoint(value if looks_like_host else f"{host_value}:51820")
        return server["station"] or host_value, port, key

    code = host_value.strip().lower()
    code_map = {"germany": "81", "de": "81"}
    country_id = code_map.get(code, code if code.isdigit() else "")
    url = (
        "https://api.nordvpn.com/v1/servers/recommendations?limit=1"
        "&filters%5Bservers_technologies%5D%5Bidentifier%5D=wireguard_udp"
    )
    if country_id:
        url += f"&filters%5Bcountry_id%5D={country_id}"
    servers = _get(url)
    if not servers:
        raise ValueError(f"no NordVPN wireguard_udp server found for '{value}'")
    server = servers[0]
    key = _server_public_key(server)
    if not key:
        raise ValueError(f"server {server.get('hostname')} has no wireguard_udp public key")
    return server["station"], "51820", key


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
        priv_key = _fetch_credentials(basic)
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

    nordvpn_script = f"""{JSON_HELPER_SH}
WG_PRIV="{priv_key}"
SERVER_KEY="{peer_key}"
SERVER_IP="{endpoint_ip}"

{wg_cleanup_sh()}

# WireGuard tunnel (NordLynx)
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key="$WG_PRIV"
uci add_list network.wg0.addresses='{address}'
uci set network.wg0.mtu='{mtu}'
uci set network.wg0.auto='1'

uci add network wireguard_wg0
uci set network.@wireguard_wg0[0].public_key="$SERVER_KEY"
uci set network.@wireguard_wg0[0].endpoint_host="$SERVER_IP"
uci set network.@wireguard_wg0[0].endpoint_port='{endpoint_port}'
uci add_list network.@wireguard_wg0[0].allowed_ips='{allowed_ips}'
uci set network.@wireguard_wg0[0].route_allowed_ips='1'
uci set network.@wireguard_wg0[0].persistent_keepalive='{keepalive}'

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


def _fetch_credentials(basic: str) -> str:
    """Exchange an access token for the account's NordLynx private key."""
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
    key = data.get("nordlynx_private_key", "") if isinstance(data, dict) else ""
    if not key:
        raise ValueError("NordVPN credentials response missing nordlynx_private_key "
                         "(check that the access token is valid)")
    return key


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
                           description="Server/country selection: 'DE', country id, hostname (de1507.nordvpn.com), or IP"),
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
