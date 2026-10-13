"""vpn-pia — Private Internet Access WireGuard VPN.

Full API integration: generates WG keypair, authenticates with PIA API
(token generation + key registration), configures WireGuard with server
response values, sets up firewall kill switch and DNS.

PIA tokens expire ~7 days. For reboot persistence, install the
pia-wg-autostart init script (see skill: openwrt-pia-wireguard, Step 9).
"""
from __future__ import annotations

from typing import Any

from profile.ops import Comment, Op, ShellCommand
from shell_safe import sh_quote

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


def _build_pia_ops(params: dict[str, Any]) -> list[Op]:
    username = params["username"]
    password = params["password"]
    region = params.get("region", "netherlands")
    gateway = params["upstream_gateway"]
    upstream_iface = params.get("upstream_iface", "wwan")
    kill_switch = params.get("kill_switch", True)

    pia_script = f"""{JSON_HELPER_SH}
{keypair_sh()}

# Authenticate with PIA — get auth token
curl -fs -m 15 -u {sh_quote(f"{username}:{password}")} \\
    "https://www.privateinternetaccess.com/gtoken/generateToken" \\
    -o /tmp/vpn_token.json
PIA_TOKEN=$(cat /tmp/vpn_token.json | json_get token)
[ -n "$PIA_TOKEN" ] || {{ echo 'PIA: auth failed — no token in API response'; exit 1; }}

# URL-encode token: PIA tokens contain +, /, = that break curl
ENC_TOKEN=$(echo "$PIA_TOKEN" | sed 's/+/%2B/g; s/=/%3D/g; s|/|%2F|g')

WG_PUB=$(cat /tmp/vpn_public.key)

# Register WG key with regional server
curl -fs -m 15 -k \\
    "https://{region}.privacy.network:1337/addKey?pt=${{ENC_TOKEN}}&pubkey=${{WG_PUB}}" \\
    -o /tmp/vpn_addkey.json

# Parse server response
SERVER_KEY=$(cat /tmp/vpn_addkey.json | json_get server_key)
SERVER_IP=$(cat /tmp/vpn_addkey.json | json_get server_ip)
SERVER_PORT=$(cat /tmp/vpn_addkey.json | json_get server_port)
PEER_IP=$(cat /tmp/vpn_addkey.json | json_get peer_ip)
# Abort BEFORE the destructive wg0 cleanup unless the response is complete
[ -n "$SERVER_KEY" ] && [ -n "$SERVER_IP" ] && [ -n "$SERVER_PORT" ] && [ -n "$PEER_IP" ] \\
    || {{ echo 'PIA: addKey response incomplete — aborting before wg0 cleanup'; exit 1; }}

{wg_cleanup_sh()}

PIA_PRIV=$(cat /tmp/vpn_private.key)

# Configure WireGuard interface
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key="$PIA_PRIV"
uci set network.wg0.listen_port='51820'
uci add_list network.wg0.addresses="${{PEER_IP}}/32"
uci set network.wg0.mtu='1280'
uci set network.wg0.auto='1'

# Add PIA peer
uci add network wireguard_wg0
uci set network.@wireguard_wg0[0].public_key="$SERVER_KEY"
uci set network.@wireguard_wg0[0].endpoint_host="$SERVER_IP"
uci set network.@wireguard_wg0[0].endpoint_port="$SERVER_PORT"
uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'
uci set network.@wireguard_wg0[0].route_allowed_ips='1'
uci set network.@wireguard_wg0[0].persistent_keepalive='25'

{static_route_sh("SERVER_IP", gateway, upstream_iface, "pia_server_route")}
"""

    ops: list[Op] = [
        Comment(text=f"--- PIA WireGuard VPN ({region}) ---"),
        ShellCommand(command=transport_sh(pia_script)),
    ]
    ops.extend(build_firewall_ops(kill_switch=kill_switch))
    ops.extend(build_dns_ops(["10.0.0.243", "10.0.0.242"]))
    ops.extend(build_verify_ops(kill_switch=kill_switch))
    return ops


register(UseCase(
    name="vpn-pia",
    description="Private Internet Access WireGuard VPN — full API integration "
                "(token gen + key registration + kill switch + DNS)",
    packages=["wireguard-tools", "luci-proto-wireguard"],
    packages_remove=[],
    params={
        "username": ParamDef(type=str, required=True, allow_empty=False,
                             description="PIA account username (e.g. p1234567)"),
        "password": ParamDef(type=str, required=True, allow_empty=False,
                             description="PIA account password"),
        "region": ParamDef(type=str, default="netherlands",
                           description="PIA region (e.g. netherlands, czech, frankfurt, swiss)"),
        "upstream_gateway": ParamDef(type=str, required=True, allow_empty=False,
                                     description="Upstream gateway IP (prevents circular routing)"),
        "upstream_iface": ParamDef(type=str, default="wwan",
                                   description="Upstream interface name (wwan, wan, etc.)"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block all non-VPN traffic if tunnel drops"),
    },
    build_configure_ops=_build_pia_ops,
    test_status="tested",
    tested_notes="OpenWrt 24.10.4, MediaTek Filogic — PIA Czechia region",
))


# -- PIA OpenVPN (vpn-pia-openvpn) ----------------------------------------------
#
# Validated recipe (recipes/glinet/mt3000/notes.md, 2026-09-14, OpenWrt
# 25.12.5): UDP 8080 endpoints + the RSA-4096 CA from pia-foss/
# manual-connections; p-number + password via auth-user-pass;
# pull-filter the IPv6 pushes (PIA has no v6 — an installed ::/3 route
# blackholes v6 on a v4-only tun0); NO persist-tun (a dead tunnel must
# tear routes down, not blackhole the LAN); OpenVPN 2.7 wants
# data-ciphers, not cipher. Endpoint pool + remote-random for failover
# (mirrors ansible/roles/pia_openvpn — the same validated config).

PIA_OPENVPN_CA = """-----BEGIN CERTIFICATE-----
MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV
BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu
dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx
IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB
FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw
MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg
QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE
AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50
ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy
bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk
hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN
De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K
V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ
25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND
fCwsnGWpWFoMGvdMbygngCn6jA/W1VSFOlRlfLuuGe7QFfDwA0jaLCxuWt/BgZyl
p7tAzYKR8lnWmtUCPm4+BtjyVDYtDCiGBD9Z4P13RFWvJHw5aapx/5W/CuvVyI7p
Kwvc2IT+KPxCUhH1XI8ca5RN3C9NoPJJf6qpg4g0rJH3aaWkoMRrYvQ+5PXXYUzj
tRHImghRGd/ydERYoAZXuGSbPkm9Y/p2X8unLcW+F0xpJD98+ZI+tzSsI99Zs5wi
jSUGYr9/j18KHFTMQ8n+1jauc5bCCegN27dPeKXNSZ5riXFL2XX6BkY68y58UaNz
meGMiUL9BOV1iV+PMb7B7PYs7oFLjAhh0EdyvfHkrh/ZV9BEhtFa7yXp8XR0J6vz
1YV9R6DYJmLjOEbhU8N0gc3tZm4Qz39lIIG6w3FDAgMBAAGjggFUMIIBUDAdBgNV
HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt
yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI
EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl
cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw
HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0
ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl
aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt
pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv
Em89xWm2MVA7nyzQxVlHa9AkcBaemcXEiyT19XdpiXOP4Vhs+J1R5m8zQOxZlV1G
tF9vsXmJqWZpOVPmZ8f35BCsYPvv4yMewnrtAC8PFEK/bOPeYcKN50bol22QYaZu
LfpkHfNiFTnfMh8sl/ablPyNY7DUNiP5DRcMdIwmfGQxR5WEQoHL3yPJ42LkB5zs
6jIm26DGNXfwura/mi105+ENH1CaROtRYwkiHb08U6qLXXJz80mWJkT90nr8Asj3
5xN2cUppg74nG3YVav/38P48T56hG1NHbYF5uOCske19F6wi9maUoto/3vEr0rnX
JUp2KODmKdvBI7co245lHBABWikk8VfejQSlCtDBXn644ZMtAdoxKNfR2WTFVEwJ
iyd1Fzx0yujuiXDROLhISLQDRjVVAvawrAtLZWYK31bY7KlezPlQnl/D9Asxe85l
8jO5+0LdJ6VyOs/Hd4w52alDW/MFySDZSfQHMTIc30hLBJ8OnCEIvluVQQ2UQvoW
+no177N9L2Y+M9TcTA62ZyMXShHQGeh20rb4kK8f+iFX8NxtdHVSkxMEFSfDDyQ=
-----END CERTIFICATE-----"""

# Validated pool (ansible/roles/pia_openvpn/defaults/main.yml).
PIA_OPENVPN_REMOTES = [
    "151.241.122.99",   # US East (New Jersey)
    "37.19.197.168",    # US East (New Jersey)
    "151.241.119.192",  # US East (New Jersey)
    "37.19.220.37",     # US Washington DC
    "181.41.206.48",    # US Denver
    "102.129.153.205",  # US Florida
    "145.79.182.176",   # US Atlanta
    "193.56.117.160",   # US Chicago
    "191.96.106.197",   # US California
    "173.239.198.91",   # US Seattle
]
PIA_OPENVPN_PORT = "8080"
PIA_OPENVPN_DNS = ["10.0.0.241", "10.0.0.242", "10.0.0.243"]


def _build_pia_openvpn_ops(params: dict[str, Any]) -> list[Op]:
    """PIA via OpenVPN (tun0) — validated static-config recipe.

    Everything is resolved at BUILD time (CA + credentials + endpoint
    pool): the device gets static files, no PIA API dependency at first
    boot. The WireGuard variant (vpn-pia) is torn down first so the two
    technologies never fight over the vpn zone.
    """
    username = params.get("username", "")
    password = params.get("password", "")
    if not username or not password:
        return [Comment(
            text="vpn-pia-openvpn: NOT CONFIGURED — set username (p-number) "
                 "and password in config.toml [use_cases.vpn-pia-openvpn]",
        )]
    remotes = params.get("remotes") or PIA_OPENVPN_REMOTES
    port = str(params.get("port", PIA_OPENVPN_PORT))
    kill_switch = params.get("kill_switch", True)
    allow_management = params.get("allow_management", True)
    gateway = params.get("upstream_gateway", "")
    upstream_iface = params.get("upstream_iface", "wan")

    remote_lines = "\n".join(
        f"uci add_list openvpn.pia.remote='{host} {port}'" for host in remotes
    )
    route_block = (
        f"# pin the endpoint pool's route to the upstream (no v4 route via tun)\n"
        f"for _pia_ep in {' '.join(remotes)}; do\n"
        f"    ip route replace $_pia_ep/32 via {gateway} dev {upstream_iface} 2>/dev/null || true\n"
        f"done\n"
        if gateway
        else ""
    )

    openvpn_script = f"""{wg_cleanup_sh()}

# Tear down any previous OpenVPN instance
uci -q delete openvpn.pia

mkdir -p /etc/openvpn
cat > /etc/openvpn/pia-ca.rsa.4096.crt << 'PIA_CA_EOF'
{PIA_OPENVPN_CA}
PIA_CA_EOF
cat > /etc/openvpn/pia.auth << 'PIA_AUTH_EOF'
{username}
{password}
PIA_AUTH_EOF
chmod 600 /etc/openvpn/pia.auth

uci set openvpn.pia=openvpn
uci set openvpn.pia.enabled='1'
uci set openvpn.pia.client='1'
uci set openvpn.pia.dev='tun'
uci set openvpn.pia.proto='udp'
{remote_lines}
uci set openvpn.pia.remote_random='1'
uci set openvpn.pia.resolv_retry='infinite'
uci set openvpn.pia.nobind='1'
uci set openvpn.pia.persist_key='1'
# NO persist_tun (validated lesson): a dead tunnel must tear its routes
# down, not blackhole the LAN behind stale routes.
uci set openvpn.pia.ca='/etc/openvpn/pia-ca.rsa.4096.crt'
uci set openvpn.pia.auth_user_pass='/etc/openvpn/pia.auth'
uci set openvpn.pia.auth_nocache='1'
uci set openvpn.pia.remote_cert_tls='server'
uci set openvpn.pia.data_ciphers='AES-256-GCM:AES-128-GCM:AES-256-CBC'
uci set openvpn.pia.data_ciphers_fallback='AES-256-CBC'
uci set openvpn.pia.auth='sha256'
uci set openvpn.pia.reneg_sec='0'
uci set openvpn.pia.disable_occ='1'
uci set openvpn.pia.mssfix='1420'
uci set openvpn.pia.verb='3'
uci set openvpn.pia.pull='1'
# PIA has no IPv6: it pushes route-ipv6/ifconfig-ipv6 anyway, which
# blackholes v6 on the v4-only tun0 (broke Signal on the validated box).
uci add_list openvpn.pia.pull_filter='ignore "route-ipv6"'
uci add_list openvpn.pia.pull_filter='ignore "ifconfig-ipv6"'
uci commit openvpn

{route_block}# tun0 joins the vpn zone (wg0 was removed by the cleanup above)
uci -q del_list firewall.vpn_zone.network='wg0'
uci -q add_list firewall.vpn_zone.network='tun0'
/etc/init.d/openvpn restart || /etc/init.d/openvpn start
"""

    ops: list[Op] = [
        Comment(text=f"--- PIA OpenVPN (udp/{port}, {len(remotes)}-endpoint pool, remote-random) ---"),
        ShellCommand(command=transport_sh(openvpn_script, "/tmp/pia_openvpn_setup.sh")),
    ]
    ops.extend(build_firewall_ops(iface="tun0", kill_switch=kill_switch,
                                  allow_management=allow_management))
    ops.extend(build_dns_ops(PIA_OPENVPN_DNS))
    ops.extend(build_verify_ops(iface="tun0", kill_switch=kill_switch, kind="openvpn"))
    return ops


register(UseCase(
    name="vpn-pia-openvpn",
    description="Private Internet Access OpenVPN — validated static recipe "
                "(RSA-4096 CA, UDP 8080 pool + remote-random, IPv6 pull-filters, "
                "no persist-tun)",
    packages=["openvpn-openssl"],
    packages_remove=[],
    params={
        "username": ParamDef(type=str, required=False, allow_empty=True,
                             description="PIA account username (the p-number, e.g. p1234567)"),
        "password": ParamDef(type=str, required=False, allow_empty=True,
                             description="PIA account password"),
        "remotes": ParamDef(type=list, required=False, allow_empty=True,
                            description="Endpoint pool override (IPs; default: validated US pool)"),
        "port": ParamDef(type=str, default=PIA_OPENVPN_PORT,
                         description="OpenVPN server port (PIA modern default: 8080)"),
        "upstream_gateway": ParamDef(type=str, required=False, allow_empty=True,
                                     description="Upstream gateway IP; pins endpoint /32 routes when set"),
        "upstream_iface": ParamDef(type=str, default="wan",
                                   description="Upstream interface name (wan, wwan, ...)"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block all non-VPN traffic if tunnel drops"),
    },
    build_configure_ops=_build_pia_openvpn_ops,
    test_status="untested",
    tested_notes="Recipe validated manually on GL-MT3000 / OpenWrt 25.12.5 "
                 "(recipes/glinet/mt3000/notes.md) — provider op-path not yet "
                 "exercised on hardware",
))
