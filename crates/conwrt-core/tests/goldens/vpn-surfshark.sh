# golden: conwrt 1.x output of scripts/use_cases/vpn_providers/surfshark.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- Surfshark WireGuard VPN ---
uci -q revert network 2>/dev/null || true
uci -q revert firewall 2>/dev/null || true
uci -q revert dhcp 2>/dev/null || true
cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'
# JSON parsing: try jq, install via apk (OpenWrt >=25.x) or opkg (<=24.x)
if ! command -v jq >/dev/null 2>&1; then
    apk add jq >/dev/null 2>&1 || { opkg update >/dev/null 2>&1 && opkg install jq >/dev/null 2>&1; }
fi
json_get() {
    # $1 = key name; reads JSON from stdin; returns first string value
    if command -v jq >/dev/null 2>&1; then
        jq -r ".$1 // empty"
    else
        tr -d '\n' | sed "s/.*\"$1\"[[:space:]]*:[[:space:]]*//" | sed 's/[,"].*//' | tr -d '"'
    fi
}

# Generate WireGuard keypair
wg genkey > /tmp/vpn_private.key
wg pubkey < /tmp/vpn_private.key > /tmp/vpn_public.key
chmod 600 /tmp/vpn_private.key


WG_PUB=$(cat /tmp/vpn_public.key)

# Authenticate with Surfshark — get auth token
AUTH_RESP=$(curl -s -m 15 -X POST \
    "https://api.surfshark.com/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"svcuser","password":"svcpass"}')
AUTH_TOKEN=$(echo "$AUTH_RESP" | json_get token)

# Generate WireGuard configuration
WG_RESP=$(curl -s -m 15 -X POST \
    "https://api.surfshark.com/v1/account/wireguard/new" \
    -H "Authorization: Bearer ${AUTH_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"publicKey":"'"${WG_PUB}"'"}')
PEER_IP=$(echo "$WG_RESP" | json_get ipAddress)
# Strip CIDR if present
PEER_IP=${PEER_IP%%/*}

# Fetch server list and pick best (v4 clusters: public endpoint, hostname-only
# entries — connectionName/pubKey; no IP field, so the endpoint is a DNS name)
SERVERS=$(curl -s -m 15 \
    "https://api.surfshark.com/v4/server/clusters/generic?countryCode=" \
    -H "Content-Type: application/json")
if [ -n "country/Germany/" ]; then
    SERVER_ENTRY=$(echo "$SERVERS" | jq -r '[.[] | select(.country | test("Germany";"i"))] | .[0]')
else
    SERVER_ENTRY=$(echo "$SERVERS" | jq -r '.[0]')
fi
SERVER_HOST=$(echo "$SERVER_ENTRY" | json_get connectionName)
SERVER_KEY=$(echo "$SERVER_ENTRY" | json_get pubKey)
SERVER_PORT=51820
# Resolve the endpoint hostname for the static /32 route; skip the route
# (netifd's wireguard proto installs its own endpoint route) when DNS fails.
# BusyBox nslookup (OpenWrt 25.12.5, verified live 2026-10-14) prints the
# resolver as "Address: <ip>:53" and each answer as "Address: <ip>".
SERVER_IP=$(nslookup "$SERVER_HOST" 2>/dev/null | awk '$1=="Address:" && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $2}' | tail -1)
[ -n "$SERVER_KEY" ] && [ -n "$SERVER_HOST" ] \
    || { echo 'Surfshark: server list incomplete — aborting before wg0 cleanup'; exit 1; }
if [ -z "$PEER_IP" ]; then echo 'Surfshark: key registration failed (no peer IP) — aborting before wg0 cleanup'; exit 1; fi

# Clean up old WireGuard interface + peers
uci -q delete network.wg0
while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg0[0]
done


SS_PRIV=$(cat /tmp/vpn_private.key)

# Configure WireGuard interface
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key="$SS_PRIV"
uci set network.wg0.listen_port='51820'
uci add_list network.wg0.addresses="${PEER_IP}/32"
uci set network.wg0.mtu='1280'
uci set network.wg0.auto='1'

uci add network wireguard_wg0
uci set network.@wireguard_wg0[0].public_key="$SERVER_KEY"
uci set network.@wireguard_wg0[0].endpoint_host="$SERVER_HOST"
uci set network.@wireguard_wg0[0].endpoint_port="$SERVER_PORT"
uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'
uci set network.@wireguard_wg0[0].route_allowed_ips='1'
uci set network.@wireguard_wg0[0].persistent_keepalive='25'


if [ -n "$SERVER_IP" ]; then
# Static route: prevent circular routing through VPN tunnel
uci -q delete network.surfshark_server_route
uci set network.surfshark_server_route=route
uci set network.surfshark_server_route.interface='wwan'
uci set network.surfshark_server_route.target="${SERVER_IP}"
uci set network.surfshark_server_route.netmask='255.255.255.255'
uci set network.surfshark_server_route.gateway='192.168.8.1'
else
    echo "Surfshark: endpoint DNS unresolved — skipping static route (netifd installs its own)"
fi

# Pre-commit IP readback (AGENTS.md): the shared ops below commit and
# restart networking — refuse to reach commit with a tunnel address
# that is not a sane /32 (Codex #604 P1 round 3).
WG_ADDR=$(uci -q get network.wg0.addresses)
case "$WG_ADDR" in
    */32) ;;
    *) echo "Surfshark: wg0 address '$WG_ADDR' not a sane /32 — aborting before commit"; exit 1 ;;
esac
VPN_SETUP_EOF
sh /tmp/vpn_setup.sh

# --- VPN firewall zone + forwarding ---
while uci show firewall 2>/dev/null | grep -q "name='vpn'"; do _s=$(uci show firewall 2>/dev/null | grep "name='vpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
while uci show firewall 2>/dev/null | grep -q "dest='vpn'"; do _s=$(uci show firewall 2>/dev/null | grep "dest='vpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
while uci show firewall 2>/dev/null | grep -q "name='KillSwitch-Reject-NonVPN'"; do _s=$(uci show firewall 2>/dev/null | grep "name='KillSwitch-Reject-NonVPN'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
while uci show firewall 2>/dev/null | grep -q "name='Allow-VPN-Management'"; do _s=$(uci show firewall 2>/dev/null | grep "name='Allow-VPN-Management'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
uci set firewall.vpn_zone=zone
uci set firewall.vpn_zone.name='vpn'
uci set firewall.vpn_zone.input='REJECT'
uci set firewall.vpn_zone.output='ACCEPT'
uci set firewall.vpn_zone.forward='REJECT'
uci set firewall.vpn_zone.masq='1'
uci set firewall.vpn_zone.mtu_fix='1'
uci set firewall.vpn_zone.network='wg0'
uci set firewall.vpn_fwd=forwarding
uci set firewall.vpn_fwd.src='lan'
uci set firewall.vpn_fwd.dest='vpn'

# --- Management (SSH/LuCI) from the VPN zone ---
uci set firewall.vpn_mgmt=rule
uci set firewall.vpn_mgmt.name='Allow-VPN-Management'
uci set firewall.vpn_mgmt.src='vpn'
uci set firewall.vpn_mgmt.proto='tcp'
uci set firewall.vpn_mgmt.dest_port='22 80 443'
uci set firewall.vpn_mgmt.target='ACCEPT'

uci set firewall.vpn_killswitch=rule
uci set firewall.vpn_killswitch.name='KillSwitch-Reject-NonVPN'
uci set firewall.vpn_killswitch.src='lan'
uci set firewall.vpn_killswitch.dest='wan'
uci set firewall.vpn_killswitch.proto='all'
uci set firewall.vpn_killswitch.target='REJECT'

# --- VPN DNS through tunnel ---
uci del_list dhcp.@dnsmasq[0].server='162.252.172.57' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='162.252.172.57'
uci del_list dhcp.@dnsmasq[0].server='149.154.159.92' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='149.154.159.92'
uci set dhcp.@dnsmasq[0].noresolv='1'
uci commit network
uci commit firewall
uci commit dhcp
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart