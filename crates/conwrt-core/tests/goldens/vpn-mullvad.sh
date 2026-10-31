# golden: conwrt 1.x output of scripts/use_cases/vpn_providers/mullvad.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- Mullvad WireGuard VPN ---
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

# Register WG public key with Mullvad API
RESPONSE=$(curl -s -m 15 -X POST \
    "https://api.mullvad.net/www/accounts/me/wg-peers/" \
    -H "Authorization: Token a1b2c3d4e5f6" \
    -H "Content-Type: application/json" \
    -d '{"public_key":"'"${WG_PUB}"'"}')

PEER_IP=$(echo "$RESPONSE" | json_get ipv4_address)
# Strip CIDR if present (Mullvad returns 10.xx.xx.xx/32)
PEER_IP=${PEER_IP%%/*}

# Fetch server list and pick best server
SERVERS=$(curl -s -m 15 -H "Accept: application/json" "https://api.mullvad.net/www/relays/wireguard/")
if [ -n "" ]; then
    SERVER_ENTRY=$(echo "$SERVERS" | jq -r '[.[] | select(.country_code=="")] | .[0]')
else
    SERVER_ENTRY=$(echo "$SERVERS" | jq -r '.[0]')
fi
SERVER_IP=$(echo "$SERVER_ENTRY" | json_get ipv4_addr_in)
SERVER_KEY=$(echo "$SERVER_ENTRY" | json_get pubkey)
SERVER_HOST=$(echo "$SERVER_ENTRY" | json_get hostname)
SERVER_PORT=51820

# Abort BEFORE the destructive wg0 cleanup unless the response is
# complete (surfshark #604-P2 class)
[ -n "$SERVER_KEY" ] && [ -n "$SERVER_IP" ] \
    || { echo 'Mullvad: server list incomplete — aborting before wg0 cleanup'; exit 1; }
if [ -z "$PEER_IP" ]; then echo 'Mullvad: key registration failed (no peer IP) — aborting before wg0 cleanup'; exit 1; fi

# Clean up old WireGuard interface + peers
uci -q delete network.wg0
while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg0[0]
done


MULLVAD_PRIV=$(cat /tmp/vpn_private.key)

uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key="$MULLVAD_PRIV"
uci set network.wg0.listen_port='51820'
uci add_list network.wg0.addresses="${PEER_IP}/32"
uci set network.wg0.mtu='1280'
uci set network.wg0.auto='1'

uci add network wireguard_wg0
uci set network.@wireguard_wg0[0].public_key="$SERVER_KEY"
uci set network.@wireguard_wg0[0].endpoint_host="$SERVER_IP"
uci set network.@wireguard_wg0[0].endpoint_port="$SERVER_PORT"
uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'
uci set network.@wireguard_wg0[0].route_allowed_ips='1'
uci set network.@wireguard_wg0[0].persistent_keepalive='25'

# Static route: prevent circular routing through VPN tunnel
uci -q delete network.mullvad_server_route
uci set network.mullvad_server_route=route
uci set network.mullvad_server_route.interface='wwan'
uci set network.mullvad_server_route.target="${SERVER_IP}"
uci set network.mullvad_server_route.netmask='255.255.255.255'
uci set network.mullvad_server_route.gateway='192.168.8.1'


# Pre-commit IP readback (AGENTS.md; surfshark #604-P1 class)
WG_ADDR=$(uci -q get network.wg0.addresses)
case "$WG_ADDR" in
    */32) ;;
    *) echo "Mullvad: wg0 address '$WG_ADDR' not a sane /32 — aborting before commit"; exit 1 ;;
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
uci del_list dhcp.@dnsmasq[0].server='10.64.0.1' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='10.64.0.1'
uci set dhcp.@dnsmasq[0].noresolv='1'
uci commit network
uci commit firewall
uci commit dhcp
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart