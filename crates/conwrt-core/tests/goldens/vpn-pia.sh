# golden: conwrt 1.x output of scripts/use_cases/vpn_providers/pia.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- PIA WireGuard VPN (czech) ---
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


# Authenticate with PIA — get auth token
curl -fs -m 15 -u 'p1234567:testpass' \
    "https://www.privateinternetaccess.com/gtoken/generateToken" \
    -o /tmp/vpn_token.json
PIA_TOKEN=$(cat /tmp/vpn_token.json | json_get token)
[ -n "$PIA_TOKEN" ] || { echo 'PIA: auth failed — no token in API response'; exit 1; }

# URL-encode token: PIA tokens contain +, /, = that break curl
ENC_TOKEN=$(echo "$PIA_TOKEN" | sed 's/+/%2B/g; s/=/%3D/g; s|/|%2F|g')

WG_PUB=$(cat /tmp/vpn_public.key)

# Register WG key with regional server
curl -fs -m 15 -k \
    "https://czech.privacy.network:1337/addKey?pt=${ENC_TOKEN}&pubkey=${WG_PUB}" \
    -o /tmp/vpn_addkey.json

# Parse server response
SERVER_KEY=$(cat /tmp/vpn_addkey.json | json_get server_key)
SERVER_IP=$(cat /tmp/vpn_addkey.json | json_get server_ip)
SERVER_PORT=$(cat /tmp/vpn_addkey.json | json_get server_port)
PEER_IP=$(cat /tmp/vpn_addkey.json | json_get peer_ip)
# Abort BEFORE the destructive wg0 cleanup unless the response is complete
[ -n "$SERVER_KEY" ] && [ -n "$SERVER_IP" ] && [ -n "$SERVER_PORT" ] && [ -n "$PEER_IP" ] \
    || { echo 'PIA: addKey response incomplete — aborting before wg0 cleanup'; exit 1; }

# Clean up old WireGuard interface + peers
uci -q delete network.wg0
while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg0[0]
done


PIA_PRIV=$(cat /tmp/vpn_private.key)

uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key="$PIA_PRIV"
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
uci -q delete network.pia_server_route
uci set network.pia_server_route=route
uci set network.pia_server_route.interface='wwan'
uci set network.pia_server_route.target="${SERVER_IP}"
uci set network.pia_server_route.netmask='255.255.255.255'
uci set network.pia_server_route.gateway='192.168.1.1'
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
uci del_list dhcp.@dnsmasq[0].server='10.0.0.243' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='10.0.0.243'
uci del_list dhcp.@dnsmasq[0].server='10.0.0.242' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='10.0.0.242'
uci set dhcp.@dnsmasq[0].noresolv='1'
uci commit network
uci commit firewall
uci commit dhcp
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart
