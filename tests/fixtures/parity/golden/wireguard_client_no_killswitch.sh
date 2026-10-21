# --- WireGuard VPN client ---
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='generate'
uci set network.wg0.addresses='10.67.0.2/32'
uci set network.wg0_peer=wireguard_wg0
uci set network.wg0_peer.public_key='KLTaGcXW9+mLTAhzQV0PdhlSbHMxU5yeZ5vlHPmZJEU='
uci set network.wg0_peer.endpoint_host='vpn.example.net'
uci set network.wg0_peer.endpoint_port='51820'
uci set network.wg0_peer.allowed_ips='0.0.0.0/0, ::/0'
uci set network.wg0_peer.route_allowed_ips='1'
uci set network.wg0_peer.persistent_keepalive='25'

# --- Cleanup stale anonymous WireGuard firewall sections ---
while uci show firewall 2>/dev/null | grep -q "name='vpn'"; do _s=$(uci show firewall 2>/dev/null | grep "name='vpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
while uci show firewall 2>/dev/null | grep -q "dest='vpn'"; do _s=$(uci show firewall 2>/dev/null | grep "dest='vpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
while uci show firewall 2>/dev/null | grep -q "name='KillSwitch-Reject-NonVPN'"; do _s=$(uci show firewall 2>/dev/null | grep "name='KillSwitch-Reject-NonVPN'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true

# --- WireGuard firewall zone + forwarding ---
uci set firewall.wg_client_vpn=zone
uci set firewall.wg_client_vpn.name='vpn'
uci set firewall.wg_client_vpn.input='REJECT'
uci set firewall.wg_client_vpn.output='ACCEPT'
uci set firewall.wg_client_vpn.forward='REJECT'
uci set firewall.wg_client_vpn.masq='1'
uci set firewall.wg_client_vpn.mtu_fix='1'
uci set firewall.wg_client_vpn.network='wg0'

uci set firewall.wg_client_fwd=forwarding
uci set firewall.wg_client_fwd.src='lan'
uci set firewall.wg_client_fwd.dest='vpn'

uci commit network
uci commit firewall
/etc/init.d/network restart
echo 'WireGuard client configured: vpn.example.net:51820'