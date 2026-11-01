# --- Cashu VPN client (vps-on-demand WireGuard exit) ---
# Tunnel address and peer key come from POST /peer on the vps-on-demand service.
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='generate'
uci set network.wg0.addresses='10.99.0.1/32'
uci add_list network.wg0.dns='1.1.1.1'
uci set network.wg0_peer=wireguard_wg0
uci set network.wg0_peer.public_key='pub0123456789abcdef0123456789abcdef01234567='
uci set network.wg0_peer.endpoint_host='66.92.204.237'
uci set network.wg0_peer.endpoint_port='51820'
uci set network.wg0_peer.allowed_ips='0.0.0.0/0'
uci set network.wg0_peer.route_allowed_ips='1'
uci set network.wg0_peer.persistent_keepalive='25'

# --- Cleanup stale anonymous WireGuard firewall sections ---
while uci show firewall 2>/dev/null | grep -q "name='vpn'"; do _s=$(uci show firewall 2>/dev/null | grep "name='vpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
while uci show firewall 2>/dev/null | grep -q "dest='vpn'"; do _s=$(uci show firewall 2>/dev/null | grep "dest='vpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
while uci show firewall 2>/dev/null | grep -q "name='KillSwitch-Reject-NonVPN'"; do _s=$(uci show firewall 2>/dev/null | grep "name='KillSwitch-Reject-NonVPN'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true

# --- WireGuard firewall zone + LAN forwarding ---
uci set firewall.cashu_vpn_zone=zone
uci set firewall.cashu_vpn_zone.name='vpn'
uci set firewall.cashu_vpn_zone.input='REJECT'
uci set firewall.cashu_vpn_zone.output='ACCEPT'
uci set firewall.cashu_vpn_zone.forward='REJECT'
uci set firewall.cashu_vpn_zone.masq='1'
uci set firewall.cashu_vpn_zone.mtu_fix='1'
uci set firewall.cashu_vpn_zone.network='wg0'

uci set firewall.cashu_vpn_fwd=forwarding
uci set firewall.cashu_vpn_fwd.src='lan'
uci set firewall.cashu_vpn_fwd.dest='vpn'

# --- Kill switch: drop LAN→WAN when the tunnel is down ---
uci set firewall.cashu_vpn_killswitch=rule
uci set firewall.cashu_vpn_killswitch.name='KillSwitch-Reject-NonVPN'
uci set firewall.cashu_vpn_killswitch.src='lan'
uci set firewall.cashu_vpn_killswitch.dest='wan'
uci set firewall.cashu_vpn_killswitch.proto='all'
uci set firewall.cashu_vpn_killswitch.target='REJECT'

# --- Commit + restart ---
uci commit network
uci commit firewall
/etc/init.d/network restart
echo 'Cashu VPN client configured: 66.92.204.237:51820 (peer_ip=10.99.0.1/32)'
i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'Cashu VPN kill-switch: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'Cashu VPN kill-switch: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.cashu_vpn_killswitch; uci commit firewall; fw4 restart