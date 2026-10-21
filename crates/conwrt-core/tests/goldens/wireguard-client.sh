# golden: conwrt 1.x output of scripts/use_cases/<plugin>.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- WireGuard VPN client ---
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='generate'
uci set network.wg0.addresses='10.67.0.2/32'
uci add_list network.wg0.dns='1.1.1.1'
uci set network.wg0_peer=wireguard_wg0
uci set network.wg0_peer.public_key='dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ='
uci set network.wg0_peer.endpoint_host='vpn.example.com'
uci set network.wg0_peer.endpoint_port='51820'
uci set network.wg0_peer.allowed_ips='0.0.0.0/0, ::/0'
uci set network.wg0_peer.route_allowed_ips='1'
uci set network.wg0_peer.persistent_keepalive='25'
uci set network.wg0_peer.preshared_key='cHNrLTMyLWJ5dGVzLXRlc3QtdmFsdWU='

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

uci set firewall.wg_client_killswitch=rule
uci set firewall.wg_client_killswitch.name='KillSwitch-Reject-NonVPN'
uci set firewall.wg_client_killswitch.src='lan'
uci set firewall.wg_client_killswitch.dest='wan'
uci set firewall.wg_client_killswitch.proto='all'
uci set firewall.wg_client_killswitch.target='REJECT'

uci commit network
uci commit firewall
/etc/init.d/network restart
echo 'WireGuard client configured: vpn.example.com:51820'
i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'WG kill-switch: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'WG kill-switch: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.wg_client_killswitch; uci commit firewall; fw4 restart