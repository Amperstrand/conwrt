# golden: conwrt 1.x output of scripts/use_cases/vpn_providers/openvpn.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- Generic OpenVPN VPN (UDP) ---
# Write OpenVPN config
mkdir -p /etc/openvpn
cat > /etc/openvpn/vpn-client.ovpn << 'OVPNEOF'
client
remote vpn.example.com 1194
proto udp
auth-user-pass
OVPNEOF


# --- Configure OpenVPN via UCI ---
while uci show openvpn 2>/dev/null | grep -q "vpn_client=config-openvpn"; do _s=$(uci show openvpn 2>/dev/null | grep "vpn_client=config-openvpn" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "openvpn.$_s" 2>/dev/null; done; true
while uci show openvpn 2>/dev/null | grep -q "vpn_client=openvpn"; do _s=$(uci show openvpn 2>/dev/null | grep "vpn_client=openvpn" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "openvpn.$_s" 2>/dev/null; done; true
uci set openvpn.vpn_client=openvpn
uci set openvpn.vpn_client.config='/etc/openvpn/vpn-client.ovpn'
uci set openvpn.vpn_client.enabled='1'
uci set openvpn.vpn_client.username='svcuser'
uci set openvpn.vpn_client.password='svcpass'
uci commit openvpn

# --- OpenVPN network interface ---
while uci show network 2>/dev/null | grep -q "proto='openvpn'"; do _s=$(uci show network 2>/dev/null | grep "proto='openvpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "network.$_s" 2>/dev/null; done; true
uci set network.vpn_if=interface
uci set network.vpn_if.proto='openvpn'
uci set network.vpn_if.config='/etc/openvpn/vpn-client.ovpn'
uci commit network

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
uci set firewall.vpn_zone.network='vpn_if'
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
uci commit firewall
/etc/init.d/openvpn restart
/etc/init.d/network restart
uci commit network
uci commit firewall
uci commit dhcp
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
i=0; while [ $i -lt 45 ]; do if ip -4 addr show dev tun0 2>/dev/null | grep -q inet; then echo 'VPN: tun interface verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tun interface failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart