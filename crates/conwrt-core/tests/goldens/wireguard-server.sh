# golden: conwrt 1.x output of scripts/use_cases/wireguard_server.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- WireGuard VPN server ---
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='generate'
uci set network.wg0.listen_port='51820'
uci add_list network.wg0.addresses='10.1.99.1/24'
mkdir -p /etc/wireguard && wg show wg0 public-key > /etc/wireguard/server_public_key 2>/dev/null || true
uci set network.wg0_peer1=wireguard_wg0
uci set network.wg0_peer1.public_key='dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ='
uci set network.wg0_peer1.allowed_ips='10.1.99.2/32'
uci set network.wg0_peer1.route_allowed_ips='1'
uci set network.wg0_peer1.preshared_key='cHNrLTMyLWJ5dGVzLXRlc3QtdmFsdWU='

while uci show firewall 2>/dev/null | grep -q "name='vpn'"; do _s=$(uci show firewall 2>/dev/null | grep "name='vpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
while uci show firewall 2>/dev/null | grep -q "name='Allow-WireGuard'"; do _s=$(uci show firewall 2>/dev/null | grep "name='Allow-WireGuard'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true

uci set firewall.wg_server_vpn=zone
uci set firewall.wg_server_vpn.name='vpn'
uci set firewall.wg_server_vpn.input='ACCEPT'
uci set firewall.wg_server_vpn.output='ACCEPT'
uci set firewall.wg_server_vpn.forward='REJECT'
uci set firewall.wg_server_vpn.masq='1'
uci set firewall.wg_server_vpn.mtu_fix='1'
uci set firewall.wg_server_vpn.network='wg0'

uci set firewall.wg_server_fwd_lan=forwarding
uci set firewall.wg_server_fwd_lan.src='vpn'
uci set firewall.wg_server_fwd_lan.dest='lan'

uci set firewall.wg_server_fwd_wan=forwarding
uci set firewall.wg_server_fwd_wan.src='vpn'
uci set firewall.wg_server_fwd_wan.dest='wan'

uci set firewall.wg_server_allow=rule
uci set firewall.wg_server_allow.name='Allow-WireGuard'
uci set firewall.wg_server_allow.src='wan'
uci set firewall.wg_server_allow.dest_port='51820'
uci set firewall.wg_server_allow.proto='udp'
uci set firewall.wg_server_allow.target='ACCEPT'

uci commit network
uci commit firewall
/etc/init.d/network restart
echo "WireGuard server configured: port 51820, subnet 10.1.99.1/24"
