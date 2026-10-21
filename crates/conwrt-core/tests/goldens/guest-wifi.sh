# golden: conwrt 1.x output of scripts/use_cases/<plugin>.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- Guest WiFi: 'Guest' ---
_lan_ip=$(uci get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1')
_guest_o3=$(echo "$_lan_ip" | cut -d. -f3)
_guest_o3=$((_guest_o3 + 1))
[ "$_guest_o3" -gt 255 ] && _guest_o3=0
_guest_prefix=$(echo "$_lan_ip" | cut -d. -f1-2).$_guest_o3

uci set network.guest=interface
uci set network.guest.ipaddr="$_guest_prefix.1"
uci set network.guest.proto='static'
uci set network.guest.netmask='255.255.255.0'
uci commit network

uci set dhcp.guest=dhcp
uci set dhcp.guest.interface='guest'
uci set dhcp.guest.start='100'
uci set dhcp.guest.limit='50'
uci set dhcp.guest.leasetime='1h'
uci commit dhcp

uci set firewall.guest=zone
uci set firewall.guest.name='guest'
uci set firewall.guest.network='guest'
uci set firewall.guest.input='REJECT'
uci set firewall.guest.output='ACCEPT'
uci set firewall.guest.forward='REJECT'
uci set firewall.guest_fwd=forwarding
uci set firewall.guest_fwd.src='guest'
uci set firewall.guest_fwd.dest='wan'
uci set firewall.guest_dns=rule
uci set firewall.guest_dns.name='Allow-DNS-guest'
uci set firewall.guest_dns.src='guest'
uci set firewall.guest_dns.dest_port='53'
uci set firewall.guest_dns.proto='tcpudp'
uci set firewall.guest_dns.target='ACCEPT'
uci set firewall.guest_dhcp=rule
uci set firewall.guest_dhcp.name='Allow-DHCP-guest'
uci set firewall.guest_dhcp.src='guest'
uci set firewall.guest_dhcp.dest_port='67-68'
uci set firewall.guest_dhcp.proto='udp'
uci set firewall.guest_dhcp.target='ACCEPT'
uci commit firewall

while uci show wireless 2>/dev/null | grep -q "network='guest'"; do _s=$(uci show wireless 2>/dev/null | grep "network='guest'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "wireless.$_s" 2>/dev/null; done; true
_radio=""; for _r in radio0 radio1 radio2 radio3; do _b=$(uci get wireless.${_r}.band 2>/dev/null); if [ "$_b" = "2g" ]; then _radio=$_r; break; fi; done; if [ -n "$_radio" ]; then uci set wireless.guest_ap=wifi-iface; uci set wireless.guest_ap.device=$_radio; uci set wireless.guest_ap.mode=ap; uci set wireless.guest_ap.ssid='Guest'; uci set wireless.guest_ap.encryption=psk2; uci set wireless.guest_ap.network=guest; uci set wireless.guest_ap.isolate=1; fi
uci commit wireless

/etc/init.d/network restart
/etc/init.d/firewall restart
echo "Guest WiFi configured: SSID='Guest' network=guest isolated=1"