# --- Guest WiFi: 'BenchGuest' ---
_lan_ip=$(uci get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1')
_guest_o3=$(echo "$_lan_ip" | cut -d. -f3)
_guest_o3=$((_guest_o3 + 1))
[ "$_guest_o3" -gt 255 ] && _guest_o3=0
_guest_prefix=$(echo "$_lan_ip" | cut -d. -f1-2).$_guest_o3

_radio=""; for _r in radio0 radio1 radio2 radio3; do _b=$(uci get wireless.${_r}.band 2>/dev/null || true); if [ "$_b" = "5g" ]; then _radio=$_r; break; fi; done; if [ -z "$_radio" ]; then echo 'guest-wifi: no 5g radio found — aborting before any config changes' >&2; exit 1; fi

uci set network.guest5=interface
uci set network.guest5.ipaddr="$_guest_prefix.1"
uci set network.guest5.proto='static'
uci set network.guest5.netmask='255.255.255.0'
uci commit network

uci set dhcp.guest5=dhcp
uci set dhcp.guest5.interface='guest5'
uci set dhcp.guest5.start='100'
uci set dhcp.guest5.limit='50'
uci set dhcp.guest5.leasetime='1h'
uci commit dhcp

uci set firewall.guest5=zone
uci set firewall.guest5.name='guest5'
uci set firewall.guest5.network='guest5'
uci set firewall.guest5.input='REJECT'
uci set firewall.guest5.output='ACCEPT'
uci set firewall.guest5.forward='REJECT'
uci set firewall.guest5_fwd=forwarding
uci set firewall.guest5_fwd.src='guest5'
uci set firewall.guest5_fwd.dest='wan'
uci set firewall.guest5_dns=rule
uci set firewall.guest5_dns.name='Allow-DNS-guest5'
uci set firewall.guest5_dns.src='guest5'
uci set firewall.guest5_dns.dest_port='53'
uci set firewall.guest5_dns.proto='tcpudp'
uci set firewall.guest5_dns.target='ACCEPT'
uci set firewall.guest5_dhcp=rule
uci set firewall.guest5_dhcp.name='Allow-DHCP-guest5'
uci set firewall.guest5_dhcp.src='guest5'
uci set firewall.guest5_dhcp.dest_port='67-68'
uci set firewall.guest5_dhcp.proto='udp'
uci set firewall.guest5_dhcp.target='ACCEPT'
uci commit firewall

while uci show wireless 2>/dev/null | grep -q "network='guest5'"; do _s=$(uci show wireless 2>/dev/null | grep "network='guest5'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "wireless.$_s" 2>/dev/null; done; true
uci set wireless.guest_ap=wifi-iface; uci set wireless.guest_ap.device=$_radio; uci set wireless.guest_ap.mode=ap; uci set wireless.guest_ap.ssid='BenchGuest'; uci set wireless.guest_ap.encryption=sae; uci set wireless.guest_ap.key='guestkey99'; uci set wireless.guest_ap.network=guest5; uci set wireless.guest_ap.isolate=0
uci commit wireless

/etc/init.d/network restart
/etc/init.d/firewall restart
echo "Guest WiFi configured: SSID='BenchGuest' network=guest5 isolated=0"