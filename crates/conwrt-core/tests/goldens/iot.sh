# golden: conwrt 1.x output of scripts/use_cases/iot.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- IoT isolated network: 'IoT' ---
_radio=""; for _r in radio0 radio1 radio2 radio3; do _b=$(uci get wireless.${_r}.band 2>/dev/null || true); if [ "$_b" = "2g" ]; then _radio=$_r; break; fi; done; if [ -z "$_radio" ]; then echo 'iot: no 2g radio found — aborting before any config changes' >&2; exit 1; fi

uci set network.iot=interface
uci set network.iot.proto='static'
uci set network.iot.ipaddr='192.168.9.1'
uci set network.iot.netmask='255.255.255.0'
uci commit network

uci set dhcp.iot=dhcp
uci set dhcp.iot.interface='iot'
uci set dhcp.iot.start='100'
uci set dhcp.iot.limit='150'
uci set dhcp.iot.leasetime='12h'
uci commit dhcp

uci set firewall.iot=zone
uci set firewall.iot.name='iot'
uci set firewall.iot.network='iot'
uci set firewall.iot.input='REJECT'
uci set firewall.iot.output='ACCEPT'
uci set firewall.iot.forward='REJECT'
uci set firewall.iot_fwd=forwarding
uci set firewall.iot_fwd.src='iot'
uci set firewall.iot_fwd.dest='wan'
uci set firewall.iot_dns=rule
uci set firewall.iot_dns.name='Allow-DNS-iot'
uci set firewall.iot_dns.src='iot'
uci set firewall.iot_dns.dest_port='53'
uci set firewall.iot_dns.proto='tcpudp'
uci set firewall.iot_dns.target='ACCEPT'
uci set firewall.iot_dhcp=rule
uci set firewall.iot_dhcp.name='Allow-DHCP-iot'
uci set firewall.iot_dhcp.src='iot'
uci set firewall.iot_dhcp.dest_port='67-68'
uci set firewall.iot_dhcp.proto='udp'
uci set firewall.iot_dhcp.target='ACCEPT'
uci commit firewall

while uci show wireless 2>/dev/null | grep -q "network='iot'"; do _s=$(uci show wireless 2>/dev/null | grep "network='iot'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "wireless.$_s" 2>/dev/null; done; true
uci set wireless.iot_ap=wifi-iface; uci set wireless.iot_ap.device=$_radio; uci set wireless.iot_ap.mode=ap; uci set wireless.iot_ap.ssid='IoT'; uci set wireless.iot_ap.encryption=psk2; uci set wireless.iot_ap.key='iotpass123'; uci set wireless.iot_ap.network=iot; uci set wireless.iot_ap.isolate=1
uci commit wireless

/etc/init.d/network restart
/etc/init.d/firewall restart
echo "IoT network configured: SSID='IoT' network=iot wan_access=1 isolated=1"