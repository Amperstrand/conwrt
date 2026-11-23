# --- IPv6 WAN (NAT66/ULA stable LAN) ---
uci set network.wan6=interface
uci set network.wan6.proto='dhcpv6'
uci set network.wan6.device='@wan'
uci set network.wan6.reqprefix='auto'
ula=$(uci -q get network.globals.ula_prefix) || ula=''; [ -n "$ula" ] || { mac=$(cat /sys/class/net/eth0/address); m1=$(echo $mac | cut -d: -f1); m2=$(echo $mac | cut -d: -f2); m3=$(echo $mac | cut -d: -f3); m4=$(echo $mac | cut -d: -f4); m5=$(echo $mac | cut -d: -f5); uci set network.globals.ula_prefix="fd$(printf %02x $((0x$m1 ^ 2))):${m2}ff:fe${m3}:${m4}${m5}::/64"; }
uci set network.lan.ip6assign='64'
z=$(uci show firewall | grep "=zone" | grep "name='wan'" | cut -d. -f2 | cut -d= -f1); [ -z "$z" ] || uci set firewall.$z.masq6='1'
uci commit network
uci commit firewall
/etc/init.d/network reload
/etc/init.d/firewall reload