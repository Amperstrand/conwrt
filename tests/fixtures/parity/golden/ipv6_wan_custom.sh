# --- IPv6 WAN (NAT66/ULA stable LAN) ---
uci set network.wan6=interface
uci set network.wan6.proto='dhcpv6'
uci set network.wan6.device='@wan'
uci set network.wan6.reqprefix='56'
uci set network.globals.ula_prefix='fd12:3456:789a::/64'
uci set network.lan.ip6assign='64'
uci commit network
uci commit firewall
/etc/init.d/network reload
/etc/init.d/firewall reload