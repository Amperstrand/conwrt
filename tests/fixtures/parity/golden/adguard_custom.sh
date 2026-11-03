# --- AdGuard Home ---
uci set adguardhome.adguardhome=adguardhome
uci set adguardhome.adguardhome.enabled='1'
uci set adguardhome.adguardhome.http_address='192.168.13.1:3001'
uci set adguardhome.adguardhome.dns_port='5354'
uci commit adguardhome
/etc/init.d/adguardhome enable
/etc/init.d/adguardhome start

uci set dhcp.@dnsmasq[0].noresolv='1'
uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5354'
uci commit dhcp
/etc/init.d/dnsmasq restart
echo "AdGuard Home configured: DNS on port 5354, web UI at 192.168.13.1:3001"