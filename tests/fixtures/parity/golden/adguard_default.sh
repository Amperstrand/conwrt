# --- AdGuard Home ---
uci set adguardhome.adguardhome=adguardhome
uci set adguardhome.adguardhome.enabled='1'
uci set adguardhome.adguardhome.http_address='0.0.0.0:3000'
uci set adguardhome.adguardhome.dns_port='5353'
uci commit adguardhome
/etc/init.d/adguardhome enable
/etc/init.d/adguardhome start

uci set dhcp.@dnsmasq[0].noresolv='1'
uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5353'
uci commit dhcp
/etc/init.d/dnsmasq restart
echo "AdGuard Home configured: DNS on port 5353, web UI at 0.0.0.0:3000"