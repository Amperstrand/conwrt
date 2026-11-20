# --- DNS-over-HTTPS (cloudflare) ---
uci -q delete https-dns-proxy >/dev/null 2>&1 || true

uci set https-dns-proxy.main=https_dns_proxy
uci set https-dns-proxy.main.bootstrap_dns='1.1.1.1,8.8.8.8'
uci set https-dns-proxy.main.listen_addr='127.0.0.1'
uci set https-dns-proxy.main.listen_port='5053'
uci set https-dns-proxy.main.resolver_url='https://cloudflare-dns.com/dns-query'
uci commit https-dns-proxy
/etc/init.d/https-dns-proxy enable
/etc/init.d/https-dns-proxy restart

# --- Point dnsmasq to DoH proxy on port 5053 ---
uci set dhcp.@dnsmasq[0].noresolv='1'
uci delete dhcp.@dnsmasq[0].server
uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5053'
uci commit dhcp
/etc/init.d/dnsmasq restart
echo "DoH configured: cloudflare on port 5053"