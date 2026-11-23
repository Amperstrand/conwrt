# --- Dynamic DNS (cloudflare) ---
uci -q delete ddns.myddns >/dev/null 2>&1 || true
uci set ddns.myddns=service
uci set ddns.myddns.enabled='1'
uci set ddns.myddns.domain='home.example.org'
uci set ddns.myddns.username=''
uci set ddns.myddns.password='tok123'
uci set ddns.myddns.use_https='1'
uci set ddns.myddns.lookup_host='home.example.org'
uci set ddns.myddns.check_interval='300'
uci set ddns.myddns.check_unit='seconds'
uci set ddns.myddns.force_interval='2592000'
uci set ddns.myddns.force_unit='seconds'
uci set ddns.myddns.service_name='cloudflare.com/v4'
uci commit ddns
/etc/init.d/ddns enable
/etc/init.d/ddns restart