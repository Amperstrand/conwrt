# --- Dynamic DNS (custom) ---
uci -q delete ddns.myddns >/dev/null 2>&1 || true
uci set ddns.myddns=service
uci set ddns.myddns.enabled='1'
uci set ddns.myddns.domain='router.example.net'
uci set ddns.myddns.username='svc'
uci set ddns.myddns.password='s3cr3t'
uci set ddns.myddns.use_https='1'
uci set ddns.myddns.lookup_host='router.example.net'
uci set ddns.myddns.check_interval='600'
uci set ddns.myddns.check_unit='seconds'
uci set ddns.myddns.force_interval='2592000'
uci set ddns.myddns.force_unit='seconds'
uci set ddns.myddns.update_url='https://upd.example.com/nic/update?hostname='
uci commit ddns
/etc/init.d/ddns enable
/etc/init.d/ddns restart