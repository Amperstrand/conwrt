# --- net-roles: uplinks=wwan(m5) serve_eth=True serve_wifi=True mgmt_vlan=off ---
# --- net-roles: wifi uplink wwan (STA on radio0) ---
uci -q revert network.wwan || true
uci set network.wwan=interface
uci set network.wwan.proto='dhcp'
uci -q revert wireless.wwansta || true
uci set wireless.wwansta=wifi-iface
uci set wireless.wwansta.device='radio0'
uci set wireless.wwansta.mode='sta'
uci set wireless.wwansta.network='wwan'
uci set wireless.wwansta.ssid='BenchAP'
uci set wireless.wwansta.encryption='psk2'
uci set wireless.wwansta.key='benchpass1'
uci set wireless.radio0.disabled='0'
for z in $(uci -q show firewall | sed -n 's/^firewall\.\([^.]*\)=zone$/\1/p'); do if [ "$(uci -q get firewall.$z.name)" = "wan" ]; then uci -q get firewall.$z.network 2>/dev/null | tr ' ' '\n' | grep -qxF 'wwan' || uci add_list firewall.$z.network='wwan'; fi; done
for w in $(uci -q show wireless | sed -n 's/^wireless\.\([^.]*\)=wifi-iface$/\1/p'); do [ "$(uci -q get wireless.$w.device)" = "radio0" ] && [ "$w" != "wwansta" ] && uci set wireless.$w.disabled=1; done; true
# --- net-roles: failover metrics (lower wins; sim section may be owned by tollgate-cellular) ---
uci set network.wwan.metric='5'
# --- net-roles: readbacks (gate the commits — staged values are visible to uci get) ---
[ "$(uci -q get network.wwan.metric)" = "5" ] || { echo "net-roles: wwan metric readback FAILED"; exit 1; }
uci commit network
uci commit wireless
uci commit firewall

/etc/init.d/network reload
wifi reload 2>/dev/null; true
echo "net-roles applied: uplinks=1 serve_eth=True serve_wifi=True mgmt=lan"