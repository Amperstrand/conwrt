# --- net-roles: uplinks=waneth(m5) serve_eth=True serve_wifi=True mgmt_vlan=20 ---
# --- net-roles: ethernet uplink waneth on tagged eth0.10 ---
uci set network.dev_waneth=device
uci set network.dev_waneth.type='8021q'
uci set network.dev_waneth.name='eth0.10'
uci set network.dev_waneth.ifname='eth0'
uci set network.dev_waneth.vid='10'
uci set network.waneth=interface
uci -q revert network.waneth || true
uci set network.waneth.proto='dhcp'
uci set network.waneth.device='eth0.10'
for z in $(uci -q show firewall | sed -n 's/^firewall\.\([^.]*\)=zone$/\1/p'); do if [ "$(uci -q get firewall.$z.name)" = "wan" ]; then uci -q get firewall.$z.network 2>/dev/null | tr ' ' '\n' | grep -qxF 'waneth' || uci add_list firewall.$z.network='waneth'; fi; done
# --- net-roles: mgmt door eth0.20 (static, lan zone) ---
uci set network.mgmtdev=device
uci set network.mgmtdev.type='8021q'
uci set network.mgmtdev.name='eth0.20'
uci set network.mgmtdev.ifname='eth0'
uci set network.mgmtdev.vid='20'
uci set network.mgmt=interface
uci -q revert network.mgmt || true
uci set network.mgmt.proto='static'
uci set network.mgmt.device='eth0.20'
uci set network.mgmt.ipaddr='192.168.20.1'
uci set network.mgmt.netmask='255.255.255.0'
for z in $(uci -q show firewall | sed -n 's/^firewall\.\([^.]*\)=zone$/\1/p'); do if [ "$(uci -q get firewall.$z.name)" = "lan" ]; then uci -q get firewall.$z.network 2>/dev/null | tr ' ' '\n' | grep -qxF 'mgmt' || uci add_list firewall.$z.network='mgmt'; fi; done
# --- net-roles: failover metrics (lower wins; sim section may be owned by tollgate-cellular) ---
uci set network.waneth.metric='5'
# --- net-roles: readbacks (gate the commits — staged values are visible to uci get) ---
[ "$(uci -q get network.waneth.device)" = "eth0.10" ] && [ "$(uci -q get network.waneth.proto)" = dhcp ] || { echo "net-roles: waneth readback FAILED"; exit 1; }
[ "$(uci -q get network.waneth.metric)" = "5" ] || { echo "net-roles: waneth metric readback FAILED"; exit 1; }
[ "$(uci -q get network.mgmt.ipaddr)" = "192.168.20.1" ] || { echo "net-roles: mgmt readback FAILED"; exit 1; }
uci commit network
uci commit firewall

/etc/init.d/network reload
echo "net-roles applied: uplinks=1 serve_eth=True serve_wifi=True mgmt=20"