# --- net-roles: uplinks=none serve_eth=True serve_wifi=True mgmt_vlan=off ---
# --- net-roles: readbacks (gate the commits — staged values are visible to uci get) ---
uci commit network
uci commit firewall

/etc/init.d/network reload
echo "net-roles applied: uplinks=0 serve_eth=True serve_wifi=True mgmt=lan"