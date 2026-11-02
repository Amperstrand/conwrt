# --- fleet identity (MAC-derived, deterministic) ---
_mac=$(cat /sys/class/net/eth0/address) && _m=$(printf '%s' "$_mac" | tr -d ':') && _pw=$(printf '%s' "conwrt-fleet-v1:root:benchsalt0123456789abcdef:$_m" | sha256sum | cut -c1-20) && _wpw=$(printf '%s' "conwrt-fleet-v1:wifi:fleet:benchsalt0123456789abcdef:$_m" | sha256sum | cut -c1-20) && printf '%s\n%s\n' "$_pw" "$_pw" | passwd root && uci set system.@system[0].hostname="fleet-$_m" && uci commit system && mkdir -p /etc/fleet && printf 'derivation=%s\nmac=%s\nhostname=%s-%s\n' 'conwrt-fleet-v1' '$_mac' 'fleet' '$_m' > /etc/fleet/identity

# --- management AP: fleet_<mac12>, wifi-domain key ---
if uci -q get wireless.radio0 >/dev/null 2>&1 && uci -q get wireless.default_radio0 >/dev/null 2>&1; then uci set wireless.radio0.disabled="0"; uci set wireless.default_radio0.ssid="fleet_$_m"; uci set wireless.default_radio0.encryption="psk2"; uci set wireless.default_radio0.key="$_wpw"; uci set wireless.default_radio0.network="lan"; uci commit wireless; wifi reload 2>/dev/null || true; fi

# --- rogue-DHCP disarm (Rogue-DHCP Discipline) ---
uci set dhcp.lan.ignore='1'
uci set dhcp.lan.ra='disabled'
uci set dhcp.lan.dhcpv6='disabled'
uci commit dhcp
/etc/init.d/dnsmasq restart
/etc/init.d/odhcpd restart
echo fleet-identity dhcp.lan.ignore=$(uci get dhcp.lan.ignore)