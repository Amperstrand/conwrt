# --- Travelmate travel router ---
uci set travelmate.global.trm_enabled='1'
uci set travelmate.global.trm_automatic='1'
uci set travelmate.global.trm_captive='0'
uci set travelmate.global.trm_timeout='90'
uci set travelmate.global.trm_retry='3'
uci set travelmate.global.trm_radio='radio1'
uci set travelmate.global.trm_iface='trm_wwan'
uci set travelmate.global.trm_uplink='trm_wwan'
# --- Seeded uplinks (travelmate setup shape) ---
uci set network.trm_wwan=interface
uci set network.trm_wwan.proto='dhcp'
uci set network.trm_wwan.metric='100'
uci set network.trm_wwan6=interface
uci set network.trm_wwan6.device='@trm_wwan'
uci set network.trm_wwan6.proto='dhcpv6'
for _z in $(uci show firewall 2>/dev/null | grep '=zone' | cut -d. -f2 | cut -d= -f1 || true); do if [ "$(uci -q get firewall."$_z".name)" = 'wan' ]; then uci -q del_list firewall."$_z".network='trm_wwan' 2>/dev/null; uci add_list firewall."$_z".network='trm_wwan'; else uci -q del_list firewall."$_z".network='trm_wwan' 2>/dev/null; fi; done; true
for _z in $(uci show firewall 2>/dev/null | grep '=zone' | cut -d. -f2 | cut -d= -f1 || true); do if [ "$(uci -q get firewall."$_z".name)" = 'wan' ]; then uci -q del_list firewall."$_z".network='trm_wwan6' 2>/dev/null; uci add_list firewall."$_z".network='trm_wwan6'; else uci -q del_list firewall."$_z".network='trm_wwan6' 2>/dev/null; fi; done; true
uci set wireless.trm_uplink1=wifi-iface
uci set wireless.trm_uplink1.device='radio0'
uci set wireless.trm_uplink1.mode='sta'
uci set wireless.trm_uplink1.network='trm_wwan'
uci set wireless.trm_uplink1.ssid='HotelNet'
uci set wireless.trm_uplink1.encryption='psk2'
uci set wireless.trm_uplink1.key='guestpass'
uci set travelmate.trm_uplink1=uplink
uci set travelmate.trm_uplink1.device='radio0'
uci set travelmate.trm_uplink1.ssid='HotelNet'
uci set travelmate.trm_uplink1.enabled='1'
uci set wireless.trm_uplink2=wifi-iface
uci set wireless.trm_uplink2.device='radio1'
uci set wireless.trm_uplink2.mode='sta'
uci set wireless.trm_uplink2.network='trm_wwan'
uci set wireless.trm_uplink2.ssid='CafeOpen'
uci set wireless.trm_uplink2.encryption='none'
uci set travelmate.trm_uplink2=uplink
uci set travelmate.trm_uplink2.device='radio1'
uci set travelmate.trm_uplink2.ssid='CafeOpen'
uci set travelmate.trm_uplink2.enabled='1'
uci commit network
uci commit wireless
wifi reload; ubus call network.interface.trm_wwan up 2>/dev/null; true

uci commit travelmate
/etc/init.d/travelmate enable
/etc/init.d/travelmate restart
echo "Travelmate configured: auto-connect on radio1 (2 uplinks)"