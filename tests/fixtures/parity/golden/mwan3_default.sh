# --- mwan3 multi-WAN ---
uci -q delete mwan3 >/dev/null 2>&1 || true

uci set mwan3.wan=interface
uci set mwan3.wan.enabled='1'
uci add_list mwan3.wan.track_ip='1.0.0.1'
uci add_list mwan3.wan.track_ip='1.1.1.1'
uci add_list mwan3.wan.track_ip='8.8.8.8'
uci add_list mwan3.wan.track_ip='8.8.4.4'
uci set mwan3.wan.family='ipv4'
uci set mwan3.wan.reliability='1'
uci set mwan3.wan.count='1'
uci set mwan3.wan.timeout='2'
uci set mwan3.wan.interval='5'
uci set mwan3.wan.down='3'
uci set mwan3.wan.up='8'

uci set mwan3.usbwan=interface
uci set mwan3.usbwan.enabled='1'
uci add_list mwan3.usbwan.track_ip='1.0.0.1'
uci add_list mwan3.usbwan.track_ip='1.1.1.1'
uci add_list mwan3.usbwan.track_ip='8.8.8.8'
uci add_list mwan3.usbwan.track_ip='8.8.4.4'
uci set mwan3.usbwan.family='ipv4'
uci set mwan3.usbwan.reliability='1'
uci set mwan3.usbwan.count='1'
uci set mwan3.usbwan.timeout='2'
uci set mwan3.usbwan.interval='5'
uci set mwan3.usbwan.down='3'
uci set mwan3.usbwan.up='8'

uci set mwan3.wan_m1_w1=member
uci set mwan3.wan_m1_w1.interface='wan'
uci set mwan3.wan_m1_w1.metric='1'
uci set mwan3.wan_m1_w1.weight='1'
uci set mwan3.usbwan_m2_w1=member
uci set mwan3.usbwan_m2_w1.interface='usbwan'
uci set mwan3.usbwan_m2_w1.metric='2'
uci set mwan3.usbwan_m2_w1.weight='1'

uci set mwan3.wan_policy=policy
uci add_list mwan3.wan_policy.use_member='wan_m1_w1'
uci add_list mwan3.wan_policy.use_member='usbwan_m2_w1'
uci set mwan3.wan_policy.last_resort='default'

uci set mwan3.default_rule_v4=rule
uci set mwan3.default_rule_v4.dest_ip='0.0.0.0/0'
uci set mwan3.default_rule_v4.use_policy='wan_policy'
uci set mwan3.default_rule_v4.family='ipv4'
uci set mwan3.https_rule=rule
uci set mwan3.https_rule.dest_port='443'
uci set mwan3.https_rule.proto='tcp'
uci set mwan3.https_rule.sticky='1'
uci set mwan3.https_rule.use_policy='wan_policy'

uci commit mwan3
/etc/init.d/mwan3 restart
echo "mwan3 configured: wan (primary) + usbwan (failover)"