# --- mwan3 multi-WAN ---
uci -q delete mwan3 >/dev/null 2>&1 || true

uci set mwan3.wan=interface
uci set mwan3.wan.enabled='1'
uci add_list mwan3.wan.track_ip='9.9.9.9'
uci add_list mwan3.wan.track_ip='149.112.112.112'
uci set mwan3.wan.family='ipv4'
uci set mwan3.wan.reliability='1'
uci set mwan3.wan.count='1'
uci set mwan3.wan.timeout='2'
uci set mwan3.wan.interval='5'
uci set mwan3.wan.down='3'
uci set mwan3.wan.up='8'

uci set mwan3.wwan=interface
uci set mwan3.wwan.enabled='1'
uci add_list mwan3.wwan.track_ip='9.9.9.9'
uci add_list mwan3.wwan.track_ip='149.112.112.112'
uci set mwan3.wwan.family='ipv4'
uci set mwan3.wwan.reliability='1'
uci set mwan3.wwan.count='1'
uci set mwan3.wwan.timeout='2'
uci set mwan3.wwan.interval='5'
uci set mwan3.wwan.down='3'
uci set mwan3.wwan.up='8'

uci set mwan3.wan_m1_w2=member
uci set mwan3.wan_m1_w2.interface='wan'
uci set mwan3.wan_m1_w2.metric='1'
uci set mwan3.wan_m1_w2.weight='2'
uci set mwan3.wwan_m1_w1=member
uci set mwan3.wwan_m1_w1.interface='wwan'
uci set mwan3.wwan_m1_w1.metric='1'
uci set mwan3.wwan_m1_w1.weight='1'

uci set mwan3.wan_policy=policy
uci add_list mwan3.wan_policy.use_member='wan_m1_w2'
uci add_list mwan3.wan_policy.use_member='wwan_m1_w1'
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
echo "mwan3 configured: wan (primary) + wwan (balanced)"