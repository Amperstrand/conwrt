# golden: conwrt 1.x output of scripts/use_cases/tollgate_security.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- TollGate Security: RFC 1918 isolation ---
uci set firewall.Block-LAN-To-RFC1918-10=rule
uci set firewall.Block-LAN-To-RFC1918-10.name='Block-LAN-To-RFC1918-10'
uci set firewall.Block-LAN-To-RFC1918-10.src='lan'
uci set firewall.Block-LAN-To-RFC1918-10.dest='wan'
uci set firewall.Block-LAN-To-RFC1918-10.dest_ip='10.0.0.0/8'
uci set firewall.Block-LAN-To-RFC1918-10.proto='all'
uci set firewall.Block-LAN-To-RFC1918-10.family='ipv4'
uci set firewall.Block-LAN-To-RFC1918-10.target='DROP'
#   Block-LAN-To-RFC1918-10: RFC 1918 private (class A)
uci set firewall.Block-LAN-To-RFC1918-172=rule
uci set firewall.Block-LAN-To-RFC1918-172.name='Block-LAN-To-RFC1918-172'
uci set firewall.Block-LAN-To-RFC1918-172.src='lan'
uci set firewall.Block-LAN-To-RFC1918-172.dest='wan'
uci set firewall.Block-LAN-To-RFC1918-172.dest_ip='172.16.0.0/12'
uci set firewall.Block-LAN-To-RFC1918-172.proto='all'
uci set firewall.Block-LAN-To-RFC1918-172.family='ipv4'
uci set firewall.Block-LAN-To-RFC1918-172.target='DROP'
#   Block-LAN-To-RFC1918-172: RFC 1918 private (class B)
uci set firewall.Block-LAN-To-RFC1918-192=rule
uci set firewall.Block-LAN-To-RFC1918-192.name='Block-LAN-To-RFC1918-192'
uci set firewall.Block-LAN-To-RFC1918-192.src='lan'
uci set firewall.Block-LAN-To-RFC1918-192.dest='wan'
uci set firewall.Block-LAN-To-RFC1918-192.dest_ip='192.168.0.0/16'
uci set firewall.Block-LAN-To-RFC1918-192.proto='all'
uci set firewall.Block-LAN-To-RFC1918-192.family='ipv4'
uci set firewall.Block-LAN-To-RFC1918-192.target='DROP'
#   Block-LAN-To-RFC1918-192: RFC 1918 private (class C — ISP router LAN)
uci set firewall.Block-LAN-To-RFC1918-LL=rule
uci set firewall.Block-LAN-To-RFC1918-LL.name='Block-LAN-To-RFC1918-LL'
uci set firewall.Block-LAN-To-RFC1918-LL.src='lan'
uci set firewall.Block-LAN-To-RFC1918-LL.dest='wan'
uci set firewall.Block-LAN-To-RFC1918-LL.dest_ip='169.254.0.0/16'
uci set firewall.Block-LAN-To-RFC1918-LL.proto='all'
uci set firewall.Block-LAN-To-RFC1918-LL.family='ipv4'
uci set firewall.Block-LAN-To-RFC1918-LL.target='DROP'
#   Block-LAN-To-RFC1918-LL: RFC 3927 link-local (mDNS, SSDP)
uci commit firewall
/etc/init.d/firewall restart
# --- WiFi client isolation ---
for _s in $(uci show wireless 2>/dev/null | grep '=wifi-iface' | cut -d. -f2 | cut -d= -f1); do uci set wireless.$_s.isolate='1'; done; true
uci commit wireless
wifi reload