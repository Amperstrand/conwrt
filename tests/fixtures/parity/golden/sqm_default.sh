# --- SQM Smart Queue Management ---
for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; true

_sqm_dev=$(uci get network.wan.device 2>/dev/null); if [ -z "$_sqm_dev" ] || ! ip addr show "$_sqm_dev" 2>/dev/null | grep -q "inet "; then _sqm_dev=$(ip route show default 0.0.0.0/0 2>/dev/null | awk '{print $5}' | head -1); fi; if [ -z "$_sqm_dev" ]; then _sqm_dev=wan; fi
uci set sqm.wan=queue
uci set sqm.wan.interface="$_sqm_dev"
uci set sqm.wan.enabled='1'
uci set sqm.wan.script='piece_of_cake.qos'
uci set sqm.wan.qdisc='cake'
uci set sqm.wan.linklayer='none'
uci set sqm.wan.overhead='0'
uci set sqm.wan.download='340000'
uci set sqm.wan.upload='19000'
uci set sqm.wan.linklayer_adaptation_mechanism='default'
uci set sqm.wan.debug_logging='0'
uci set sqm.wan.verbosity='5'
uci commit sqm

/etc/init.d/sqm enable
/etc/init.d/sqm restart
echo "SQM configured: 340000/19000 kbit/s (cake) on $_sqm_dev"