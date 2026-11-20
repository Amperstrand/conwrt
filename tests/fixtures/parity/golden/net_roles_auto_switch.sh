# --- net-roles: uplinks=waneth(m5) serve_eth=True serve_wifi=True mgmt_vlan=off ---
# --- net-roles: ethernet uplink waneth on tagged eth0.10 ---
uci set network.dev_waneth=device
uci set network.dev_waneth.type='8021q'
uci set network.dev_waneth.name='eth0.10'
uci set network.dev_waneth.ifname='eth0'
uci set network.dev_waneth.vid='10'
uci -q revert network.waneth || true
uci set network.waneth=interface
uci set network.waneth.proto='dhcp'
uci set network.waneth.device='eth0.10'
for z in $(uci -q show firewall | sed -n 's/^firewall\.\([^.]*\)=zone$/\1/p'); do if [ "$(uci -q get firewall.$z.name)" = "wan" ]; then uci -q get firewall.$z.network 2>/dev/null | tr ' ' '\n' | grep -qxF 'waneth' || uci add_list firewall.$z.network='waneth'; fi; done
# --- net-roles: failover metrics (lower wins; sim section may be owned by tollgate-cellular) ---
uci set network.waneth.metric='5'
# --- net-roles: readbacks (gate the commits — staged values are visible to uci get) ---
[ "$(uci -q get network.waneth.device)" = "eth0.10" ] && [ "$(uci -q get network.waneth.proto)" = dhcp ] || { echo "net-roles: waneth readback FAILED"; exit 1; }
[ "$(uci -q get network.waneth.metric)" = "5" ] || { echo "net-roles: waneth metric readback FAILED"; exit 1; }
uci commit network
uci commit firewall

/etc/init.d/network reload
echo "net-roles applied: uplinks=1 serve_eth=True serve_wifi=True mgmt=lan"

# --- net-roles: tollgate-mode engine (active-uplink price switch + WPS button override) ---
mkdir -p "$(dirname /etc/tollgate/mode.conf)" && printf '%s' 'waneth 5 3
' > /etc/tollgate/mode.conf && chmod 600 /etc/tollgate/mode.conf
mkdir -p "$(dirname /usr/bin/tollgate-mode)" && printf '%s' '#!/bin/sh
# Watches the configured uplinks; when the active (lowest-metric live)
# uplink changes, rewrites tollgate pricing for it. The WPS button
# rotates a manual override (auto -> uplink1 -> uplink2 -> ... -> auto).
# Network failover itself is netifd metrics — this adapts the TOLLGATE
# to whichever uplink is winning, e.g. cheap/free eth primary with the
# metered SIM priced higher once it takes over.
CONF=${TOLLGATE_MODE_CONF:-/etc/tollgate/mode.conf}
OVR=${TOLLGATE_MODE_OVERRIDE:-/etc/tollgate/mode.override}
STATE=${TOLLGATE_MODE_STATE:-/tmp/tollgate-mode.state}
TGJSON=${TOLLGATE_MODE_JSON:-/etc/tollgate/config.json}
log() { ${TOLLGATE_MODE_LOGGER:-logger} -t tollgate-mode "$@"; }

apply_price() {
    [ "$1" = "-" ] && return 0
    [ -f "$TGJSON" ] || return 0
    CUR=$(sed -n '\''s/.*"price_per_step":[ ]*\([0-9][0-9]*\).*/\1/p'\'' "$TGJSON" | head -1)
    [ "$CUR" = "$1" ] && return 0
    SS=$(sed -n '\''s/.*"step_size":[ ]*\([0-9][0-9]*\).*/\1/p'\'' "$TGJSON" | head -1)
    [ -n "$SS" ] || SS=1048576
    P=$(( ( $1 * SS + 1048575 ) / 1048576 ))
    sed -i "s/\"price_per_step\":[ ]*[0-9]*/\"price_per_step\": $P/g" "$TGJSON" \
        && { /etc/init.d/tollgate-wrt restart >/dev/null 2>&1 || true; } \
        && log "price -> $1 sat/MiB (step_size $SS -> $P)" \
        || log "price patch FAILED"
}

iface_up() {
    ubus call network.interface."$1" status 2>/dev/null | grep -q '\''"up":[ ]*true'\''
}

pick_active() {
    OVRN=$(cat "$OVR" 2>/dev/null)
    if [ -n "$OVRN" ] && [ "$OVRN" != "auto" ]; then
        iface_up "$OVRN" && { echo "$OVRN"; return 0; }
        log "override $OVRN is down — falling back to auto"
    fi
    sort -k2 -n "$CONF" | while read IF M PR; do
        iface_up "$IF" && { echo "$IF"; return 0; }
    done
}

evaluate() {
    LAST=$(cat "$STATE" 2>/dev/null)
    A=$(pick_active)
    [ -n "$A" ] || { log "no live uplink — holding last state"; return 0; }
    [ "$A" = "$LAST" ] && return 0
    echo "$A" > "$STATE"
    PR=$(awk -v i="$A" '\''$1 == i {print $3}'\'' "$CONF")
    [ -n "$PR" ] || PR=-
    apply_price "$PR"
    log "active uplink: $A (price $PR)"
}

rotate_button() {
    CUR=$(cat "$OVR" 2>/dev/null)
    [ -n "$CUR" ] || CUR=auto
    N=auto
    PREV=""
    for i in auto $(awk '\''{printf "%s ", $1}'\'' "$CONF"); do
        if [ -n "$PREV" ] && [ "$PREV" = "$CUR" ]; then N=$i; break; fi
        PREV=$i
    done
    echo "$N" > "$OVR"
    log "button: override -> $N"
    evaluate
}

case "$1" in
    --button) rotate_button ;;
    --watch)
        while true; do
            evaluate
            sleep ${TOLLGATE_MODE_INTERVAL:-10}
        done
        ;;
    *) evaluate ;;
esac
' > /usr/bin/tollgate-mode && chmod 755 /usr/bin/tollgate-mode
mkdir -p "$(dirname /etc/init.d/tollgate-mode)" && printf '%s' '#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/tollgate-mode --watch
    procd_set_param env TOLLGATE_MODE_INTERVAL=15
    procd_set_param respawn 3600 5 0
    procd_close_instance
}
' > /etc/init.d/tollgate-mode && chmod 755 /etc/init.d/tollgate-mode
mkdir -p "$(dirname /etc/hotplug.d/iface/90-tollgate-mode)" && printf '%s' '#!/bin/sh
[ "$ACTION" = "ifup" ] || [ "$ACTION" = "ifdown" ] || exit 0
/usr/bin/tollgate-mode >/dev/null 2>&1 &
' > /etc/hotplug.d/iface/90-tollgate-mode && chmod 755 /etc/hotplug.d/iface/90-tollgate-mode
mkdir -p "$(dirname /etc/rc.button/wps)" && printf '%s' '#!/bin/sh
[ "$BUTTON" = "wps" ] || exit 0
/usr/bin/tollgate-mode --button >/dev/null 2>&1 &
exit 0
' > /etc/rc.button/wps && chmod 755 /etc/rc.button/wps
rm -f /etc/tollgate/mode.override /tmp/tollgate-mode.state
/etc/init.d/tollgate-mode enable
/etc/init.d/tollgate-mode restart
[ -x /usr/bin/tollgate-mode ] && [ -f /etc/tollgate/mode.conf ] || { echo "net-roles: tollgate-mode staging FAILED"; exit 1; }