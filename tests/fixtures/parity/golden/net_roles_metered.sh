# --- net-roles: uplinks=wwan(m5) wwan0(m100) serve_eth=True serve_wifi=True mgmt_vlan=off ---
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
uci set network.wwan0.metric='100'
# --- net-roles: readbacks (gate the commits — staged values are visible to uci get) ---
[ "$(uci -q get network.wwan.metric)" = "5" ] || { echo "net-roles: wwan metric readback FAILED"; exit 1; }
[ "$(uci -q get network.wwan0.metric)" = "100" ] || { echo "net-roles: wwan0 metric readback FAILED"; exit 1; }
uci commit network
uci commit wireless
uci commit firewall

/etc/init.d/network reload
wifi reload 2>/dev/null; true
echo "net-roles applied: uplinks=2 serve_eth=True serve_wifi=True mgmt=lan"

# --- net-roles: metered-guard (wwan0 metered; wwan free — non-client forwarding rejected while free is up) ---
mkdir -p "$(dirname /usr/bin/metered-guard)" && printf '%s' '#!/bin/sh
# metered-guard: no non-revenue traffic on the metered uplink while a
# free uplink is alive. Arms an nftables reject (with counter) for
# forwarded traffic leaving the metered interface UNLESS the source IP
# belongs to a nodogsplash-authenticated (paying) client. The whole
# table exists only while armed — disarm removes it, restoring the
# ungated baseline exactly.
CONF=${GUARD_CONF:-/etc/tollgate/metered-guard.conf}
NFT=${GUARD_NFT:-nft}
NDSCTL=${GUARD_NDSCTL:-ndsctl}
log() { ${GUARD_LOGGER:-logger} -t metered-guard "$@"; }
get_opt() { sed -n "s/^$1=//p" "$CONF" 2>/dev/null | head -1; }

ARMED=0

iface_up() {
    ubus call network.interface."$1" status 2>/dev/null | grep -q '\''"up":[ ]*true'\''
}

free_up() {
    for f in $(get_opt free_ifaces | tr '\'','\'' '\'' '\''); do
        [ -n "$f" ] || continue
        iface_up "$f" && return 0
    done
    return 1
}

auth_ips() {
    $NDSCTL json 2>/dev/null | awk '\''
        match($0, /"ip"[ ]*:[ ]*"[0-9.]+"/) {
            t = substr($0, RSTART, RLENGTH)
            gsub(/[^0-9.]/, "", t)
            ip = t
        }
        match($0, /"state"[ ]*:[ ]*"[A-Za-z]+"/) {
            t = substr($0, RSTART, RLENGTH)
            if (t ~ /uthenticated/ && ip != "") print ip
            ip = ""
        }'\''
}

arm() {
    M=$(get_opt metered_iface); [ -n "$M" ] || M=wan
    DEV=$(ubus call network.interface."$M" status 2>/dev/null \
        | grep -o '\''"device":[ ]*"[^"]*"'\'' | head -1 | cut -d'\''"'\'' -f4)
    if [ -z "$DEV" ]; then
        log "metered iface $M not ready (no device yet) — retrying next loop"
        return 1
    fi
    M="$DEV"
    BATCH=/tmp/metered-guard.arm.$$
    {
        echo "add table inet metered_guard"
        echo "add set inet metered_guard allowed '\''{ type ipv4_addr; flags interval; }'\''"
        echo "add chain inet metered_guard mg_fwd '\''{ type filter hook forward priority -1; policy accept; }'\''"
        for ip in $(auth_ips); do
            echo "add element inet metered_guard allowed { $ip }"
        done
        echo "add rule inet metered_guard mg_fwd oifname \"$M\" ip saddr != @allowed counter reject"
        echo "add rule inet metered_guard mg_fwd oifname \"$M\" meta nfproto ipv6 counter reject"
    } > "$BATCH"
    if $NFT -f "$BATCH" >/dev/null 2>&1; then
        ARMED=1
        log "ARMED: free uplink up — non-client traffic to $M now rejected (counter on rule)"
    else
        log "arm batch failed — retrying next loop"
    fi
    rm -f "$BATCH"
}

sync_allowed() {
    BATCH=/tmp/metered-guard.sync.$$
    {
        echo "flush set inet metered_guard allowed"
        for ip in $(auth_ips); do
            echo "add element inet metered_guard allowed { $ip }"
        done
    } > "$BATCH"
    $NFT -f "$BATCH" >/dev/null 2>&1
    rm -f "$BATCH"
}

disarm() {
    $NFT delete table inet metered_guard 2>/dev/null
    ARMED=0
    log "DISARMED: no free uplink — metered iface back to normal routing"
}

sync_allowed() {
    $NFT flush set inet metered_guard allowed 2>/dev/null
    for ip in $(auth_ips); do
        $NFT add element inet metered_guard allowed "{ $ip }" 2>/dev/null
    done
}

case "$1" in
    --status)
        $NFT list table inet metered_guard >/dev/null 2>&1 && echo "armed" || echo "disarmed"
        $NFT list table inet metered_guard 2>/dev/null | grep -E '\''reject|elements'\''
        ;;
    --once) free_up && { [ "$ARMED" = 1 ] || arm; sync_allowed; } || disarm ;;
    --watch)
        $NFT list table inet metered_guard >/dev/null 2>&1 && ARMED=1
        INT=$(get_opt interval); [ -n "$INT" ] || INT=15
        while true; do
            if free_up; then
                [ "$ARMED" = 1 ] || arm
                sync_allowed
            else
                [ "$ARMED" = 0 ] || disarm
            fi
            sleep "$INT"
        done
        ;;
esac
' > /usr/bin/metered-guard && chmod 755 /usr/bin/metered-guard
mkdir -p "$(dirname /etc/tollgate/metered-guard.conf)" && printf '%s' 'metered_iface=wwan0
free_ifaces=wwan
interval=45
' > /etc/tollgate/metered-guard.conf && chmod 600 /etc/tollgate/metered-guard.conf
mkdir -p "$(dirname /etc/init.d/metered-guard)" && printf '%s' '#!/bin/sh /etc/rc.common
START=96
USE_PROCD=1
stop_service() {
    nft delete table inet metered_guard 2>/dev/null
    logger -t metered-guard "stopped — guard table removed"
}
start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/metered-guard --watch
    procd_set_param respawn 3600 5 0
    procd_close_instance
}
' > /etc/init.d/metered-guard && chmod 755 /etc/init.d/metered-guard
/etc/init.d/metered-guard enable
/etc/init.d/metered-guard restart
[ -x /usr/bin/metered-guard ] && [ -f /etc/tollgate/metered-guard.conf ] || { echo "net-roles: metered-guard staging FAILED"; exit 1; }