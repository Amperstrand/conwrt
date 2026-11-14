# --- net-roles: uplinks=none serve_eth=True serve_wifi=True mgmt_vlan=off ---
# --- net-roles: readbacks (gate the commits — staged values are visible to uci get) ---
uci commit network
uci commit firewall

/etc/init.d/network reload
echo "net-roles applied: uplinks=0 serve_eth=True serve_wifi=True mgmt=lan"

# --- net-roles: conn-adapter (client-first ladder: probe/discriminate/adopt/yield; vlans=[10, 20] serve_when_greenfield=1) ---
mkdir -p "$(dirname /usr/share/conn-adapter/probe-noop.sh)" && printf '%s' '#!/bin/sh
# udhcpc event script that applies NOTHING. conn-adapter records the
# offered lease fields (incl. DHCP option 54, the server identifier) so
# the probe stays side-effect-free — the same trick dnsmasq'\''s own
# dhcp_check has used since r39152.
case "$1" in
    bound|renew)
        {
            echo "serverid=$serverid"
            echo "ip=$ip"
            echo "mask=$subnet"
            echo "router=${router%% *}"
        } > "$PROBEINFO"
        ;;
esac
exit 0
' > /usr/share/conn-adapter/probe-noop.sh && chmod 755 /usr/share/conn-adapter/probe-noop.sh
mkdir -p "$(dirname /usr/bin/conn-adapter)" && printf '%s' '#!/bin/sh
# conn-adapter: client-first connectivity adapter.
# Per-interface role ladder with zero-side-effect probing:
#   PROBE  — udhcpc with a no-op script; the server identifier (opt 54)
#            discriminates OUR dhcp server from a FOREIGN one
#   CLIENT — a verified foreign network is adopted as an uplink via
#            netifd (metric per conf) after a pinned-/32 round-trip test
#   SERVER — when greenfield is confirmed, DHCP serving may be armed
#   YIELD  — a foreign DHCP server on the serving bridge strips our
#            dhcp authority immediately and sticky-prevents re-arming
# Never probes away the default route: verification uses host + /32
# routes only, and adoption goes through the normal netifd path.
#
# PLATFORM CAVEAT (verified live on NR7101 / mt7621 DSA / 25.12):
# raw AF_PACKET DHCP discovers (BusyBox udhcpc) do NOT egress a bridged
# DSA port — neither via the bridge master nor a slave (wire-verified
# with tcpdump: zero frames). UDP-socket broadcasts DO egress (the
# device'\''s own dnsmasq answers foreign clients in ~2ms). On such
# platforms the probe is structurally silent: yield detection and VLAN
# adoption stay inert-but-harmless (timeouts count as SILENT; with
# serve_when_greenfield=0 nothing fires). A UDP-socket prober (tiny
# compiled helper or python3-light) is the tracked follow-up that
# re-enables live detection on DSA devices.
CONF=${CONN_ADAPTER_CONF:-/etc/tollgate/conn-adapter.conf}
STATE=${CONN_ADAPTER_STATE:-/tmp/conn-adapter.state}
NOOP=${CONN_ADAPTER_NOOP:-/usr/share/conn-adapter/probe-noop.sh}
PROBEINFO=${CONN_ADAPTER_PROBEINFO:-/tmp/conn-adapter.probe}
log() { ${CONN_ADAPTER_LOGGER:-logger} -t conn-adapter "$@"; }

get_opt() { sed -n "s/^$1=//p" "$CONF" 2>/dev/null | head -1; }

PROBE_KIND=""; PROBE_SID=""
probe() {
    rm -f "$PROBEINFO"
    PROBEINFO="$PROBEINFO" udhcpc -n -q -s "$NOOP" -T 3 -t 4 -i "$1" >/dev/null 2>&1
    PROBE_SID=$(sed -n '\''s/^serverid=//p'\'' "$PROBEINFO" 2>/dev/null | head -1)
    [ -n "$PROBE_SID" ] || return 1
    if ip -4 addr show 2>/dev/null | grep -q "inet $PROBE_SID/"; then
        PROBE_KIND=OURS
    else
        PROBE_KIND=FOREIGN
    fi
    return 0
}

verify() {
    IP=$(sed -n '\''s/^ip=//p'\'' "$PROBEINFO" | head -1)
    MASK=$(sed -n '\''s/^mask=//p'\'' "$PROBEINFO" | head -1)
    GW=$(sed -n '\''s/^router=//p'\'' "$PROBEINFO" | head -1)
    DEV=$(sed -n '\''s/^dev=//p'\'' "$PROBEINFO" | head -1)
    [ -n "$IP" ] && [ -n "$GW" ] && [ -n "$DEV" ] || return 1
    ip addr add "$IP/$MASK" dev "$DEV" 2>/dev/null
    ip route add "$GW" dev "$DEV" 2>/dev/null
    ip route add 1.1.1.1/32 via "$GW" dev "$DEV" 2>/dev/null
    ping -I "$DEV" -c 1 -W 2 1.1.1.1 >/dev/null 2>&1
    RC=$?
    ip route del 1.1.1.1/32 dev "$DEV" 2>/dev/null
    ip route del "$GW" dev "$DEV" 2>/dev/null
    ip addr del "$IP/$MASK" dev "$DEV" 2>/dev/null
    return $RC
}

adopt() {
    WANIF=$(get_opt wan_iface); [ -n "$WANIF" ] || WANIF=waneth
    METRIC=$(get_opt wan_metric); [ -n "$METRIC" ] || METRIC=100
    BASE=$(get_opt base_port); [ -n "$BASE" ] || BASE=eth0
    DEV="$BASE.$1"
    uci set network.$WANIF=interface
    uci set network.$WANIF.proto='\''dhcp'\''
    uci set network.$WANIF.device="$DEV"
    uci set network.$WANIF.metric="$METRIC"
    for z in $(uci -q show firewall | sed -n '\''s/^firewall\.\([^.]*\)=zone$/\1/p'\''); do
        if [ "$(uci -q get firewall.$z.name)" = "wan" ]; then
            uci -q get firewall.$z.network 2>/dev/null | tr '\'' '\'' '\''\n'\'' | grep -qxF "$WANIF" \
                || uci add_list firewall.$z.network="$WANIF"
        fi
    done
    [ "$(uci -q get network.$WANIF.device)" = "$DEV" ] || { log "adopt readback FAILED"; return 1; }
    uci commit network
    uci commit firewall
    ifup "$WANIF"
    echo "$DEV" > "$STATE.adopted"
    log "adopted $DEV as $WANIF (metric $METRIC) after verified round-trip"
}

uplink_alive() {
    WANIF=$(get_opt wan_iface); [ -n "$WANIF" ] || WANIF=waneth
    [ -f "$STATE.adopted" ] || return 1
    ubus call network.interface."$WANIF" status 2>/dev/null | grep -q '\''"up":[ ]*true'\''
}

probe_vlans() {
    uplink_alive && return 0
    BASE=$(get_opt base_port); [ -n "$BASE" ] || BASE=eth0
    for v in $(get_opt probe_vlans | tr '\'','\'' '\'' '\''); do
        [ -n "$v" ] || continue
        DEV="$BASE.$v"
        ip link show "$DEV" >/dev/null 2>&1 || ip link add "$DEV" type vlan id "$v" 2>/dev/null || true
        ip link set "$DEV" up 2>/dev/null || true
        if probe "$DEV"; then
            [ "$PROBE_KIND" = FOREIGN ] || continue
            echo "dev=$DEV" >> "$PROBEINFO"
            if verify; then
                adopt "$v"
                return 0
            fi
            log "vlan $v: foreign DHCP ($PROBE_SID) but no traffic — not adopted"
        fi
    done
}

serve_watch() {
    IFACE=$(get_opt serve_iface)
    [ -n "$IFACE" ] || return 0
    # Probe bridge MEMBERS, not the bridge: a raw self-sent DHCP discover
    # on a bridge master never loops back into the local receive path, so
    # the serving dnsmasq would never see it (verified live on NR7101).
    BRIF=${CONN_ADAPTER_BRIF:-/sys/class/net/$IFACE/brif}
    FOUND=0
    for m in "$BRIF"/*; do
        [ -e "$m" ] || break
        m=${m##*/}
        [ "$(cat "${CONN_ADAPTER_NETSYS:-/sys/class/net}/$m/operstate" 2>/dev/null)" = "up" ] || continue
        FOUND=1
        probe "$m" || continue
        if [ "$PROBE_KIND" = FOREIGN ]; then
            log "CRITICAL: foreign DHCP server $PROBE_SID on $IFACE ($m) — yielding DHCP authority"
            if [ "$(uci -q get dhcp.lan.ignore)" != "1" ]; then
                uci set dhcp.lan.ignore='\''1'\''
                uci set dhcp.lan.ra='\''disabled'\''
                uci set dhcp.lan.dhcpv6='\''disabled'\''
                uci commit dhcp
                /etc/init.d/dnsmasq restart >/dev/null 2>&1
                /etc/init.d/odhcpd restart >/dev/null 2>&1
            fi
            touch "$STATE.yielded"
            return 0
        fi
        rm -f "$STATE.silent"
        return 0
    done
    [ "$FOUND" = 1 ] || { log "serve: no probeable member up on $IFACE — holding"; return 0; }
    [ "$(get_opt serve_when_greenfield)" = "1" ] || return 0
    if [ -f "$STATE.yielded" ]; then
        log "greenfield but sticky-yielded — re-arm manually: rm $STATE.yielded"
        return 0
    fi
    C=$(cat "$STATE.silent" 2>/dev/null || echo 0)
    C=$((C + 1))
    echo $C > "$STATE.silent"
    if [ "$C" -ge 3 ]; then
        rm -f "$STATE.silent"
        if [ "$(uci -q get dhcp.lan.ignore)" = "1" ]; then
            uci set dhcp.lan.ignore='\''0'\''
            uci commit dhcp
            /etc/init.d/dnsmasq restart >/dev/null 2>&1
            log "greenfield confirmed x3 — armed DHCP serving on $IFACE"
        else
            log "greenfield x3; already serving on $IFACE — no change"
        fi
    fi
}

case "$1" in
    --watch)
        INT=$(get_opt interval); [ -n "$INT" ] || INT=30
        while true; do
            serve_watch
            probe_vlans
            sleep "$INT"
        done
        ;;
    --status)
        echo "conf: $(cat "$CONF" 2>/dev/null | tr '\''\n'\'' '\'' '\'')"
        echo "adopted: $(cat "$STATE.adopted" 2>/dev/null || echo none)"
        echo "yielded: $([ -f "$STATE.yielded" ] && echo yes || echo no)"
        echo "silent-rounds: $(cat "$STATE.silent" 2>/dev/null || echo 0)"
        ;;
    *) serve_watch; probe_vlans ;;
esac
' > /usr/bin/conn-adapter && chmod 755 /usr/bin/conn-adapter
mkdir -p "$(dirname /etc/tollgate/conn-adapter.conf)" && printf '%s' 'probe_vlans=10,20
serve_when_greenfield=1
serve_iface=br-lan
wan_iface=waneth
base_port=eth0
interval=60
' > /etc/tollgate/conn-adapter.conf && chmod 600 /etc/tollgate/conn-adapter.conf
mkdir -p "$(dirname /etc/init.d/conn-adapter)" && printf '%s' '#!/bin/sh /etc/rc.common
START=98
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/conn-adapter --watch
    procd_set_param respawn 3600 5 0
    procd_close_instance
}
' > /etc/init.d/conn-adapter && chmod 755 /etc/init.d/conn-adapter
rm -f /tmp/conn-adapter.state.adopted /tmp/conn-adapter.state.yielded /tmp/conn-adapter.state.silent
/etc/init.d/conn-adapter enable
/etc/init.d/conn-adapter restart
[ -x /usr/bin/conn-adapter ] && [ -f /etc/tollgate/conn-adapter.conf ] || { echo "net-roles: conn-adapter staging FAILED"; exit 1; }