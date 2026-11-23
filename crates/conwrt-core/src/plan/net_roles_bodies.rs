// GENERATED from scripts/use_cases/net_roles.py by
// scripts/gen_net_roles_bodies.py — DO NOT EDIT BY HAND; byte parity
// with 1.x is asserted by the fixture corpus.

/// 1.x `_MODE_DAEMON` (byte-exact).
pub(super) const MODE_DAEMON_SH: &str = r#"#!/bin/sh
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
    CUR=$(sed -n 's/.*"price_per_step":[ ]*\([0-9][0-9]*\).*/\1/p' "$TGJSON" | head -1)
    [ "$CUR" = "$1" ] && return 0
    SS=$(sed -n 's/.*"step_size":[ ]*\([0-9][0-9]*\).*/\1/p' "$TGJSON" | head -1)
    [ -n "$SS" ] || SS=1048576
    P=$(( ( $1 * SS + 1048575 ) / 1048576 ))
    sed -i "s/\"price_per_step\":[ ]*[0-9]*/\"price_per_step\": $P/g" "$TGJSON" \
        && { /etc/init.d/tollgate-wrt restart >/dev/null 2>&1 || true; } \
        && log "price -> $1 sat/MiB (step_size $SS -> $P)" \
        || log "price patch FAILED"
}

iface_up() {
    ubus call network.interface."$1" status 2>/dev/null | grep -q '"up":[ ]*true'
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
    PR=$(awk -v i="$A" '$1 == i {print $3}' "$CONF")
    [ -n "$PR" ] || PR=-
    apply_price "$PR"
    log "active uplink: $A (price $PR)"
}

rotate_button() {
    CUR=$(cat "$OVR" 2>/dev/null)
    [ -n "$CUR" ] || CUR=auto
    N=auto
    PREV=""
    for i in auto $(awk '{printf "%s ", $1}' "$CONF"); do
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
"#;

/// 1.x `_MODE_INIT` (byte-exact).
pub(super) const MODE_INIT_SH: &str = r#"#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/tollgate-mode --watch
    procd_set_param env TOLLGATE_MODE_INTERVAL=__INTERVAL__
    procd_set_param respawn 3600 5 0
    procd_close_instance
}
"#;

/// 1.x `_MODE_HOTPLUG` (byte-exact).
pub(super) const MODE_HOTPLUG_SH: &str = r#"#!/bin/sh
[ "$ACTION" = "ifup" ] || [ "$ACTION" = "ifdown" ] || exit 0
/usr/bin/tollgate-mode >/dev/null 2>&1 &
"#;

/// 1.x `_MODE_BUTTON` (byte-exact).
pub(super) const MODE_BUTTON_SH: &str = r#"#!/bin/sh
[ "$BUTTON" = "wps" ] || exit 0
/usr/bin/tollgate-mode --button >/dev/null 2>&1 &
exit 0
"#;

/// 1.x `_CONN_NOOP` (byte-exact).
pub(super) const CONN_NOOP_SH: &str = r#"#!/bin/sh
# udhcpc event script that applies NOTHING. conn-adapter records the
# offered lease fields (incl. DHCP option 54, the server identifier) so
# the probe stays side-effect-free — the same trick dnsmasq's own
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
"#;

/// 1.x `_CONN_ADAPTER` (byte-exact).
pub(super) const CONN_ADAPTER_SH: &str = r#"#!/bin/sh
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
# device's own dnsmasq answers foreign clients in ~2ms). On such
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
    PROBE_SID=$(sed -n 's/^serverid=//p' "$PROBEINFO" 2>/dev/null | head -1)
    [ -n "$PROBE_SID" ] || return 1
    if ip -4 addr show 2>/dev/null | grep -q "inet $PROBE_SID/"; then
        PROBE_KIND=OURS
    else
        PROBE_KIND=FOREIGN
    fi
    return 0
}

verify() {
    IP=$(sed -n 's/^ip=//p' "$PROBEINFO" | head -1)
    MASK=$(sed -n 's/^mask=//p' "$PROBEINFO" | head -1)
    GW=$(sed -n 's/^router=//p' "$PROBEINFO" | head -1)
    DEV=$(sed -n 's/^dev=//p' "$PROBEINFO" | head -1)
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
    uci set network.$WANIF.proto='dhcp'
    uci set network.$WANIF.device="$DEV"
    uci set network.$WANIF.metric="$METRIC"
    for z in $(uci -q show firewall | sed -n 's/^firewall\.\([^.]*\)=zone$/\1/p'); do
        if [ "$(uci -q get firewall.$z.name)" = "wan" ]; then
            uci -q get firewall.$z.network 2>/dev/null | tr ' ' '\n' | grep -qxF "$WANIF" \
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
    ubus call network.interface."$WANIF" status 2>/dev/null | grep -q '"up":[ ]*true'
}

probe_vlans() {
    uplink_alive && return 0
    BASE=$(get_opt base_port); [ -n "$BASE" ] || BASE=eth0
    for v in $(get_opt probe_vlans | tr ',' ' '); do
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
                uci set dhcp.lan.ignore='1'
                uci set dhcp.lan.ra='disabled'
                uci set dhcp.lan.dhcpv6='disabled'
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
            uci set dhcp.lan.ignore='0'
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
        echo "conf: $(cat "$CONF" 2>/dev/null | tr '\n' ' ')"
        echo "adopted: $(cat "$STATE.adopted" 2>/dev/null || echo none)"
        echo "yielded: $([ -f "$STATE.yielded" ] && echo yes || echo no)"
        echo "silent-rounds: $(cat "$STATE.silent" 2>/dev/null || echo 0)"
        ;;
    *) serve_watch; probe_vlans ;;
esac
"#;

/// 1.x `_CONN_INIT` (byte-exact).
pub(super) const CONN_INIT_SH: &str = r#"#!/bin/sh /etc/rc.common
START=98
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/conn-adapter --watch
    procd_set_param respawn 3600 5 0
    procd_close_instance
}
"#;

/// 1.x `_GUARD_DAEMON` (byte-exact).
pub(super) const GUARD_DAEMON_SH: &str = r#"#!/bin/sh
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
    ubus call network.interface."$1" status 2>/dev/null | grep -q '"up":[ ]*true'
}

free_up() {
    for f in $(get_opt free_ifaces | tr ',' ' '); do
        [ -n "$f" ] || continue
        iface_up "$f" && return 0
    done
    return 1
}

auth_ips() {
    $NDSCTL json 2>/dev/null | awk '
        match($0, /"ip"[ ]*:[ ]*"[0-9.]+"/) {
            t = substr($0, RSTART, RLENGTH)
            gsub(/[^0-9.]/, "", t)
            ip = t
        }
        match($0, /"state"[ ]*:[ ]*"[A-Za-z]+"/) {
            t = substr($0, RSTART, RLENGTH)
            if (t ~ /uthenticated/ && ip != "") print ip
            ip = ""
        }'
}

arm() {
    M=$(get_opt metered_iface); [ -n "$M" ] || M=wan
    DEV=$(ubus call network.interface."$M" status 2>/dev/null \
        | grep -o '"device":[ ]*"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -z "$DEV" ]; then
        log "metered iface $M not ready (no device yet) — retrying next loop"
        return 1
    fi
    M="$DEV"
    BATCH=/tmp/metered-guard.arm.$$
    {
        echo "add table inet metered_guard"
        echo "add set inet metered_guard allowed '{ type ipv4_addr; flags interval; }'"
        echo "add chain inet metered_guard mg_fwd '{ type filter hook forward priority -1; policy accept; }'"
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
        $NFT list table inet metered_guard 2>/dev/null | grep -E 'reject|elements'
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
"#;

/// 1.x `_GUARD_INIT` (byte-exact).
pub(super) const GUARD_INIT_SH: &str = r#"#!/bin/sh /etc/rc.common
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
"#;
