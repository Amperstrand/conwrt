"""net-roles — interface role assignment for constrained single-port/single-radio devices.

Assigns the three roles a TollGate-style device needs — internet uplink
(ordered, metric-based failover), serving LAN, and management access — on
hardware like the Zyxel NR7101 (1x GigE PoE + 1x 2.4GHz radio + 5G modem).

Uplink ordering renders as netifd interface metrics (5, 100, 200, ...):
passive failover for new flows, zero extra packages. Stack the `mwan3` preset
for health-checked per-flow failover (mwan3 requires unique interface metrics
anyway — this preset provides them).

Role conflicts are validated at build time, not on the device:
- untagged ethernet uplink consumes the only port -> requires
  serve_ethernet=false
- a VLAN-tagged ethernet uplink shares the port with the serving LAN
  (upstream switch must trunk the tag and supply PoE)
- wifi uplink takes the single radio -> serving APs on that radio are
  disabled (concurrent STA+AP is channel-locked and unreliable on mt76)
- optional mgmt VLAN (eth0.N static) keeps an SSH door when the untagged
  side is gated or repurposed

Composability: `sim` uplink entries only assign the metric — the interface
itself is owned by the `tollgate-cellular` preset. Enable `net-roles` AFTER
`tollgate-cellular` so the metric pass runs last (apply order follows the
enabled list).
"""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell
from shell_safe import interface_name

from . import ParamDef, UseCase, register

_UPLINK_TYPES = ("sim", "wifi", "ethernet")
_METRICS = (5, 100, 200, 300, 400)
_DEFAULT_IFACES = {"sim": "wan", "wifi": "wwan", "ethernet": "waneth"}
_WIFI_ENCRYPTIONS = ("none", "psk2", "sae", "sae-mixed")
_PRICE_PARAM_BY_TYPE = {"sim": "price_sim_sats_per_mib", "wifi": "price_wifi_sats_per_mib",
                        "ethernet": "price_eth_sats_per_mib"}

# tollgate-mode daemon. Paths are env-overridable purely for host-side
# behavioral testing; on-device the defaults apply.
_MODE_DAEMON = r"""#!/bin/sh
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
"""

_MODE_INIT = """\
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/tollgate-mode --watch
    procd_set_param env TOLLGATE_MODE_INTERVAL=__INTERVAL__
    procd_set_param respawn 3600 5 0
    procd_close_instance
}
"""

_MODE_HOTPLUG = """\
#!/bin/sh
[ "$ACTION" = "ifup" ] || [ "$ACTION" = "ifdown" ] || exit 0
/usr/bin/tollgate-mode >/dev/null 2>&1 &
"""

_MODE_BUTTON = """\
#!/bin/sh
[ "$BUTTON" = "wps" ] || exit 0
/usr/bin/tollgate-mode --button >/dev/null 2>&1 &
exit 0
"""

_CONN_NOOP = r"""#!/bin/sh
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
"""

_CONN_ADAPTER = r"""#!/bin/sh
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
"""

_CONN_INIT = """\
#!/bin/sh /etc/rc.common
START=98
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/conn-adapter --watch
    procd_set_param respawn 3600 5 0
    procd_close_instance
}
"""

_GUARD_DAEMON = r"""#!/bin/sh
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
    [ -n "$DEV" ] && M="$DEV"
    $NFT add table inet metered_guard 2>/dev/null
    $NFT add set inet metered_guard allowed '{ type ipv4_addr; flags interval; }' 2>/dev/null
    $NFT add chain inet metered_guard mg_fwd '{ type filter hook forward priority -1; policy accept; }' 2>/dev/null
    $NFT flush set inet metered_guard allowed 2>/dev/null
    for ip in $(auth_ips); do
        $NFT add element inet metered_guard allowed "{ $ip }" 2>/dev/null
    done
    $NFT add rule inet metered_guard mg_fwd oifname "$M" ip saddr != @allowed counter reject 2>/dev/null
    $NFT add rule inet metered_guard mg_fwd oifname "$M" meta nfproto ipv6 counter reject 2>/dev/null
    ARMED=1
    log "ARMED: free uplink up — non-client traffic to $M now rejected (counter on rule)"
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
"""

_GUARD_INIT = """\
#!/bin/sh /etc/rc.common
START=96
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/metered-guard --watch
    procd_set_param respawn 3600 5 0
    procd_close_instance
}
"""


def _stage_file_ops(ops: list[Op], path: str, content: str, mode: str) -> None:
    escaped = content.replace("'", "'\\''")
    ops.append(ShellCommand(
        command=f"mkdir -p \"$(dirname {path})\" && printf '%s' '{escaped}' > {path} && chmod {mode} {path}"
    ))


def _resolve_uplinks(raw: list[Any]) -> list[dict[str, Any]]:
    if not raw:
        return []
    if len(raw) > len(_METRICS):
        raise ValueError(f"net-roles: at most {len(_METRICS)} uplinks supported")
    seen_ifaces: set[str] = set()
    seen_radios: set[str] = set()
    uplinks: list[dict[str, Any]] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"net-roles: uplinks[{i}] must be a table")
        u = dict(entry)
        u["type"] = str(u.get("type", ""))
        if u["type"] not in _UPLINK_TYPES:
            raise ValueError(f"net-roles: uplinks[{i}].type must be one of {', '.join(_UPLINK_TYPES)}")
        u["iface"] = interface_name(str(u.get("iface") or _DEFAULT_IFACES[u["type"]]), f"uplinks[{i}] interface")
        if u["iface"] in seen_ifaces:
            raise ValueError(f"net-roles: duplicate interface '{u['iface']}' in uplinks")
        seen_ifaces.add(u["iface"])
        u["metric"] = _METRICS[i]
        if u["type"] == "wifi":
            u["ssid"] = str(u.get("ssid", ""))
            if not u["ssid"]:
                raise ValueError(f"net-roles: uplinks[{i}] wifi requires ssid")
            u["key"] = str(u.get("key", ""))
            u["encryption"] = str(u.get("encryption", "psk2"))
            if u["encryption"] not in _WIFI_ENCRYPTIONS:
                raise ValueError(f"net-roles: uplinks[{i}].encryption must be one of {', '.join(_WIFI_ENCRYPTIONS)}")
            if u["encryption"] != "none" and not u["key"]:
                raise ValueError(f"net-roles: uplinks[{i}] encryption '{u['encryption']}' requires key")
            u["radio"] = str(u.get("radio", "radio0"))
            if u["radio"] in seen_radios:
                raise ValueError(f"net-roles: radio '{u['radio']}' used by two wifi uplinks (one STA per radio)")
            seen_radios.add(u["radio"])
        if u["type"] == "ethernet":
            vlan = u.get("vlan", 0)
            if vlan not in (0,) and not (isinstance(vlan, int) and 2 <= vlan <= 4094 and not isinstance(vlan, bool)):
                raise ValueError(f"net-roles: uplinks[{i}].vlan must be an int in 2..4094 or unset (untagged)")
            u["vlan"] = vlan
        uplinks.append(u)
    return uplinks


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    uplinks = _resolve_uplinks(list(params.get("uplinks") or []))
    serve_ethernet = bool(params.get("serve_ethernet", True))
    serve_wifi = bool(params.get("serve_wifi", True))
    mgmt_vlan = int(params.get("mgmt_vlan", 0))
    mgmt_ip = str(params.get("mgmt_ip", ""))
    mgmt_netmask = str(params.get("mgmt_netmask", "255.255.255.0"))

    untagged_eth = [u for u in uplinks if u["type"] == "ethernet" and not u["vlan"]]
    if untagged_eth and serve_ethernet:
        raise ValueError(
            "net-roles: untagged ethernet uplink consumes the only port — set serve_ethernet=false, "
            "or give the uplink a vlan (tagged) so eth0 can stay in the serving bridge"
        )
    if mgmt_vlan:
        if not (isinstance(mgmt_vlan, int) and 2 <= mgmt_vlan <= 4094):
            raise ValueError("net-roles: mgmt_vlan must be an int in 2..4094 (0 = off)")
        if not mgmt_ip:
            raise ValueError("net-roles: mgmt_vlan requires mgmt_ip")
        if any(u["type"] == "ethernet" and u["vlan"] == mgmt_vlan for u in uplinks):
            raise ValueError("net-roles: mgmt_vlan must differ from the ethernet uplink vlan")
    auto_switch = bool(params.get("auto_switch", False))
    switch_interval = int(params.get("switch_interval", 10))
    wifi_shared_radio = bool(params.get("wifi_shared_radio", False))
    prices = {
        t: int(params.get(_PRICE_PARAM_BY_TYPE[t], 0)) for t in _UPLINK_TYPES
    }
    if any(p < 0 for p in prices.values()):
        raise ValueError("net-roles: price params must be >= 0")
    if any(p > 0 for p in prices.values()) and not auto_switch:
        raise ValueError("net-roles: price params require auto_switch=true")
    if auto_switch and not uplinks:
        raise ValueError("net-roles: auto_switch requires at least one uplink")
    if wifi_shared_radio and not any(u["type"] == "wifi" for u in uplinks):
        raise ValueError("net-roles: wifi_shared_radio requires a wifi uplink")
    if not (5 <= switch_interval <= 120):
        raise ValueError("net-roles: switch_interval must be in 5..120 seconds")
    adaptive_vlans = [v for v in (params.get("adaptive_vlans") or [])]
    for i, v in enumerate(adaptive_vlans):
        if isinstance(v, bool) or not isinstance(v, int) or not 2 <= v <= 4094:
            raise ValueError(f"net-roles: adaptive_vlans[{i}] must be an int in 2..4094")
    adaptive_serve_dhcp = bool(params.get("adaptive_serve_dhcp", False))
    adaptive_interval = int(params.get("adaptive_interval", 30))
    adaptive_base_port = str(params.get("adaptive_base_port", "eth0"))
    if not adaptive_base_port.replace(".", "").replace("_", "").isalnum():
        raise ValueError("net-roles: adaptive_base_port must be a plain interface name")
    metered_guard = bool(params.get("metered_guard", False))
    if metered_guard and not uplinks:
        raise ValueError("net-roles: metered_guard requires uplinks (free/metered derive from them)")
    if not 5 <= adaptive_interval <= 300:
        raise ValueError("net-roles: adaptive_interval must be in 5..300 seconds")
    if adaptive_vlans and any(u["type"] == "ethernet" for u in uplinks):
        raise ValueError(
            "net-roles: adaptive_vlans cannot be combined with a static ethernet uplink "
            "(the adapter owns ethernet uplink discovery)"
        )
    return {
        "uplinks": uplinks,
        "serve_ethernet": serve_ethernet,
        "serve_wifi": serve_wifi,
        "mgmt_vlan": mgmt_vlan,
        "mgmt_ip": mgmt_ip,
        "mgmt_netmask": mgmt_netmask,
        "auto_switch": auto_switch,
        "switch_interval": switch_interval,
        "wifi_shared_radio": wifi_shared_radio,
        "prices": prices,
        "adaptive_vlans": adaptive_vlans,
        "adaptive_serve_dhcp": adaptive_serve_dhcp,
        "adaptive_interval": adaptive_interval,
        "adaptive_base_port": adaptive_base_port,
        "metered_guard": metered_guard,
    }


def _zone_add(iface: str, zone: str) -> str:
    return (
        f"for z in $(uci -q show firewall | sed -n 's/^firewall\\.\\([^.]*\\)=zone$/\\1/p'); do "
        f"if [ \"$(uci -q get firewall.$z.name)\" = \"{zone}\" ]; then "
        f"uci -q get firewall.$z.network 2>/dev/null | tr ' ' '\\n' | grep -qxF '{iface}' "
        f"|| uci add_list firewall.$z.network='{iface}'; fi; done"
    )


def _build_net_roles_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    uplinks = r["uplinks"]
    mgmt_vlan = r["mgmt_vlan"]
    uplink_summary = " ".join(f"{u['iface']}(m{u['metric']})" for u in uplinks) or "none"

    ops: list[Op] = []
    ops.append(Comment(text=(
        f"--- net-roles: uplinks={uplink_summary} "
        f"serve_eth={r['serve_ethernet']} serve_wifi={r['serve_wifi']} "
        f"mgmt_vlan={mgmt_vlan or 'off'} ---"
    )))

    for u in uplinks:
        if u["type"] != "ethernet":
            continue
        device = f"eth0.{u['vlan']}" if u["vlan"] else "eth0"
        if u["vlan"]:
            ops.append(Comment(text=f"--- net-roles: ethernet uplink {u['iface']} on tagged {device} ---"))
            ops.append(ShellCommand(command=f"uci set network.dev_{u['iface']}=device"))
            ops.append(UciSet(config="network", section=f"dev_{u['iface']}", values={
                "type": "8021q", "name": device, "ifname": "eth0", "vid": str(u["vlan"]),
            }))
        else:
            ops.append(Comment(text=f"--- net-roles: ethernet uplink {u['iface']} on the untagged port ---"))
        if not r["serve_ethernet"] and not u["vlan"]:
            ops.append(ShellCommand(command=(
                "for s in $(uci -q show network | sed -n 's/^network\\.\\([^.]*\\)=device$/\\1/p'); do "
                "[ \"$(uci -q get network.$s.name)\" = \"br-lan\" ] "
                "&& uci -q del_list network.$s.ports='eth0'; done; true"
            )))
        ops.append(ShellCommand(command=f"uci set network.{u['iface']}=interface"))
        ops.append(ShellCommand(command=f"uci -q revert network.{u['iface']} || true"))
        ops.append(UciSet(config="network", section=u["iface"], values={"proto": "dhcp", "device": device}))
        ops.append(ShellCommand(command=_zone_add(u["iface"], "wan")))

    for u in uplinks:
        if u["type"] != "wifi":
            continue
        ops.append(Comment(text=f"--- net-roles: wifi uplink {u['iface']} (STA on {u['radio']}) ---"))
        ops.append(ShellCommand(command=f"uci set network.{u['iface']}=interface"))
        ops.append(ShellCommand(command=f"uci -q revert network.{u['iface']} || true"))
        ops.append(UciSet(config="network", section=u["iface"], values={"proto": "dhcp"}))
        sta_values: dict[str, str] = {
            "device": u["radio"], "mode": "sta", "network": u["iface"],
            "ssid": u["ssid"], "encryption": u["encryption"],
        }
        if u["encryption"] != "none":
            sta_values["key"] = u["key"]
        ops.append(ShellCommand(command=f"uci set wireless.{u['iface']}sta=wifi-iface"))
        ops.append(ShellCommand(command=f"uci -q revert wireless.{u['iface']}sta || true"))
        ops.append(UciSet(config="wireless", section=f"{u['iface']}sta", values=sta_values))
        ops.append(UciSet(config="wireless", section=u["radio"], values={"disabled": "0"}))
        ops.append(ShellCommand(command=_zone_add(u["iface"], "wan")))
        if r["wifi_shared_radio"]:
            ops.append(Comment(text=(
                f"--- net-roles: wifi_shared_radio — APs on {u['radio']} stay up alongside the STA "
                "(same-channel locked, ~half throughput, AP follows STA association; travelmate-class caveat) ---"
            )))
        else:
            ops.append(ShellCommand(command=(
                f"for w in $(uci -q show wireless | sed -n 's/^wireless\\.\\([^.]*\\)=wifi-iface$/\\1/p'); do "
                f"[ \"$(uci -q get wireless.$w.device)\" = \"{u['radio']}\" ] "
                f"&& [ \"$w\" != \"{u['iface']}sta\" ] && uci set wireless.$w.disabled=1; done; true"
            )))

    if not r["serve_wifi"]:
        ops.append(Comment(text="--- net-roles: serving disabled — take all AP vifs off the air ---"))
        ops.append(ShellCommand(command=(
            "for w in $(uci -q show wireless | sed -n 's/^wireless\\.\\([^.]*\\)=wifi-iface$/\\1/p'); do "
            "[ \"$(uci -q get wireless.$w.mode)\" = \"ap\" ] && uci set wireless.$w.disabled=1; done; true"
        )))

    untagged_eth_uplink = any(u["type"] == "ethernet" and not u["vlan"] for u in uplinks)
    if not r["serve_ethernet"] and not untagged_eth_uplink:
        ops.append(Comment(text="--- net-roles: serving disabled — eth0 leaves the serving bridge ---"))
        ops.append(ShellCommand(command=(
            "for s in $(uci -q show network | sed -n 's/^network\\.\\([^.]*\\)=device$/\\1/p'); do "
            "[ \"$(uci -q get network.$s.name)\" = \"br-lan\" ] "
            "&& uci -q del_list network.$s.ports='eth0'; done; true"
        )))

    if mgmt_vlan:
        ops.append(Comment(text=f"--- net-roles: mgmt door eth0.{mgmt_vlan} (static, lan zone) ---"))
        ops.append(ShellCommand(command="uci set network.mgmtdev=device"))
        ops.append(UciSet(config="network", section="mgmtdev", values={
            "type": "8021q", "name": f"eth0.{mgmt_vlan}", "ifname": "eth0", "vid": str(mgmt_vlan),
        }))
        ops.append(ShellCommand(command="uci set network.mgmt=interface"))
        ops.append(ShellCommand(command="uci -q revert network.mgmt || true"))
        ops.append(UciSet(config="network", section="mgmt", values={
            "proto": "static", "device": f"eth0.{mgmt_vlan}",
            "ipaddr": r["mgmt_ip"], "netmask": r["mgmt_netmask"],
        }))
        ops.append(ShellCommand(command=_zone_add("mgmt", "lan")))

    if uplinks:
        ops.append(Comment(text="--- net-roles: failover metrics (lower wins; sim section may be owned by tollgate-cellular) ---"))
        for u in uplinks:
            ops.append(UciSet(config="network", section=u["iface"], values={"metric": str(u["metric"])}))

    ops.append(Comment(text="--- net-roles: readbacks (gate the commits — staged values are visible to uci get) ---"))
    for u in uplinks:
        if u["type"] == "ethernet":
            device = f"eth0.{u['vlan']}" if u["vlan"] else "eth0"
            ops.append(ShellCommand(command=(
                f'[ "$(uci -q get network.{u["iface"]}.device)" = "{device}" ] '
                f'&& [ "$(uci -q get network.{u["iface"]}.proto)" = dhcp ] '
                f'|| {{ echo "net-roles: {u["iface"]} readback FAILED"; exit 1; }}'
            )))
        ops.append(ShellCommand(command=(
            f'[ "$(uci -q get network.{u["iface"]}.metric)" = "{u["metric"]}" ] '
            f'|| {{ echo "net-roles: {u["iface"]} metric readback FAILED"; exit 1; }}'
        )))
    if mgmt_vlan:
        ops.append(ShellCommand(command=(
            f'[ "$(uci -q get network.mgmt.ipaddr)" = "{r["mgmt_ip"]}" ] '
            f'|| {{ echo "net-roles: mgmt readback FAILED"; exit 1; }}'
        )))

    ops.append(UciCommit(config="network"))
    if any(u["type"] == "wifi" for u in uplinks) or not r["serve_wifi"]:
        ops.append(UciCommit(config="wireless"))
    ops.append(UciCommit(config="firewall"))

    ops.append(BlankLine())
    if any(u["type"] == "wifi" for u in uplinks):
        ops.append(ServiceAction(name="network", action="reload"))
        ops.append(ShellCommand(command="wifi reload 2>/dev/null; true"))
    else:
        ops.append(ServiceAction(name="network", action="reload"))
    ops.append(ShellCommand(command=(
        f'echo "net-roles applied: uplinks={len(uplinks)} '
        f'serve_eth={r["serve_ethernet"]} serve_wifi={r["serve_wifi"]} mgmt={mgmt_vlan or "lan"}"'
    )))

    if r["auto_switch"]:
        ops.append(BlankLine())
        ops.append(Comment(text="--- net-roles: tollgate-mode engine (active-uplink price switch + WPS button override) ---"))
        mode_conf_lines = []
        for u in uplinks:
            price = r["prices"][u["type"]]
            mode_conf_lines.append(f"{u['iface']} {u['metric']} {price if price > 0 else '-'}")
        if r["adaptive_vlans"] and r["auto_switch"]:
            slot = uplinks[-1]["metric"] if uplinks else 0
            ad_metric = _METRICS[min(len(uplinks), len(_METRICS) - 1)]
            if ad_metric <= slot:
                ad_metric = slot + 100
            ad_price = r["prices"]["ethernet"]
            mode_conf_lines.append(f"waneth {ad_metric} {ad_price if ad_price > 0 else '-'}")
        mode_conf = "\n".join(mode_conf_lines) + "\n"
        _stage_file_ops(ops, "/etc/tollgate/mode.conf", mode_conf, "600")
        _stage_file_ops(ops, "/usr/bin/tollgate-mode", _MODE_DAEMON, "755")
        _stage_file_ops(ops, "/etc/init.d/tollgate-mode",
                        _MODE_INIT.replace("__INTERVAL__", str(r["switch_interval"])), "755")
        _stage_file_ops(ops, "/etc/hotplug.d/iface/90-tollgate-mode", _MODE_HOTPLUG, "755")
        _stage_file_ops(ops, "/etc/rc.button/wps", _MODE_BUTTON, "755")
        ops.append(ShellCommand(command="rm -f /etc/tollgate/mode.override /tmp/tollgate-mode.state"))
        ops.append(ServiceAction(name="tollgate-mode", action="enable"))
        ops.append(ServiceAction(name="tollgate-mode", action="restart"))
        ops.append(ShellCommand(command=(
            '[ -x /usr/bin/tollgate-mode ] && [ -f /etc/tollgate/mode.conf ] '
            '|| { echo "net-roles: tollgate-mode staging FAILED"; exit 1; }'
        )))

    if r["adaptive_vlans"] or r["adaptive_serve_dhcp"]:
        ops.append(BlankLine())
        ops.append(Comment(text=(
            f"--- net-roles: conn-adapter (client-first ladder: probe/discriminate/adopt/yield; "
            f"vlans={r['adaptive_vlans'] or 'none'} serve_when_greenfield={int(r['adaptive_serve_dhcp'])}) ---"
        )))
        conf_lines = [
            f"probe_vlans={','.join(str(v) for v in r['adaptive_vlans'])}",
            f"serve_when_greenfield={int(r['adaptive_serve_dhcp'])}",
            "serve_iface=br-lan",
            "wan_iface=waneth",
            f"base_port={r['adaptive_base_port']}",
            "interval=" + str(r["adaptive_interval"]),
        ]
        _stage_file_ops(ops, "/usr/share/conn-adapter/probe-noop.sh", _CONN_NOOP, "755")
        _stage_file_ops(ops, "/usr/bin/conn-adapter", _CONN_ADAPTER, "755")
        _stage_file_ops(ops, "/etc/tollgate/conn-adapter.conf", "\n".join(conf_lines) + "\n", "600")
        _stage_file_ops(ops, "/etc/init.d/conn-adapter", _CONN_INIT, "755")
        ops.append(ShellCommand(command="rm -f /tmp/conn-adapter.state.adopted /tmp/conn-adapter.state.yielded /tmp/conn-adapter.state.silent"))
        ops.append(ServiceAction(name="conn-adapter", action="enable"))
        ops.append(ServiceAction(name="conn-adapter", action="restart"))
        ops.append(ShellCommand(command=(
            '[ -x /usr/bin/conn-adapter ] && [ -f /etc/tollgate/conn-adapter.conf ] '
            '|| { echo "net-roles: conn-adapter staging FAILED"; exit 1; }'
        )))

    if r["metered_guard"]:
        metered_iface = next((u["iface"] for u in uplinks if u["type"] == "sim"), "wan")
        free_ifaces = [u["iface"] for u in uplinks if u["type"] != "sim"]
        if r["adaptive_vlans"] and "waneth" not in free_ifaces:
            free_ifaces.append("waneth")
        ops.append(BlankLine())
        ops.append(Comment(text=(
            f"--- net-roles: metered-guard ({metered_iface} metered; "
            f"{','.join(free_ifaces) or 'none'} free — non-client forwarding rejected while free is up) ---"
        )))
        guard_conf = "\n".join([
            f"metered_iface={metered_iface}",
            f"free_ifaces={','.join(free_ifaces)}",
            f"interval={r['adaptive_interval']}",
        ]) + "\n"
        _stage_file_ops(ops, "/usr/bin/metered-guard", _GUARD_DAEMON, "755")
        _stage_file_ops(ops, "/etc/tollgate/metered-guard.conf", guard_conf, "600")
        _stage_file_ops(ops, "/etc/init.d/metered-guard", _GUARD_INIT, "755")
        ops.append(ServiceAction(name="metered-guard", action="enable"))
        ops.append(ServiceAction(name="metered-guard", action="restart"))
        ops.append(ShellCommand(command=(
            '[ -x /usr/bin/metered-guard ] && [ -f /etc/tollgate/metered-guard.conf ] '
            '|| { echo "net-roles: metered-guard staging FAILED"; exit 1; }'
        )))
    return ops


register(UseCase(
    name="net-roles",
    description=(
        "Interface role assignment for constrained devices (NR7101 class): ordered "
        "uplinks (sim/wifi/ethernet) rendered as netifd metrics for passive failover, "
        "optional tagged-VLAN ethernet uplink or mgmt door on the single port, and "
        "single-radio STA/AP exclusivity. Stack mwan3 for health-checked failover. "
        "Enable AFTER tollgate-cellular (metric pass must run last)."
    ),
    packages=[],
    params={
        "uplinks": ParamDef(type=list, default=[],
            description=(
                "Ordered uplink tables: {type='sim'|'wifi'|'ethernet', iface='wan' (optional override), "
                "wifi: ssid/key/encryption/radio, ethernet: vlan (0/absent = untagged, consumes the port)}. "
                "Metrics auto-assigned 5,100,200,... sim entries only set the metric "
                "(interface owned by tollgate-cellular)."
            )),
        "serve_ethernet": ParamDef(type=bool, default=True,
            description="Keep eth0 in the serving bridge (must be false for an untagged ethernet uplink)"),
        "serve_wifi": ParamDef(type=bool, default=True,
            description="Keep serving APs (a wifi uplink disables other ifaces on its radio regardless — single radio)"),
        "mgmt_vlan": ParamDef(type=int, default=0, min_value=0, max_value=4094,
            description="VLAN id for a static mgmt door on eth0 (0 = off; requires mgmt_ip)"),
        "mgmt_ip": ParamDef(type=str, default="",
            description="Static IP for the mgmt VLAN interface (e.g. 192.168.50.1)"),
        "mgmt_netmask": ParamDef(type=str, default="255.255.255.0",
            description="Netmask for the mgmt VLAN interface"),
        "auto_switch": ParamDef(type=bool, default=False,
            description="Install the tollgate-mode engine: watches uplink liveness, rewrites tollgate "
                        "pricing when the active uplink changes, WPS button rotates a manual override"),
        "switch_interval": ParamDef(type=int, default=10, min_value=5, max_value=120,
            description="tollgate-mode watch loop interval in seconds (hotplug events react instantly)"),
        "price_sim_sats_per_mib": ParamDef(type=int, default=0, min_value=0,
            description="Price applied while the sim uplink is active (sats/MiB; 0 = leave unchanged)"),
        "price_wifi_sats_per_mib": ParamDef(type=int, default=0, min_value=0,
            description="Price applied while the wifi uplink is active (sats/MiB; 0 = leave unchanged)"),
        "price_eth_sats_per_mib": ParamDef(type=int, default=0, min_value=0,
            description="Price applied while the ethernet uplink is active (sats/MiB; 0 = leave unchanged)"),
        "wifi_shared_radio": ParamDef(type=bool, default=False,
            description="Keep serving APs up alongside the wifi STA on the same radio "
                        "(channel-locked to the STA's BSS, roughly half throughput, AP dies with the STA — "
                        "travelmate-class repeater caveat)"),
        "adaptive_vlans": ParamDef(type=list, default=[],
            description="VLAN ids the conn-adapter probes for a foreign DHCP uplink (side-effect-free "
                        "probe, /32-verified, adopted via netifd with metric per conf). First verified "
                        "answer wins; cannot be combined with a static ethernet uplink"),
        "adaptive_serve_dhcp": ParamDef(type=bool, default=False,
            description="Arm the client-first DHCP ladder on the serving bridge: greenfield confirmed "
                        "x3 probes arms DHCP serving; any FOREIGN dhcp server yields authority instantly "
                        "(sticky until manual re-arm) — automates the rogue-DHCP discipline"),
        "adaptive_interval": ParamDef(type=int, default=30, min_value=5, max_value=300,
            description="conn-adapter watch interval in seconds"),
        "adaptive_base_port": ParamDef(type=str, default="eth0",
            description="Base port for adaptive VLAN candidates (DSA devices use their port name, "
                        "e.g. 'lan' on the NR7101)"),
        "metered_guard": ParamDef(type=bool, default=False,
            description="Reject non-customer forwarding out the metered (sim) uplink while any free "
                        "uplink is up — paying (nodogsplash-authenticated) clients keep flowing; "
                        "disarms to plain routing when the metered link is the only one"),
    },
    test_status="experimental",
    tested_notes="renders validated (multi-mode sh -n); hardware run pending next TollGate build",
    build_configure=lambda p: render_shell(_build_net_roles_ops(p)),
    build_configure_ops=_build_net_roles_ops,
))
