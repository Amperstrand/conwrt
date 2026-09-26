#!/bin/sh
# gs1900-portmap.sh — device discovery + PoE control for the GS1900-8HP testbed switch.
#
# Runs ON the GS1900 (BusyBox ash). Each LAN port N is isolated in VLAN 1000+N
# (lan2->1002 ... lan8->1008); the switch holds 192.168.1.2 in each VLAN so
# default-IP routers (192.168.1.1) are reachable without conflicts.
#
# Usage:
#   portmap.sh [port...]          map ports (default: 2 3 4 5 6 7 8; arg is N or lanN)
#   portmap.sh --scan PORT        ping common router IPs on PORT's VLAN (parallel)
#   portmap.sh --cycle PORT       PoE off/on + capture boot traffic -> identify device
#   portmap.sh --poe PORT on|off|reset   runtime PoE control
#
# Lessons encoded here:
#   - `ubus poe info` lags up to poll_interval (30s): carrier + ping are ground truth
#   - brctl showmacs port numbers do NOT match lan numbering: use rx counters instead
#   - switch.100X L3 only exists when referenced: create idempotently at runtime
#   - silent devices reveal IP/identity via boot ARP probes/DHCP/IPv6-RS during a cycle
#
# boot round-trip reference: WS-AP3915i answers ping ~37s after PoE enable.

BRIDGE=switch
MGMT_IP=192.168.1.2
CAPDIR=/tmp
die() { echo "ERROR: $*" >&2; exit 1; }

vlan_of() { echo $((1000 + ${1#lan})); }

# ---- idempotent L3 on switch.100N ----
ensure_l3() {
    local v=$1 d="$BRIDGE.$1"
    ip link show "$d" >/dev/null 2>&1 || ip link add "$d" link "$BRIDGE" type vlan id "$v" || return 1
    ip link set "$d" up
    ip addr show "$d" | grep -q "$MGMT_IP/" || ip addr add "$MGMT_IP/24" dev "$d"
}

# ---- PoE helpers (info is ADVISORY - may lag 30s) ----
poe_field() { # jsonfilter wants @.ports.lan5.status for ident keys; sed fallback
    local r
    r=$(ubus call poe info 2>/dev/null | jsonfilter -s -e "@.ports.$1.$2" 2>/dev/null)
    [ -n "$r" ] && { echo "$r"; return; }
    ubus call poe info 2>/dev/null | grep -o "\"$1\":\|\"$2\":[^,}]*" >/dev/null 2>&1
    ubus call poe info 2>/dev/null | sed -n "/\"$1\"/,/}/p" | grep -o "\"$2\":[^,}]*" | sed 's/.*:[[:space:]]*//' | head -1
}
poe_manage() { ubus call poe manage "{\"port\":\"$1\",\"action\":\"$2\"}"; }

carrier() { cat /sys/class/net/$1/carrier 2>/dev/null || echo "?"; }
speedof() { cat /sys/class/net/$1/speed 2>/dev/null || echo "?"; }
rxof()    { cat /sys/class/net/$1/statistics/rx_packets 2>/dev/null || echo 0; }

ping_v() { # ping_v <vlan-dev> <ip>
    ping -c 1 -W 2 -I "$1" "$2" >/dev/null 2>&1
}

# ---- identity probe: switch ssh-key may not be trusted by every router ----
identity() { # identity <vlan-dev> <ip>
    local out d="$1" ip="$2"
    # Pin the probe to THIS VLAN: every isolated VLAN carries an identical
    # connected route to 192.168.1.0/24 (each holds a device at 192.168.1.1),
    # so an unpinned ssh can leave via the wrong port and attach a healthy
    # unit's identity to the wrong physical entry in the port map.
    ip route add "$ip/32" dev "$d" 2>/dev/null
    out=$(ssh -y -y -i /root/.ssh/id_ed25519 -o ConnectTimeout=4 root@"$ip" \
        'printf "%s|%s|%s|%s\n" "$(cat /tmp/sysinfo/board_name 2>/dev/null)" \
         "$(cat /tmp/sysinfo/model 2>/dev/null)" \
         "$(grep DISTRIB_DESCRIPTION /etc/openwrt_release 2>/dev/null | cut -d"'"'"' -f2)" \
         "$(cut -d. -f1 /proc/uptime 2>/dev/null)s"' </dev/null 2>/dev/null)
    rc=$?
    ip route del "$ip/32" dev "$d" 2>/dev/null
    [ "$rc" -eq 0 ] && [ -n "$out" ] && echo "$out" || echo "no-key-trust"
}

# ---- passive map of one port ----
map_port() {
    local p=$1 v d car sp poe_st w ips mac model
    v=$(vlan_of "$p"); d="$BRIDGE.$v"
    ensure_l3 "$v" || { echo "$p vlan=$v L3-SETUP-FAILED"; return; }
    car=$(carrier "$p"); sp=$(speedof "$p")
    poe_st=$(poe_field "$p" status); w=$(poe_field "$p" consumption)
    ping_v "$d" 192.168.1.1 && ips="192.168.1.1" || ips="-"
    mac=$(ip neigh show dev "$d" 2>/dev/null | awk '/REACHABLE|STALE|DELAY/{print $3; exit}')
    model=""
    [ "$ips" = "192.168.1.1" ] && { model=$(identity "$d" 192.168.1.1); }
    echo "$p vlan=$v poe=$poe_st ${w:-0}W link=$car/${sp}Mbps ping.1.1=$ips mac=${mac:--} id=${model:--}"
}

# ---- fast parallel scan of common router IPs on a port's VLAN ----
scan_port() {
    local p=$1 v d f hits="" ip
    v=$(vlan_of "$p"); d="$BRIDGE.$v"; ensure_l3 "$v"
    f="$CAPDIR/scan.$v"; : > "$f"
    for a in 0 1 2 3 4 5 8 9; do
        for base in 192.168 10.0; do
            ping -c 1 -W 1 -I "$d" "$base.$a.1" >>"$f" 2>/dev/null &
        done
    done
    for ip in 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.1.1.1 10.10.1.1 172.16.1.1 172.31.1.1; do
        ping -c 1 -W 1 -I "$d" "$ip" >>"$f" 2>/dev/null &
    done
    wait
    hits=$(grep -h "time=" "$f" 2>/dev/null | grep -oE "from [0-9.]+ " | sort -u | tr -d 'from ' | tr '\n' ' ')
    echo "$p scan: ${hits:--none-}"
    rm -f "$f"
}

# ---- PoE cycle + boot-traffic capture: identifies silent devices ----
cycle_port() {
    local p=$1 v d cap pid ours car hits cands ip first
    v=$(vlan_of "$p"); d="$BRIDGE.$v"; ensure_l3 "$v"
    cap="$CAPDIR/boot.$p.txt"; : > "$cap"
    ours=$(cat /sys/class/net/$BRIDGE/address 2>/dev/null)
    echo "== CYCLE $p (vlan $v) =="
    echo "before: poe=$(poe_field "$p" status) carrier=$(carrier "$p")"
    tcpdump -i "$p" -enn -l > "$cap" 2>/dev/null & pid=$!
    poe_manage "$p" disable >/dev/null || die "poe manage disable failed"
    sleep 4
    echo "off:    carrier=$(carrier "$p") (expect 0)"
    poe_manage "$p" enable >/dev/null || die "poe manage enable failed"
    sleep 2
    echo "on:     carrier=$(carrier "$p") (link may take a few seconds)"
    # wait for first sign of life from the device (max 75s)
    first=""
    for i in $(seq 1 15); do
        ping_v "$d" 192.168.1.1 && { first="ping"; break; }
        if grep -qv "^$" "$cap" 2>/dev/null && [ "$(grep -vc "^[[:space:]]*$" "$cap")" -gt 0 ]; then
            grep -v "$ours" "$cap" | grep -q . && { first="traffic"; break; }
        fi
        sleep 5
    done
    sleep 3; kill $pid 2>/dev/null
    echo "sign-of-life: ${first:-none within 75s}"
    # candidate IPs: any IPv4 addr in packets NOT sent by us
    cands=$(grep -v "$ours" "$cap" 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" |
        grep -vE "^(0\.0\.0\.0|255\.255\.255\.255|$MGMT_IP|22[4-9]\.|23[0-9]\.)" | sort -u)
    echo "candidates: ${cands:--none-}"
    for ip in $cands; do ping_v "$d" "$ip" && echo "ALIVE: $ip  id=$(identity "$d" "$ip")"; done
    ping_v "$d" 192.168.1.1 && echo "ALIVE: 192.168.1.1  id=$(identity "$d" 192.168.1.1)"
    echo "boot-traffic (non-us, first 8):"
    grep -v "$ours" "$cap" 2>/dev/null | head -8
    cp "$cap" "$CAPDIR/last-boot-capture.txt"
}

# ---- active probe: stimuli for devices that never transmit ----
SWEEP_IPS="192.168.0.1 192.168.1.1 192.168.2.1 192.168.3.1 192.168.4.1 192.168.5.1
192.168.8.1 192.168.9.1 192.168.10.1 192.168.11.1 192.168.50.1 192.168.62.1
192.168.100.1 192.168.254.1 10.0.0.1 10.0.0.138 10.1.1.1 10.10.1.1 172.16.1.1 172.31.31.1"

probe_port() {
    local p=$1 v d cap pid ours
    v=$(vlan_of "$p"); d="$BRIDGE.$v"; ensure_l3 "$v"
    cap="$CAPDIR/probe.$p.txt"; : > "$cap"
    ours=$(cat /sys/class/net/$BRIDGE/address 2>/dev/null)
    echo "== PROBE $p (vlan $v) link=$(carrier "$p")/$(speedof "$p")Mbps poe=$(poe_field "$p" status) =="
    tcpdump -i "$p" -enn -l > "$cap" 2>/dev/null & pid=$!
    printf '#!/bin/sh\nexit 0\n' > "$CAPDIR/noop.sh"; chmod +x "$CAPDIR/noop.sh"
    echo "-- ICMPv6 all-nodes (any IPv6 stack must answer) --"
    ping -6 -c 3 -W 2 -I "$d" ff02::1 2>&1 | grep -E "from|transmitted" | head -5
    echo "-- DHCP client probe (server reveals subnet+MAC) --"
    udhcpc -i "$d" -s "$CAPDIR/noop.sh" -f -n -q -t 2 -T 2 2>&1 | grep -iE "offer|lease|obtain|server" | head -5
    echo "-- ARP sweep of vendor-default router IPs --"
    for ip in $SWEEP_IPS; do
        if which arping >/dev/null 2>&1; then arping -I "$d" -c 1 -w 2 "$ip" >/dev/null 2>&1 &
        else ip route add "$ip/32" dev "$d" 2>/dev/null; ping -c 1 -W 1 -I "$d" "$ip" >/dev/null 2>&1 & fi
    done
    wait
    sleep 2; kill $pid 2>/dev/null
    echo "-- captured frames NOT from us (src-mac -> first bytes) --"
    grep -v "$ours" "$cap" 2>/dev/null | head -12
    echo "-- distinct remote MACs seen --"
    grep -v "$ours" "$cap" 2>/dev/null | awk 'NF>2{print $2}' | grep -v "ff:ff:ff:ff:ff:ff\|33:33:" | sort -u | head -6
    cp "$cap" "$CAPDIR/last-probe-capture.txt"
}

case "$1" in
    --poe)  [ $# -eq 3 ] || die "usage: $0 --poe PORT on|off|reset"
            # documented states -> ubus actions (the fork's API takes
            # enable/disable; "reset" is a bounded off/on cycle)
            case "$3" in
                on)    act=enable ;;
                off)   act=disable ;;
                reset) act=cycle ;;
                *)     die "unknown poe state '$3' (expected on|off|reset)" ;;
            esac
            if [ "$act" = "cycle" ]; then
                poe_manage "lan$2" disable >/dev/null || die "poe manage disable failed"
                sleep 4
                poe_manage "lan$2" enable >/dev/null || die "poe manage enable failed"
                echo "lan$2 -> cycled (4s off, on; info may lag 30s)"
            else
                poe_manage "lan$2" "$act" >/dev/null && echo "lan$2 -> $3 (info may lag 30s)" \
                    || die "poe manage $act failed"
            fi ;;
    --scan) scan_port "lan$2" ;;
    --cycle) cycle_port "lan$2" ;;
    --probe) probe_port "lan$2" ;;
    "")     for n in 2 3 4 5 6 7 8; do map_port "lan$n"; done ;;
    *)      for a in "$@"; do map_port "lan${a#lan}"; done ;;
esac
