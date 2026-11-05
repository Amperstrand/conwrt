#!/bin/sh
# gs1900-bench-arm.sh — THE idempotent bench re-arm tool for the GS1900-8HP
# bench switch (CONWRT_BENCH_SWITCH, zyxel gs1900-8hp-a1).
#
# Usage (from the Mac, over ssh):
#   export CONWRT_BENCH_SWITCH=<switch-mgmt>   # bare host; root@ is inferred
#   sh scripts/gs1900-bench-arm.sh
#
# RE-RUN AFTER ANY SWITCH REBOOT — every component below is runtime-only
# (tmpfs pidfiles/tftproots, runtime /32 route and nft rules), so a reboot
# disarms the whole bench. This tool is the Mac-side SUPERSET: when the
# switch reports the bait gone it scps the 10.1MB 24.10.2 FIT from the Mac
# (the FIT does not fit the 7MB /overlay — it can only live on tmpfs).
#
# Components (each adopted-if-alive, never double-started):
#   fw4-1002/1003/1005  nft input accepts for the DUT VLANs (unzoned VLANs
#                       silently drop inbound UDP/TCP; lan-zone membership
#                       counts as accepted)
#   alias-1002/1005     192.168.1.2/24 recovery aliases (U-Boot serverip on
#                       boot_net units)
#   fit                 TFTP bait in /tmp/bench-tftp + /tmp/tftproot1003:
#                       the 24.10.2 sysupgrade FIT (md5 2242e9b7...) under
#                       vmlinux.gz.uImage.3912 AND the full .itb name, as
#                       hardlinks of one validated inode; unknown files are
#                       quarantined, never served, never deleted
#   shared-dnsmasq      TFTP on switch.1002+1005 (pid /tmp/dnsmasq-bench.pid,
#                       log /tmp/bench-arm.log) — adopted if a live instance
#                       already serves BOTH interfaces
#   lifeline-1003       dedicated TFTP on switch.1003 (pid
#                       /tmp/dnsmasq-bench-1003.pid, log /tmp/bench-arm-1003.log)
#   route-1.1-pin       192.168.1.1/32 dev switch.1005 — pins DUT default-IP
#                       replies to the right VLAN (wrong-VLAN ECMP reply bug)
#   ap-lan2-watch       aliveness recorder, if /etc/ap-lan2-watch.sh deployed
#
# NEVER touches: switch.1007 / the scout dnsmasq (parallel session — the
# adopt signature requires bench-tftp + switch.1002 + switch.1005 in the
# process cmdline, which the 1007-only DHCP scout lacks), DUTs, PoE, uci.
# Runtime-only switch state; no commits anywhere.
#
# The deployed boot-time subset /etc/bench-arm.sh (called from rc.local)
# re-arms only fw4 + aliases + shared dnsmasq + watcher. The VLAN-1003
# lifeline, the /32 pin and Mac-side FIT staging exist ONLY here — keep
# this file the source of truth.
#
# Lessons encoded here (AGENTS.md):
#   - runtime-only lifelines die on every switch reboot: re-arm, don't trust
#   - boot_net serves whatever sits in a tftp root: quarantine unknowns
#   - dropbear has no sftp: scp needs -O
#   - this bench switch self-rebooted 3-4x on 2026-09-23: assume tmpfs wiped

# ---- switch identity: the address lives in the operator's private registry,
# ---- never in this public repo. CONWRT_BENCH_SWITCH may be "host" or
# ---- "root@host"; SSH always goes in as root.
: "${CONWRT_BENCH_SWITCH:?set CONWRT_BENCH_SWITCH to the bench switch management host (host or root@host)}"
case "$CONWRT_BENCH_SWITCH" in
    *@*) SWITCH="$CONWRT_BENCH_SWITCH" ;;
    *)   SWITCH="root@$CONWRT_BENCH_SWITCH" ;;
esac
SWITCH_HOST=${SWITCH#*@}

STAGE_DST=/tmp/bench-arm-fit.stage
FIT_FILE=openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-squashfs-sysupgrade.bin
FIT_MD5=2242e9b7b31eec6251d8c168474a919d

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
FIT_PATH="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)/data/images/$FIT_FILE"

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "== $*"; }

# Mgmt reachability + ARP + PVID preflight. The 2026-11-05 outage: the
# VLAN-1008 bridge-vlan carrying an untagged host port made the management
# address silent while the VLAN-1008 SVI answered. Detect both the stale-ARP
# symptom and the PVID collision before touching anything.
preflight_switch() {
    note "preflight: switch $SWITCH_HOST"
    if ! ping -c 1 "$SWITCH_HOST" >/dev/null 2>&1; then
        if command -v ip >/dev/null 2>&1; then
            echo "   local IPv4 neighbours:"
            ip -4 neigh show 2>/dev/null | sed 's/^/     /' || true
        fi
        die "switch $SWITCH_HOST does not answer. If another SVI answers instead, check the VLAN-1008 bridge-vlan ports for an untagged PVID collision with the management VLAN."
    fi
    if command -v ip >/dev/null 2>&1; then
        ROUTE=$(ip route get "$SWITCH_HOST" 2>/dev/null | head -1)
        [ -n "$ROUTE" ] && echo "   route: $ROUTE"
        ARP=$(ip -4 neigh show "$SWITCH_HOST" 2>/dev/null | head -1)
        case "$ROUTE" in
            *" via "*)
                # Routed management: the direct neighbour is the next hop,
                # not the switch. Its absence is diagnostic, not fatal.
                if [ -n "$ARP" ]; then
                    echo "   arp: $ARP"
                else
                    echo "   arp: none for the switch (routed via the next hop)"
                fi
                ;;
            *)
                [ -n "$ARP" ] || die "no IPv4 neighbour entry for $SWITCH_HOST after ping (ARP unresolved on an on-link route)"
                echo "   arp: $ARP"
                case "$ARP" in
                    *INCOMPLETE*|*FAILED*) die "ARP for $SWITCH_HOST is incomplete — wrong management VLAN/PVID?" ;;
                esac
                ;;
        esac
    elif command -v arp >/dev/null 2>&1; then
        ARP=$(arp -n "$SWITCH_HOST" 2>/dev/null | tail -1)
        echo "   arp: $ARP"
        case "$ARP" in
            *incomplete*) die "ARP for $SWITCH_HOST is incomplete — wrong management VLAN/PVID?" ;;
        esac
    fi
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$SWITCH" true 2>/dev/null || \
        die "SSH to $SWITCH failed (key auth? wrong host? wrong management VLAN?)"
    # Read the VLAN-1008 layout without assuming one section naming. The
    # deploy tool emits vlan1008 (bridge-vlan) + dut1008 (interface); older
    # bench configs use a single v1008 section. Resolve by name, then by
    # vlan=1008/device=switch.1008, so both shapes work.
    if ! V1008_INFO=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$SWITCH" 'sh -s' <<'__PREFLIGHT__'
vlan_sec=""; vlan_ports=""
for s in v1008 vlan1008; do
    p=$(uci -q get network.$s.ports)
    [ -n "$p" ] && { vlan_sec=$s; vlan_ports=$p; break; }
done
if [ -z "$vlan_sec" ]; then
    for s in $(uci -q show network | sed -n "s/^network\.\([^.=]*\)\.vlan='\?1008'\?\$/\1/p"); do
        p=$(uci -q get network.$s.ports)
        [ -n "$p" ] && { vlan_sec=$s; vlan_ports=$p; break; }
    done
fi
svi_sec=""; svi_ip=""
for s in v1008 dut1008; do
    a=$(uci -q get network.$s.ipaddr)
    [ -n "$a" ] && { svi_sec=$s; svi_ip=$a; break; }
done
if [ -z "$svi_sec" ]; then
    for s in $(uci -q show network | sed -n "s/^network\.\([^.=]*\)\.device='\?\(switch\|br-lan\)\.1008'\?\$/\1/p"); do
        a=$(uci -q get network.$s.ipaddr)
        [ -n "$a" ] && { svi_sec=$s; svi_ip=$a; break; }
    done
fi
mgmt_sec=""; mgmt_vlan=""; mgmt_ports=""
mgmt_dev=$(uci -q get network.lan.device)
if [ -n "$mgmt_dev" ]; then
    mgmt_vlan=${mgmt_dev##*.}
    for s in vlan$mgmt_vlan v$mgmt_vlan; do
        p=$(uci -q get network.$s.ports)
        [ -n "$p" ] && { mgmt_sec=$s; mgmt_ports=$p; break; }
    done
fi
printf 'vlan_sec=%s\nvlan_ports=%s\nsvi_sec=%s\nsvi_ip=%s\nmgmt_sec=%s\nmgmt_vlan=%s\nmgmt_ports=%s\n' \
    "$vlan_sec" "$vlan_ports" "$svi_sec" "$svi_ip" "$mgmt_sec" "$mgmt_vlan" "$mgmt_ports"
__PREFLIGHT__
    ); then
        die "cannot read the VLAN-1008 layout from $SWITCH — is this the bench switch?"
    fi
    VLAN_SEC=$(printf '%s\n' "$V1008_INFO" | sed -n 's/^vlan_sec=//p')
    VLAN_PORTS=$(printf '%s\n' "$V1008_INFO" | sed -n 's/^vlan_ports=//p')
    SVI_SEC=$(printf '%s\n' "$V1008_INFO" | sed -n 's/^svi_sec=//p')
    SVI_IP=$(printf '%s\n' "$V1008_INFO" | sed -n 's/^svi_ip=//p' | cut -d/ -f1)
    MGMT_SEC=$(printf '%s\n' "$V1008_INFO" | sed -n 's/^mgmt_sec=//p')
    MGMT_VLAN=$(printf '%s\n' "$V1008_INFO" | sed -n 's/^mgmt_vlan=//p')
    MGMT_PORTS=$(printf '%s\n' "$V1008_INFO" | sed -n 's/^mgmt_ports=//p')
    [ -n "$VLAN_SEC" ] && [ -n "$VLAN_PORTS" ] || \
        die "cannot find the VLAN-1008 bridge-vlan ports on $SWITCH — wrong device or unconfigured?"
    echo "   v1008 VLAN section: $VLAN_SEC.ports=$VLAN_PORTS"
    if [ -n "$SVI_SEC" ]; then
        echo "   v1008 SVI section:  $SVI_SEC.ipaddr=$SVI_IP"
    fi
    if [ -n "$MGMT_SEC" ]; then
        echo "   management VLAN:    $MGMT_SEC (vlan $MGMT_VLAN).ports=$MGMT_PORTS"
    else
        echo "   management VLAN:    not resolved (network.lan.device is empty); PVID check skipped"
    fi

    # PVID collision: only a port that is ':u*' (untagged + PVID) in BOTH
    # VLAN 1008 and the management VLAN is a collision. A DUT access port
    # (:u* in 1008, absent from the management VLAN) is valid.
    V1008_PVID=""
    for p in $VLAN_PORTS; do
        case "$p" in
            *:u\**) V1008_PVID="$V1008_PVID ${p%%:*}";;
        esac
    done
    MGMT_PVID=""
    for p in $MGMT_PORTS; do
        case "$p" in
            *:u\**) MGMT_PVID="$MGMT_PVID ${p%%:*}";;
        esac
    done
    COLLISION=""
    for p in $V1008_PVID; do
        case " $MGMT_PVID " in
            *" $p "*) COLLISION="$COLLISION $p";;
        esac
    done
    if [ -n "$COLLISION" ]; then
        COLLISION_CMDS=""
        for p in $COLLISION; do
            COLLISION_CMDS="${COLLISION_CMDS}
  # ${p}: host-wire/uplink option -> tag it in the DUT VLAN
  uci del_list network.${VLAN_SEC}.ports='${p}:u*'; uci add_list network.${VLAN_SEC}.ports='${p}:t'
  # ${p}: DUT access-port option -> remove the management PVID
  uci del_list network.${MGMT_SEC}.ports='${p}:u*'"
        done
        die "PVID collision: port(s)${COLLISION} are ':u*' in both ${VLAN_SEC} and ${MGMT_SEC}.
Repair on the switch with a deadman and a readback (do not run a bare uci commit):
  ssh ${SWITCH_HOST}
  nohup sh -c 'sleep 300 && reboot' >/dev/null 2>&1 &   # deadman: 300s
  # Choose ONE option per port, then read both values back:
${COLLISION_CMDS}
  uci get network.${VLAN_SEC}.ports
  [ -n '${MGMT_SEC}' ] && uci get network.${MGMT_SEC}.ports
  uci commit network
  ubus call network reload
  # From the management host, verify the path before cancelling the deadman:
  ping -c 1 ${SWITCH_HOST} && ssh ${SWITCH} true
  # kill the sleep PID only after that verification"
    fi
    V1008_PORTS=$VLAN_PORTS
    V1008_IP=$SVI_IP
    if [ -n "$V1008_IP" ]; then
        echo "   v1008.ipaddr: $V1008_IP"
        if command -v ip >/dev/null 2>&1; then
            ip -4 neigh show "$SWITCH_HOST" "$V1008_IP" 2>/dev/null | sed 's/^/   neigh: /' || true
        fi
    fi
}

mac_md5() { md5 -q "$1" 2>/dev/null || md5sum "$1" 2>/dev/null | awk '{print $1}'; }

stage_fit() {
    [ -f "$FIT_PATH" ] || die "FIT not found locally: $FIT_PATH"
    GOT=$(mac_md5 "$FIT_PATH")
    [ "$GOT" = "$FIT_MD5" ] || die "local FIT md5 mismatch: $GOT != $FIT_MD5"
    note "staging FIT from the Mac ($FIT_FILE, md5 $FIT_MD5)"
    scp -O -q "$FIT_PATH" "$SWITCH:$STAGE_DST" || die "scp of FIT failed (dropbear needs -O)"
}

# ---- switch-side payload: stdin-fed (`ssh sh -s`), so ps/pgrep never
# ---- self-match the caller's command line. The FIT_* constants below must
# ---- stay in sync with the Mac-side block above (both are md5-gated on
# ---- every run, so drift fails loudly).
payload() {
cat <<'__REMOTE__'
FIT_MD5=2242e9b7b31eec6251d8c168474a919d
FIT_ALIAS=vmlinux.gz.uImage.3912
FIT_ITB=openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-initramfs-uImage.itb
SHARED_DIR=/tmp/bench-tftp
SHARED_PIDF=/tmp/dnsmasq-bench.pid
SHARED_LOG=/tmp/bench-arm.log
L1003_DIR=/tmp/tftproot1003
L1003_PIDF=/tmp/dnsmasq-bench-1003.pid
L1003_LOG=/tmp/bench-arm-1003.log
STAGE=/tmp/bench-arm-fit.stage

armed=""; disarmed=""
ok()  { armed="$armed $1";         echo "ARMED    $1: $2"; }
bad() { disarmed="$disarmed $1";   echo "DISARMED $1: $2"; }

md5of() { md5sum "$1" 2>/dev/null | awk '{print $1}'; }
cmdline_has() { tr '\0' ' ' </proc/$1/cmdline 2>/dev/null | grep -q "$2"; }

# ---- 1. fw4 input accepts (unzoned DUT VLANs drop UDP/TCP otherwise) ----
fw4_accepted() { # fw4_accepted <vlan>: direct input accept OR lan-zone accept
    nft list ruleset 2>/dev/null | grep "switch\\.$1\"" | grep -q accept
}
for V in 1002 1003 1005; do
    if fw4_accepted "$V"; then
        ok "fw4-$V" "accept already present (input chain or lan zone)"
    elif nft insert rule inet fw4 input iifname "switch.$V" accept 2>/dev/null && fw4_accepted "$V"; then
        ok "fw4-$V" "accept inserted into inet fw4 input"
    else
        bad "fw4-$V" "no accept found and insert failed"
    fi
done

# ---- 2. recovery aliases (U-Boot serverip=192.168.1.2 on boot_net units) ----
for V in 1002 1005; do
    if ip addr show "switch.$V" 2>/dev/null | grep -q '192.168.1.2/'; then
        ok "alias-$V" "192.168.1.2 already on switch.$V"
    elif ip addr add 192.168.1.2/24 dev "switch.$V" 2>/dev/null && \
         ip addr show "switch.$V" 2>/dev/null | grep -q '192.168.1.2/'; then
        ok "alias-$V" "192.168.1.2/24 added to switch.$V"
    else
        bad "alias-$V" "cannot add 192.168.1.2/24 (interface missing?)"
    fi
done

# ---- 3. TFTP bait: one validated FIT inode, hardlinked under all names ----
fit_src=""
for CAND in "$SHARED_DIR/$FIT_ALIAS" "$L1003_DIR/$FIT_ALIAS" "$L1003_DIR/$FIT_ITB" "$STAGE"; do
    [ -f "$CAND" ] && [ "$(md5of "$CAND")" = "$FIT_MD5" ] && { fit_src="$CAND"; break; }
done
if [ -z "$fit_src" ]; then
    echo "NEED-STAGE: no file with md5 $FIT_MD5 on the switch — Mac must scp the FIT"
    exit 2
fi
quarantine_unknowns() { # quarantine_unknowns <dir> <known-name>...
    d=$1; shift
    for f in "$d"/*; do
        [ -f "$f" ] || continue
        b=$(basename "$f"); keep=0
        for k in "$@"; do [ "$b" = "$k" ] && keep=1; done
        [ "$keep" = 1 ] && continue
        m=$(md5of "$f")
        mkdir -p "$d/quarantine"
        if mv "$f" "$d/quarantine/$b.$(date +%H%M%S)" 2>/dev/null; then
            echo "NOTE     quarantine: $d/$b (md5 $m) — boot_net serves whatever sits in a root"
        fi
    done
}
ensure_bait() { # ensure_bait <dir> <name> — hardlink fit_src, md5-gated
    p="$1/$2"
    [ -f "$p" ] && [ "$(md5of "$p")" = "$FIT_MD5" ] && return 0
    rm -f "$p"
    ln "$fit_src" "$p" 2>/dev/null
    [ "$(md5of "$p")" = "$FIT_MD5" ]
}
mkdir -p "$SHARED_DIR" "$L1003_DIR"
quarantine_unknowns "$SHARED_DIR" "$FIT_ALIAS"
quarantine_unknowns "$L1003_DIR" "$FIT_ALIAS" "$FIT_ITB"
if ensure_bait "$SHARED_DIR" "$FIT_ALIAS" && \
   ensure_bait "$L1003_DIR" "$FIT_ALIAS" && ensure_bait "$L1003_DIR" "$FIT_ITB"; then
    ok "fit" "md5 $FIT_MD5 under $FIT_ALIAS + $FIT_ITB (hardlinked, both roots)"
    rm -f "$STAGE"
else
    bad "fit" "could not stage bait from $fit_src"
fi

# ---- 4. shared TFTP dnsmasq on 1002+1005 (adopt-if-absent) ----
# Scout guard: adoption requires a dnsmasq whose cmdline carries
# bench-tftp AND switch.1002 AND switch.1005. The scout instance
# (1007-only DHCP, no tftp-root) can never match; this tool never
# references switch.1007.
shared_pid=""
for p in $(pgrep -f 'dnsmasq.*bench-tftp' 2>/dev/null); do
    if cmdline_has "$p" switch.1002 && cmdline_has "$p" switch.1005; then
        shared_pid=$p; break
    fi
done
if [ -n "$shared_pid" ]; then
    ok "shared-dnsmasq" "adopted pid $shared_pid (already serving 1002+1005)"
else
    rm -f "$SHARED_PIDF"
    dnsmasq --port=0 --enable-tftp --tftp-root="$SHARED_DIR" \
        --interface=switch.1002 --interface=switch.1005 --bind-dynamic \
        --pid-file="$SHARED_PIDF" --log-facility="$SHARED_LOG" 2>>"$SHARED_LOG"
    sleep 1
    p=$(cat "$SHARED_PIDF" 2>/dev/null)
    if [ -n "$p" ] && kill -0 "$p" 2>/dev/null && netstat -lnu 2>/dev/null | grep -q ':69 '; then
        ok "shared-dnsmasq" "started pid $p (UDP:69 bound, log $SHARED_LOG)"
    else
        bad "shared-dnsmasq" "start failed (see $SHARED_LOG)"
    fi
fi

# ---- 5. dedicated VLAN-1003 TFTP lifeline (ap-lan3 insurance) ----
p=$(cat "$L1003_PIDF" 2>/dev/null)
if [ -n "$p" ] && kill -0 "$p" 2>/dev/null && cmdline_has "$p" tftproot1003; then
    ok "lifeline-1003" "adopted pid $p (TFTP root $L1003_DIR)"
else
    rm -f "$L1003_PIDF"
    dnsmasq --port=0 --enable-tftp --tftp-root="$L1003_DIR" \
        --interface=switch.1003 --bind-dynamic \
        --pid-file="$L1003_PIDF" --log-facility="$L1003_LOG" 2>>"$L1003_LOG"
    sleep 1
    p=$(cat "$L1003_PIDF" 2>/dev/null)
    if [ -n "$p" ] && kill -0 "$p" 2>/dev/null && \
       netstat -lnu 2>/dev/null | grep -q '192.168.103.1:69'; then
        ok "lifeline-1003" "armed pid $p (UDP 192.168.103.1:69, log $L1003_LOG)"
    else
        bad "lifeline-1003" "start failed (see $L1003_LOG)"
    fi
fi

# ---- 6. /32 pin: DUT default-IP replies must leave via VLAN 1005 only ----
if ip route show 192.168.1.1/32 2>/dev/null | grep -q 'dev switch\.1005'; then
    ok "route-1.1-pin" "192.168.1.1/32 dev switch.1005 already pinned"
elif { ip route replace 192.168.1.1/32 dev switch.1005 2>/dev/null || \
       ip route add 192.168.1.1/32 dev switch.1005 2>/dev/null; } && \
     ip route show 192.168.1.1/32 2>/dev/null | grep -q 'dev switch\.1005'; then
    ok "route-1.1-pin" "pinned 192.168.1.1/32 -> switch.1005 (wrong-VLAN ECMP bug fix)"
else
    bad "route-1.1-pin" "could not pin route"
fi

# ---- 7. ap-lan2 aliveness recorder (canary for the fragile unit) ----
if [ -f /etc/ap-lan2-watch.sh ]; then
    w=$(cat /tmp/ap-lan2-watch.pid 2>/dev/null)
    if [ -n "$w" ] && kill -0 "$w" 2>/dev/null; then
        ok "ap-lan2-watch" "recorder alive (pid $w)"
    else
        setsid sh /etc/ap-lan2-watch.sh >/dev/null 2>&1 &
        sleep 1
        w=$(cat /tmp/ap-lan2-watch.pid 2>/dev/null)
        if [ -n "$w" ] && kill -0 "$w" 2>/dev/null; then
            ok "ap-lan2-watch" "recorder started (pid $w)"
        else
            bad "ap-lan2-watch" "start failed"
        fi
    fi
else
    echo "NOTE     ap-lan2-watch: /etc/ap-lan2-watch.sh not deployed (skip)"
fi

echo "--------"
if [ -n "$disarmed" ]; then
    echo "BENCH-ARM-RESULT: DISARMED:$disarmed"
    exit 1
fi
echo "BENCH-ARM-RESULT: ARMED — re-run scripts/gs1900-bench-arm.sh after any switch reboot"
exit 0
__REMOTE__
}

arm_once() {
    _out=$(payload | ssh -o BatchMode=yes -o ConnectTimeout=10 "$SWITCH" sh -s 2>&1); _rc=$?
    printf '%s\n' "$_out"
    return "$_rc"
}

note "re-arming bench failsafes on $SWITCH"
preflight_switch
arm_once; RC=$?
if [ "$RC" -eq 2 ]; then
    stage_fit
    note "bait staged — re-running arm"
    arm_once; RC=$?
fi
[ "$RC" -eq 0 ] && exit 0
die "bench remains DISARMED (see DISARMED lines above)"
