#!/bin/sh
# gs1900-bench-arm.sh — THE idempotent bench re-arm tool for the GS1900-8HP
# bench switch (root@192.168.13.2, zyxel gs1900-8hp-a1).
#
# Usage (from the Mac, over ssh):
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
#                       the 24.10.2 sysupgrade FIT (sha256 38ca3856...) under
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

SWITCH=root@192.168.13.2
STAGE_DST=/tmp/bench-arm-fit.stage
FIT_FILE=openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-squashfs-sysupgrade.bin
# sha256 of the FIT above (md5 2242e9b7b31eec6251d8c168474a919d for
# cross-checking against older notes): the BusyBox baseline guarantees
# sha256sum, NOT md5sum — an md5 gate quarantines a perfectly good FIT.
FIT_SHA256=38ca385660e46aa084017b80e620ab07fb30716a07bcaab8f3d5435bc88bf848

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
FIT_PATH="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)/data/images/$FIT_FILE"

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "== $*"; }

mac_sha256() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}' || sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

stage_fit() {
    [ -f "$FIT_PATH" ] || die "FIT not found locally: $FIT_PATH"
    GOT=$(mac_sha256 "$FIT_PATH")
    [ "$GOT" = "$FIT_SHA256" ] || die "local FIT sha256 mismatch: $GOT != $FIT_SHA256"
    note "staging FIT from the Mac ($FIT_FILE, sha256 $FIT_SHA256)"
    scp -O -q "$FIT_PATH" "$SWITCH:$STAGE_DST" || die "scp of FIT failed (dropbear needs -O)"
}

# ---- switch-side payload: stdin-fed (`ssh sh -s`), so ps/pgrep never
# ---- self-match the caller's command line. The FIT_* constants below must
# ---- stay in sync with the Mac-side block above (both are sha256-gated on
# ---- every run, so drift fails loudly).
payload() {
cat <<'__REMOTE__'
FIT_SHA256=38ca385660e46aa084017b80e620ab07fb30716a07bcaab8f3d5435bc88bf848
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

sha256of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
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
    [ -f "$CAND" ] && [ "$(sha256of "$CAND")" = "$FIT_SHA256" ] && { fit_src="$CAND"; break; }
done
if [ -z "$fit_src" ]; then
    echo "NEED-STAGE: no file with sha256 $FIT_SHA256 on the switch — Mac must scp the FIT"
    exit 2
fi
quarantine_unknowns() { # quarantine_unknowns <dir> <known-name>...
    d=$1; shift
    for f in "$d"/*; do
        [ -f "$f" ] || continue
        b=$(basename "$f"); keep=0
        for k in "$@"; do [ "$b" = "$k" ] && keep=1; done
        [ "$keep" = 1 ] && continue
        m=$(sha256of "$f")
        mkdir -p "$d/quarantine"
        if mv "$f" "$d/quarantine/$b.$(date +%H%M%S)" 2>/dev/null; then
            echo "NOTE     quarantine: $d/$b (sha256 $m) — boot_net serves whatever sits in a root"
        fi
    done
}
ensure_bait() { # ensure_bait <dir> <name> — hardlink fit_src, sha256-gated
    p="$1/$2"
    [ -f "$p" ] && [ "$(sha256of "$p")" = "$FIT_SHA256" ] && return 0
    rm -f "$p"
    ln "$fit_src" "$p" 2>/dev/null
    [ "$(sha256of "$p")" = "$FIT_SHA256" ]
}
mkdir -p "$SHARED_DIR" "$L1003_DIR"
quarantine_unknowns "$SHARED_DIR" "$FIT_ALIAS"
quarantine_unknowns "$L1003_DIR" "$FIT_ALIAS" "$FIT_ITB"
if ensure_bait "$SHARED_DIR" "$FIT_ALIAS" && \
   ensure_bait "$L1003_DIR" "$FIT_ALIAS" && ensure_bait "$L1003_DIR" "$FIT_ITB"; then
    ok "fit" "sha256 $FIT_SHA256 under $FIT_ALIAS + $FIT_ITB (hardlinked, both roots)"
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
arm_once; RC=$?
if [ "$RC" -eq 2 ]; then
    stage_fit
    note "bait staged — re-running arm"
    arm_once; RC=$?
fi
[ "$RC" -eq 0 ] && exit 0
die "bench remains DISARMED (see DISARMED lines above)"
