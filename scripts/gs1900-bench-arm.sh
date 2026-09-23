#!/bin/sh
# gs1900-bench-arm.sh — re-arm runtime bench failsafes on the GS1900-8HP bench
# switch. Idempotent and boot-safe: every step is guarded, failures log and
# continue. Deployed copy lives at /etc/bench-arm.sh on the switch (committed
# overlay, survives reboot) and is called from /etc/rc.local.
#
# Why this exists (2026-09-23): the nft accept rule, TFTP lifelines and DUT
# watchers were runtime-only and died silently (dnsmasq + watcher found dead
# mid-session with no reboot). Runtime state must be re-armed at every boot.
#
# The 24.10.2 sysupgrade FIT (10.1MB) does NOT fit the 7MB /overlay — it lives
# on tmpfs and MUST be re-staged after a switch reboot. The script logs the
# exact scp command when it finds the root empty.

LOG=/tmp/bench-arm.log
FIT_MD5=2242e9b7b31eec6251d8c168474a919d
FIT_NAME=vmlinux.gz.uImage.3912
TFTPDIR=/tmp/bench-tftp

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }

# 1. fw4: unzoned DUT VLANs drop inbound UDP/TCP otherwise (runtime rule)
if nft list chain inet fw4 input 2>/dev/null | grep -q 'switch\.10'; then
    log "nft: accept rule already present"
else
    if nft insert rule inet fw4 input iifname '"switch.10*"' accept 2>/dev/null; then
        log "nft: accept rule inserted"
    else
        log "nft: FAILED to insert accept rule"
    fi
fi

# 2. per-VLAN recovery aliases (U-Boot serverip=192.168.1.2 on boot_net units)
for V in 1002 1005; do
    if ip addr show "switch.$V" 2>/dev/null | grep -q '192.168.1.2/'; then
        log "alias: 192.168.1.2 already on switch.$V"
    else
        if ip addr add 192.168.1.2/24 dev "switch.$V" 2>/dev/null; then
            log "alias: 192.168.1.2 added to switch.$V"
        else
            log "alias: FAILED to add 192.168.1.2 to switch.$V (interface up?)"
        fi
    fi
done

# 3. TFTP lifeline image (tmpfs — wiped on reboot). Unknown files are
#    quarantined, never deleted: boot_net serves whatever sits in the root,
#    so the root must hold exactly one KNOWN image (md5-gated).
mkdir -p "$TFTPDIR"
for F in "$TFTPDIR"/*; do
    [ -f "$F" ] || continue
    GOT=$(md5sum "$F" 2>/dev/null | awk '{print $1}')
    if [ "$GOT" != "$FIT_MD5" ]; then
        mkdir -p "$TFTPDIR/quarantine"
        MV="$TFTPDIR/quarantine/$(basename "$F").$(date '+%H%M%S')"
        mv "$F" "$MV" 2>/dev/null && log "fit: UNKNOWN file quarantined -> $MV (md5 $GOT)"
    fi
done
if [ -f "$TFTPDIR/$FIT_NAME" ]; then
    log "fit: $FIT_NAME ok ($FIT_MD5)"
else
    log "fit: LIFELINE DEGRADED — $FIT_NAME missing (tmpfs wiped by reboot). Re-stage from the Mac:"
    log "fit:   scp -O ~/src/conwrt/data/images/openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-squashfs-sysupgrade.bin root@192.168.13.2:$TFTPDIR/$FIT_NAME"
fi

# 4. dnsmasq TFTP server on the DUT VLANs (boot_net fetches $FIT_NAME)
if pgrep -f 'dnsmasq.*bench-tftp' >/dev/null 2>&1; then
    log "dnsmasq: tftp already serving"
elif [ -f "$TFTPDIR/$FIT_NAME" ]; then
    if dnsmasq --port=0 --enable-tftp --tftp-root="$TFTPDIR" \
        --interface=switch.1002 --interface=switch.1005 --bind-dynamic \
        --pid-file=/tmp/dnsmasq-bench.pid \
        --log-facility="$LOG" 2>>"$LOG"; then
        log "dnsmasq: tftp armed on switch.1002 + switch.1005"
    else
        log "dnsmasq: FAILED to start"
    fi
else
    log "dnsmasq: not started (fit missing)"
fi

# 5. ap-lan2 aliveness recorder (canary for the fragile unit) — pidfile
#    check only; pgrep -f self-matches the caller's command line.
if [ -f /etc/ap-lan2-watch.sh ]; then
    WPID=$(cat /tmp/ap-lan2-watch.pid 2>/dev/null)
    if [ -n "$WPID" ] && kill -0 "$WPID" 2>/dev/null; then
        log "watch: ap-lan2 recorder already running (pid $WPID)"
    else
        setsid sh /etc/ap-lan2-watch.sh >/dev/null 2>&1 &
        sleep 1
        WPID=$(cat /tmp/ap-lan2-watch.pid 2>/dev/null)
        log "watch: ap-lan2 recorder started (pid $WPID)"
    fi
else
    log "watch: /etc/ap-lan2-watch.sh missing (stage from conwrt scripts/)"
fi

log "bench-arm complete"
tail -50 "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG"
exit 0
