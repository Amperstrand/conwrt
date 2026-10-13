#!/bin/sh
# mac-lifeline-guard.sh — Mac-side self-heal for the bench TFTP lifeline.
#
# The lifeline FIT (10.1MB) cannot fit the bench switch's 7MB /overlay, so it
# lives on the switch's tmpfs and dies on every switch reboot (bench-arm logs
# "LIFELINE DEGRADED" with the re-stage command). This guard performs that
# re-stage automatically from the Mac, then re-runs bench-arm so the dnsmasq
# lifelines come back with it.
#
# Install (Mac crontab, every 10 minutes):
#   crontab -l 2>/dev/null; echo '*/10 * * * * $HOME/src/conwrt/scripts/mac-lifeline-guard.sh >> $HOME/src/conwrt/data/bench/lifeline-guard.log 2>&1' | crontab -
#
# Fails SOFT on unreachable switch (logs, exit 0) — a bench being physically
# worked (cables moved) must not page anyone; it heals on the next pass.

SWITCH=root@192.168.13.2
FIT_LOCAL="$HOME/src/conwrt/data/images/openwrt-24.10.2-ipq40xx-generic-extreme-networks_ws-ap3915i-squashfs-sysupgrade.bin"
FIT_REMOTE="/tmp/bench-tftp/vmlinux.gz.uImage.3912"
FIT_MD5=2242e9b7b31eec6251d8c168474a919d
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=8"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*"; }

GOT=$(ssh $SSH_OPTS $SWITCH "md5sum $FIT_REMOTE 2>/dev/null" 2>/dev/null | awk '{print $1}')
if [ "$GOT" = "$FIT_MD5" ]; then
    exit 0
fi
if ! ssh $SSH_OPTS $SWITCH true 2>/dev/null; then
    log "switch unreachable — skipping this pass (bench physically worked?)"
    exit 0
fi
log "lifeline FIT missing/wrong (got ${GOT:-none}) — re-staging"
if scp -O -q "$FIT_LOCAL" "$SWITCH:$FIT_REMOTE"; then
    ssh $SSH_OPTS $SWITCH "sh /etc/bench-arm.sh" >/dev/null 2>&1
    GOT2=$(ssh $SSH_OPTS $SWITCH "md5sum $FIT_REMOTE" 2>/dev/null | awk '{print $1}')
    if [ "$GOT2" = "$FIT_MD5" ]; then
        log "lifeline re-armed (md5 verified, bench-arm re-run)"
    else
        log "RESTAGE FAILED — md5 $GOT2 after scp; manual intervention"
        exit 1
    fi
else
    log "scp failed — check Mac image copy at $FIT_LOCAL"
    exit 1
fi
