#!/usr/bin/env bash
# bench_rsyslog_deploy.sh — deploy the conwrt bench UDP syslog receiver.
#
# Substitutes the pattern conf (labgrid/rsyslog-bench.conf) with the real
# log dir, installs it as /etc/rsyslog.d/30-bench.conf, fixes ownership
# (rsyslog runs as 'syslog', uid 102 — a root-owned logdir discards every
# message), validates the config with `rsyslogd -N1` BEFORE restarting,
# and verifies the UDP :514 listener bound.
# Idempotent: re-running re-substitutes and restarts.
#
# Usage: scripts/bench_rsyslog_deploy.sh [--logdir DIR]
set -euo pipefail

LOGDIR="${LOGDIR:-/var/log/bench}"
CONF_SRC="$(dirname "$0")/../labgrid/rsyslog-bench.conf"
CONF_DST="/etc/rsyslog.d/30-bench.conf"

while [ $# -gt 0 ]; do
    case "$1" in
        --logdir) LOGDIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ -f "$CONF_SRC" ] || { echo "missing $CONF_SRC" >&2; exit 1; }
command -v rsyslogd >/dev/null || { echo "rsyslog not installed (apt install rsyslog)" >&2; exit 1; }
id syslog >/dev/null 2>&1 || { echo "no 'syslog' user (rsyslog not set up?)" >&2; exit 1; }

mkdir -p "$LOGDIR"
SYSLOG_UID=$(id -u syslog)
SYSLOG_GID=$(id -g syslog)
chown "$SYSLOG_UID:$SYSLOG_GID" "$LOGDIR"
chmod 755 "$LOGDIR"

sed -e "s|{{LOGDIR}}|${LOGDIR}|g" "$CONF_SRC" > "$CONF_DST"
chmod 644 "$CONF_DST"

# Validate BEFORE restarting: a broken conf leaves rsyslog half-up (the
# imudp socket still binds, so a socket-only check passes while every
# message is discarded — that false-green bit this deploy's first version).
if ! rsyslogd -N1 -f "$CONF_DST" >/dev/null 2>&1; then
    echo "FAIL: config does not parse (rsyslogd -N1)" >&2
    rsyslogd -N1 -f "$CONF_DST" 2>&1 | tail -3 >&2
    rm -f "$CONF_DST"
    exit 1
fi

systemctl restart rsyslog
sleep 1

if ss -ulnp | grep -q ':514 '; then
    echo "OK: UDP :514 listening (config validated); device logs -> ${LOGDIR}/<ip>/<date>.log"
    echo "verify from a DUT: uci set system.@system[0].log_ip=<host-ip-on-DUT-subnet>;"
    echo "                  uci set system.@system[0].log_port='514'; uci commit system;"
    echo "                  /etc/init.d/log restart; logger -t test hello"
else
    echo "FAIL: no UDP :514 listener after restart" >&2
    journalctl -u rsyslog -n 10 --no-pager >&2
    exit 1
fi
