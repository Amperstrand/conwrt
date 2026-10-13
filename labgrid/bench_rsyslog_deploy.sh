#!/bin/sh
# bench_rsyslog_deploy.sh — install the bench syslog receiver on ai-legion.
# STAGED, NOT AUTO-RUN: coordinate with the fleet-plan session before
# deploying (their recovery loops + exporter live on that host). The script
# is additive (new rsyslog drop-in + log dir) and idempotent.
#
# Usage: sh bench_rsyslog_deploy.sh <ai-legion-ssh-alias> <switch-mgmt-ip>
set -eu
HOST="${1:?ai-legion ssh alias required}"
SWITCH_IP="${2:?switch mgmt IP required (goes into the device map)}"

ssh "$HOST" 'command -v rsyslogd >/dev/null || { echo "MISSING: rsyslogd (sudo apt install rsyslog first)"; exit 1; }'
sed "s|SWITCH_MGMT_IP|${SWITCH_IP}|g" "$(dirname "$0")/rsyslog-bench.conf" \
    | ssh "$HOST" 'cat > /tmp/rsyslog-bench.conf && sudo install -m 644 /tmp/rsyslog-bench.conf /etc/rsyslog.d/30-bench.conf && sudo mkdir -p /var/log/bench && sudo systemctl restart rsyslog && echo DEPLOYED'
echo "Verify from the switch: logread -f -r <ai-legion-ip> 514   # lines should appear in /var/log/bench/switch/"
