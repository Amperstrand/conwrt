#!/bin/sh
# poe.sh — bench-switch PoE control for labgrid ExternalPowerDriver.
# Usage: poe.sh <port> <enable|disable> [switch-host]
# Switch host defaults to $BENCH_SWITCH_HOST (real coords live in local
# bench records only — no IP is committed).
# The realtek-poe fork speaks action:strings (not enable:bools — see
# docs/BENCH-SWITCH-PATTERN.md for the labgrid-native follow-up).
# ControlMaster: repeated calls reuse one authenticated SSH connection.
set -u
PORT="${1:?port required, e.g. lan4}"
ACTION="${2:?action required: enable|disable}"
HOST="${3:-${BENCH_SWITCH_HOST:?set BENCH_SWITCH_HOST or pass switch host as arg 3}}"
exec ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ControlMaster=auto -o "ControlPath=/tmp/conwrt-poe-%r@%h:%p" -o ControlPersist=30s \
    "root@${HOST}" \
    "ubus call poe manage '{\"port\":\"${PORT}\",\"action\":\"${ACTION}\"}'"
