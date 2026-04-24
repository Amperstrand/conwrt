#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

source "$(dirname "$0")/lib/common.sh"

for cmd in bash git curl jq nmap npx; do
  conwrt::require_cmd "$cmd"
done

target_ip=""
operator="${USER:-anonymous}"
iface=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)   target_ip="${2:?--target requires a value}"; shift 2 ;;
    --operator) operator="$2"; shift 2 ;;
    --interface) iface="$2"; shift 2 ;;
    *) conwrt::die "Unknown argument: $1" ;;
  esac
done

if [[ -z "$target_ip" ]]; then
  conwrt::die "Usage: $0 --target <ip-or-slug> [--operator <name>] [--interface <name>]"
fi

if [[ -z "$iface" ]]; then
  iface="$(ip route show default 2>/dev/null | awk '/default/ { for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit }')"
  if [[ -z "$iface" ]]; then
    conwrt::die "Could not auto-detect default interface. Specify --interface."
  fi
  conwrt::log "info" "Auto-detected interface: ${iface}"
fi

# Sanitize target IP to slug: 192.168.1.1 → 192-168-1-1
slug="$(echo "$target_ip" | tr '.' '-')"
run_id="$(conwrt::new_run_id "$slug")"
run_dir="${CONWRTER_RUNS_DIR}/${run_id}"

if [[ -d "$run_dir" ]]; then
  conwrt::die "Run directory already exists: ${run_dir}"
fi

mkdir -p "$run_dir"
conwrt::log "info" "Created run directory: ${run_dir}"

created_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

jq -n \
  --arg run_id         "$run_id" \
  --arg created_at     "$created_at" \
  --arg target_ip      "$target_ip" \
  --arg interface      "$iface" \
  --arg operator       "$operator" \
  --arg conwrt_version "$CONWRTER_VERSION" \
  '{
    run_id:           $run_id,
    created_at:       $created_at,
    target: {
      target_ip:  $target_ip,
      interface:  $interface
    },
    operator:         $operator,
    conwrt_version: $conwrt_version,
    steps_completed:  []
  }' > "${run_dir}/run-metadata.json"

conwrt::log "info" "Wrote run-metadata.json"

conwrt::ensure_state_json "$run_dir"

# ONLY stdout output — machine-parseable absolute path
echo "$run_dir"
