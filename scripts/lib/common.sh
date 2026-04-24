#!/usr/bin/env bash
# scripts/lib/common.sh — Shared helper library for conwrt scripts.
# Source this file; do not execute it directly.
# Usage: source "$(dirname "$0")/lib/common.sh"

set -euo pipefail
IFS=$'\n\t'

# Guard against double-sourcing
[[ -n "${_CONWRTER_COMMON_LOADED:-}" ]] && return
_CONWRTER_COMMON_LOADED=1

# Absolute path to project root (the directory containing scripts/)
CONWRTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONWRTER_RUNS_DIR="${CONWRTER_ROOT}/runs"
CONWRTER_VERSION="${CONWRTER_VERSION:-0.1.0-dev}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

conwrt::log() {
  local level="${1:?level required}"
  local msg="${2:?message required}"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "[${level^^}] ${ts} ${msg}" >&2
}

conwrt::die() {
  conwrt::log "error" "${1:-fatal error}"
  exit 1
}

# ---------------------------------------------------------------------------
# Dependency checking
# ---------------------------------------------------------------------------

conwrt::require_cmd() {
  local cmd="${1:?command name required}"
  if ! command -v "$cmd" &>/dev/null; then
    local hint
    case "$cmd" in
      nmap)   hint="Install nmap: sudo apt-get install nmap  OR  brew install nmap" ;;
      jq)     hint="Install jq: sudo apt-get install jq  OR  brew install jq" ;;
      npx)    hint="Install Node.js (>=18): https://nodejs.org/ (npx is bundled)" ;;
      git)    hint="Install git: sudo apt-get install git  OR  brew install git" ;;
      curl)   hint="Install curl: sudo apt-get install curl  OR  brew install curl" ;;
      bats)   hint="Install bats-core: https://bats-core.readthedocs.io/ (dev dependency)" ;;
      *)      hint="Install '${cmd}' using your system package manager" ;;
    esac
    conwrt::die "Required command '${cmd}' not found. ${hint}"
  fi
}

# ---------------------------------------------------------------------------
# Run ID management
# ---------------------------------------------------------------------------

conwrt::new_run_id() {
  local slug="${1:?slug required}"
  # Sanitize slug: lowercase, replace non-alphanumeric with hyphens
  slug="$(echo "$slug" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/-\+/-/g' | sed 's/^-\|-$//g')"
  local ts
  ts="$(date -u +"%Y%m%d-%H%M%S")"
  echo "${ts}-${slug}"
}

conwrt::resolve_run_id() {
  local arg="${1:-latest}"
  local run_dir

  if [[ "$arg" == "latest" ]]; then
    # Find the most recently modified run directory
    run_dir="$(find "${CONWRTER_RUNS_DIR}" -maxdepth 1 -mindepth 1 -type d | sort | tail -1)"
    if [[ -z "$run_dir" ]]; then
      conwrt::die "No runs found in ${CONWRTER_RUNS_DIR}. Run 'make init' first."
    fi
  else
    run_dir="${CONWRTER_RUNS_DIR}/${arg}"
    if [[ ! -d "$run_dir" ]]; then
      conwrt::die "Run directory not found: ${run_dir}"
    fi
  fi

  echo "$run_dir"
}

# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

conwrt::ensure_state_json() {
  local run_dir="${1:?run_dir required}"
  local state_file="${run_dir}/state.json"
  if [[ ! -f "$state_file" ]]; then
    echo '{"steps_completed":[]}' > "$state_file"
    conwrt::log "info" "Initialized state.json at ${state_file}"
  fi
}

conwrt::mark_step_complete() {
  local run_dir="${1:?run_dir required}"
  local step_id="${2:?step_id required}"
  local state_file="${run_dir}/state.json"

  conwrt::require_cmd jq

  # Append step_id if not already present
  local updated
  updated="$(jq --arg step "$step_id" \
    'if (.steps_completed | index($step)) then . else .steps_completed += [$step] end' \
    "$state_file")"
  echo "$updated" > "$state_file"
  conwrt::log "info" "Marked ${step_id} complete in ${state_file}"
}
