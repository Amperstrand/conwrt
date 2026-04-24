#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

SCHEMA_DIR="${CONWRTER_ROOT}/schemas"

# ── CLI ──────────────────────────────────────────────────────────────────────

RUN_ID=""
STEP_FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)  RUN_ID="${2:?--run requires an argument}"; shift 2 ;;
    --step) STEP_FILTER="${2:?--step requires an argument}"; shift 2 ;;
    *)      conwrt::die "Unknown flag: $1" ;;
  esac
done

if [[ -z "$RUN_ID" ]]; then
  RUN_ID="latest"
fi

RUN_DIR="$(conwrt::resolve_run_id "$RUN_ID")"

# ── Dependencies ─────────────────────────────────────────────────────────────

conwrt::require_cmd npx

# ── Helpers ──────────────────────────────────────────────────────────────────

_failures=0
_total=0

validate_file() {
  local schema="${1:?}" datafile="${2:?}" label="${3:?}"
  _total=$((_total + 1))
  local _out
  if _out="$(npx -y ajv-cli@5 validate -s "$schema" -d "$datafile" 2>&1)"; then
    conwrt::log "info" "  VALID   ${label}"
    return 0
  else
    conwrt::log "error" "  INVALID ${label}"
    echo "$_out" >&2
    _failures=$((_failures + 1))
    return 1
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
  declare -a _step_dirs=()

  if [[ -n "$STEP_FILTER" ]]; then
    local _padded
    _padded="$(printf '%02d' "$STEP_FILTER")"
    local _cand="${RUN_DIR}/step-${_padded}"
    [[ -d "$_cand" ]] || conwrt::die "Step directory not found: ${_cand}"
    _step_dirs+=("$_cand")
  else
    while IFS= read -r -d '' _d; do
      _step_dirs+=("$_d")
    done < <(find "$RUN_DIR" -maxdepth 1 -mindepth 1 -type d -name 'step-*' -print0 | sort -z)
  fi

  # Validate run-metadata.json
  local _meta="${RUN_DIR}/run-metadata.json"
  if [[ -f "$_meta" ]]; then
    validate_file \
      "${SCHEMA_DIR}/run-metadata.schema.json" \
      "$_meta" \
      "run-metadata.json"
  else
    conwrt::log "error" "  MISSING run-metadata.json at ${_meta}"
    _failures=$((_failures + 1))
  fi

  for _step_dir in "${_step_dirs[@]}"; do
    local _step_name _findings
    _step_name="$(basename "$_step_dir")"
    _findings="${_step_dir}/findings.json"

    if [[ ! -f "$_findings" ]]; then
      conwrt::log "error" "  MISSING ${_step_name}/findings.json"
      _failures=$((_failures + 1))
      continue
    fi

    validate_file \
      "${SCHEMA_DIR}/step-findings.schema.json" \
      "$_findings" \
      "${_step_name}/findings.json"

    # Validate each candidate entry if present
    local _ncandidates
    _ncandidates="$(jq -r '(.candidates // []) | length' "$_findings" 2>/dev/null || echo 0)"
    if [[ "$_ncandidates" -gt 0 ]]; then
      local _i
      for _i in $(seq 0 $((_ncandidates - 1))); do
        local _tmpf
        _tmpf="$(mktemp /tmp/conwrt-candidate-XXXXXX.json)"
        jq ".candidates[$_i]" "$_findings" > "$_tmpf"
        validate_file \
          "${SCHEMA_DIR}/target-device-candidate.schema.json" \
          "$_tmpf" \
          "${_step_name}/candidates[$_i]"
        rm -f "$_tmpf"
      done
    fi

    # Validate next_step_input if present
    if jq -e '.next_step_input' "$_findings" &>/dev/null; then
      local _tmpf2
      _tmpf2="$(mktemp /tmp/conwrt-nextstep-XXXXXX.json)"
      jq '.next_step_input' "$_findings" > "$_tmpf2"
      validate_file \
        "${SCHEMA_DIR}/next-step-input.schema.json" \
        "$_tmpf2" \
        "${_step_name}/next_step_input"
      rm -f "$_tmpf2"
    fi

  done

  echo ""
  echo "Validation summary: ${_total} checks, ${_failures} failure(s)"
  if [[ "$_failures" -gt 0 ]]; then
    conwrt::die "Validation FAILED: ${_failures} error(s)"
  fi
  conwrt::log "info" "All validations PASSED"
}

main "$@"
