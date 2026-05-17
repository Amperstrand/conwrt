#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# ── CLI ──────────────────────────────────────────────────────────────────────

RUN_ID="latest"
STEP_FILTER=""
COMMIT_MSG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)     RUN_ID="${2:?--run requires an argument}"; shift 2 ;;
    --step)    STEP_FILTER="${2:?--step requires an argument}"; shift 2 ;;
    --message) COMMIT_MSG="${2:?--message requires an argument}"; shift 2 ;;
    *)         conwrt::die "Unknown flag: $1" ;;
  esac
done

# ── Step 1: Resolve run dir ─────────────────────────────────────────────────

RUN_DIR="$(conwrt::resolve_run_id "$RUN_ID")"
conwrt::log "info" "Resolved run directory: ${RUN_DIR}"

# ── Step 2: Require commands ────────────────────────────────────────────────

conwrt::require_cmd git
conwrt::require_cmd jq
conwrt::require_cmd npx

# ── Step 3: Run redact-output.sh (idempotent) ───────────────────────────────

if ! bash "${SCRIPT_DIR}/redact-output.sh" --run "$RUN_ID"; then
  conwrt::die "redact-output.sh failed — aborting commit"
fi

# ── Step 4: Run validate-findings.sh ────────────────────────────────────────

if [[ -n "$STEP_FILTER" ]]; then
  if ! bash "${SCRIPT_DIR}/validate-findings.sh" --run "$RUN_ID" --step "$STEP_FILTER"; then
    conwrt::die "validate-findings.sh failed — aborting commit"
  fi
else
  if ! bash "${SCRIPT_DIR}/validate-findings.sh" --run "$RUN_ID"; then
    conwrt::die "validate-findings.sh failed — aborting commit"
  fi
fi

# ── Step 5: Safety — verify raw/ is gitignored ─────────────────────────────

git -C "$CONWRTER_ROOT" check-ignore -q "${RUN_DIR}/raw" 2>/dev/null || true

if git -C "$CONWRTER_ROOT" status --porcelain "${RUN_DIR}" | grep -q "/raw/"; then
  conwrt::die "ABORT: raw/ artifacts are not gitignored — refusing to commit"
fi

# ── Step 6: PII safety grep on redacted/** ──────────────────────────────────

_pii_found=0

# Full MAC address
while IFS= read -r -d '' _f; do
  if grep -qP '[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}' "$_f" 2>/dev/null; then
    conwrt::log "error" "PII: full MAC address detected in ${_f}"
    _pii_found=$((_pii_found + 1))
  fi
done < <(find "${RUN_DIR}" -path '*/redacted/*' -type f -print0 2>/dev/null)

# Serial-number-looking strings
while IFS= read -r -d '' _f; do
  if grep -qP '\b[A-Z]{2,4}[0-9]{6,}\b' "$_f" 2>/dev/null; then
    conwrt::log "error" "PII: serial-number pattern detected in ${_f}"
    _pii_found=$((_pii_found + 1))
  fi
done < <(find "${RUN_DIR}" -path '*/redacted/*' -type f -print0 2>/dev/null)

# Public IP addresses (non-RFC1918)
while IFS= read -r -d '' _f; do
  if grep -qP '\b(?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$_f" 2>/dev/null; then
    conwrt::log "error" "PII: public IP address detected in ${_f}"
    _pii_found=$((_pii_found + 1))
  fi
done < <(find "${RUN_DIR}" -path '*/redacted/*' -type f -print0 2>/dev/null)

if [[ "$_pii_found" -gt 0 ]]; then
  conwrt::die "ABORT: PII pattern detected in redacted output — redaction may be incomplete"
fi

# ── Step 7: git add ONLY safe paths ─────────────────────────────────────────

declare -a _add_paths=()

# run-metadata.json
if [[ -f "${RUN_DIR}/run-metadata.json" ]]; then
  _add_paths+=("${RUN_DIR}/run-metadata.json")
fi

# state.json
if [[ -f "${RUN_DIR}/state.json" ]]; then
  _add_paths+=("${RUN_DIR}/state.json")
fi

# All step-*/findings.json
while IFS= read -r -d '' _f; do
  _add_paths+=("$_f")
done < <(find "${RUN_DIR}" -maxdepth 2 -name 'findings.json' -type f -print0 2>/dev/null)

# All step-*/redacted/ directories (recursively)
while IFS= read -r -d '' _d; do
  _add_paths+=("$_d")
done < <(find "${RUN_DIR}" -maxdepth 2 -type d -name 'redacted' -print0 2>/dev/null)

if [[ ${#_add_paths[@]} -eq 0 ]]; then
  conwrt::log "info" "Nothing to commit — already up to date"
  exit 0
fi

git -C "$CONWRTER_ROOT" add -- "${_add_paths[@]}"

# ── Step 8: Check if anything staged ────────────────────────────────────────

if git -C "$CONWRTER_ROOT" diff --cached --quiet; then
  conwrt::log "info" "Nothing to commit — already up to date"
  exit 0
fi

# ── Step 9: Auto-generate commit message ────────────────────────────────────

if [[ -z "$COMMIT_MSG" ]]; then
  local_run_id="$(jq -r '.run_id' "${RUN_DIR}/run-metadata.json")"
  if [[ -n "$STEP_FILTER" ]]; then
    local_padded="$(printf '%02d' "$STEP_FILTER")"
    COMMIT_MSG="chore(run): ${local_run_id} step-${local_padded} redacted artifacts"
  else
    COMMIT_MSG="chore(run): ${local_run_id} all steps redacted artifacts"
  fi
fi

# ── Step 10: Commit ─────────────────────────────────────────────────────────

git -C "$CONWRTER_ROOT" commit -m "$COMMIT_MSG"

# ── Step 11: Log success ────────────────────────────────────────────────────

conwrt::log "info" "Committed: ${COMMIT_MSG}"
