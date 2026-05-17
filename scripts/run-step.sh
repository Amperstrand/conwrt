#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

for cmd in bash jq npx; do
  conwrt::require_cmd "$cmd"
done

usage() {
  conwrt::die "Usage: $0 --run <id-or-latest> --step <NN> [--force]"
}

RUN_ARG=""
STEP_ARG=""
FORCE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)
      RUN_ARG="${2:?--run requires a value}"
      shift 2
      ;;
    --step)
      STEP_ARG="${2:?--step requires a value}"
      shift 2
      ;;
    --force)
      FORCE=true
      shift
      ;;
    *)
      conwrt::die "Unknown argument: $1"
      ;;
  esac
done

[[ -n "$RUN_ARG" ]] || usage
[[ -n "$STEP_ARG" ]] || usage
[[ "$STEP_ARG" =~ ^[0-9]+$ ]] || conwrt::die "--step must be numeric"

STEP_NUM=$((10#$STEP_ARG))
(( STEP_NUM >= 1 )) || conwrt::die "--step must be >= 1"

STEP_ID="step-$(printf '%02d' "$STEP_NUM")"
RUN_DIR="$(conwrt::resolve_run_id "$RUN_ARG")"
STATE_FILE="$RUN_DIR/state.json"
METADATA_FILE="$RUN_DIR/run-metadata.json"
STEP_DIR="$RUN_DIR/$STEP_ID"
PROMPT_GLOB="$CONWRTER_ROOT/prompts/${STEP_ID}-*.md"

[[ -f "$METADATA_FILE" ]] || conwrt::die "Missing run metadata: $METADATA_FILE"

conwrt::ensure_state_json "$RUN_DIR"

if jq -e --arg step "$STEP_ID" '.steps_completed | index($step) != null' "$STATE_FILE" >/dev/null; then
  if [[ "$FORCE" != true ]]; then
    conwrt::die "${STEP_ID} already completed for run $(basename "$RUN_DIR"); re-run with --force"
  fi
  conwrt::log "info" "Re-running completed step due to --force: ${STEP_ID}"
fi

shopt -s nullglob
prompt_matches=( $PROMPT_GLOB )
shopt -u nullglob

if (( ${#prompt_matches[@]} == 0 )); then
  conwrt::die "No prompt template found for ${STEP_ID} under ${CONWRTER_ROOT}/prompts"
fi
if (( ${#prompt_matches[@]} > 1 )); then
  conwrt::die "Multiple prompt templates found for ${STEP_ID}; expected exactly one"
fi

PROMPT_FILE="${prompt_matches[0]}"

mkdir -p "$STEP_DIR/raw" "$STEP_DIR/redacted" "$STEP_DIR/.tmp"

COMPOSITE_PROMPT="$STEP_DIR/.tmp/composite-prompt.md"
RUN_ID="$(jq -r '.run_id' "$METADATA_FILE")"
TARGET_IP="$(jq -r '.target.target_ip' "$METADATA_FILE")"
SCHEMA_FILE="$CONWRTER_ROOT/schemas/step-findings.schema.json"

[[ "$RUN_ID" != "null" && -n "$RUN_ID" ]] || conwrt::die "Invalid run metadata: missing run_id"
[[ "$TARGET_IP" != "null" && -n "$TARGET_IP" ]] || conwrt::die "Invalid run metadata: missing target.target_ip"
[[ -f "$SCHEMA_FILE" ]] || conwrt::die "Missing schema file: $SCHEMA_FILE"

{
  printf '# conwrt composite prompt\n\n'
  printf '## Run Metadata\n'
  printf -- '- run_id: %s\n' "$RUN_ID"
  printf -- '- target_ip: %s\n' "$TARGET_IP"
  printf -- '- step_id: %s\n\n' "$STEP_ID"

  if (( STEP_NUM > 1 )); then
    PREV_STEP_ID="step-$(printf '%02d' "$((STEP_NUM - 1))")"
    PREV_FINDINGS="$RUN_DIR/$PREV_STEP_ID/findings.json"
    if [[ -f "$PREV_FINDINGS" ]]; then
      printf '## Previous Step Findings (%s)\n' "$PREV_STEP_ID"
      printf '```json\n'
      jq '.' "$PREV_FINDINGS"
      printf '\n```\n\n'
    fi
  fi

  printf '## Prompt Template\n\n'
  cat "$PROMPT_FILE"
} > "$COMPOSITE_PROMPT"

### ADAPTER START
# TODO: Replace OPENCODE_CMD default if your CLI differs.
# Contract: command receives the prompt-file path as last arg, writes
# any artifacts under $STEP_DIR/raw/, writes findings to $STEP_DIR/findings.json
# (matching schemas/step-findings.schema.json), and exits 0 on success.
OPENCODE_CMD="${OPENCODE_CMD:-opencode run --prompt-file}"
STEP_DIR="$STEP_DIR" RUN_DIR="$RUN_DIR" \
  $OPENCODE_CMD "$STEP_DIR/.tmp/composite-prompt.md"
### ADAPTER END

[[ -f "$STEP_DIR/findings.json" ]] || conwrt::die "adapter did not produce findings.json"

npx -y ajv-cli@5 validate \
  -s "$SCHEMA_FILE" \
  -d "$STEP_DIR/findings.json"

conwrt::mark_step_complete "$RUN_DIR" "$STEP_ID"

printf 'step_id=%s\nrun_dir=%s\nstatus=complete\n' "$STEP_ID" "$RUN_DIR"
