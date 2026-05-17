#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SMOKE_TMPDIR="$(mktemp -d)"
trap 'rm -rf "$SMOKE_TMPDIR"' EXIT

# common.sh hardcodes CONWRTER_RUNS_DIR=$CONWRTER_ROOT/runs, so we create a
# shadow tree with our own runs/ directory and symlink everything else.
mkdir "$SMOKE_TMPDIR/runs"
for item in "$REPO_ROOT"/*; do
  base="$(basename "$item")"
  [[ "$base" == "runs" ]] && continue
  ln -s "$item" "$SMOKE_TMPDIR/$base"
done
for item in "$REPO_ROOT"/.*; do
  base="$(basename "$item")"
  [[ "$base" == "." || "$base" == ".." || "$base" == ".git" || "$base" == ".sisyphus" || "$base" == ".playwright-mcp" || "$base" == ".opencode" ]] && continue
  ln -s "$item" "$SMOKE_TMPDIR/$base" 2>/dev/null || true
done

export CONWRTER_ROOT="$SMOKE_TMPDIR"

STUB="$(mktemp)"
chmod +x "$STUB"
cat > "$STUB" <<'STUB_EOF'
#!/usr/bin/env bash
set -euo pipefail
PROMPT_FILE="${1:?prompt file required}"
mkdir -p "${STEP_DIR}/raw"

cat > "${STEP_DIR}/raw/output.md" <<'OUT'
# Stub LLM output — smoke test

Target scanned at 192.168.1.1. Public IP 8.8.8.8 was observed.
MAC address AA:BB:CC:DD:EE:FF detected on interface eth0.
OUT

cat > "${STEP_DIR}/findings.json" <<FINDINGS
{
  "step_id": "step-01",
  "step_name": "identify-device",
  "started_at": "2026-01-01T12:00:00Z",
  "completed_at": "2026-01-01T12:00:01Z",
  "status": "ok",
  "summary": "Stub findings from smoke-test adapter"
}
FINDINGS

exit 0
STUB_EOF

export OPENCODE_CMD="$STUB"

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; exit 1; }

echo "=== conwrt smoke test ==="
echo ""

echo "[1/5] init-run"
RUN_DIR="$("$SMOKE_TMPDIR/scripts/init-run.sh" --target 192.168.1.1 --operator smoke-test)"
RUN_ID="$(basename "$RUN_DIR")"
[[ -n "$RUN_ID" ]] || fail "no run directory created"
[[ -f "$RUN_DIR/run-metadata.json" ]] || fail "missing run-metadata.json"
pass "init-run created $RUN_ID"
echo ""

echo "[2/5] run-step (step-01)"
"$SMOKE_TMPDIR/scripts/run-step.sh" --run "$RUN_ID" --step 01
[[ -f "$RUN_DIR/step-01/findings.json" ]] || fail "missing findings.json after run-step"
[[ -f "$RUN_DIR/step-01/raw/output.md" ]] || fail "missing raw/output.md after run-step"
pass "run-step produced findings.json and raw output"
echo ""

echo "[3/5] redact-output"
"$SMOKE_TMPDIR/scripts/redact-output.sh" --run "$RUN_ID"
REDACTED_COUNT="$(find "$RUN_DIR" -path '*/redacted/*' -type f | wc -l)"
[[ "$REDACTED_COUNT" -gt 0 ]] || fail "no redacted files produced"
REDACTED_FILE="$(find "$RUN_DIR" -path '*/redacted/*' -type f | head -1)"
if grep -q '8\.8\.8\.8' "$REDACTED_FILE" 2>/dev/null; then
  fail "public IP 8.8.8.8 not redacted in $REDACTED_FILE"
fi
if grep -qE 'AA:BB:CC:DD:EE:FF' "$REDACTED_FILE" 2>/dev/null; then
  fail "full MAC address not redacted in $REDACTED_FILE"
fi
pass "redact-output produced $REDACTED_COUNT file(s), PII stripped"
echo ""

echo "[4/5] validate-findings"
"$SMOKE_TMPDIR/scripts/validate-findings.sh" --run "$RUN_ID"
pass "validate-findings passed"
echo ""

echo "[5/5] commit-run (syntax check — tmpdir has no git repo)"
bash -n "$REPO_ROOT/scripts/commit-run.sh"
pass "commit-run.sh syntax OK (git commit skipped in smoke)"
echo ""

echo "=== ALL SMOKE CHECKS PASSED ==="
