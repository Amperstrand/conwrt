#!/bin/bash
# PII Redaction Script for conwrt repo history rewrite
# Designed for git filter-branch --tree-filter
# Only targets files known to contain PII (29 files out of 234)
set -euo pipefail

# Build sed expression once — applied to all PII files
SEDEXPR=()


# Private rules: raw identifier values must NOT live in this tracked
# script (they would re-publish what they scrub). Each .sh file in the
# rules dir appends entries:  SEDEXPR+=( -e 's/<raw>/<redacted>/g' )
# The rules dir MUST live OUTSIDE any git worktree: filter-branch's
# tree-filter runs `git clean -d -q -f -x` per commit, which deletes
# gitignored (untracked) files — in-tree rules would be wiped before
# they ever apply. Default: ~/.config/conwrt/redact-pii-rules/ (create
# from the canonical copies in the private lab project, conwrt-bench
# docs/redact-pii-rules/). Override: REDACT_PII_RULES_DIR=<dir>.
_rules_dir="${REDACT_PII_RULES_DIR:-$HOME/.config/conwrt/redact-pii-rules}"
if [ -d "$_rules_dir" ]; then
  for _rules in "$_rules_dir"/*.sh; do
    [ -e "$_rules" ] || continue
    # shellcheck disable=SC1090
    source "$_rules"
  done
fi

# List of files that contain PII (from audit)
PII_FILES=(
  AGENTS.md
  docs/NETWORK-SEGMENTATION.md
  docs/NR7101-FLEET.md
  docs/device-recovery-status.md
  docs/process.md
  models/dlink-covr-x1860-a1.json
  models/extreme-networks-ws-ap3915i.json
  models/ubnt-edgerouter-6p.json
  models/zyxel-gs1900-24e.json
  models/zyxel-gs1900-8hp-a1.json
  models/zyxel-gs1900-8hp-b1.json
  models/zyxel-gs1920-24.json
  models/zyxel-nr7101.json
  recipes/dlink/covr-x1860/notes.md
  recipes/asus/lyra-map-ac2200/NOTES.md
  recipes/zyxel/nr7101/open-issues.md
  recipes/zyxel/nr7101/serial-recovery-session-2026-06-28.md
  recipes/extreme-networks/ws-ap3915i/RECOVERY-2026-09-22-lan7-lan8.md
  recipes/extreme-networks/ws-ap3915i/SERIAL-RESCUE-2026-09.md
  recipes/zyxel/gs1920-24/notes.md
  recipes/extreme-networks/ws-ap3915i/REVIEW-UNIT2-FLASH-PLAN.md
  recipes/extreme-networks/ws-ap3915i/SESSION-WRITEUP.md
  recipes/extreme-networks/ws-ap3915i/UNIT2-AP3915i-ROW.md
  recipes/extreme-networks/ws-ap3915i/no-serial-openwrt.md
  recipes/linksys-whw03/NOTES.md
  recipes/ubiquiti/edgerouter-6p/isl28022-research-plan.md
  recipes/ubiquiti/edgerouter-6p/notes.md
  recipes/ubiquiti/edgerouter-6p/poe-diagnosis.md
  recipes/ubiquiti/edgerouter-6p/test-evidence/b3-b4-b5-gpio-i2c-engine/evidence.md
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-1-baseline/gpio-reg-tx-dat.txt
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-2-isl28022-zero-load/isl-0x3F-registers.txt
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-2-isl28022-zero-load/isl-0x40-registers.txt
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-3-gpio-bit-cfg/analysis.md
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-4-pin-mux/findings.md
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-5-i2c-aggressive/analysis.md
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-6-regression/regression-report.md
  recipes/zyxel/gs1900-24e/notes.md
  recipes/zyxel/gs1900-8hp/notes.md
  recipes/zyxel/gs1920-24/notes.md
  recipes/zyxel/nr7101/notes.md
  tests/test_extreme_ap391x.py
)

for f in "${PII_FILES[@]}"; do
  # Skip if file doesn't exist in this commit (wasn't created yet)
  [ -f "$f" ] || continue
  sed -i '' "${SEDEXPR[@]}" "$f"
done
