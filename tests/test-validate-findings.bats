#!/usr/bin/env bats
# bats file_tags=conwrt

# Derive repo root from this test file's location so the suite is portable
# across machines (tests/ lives directly under the repo root).
REPO_ROOT="$(cd "$(dirname "$BATS_TEST_DIRNAME")" && pwd)"
RUNS_DIR="${REPO_ROOT}/runs"
_TEST_RUN_DIR=""

setup() {
  mkdir -p "$RUNS_DIR"
}

teardown() {
  if [[ -n "$_TEST_RUN_DIR" && -d "$_TEST_RUN_DIR" ]]; then
    rm -rf "$_TEST_RUN_DIR"
  fi
}

@test "validate-findings.sh accepts valid findings" {
  _TEST_RUN_DIR="$(mktemp -d "${RUNS_DIR}/bats-validate-XXXXXX")"
  local run_name
  run_name="$(basename "$_TEST_RUN_DIR")"

  # Copy example files into test run dir
  cp "${REPO_ROOT}/examples/run-metadata.json" "${_TEST_RUN_DIR}/"
  mkdir -p "${_TEST_RUN_DIR}/step-01"
  cp "${REPO_ROOT}/examples/findings.json" "${_TEST_RUN_DIR}/step-01/"

  run bash "${REPO_ROOT}/scripts/validate-findings.sh" --run "$run_name"
  [ "$status" -eq 0 ]
}

@test "validate-findings.sh rejects missing findings" {
  _TEST_RUN_DIR="$(mktemp -d "${RUNS_DIR}/bats-validate-XXXXXX")"
  local run_name
  run_name="$(basename "$_TEST_RUN_DIR")"

  # Create only run-metadata.json and an empty step-01 dir (no findings.json)
  cp "${REPO_ROOT}/examples/run-metadata.json" "${_TEST_RUN_DIR}/"
  mkdir -p "${_TEST_RUN_DIR}/step-01"
  # Intentionally no findings.json

  run bash "${REPO_ROOT}/scripts/validate-findings.sh" --run "$run_name"
  [ "$status" -ne 0 ]
}
