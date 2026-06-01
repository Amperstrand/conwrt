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

@test "init-run.sh creates run directory" {
  run bash "${REPO_ROOT}/scripts/init-run.sh" --target 10.99.99.99 --operator test-op
  [ "$status" -eq 0 ]

  # init-run.sh echoes the run dir path on stdout (last line of combined output;
  # log messages go to stderr so the path line is the final one).
  _TEST_RUN_DIR="$(echo "$output" | tail -1)"
  [ -d "$_TEST_RUN_DIR" ]
}

@test "init-run.sh creates run-metadata.json" {
  run bash "${REPO_ROOT}/scripts/init-run.sh" --target 10.99.99.98 --operator test-op
  [ "$status" -eq 0 ]

  _TEST_RUN_DIR="$(echo "$output" | tail -1)"

  [ -f "${_TEST_RUN_DIR}/run-metadata.json" ]
  # Verify the file is valid JSON
  jq . < "${_TEST_RUN_DIR}/run-metadata.json" >/dev/null
}

@test "init-run.sh requires --target" {
  run bash "${REPO_ROOT}/scripts/init-run.sh" --operator test-op
  [ "$status" -ne 0 ]
}
