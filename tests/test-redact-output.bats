#!/usr/bin/env bats
# bats file_tags=conwrt

REPO_ROOT="/home/ubuntu/src/conwrt"
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

@test "redact-output.sh redacts public IPs" {
  _TEST_RUN_DIR="$(mktemp -d "${RUNS_DIR}/bats-redact-XXXXXX")"
  local run_name
  run_name="$(basename "$_TEST_RUN_DIR")"

  mkdir -p "${_TEST_RUN_DIR}/step-01/raw"
  # 8.8.8.8 is a real public IP (not RFC1918, not RFC5737, not multicast, etc.)
  echo "Public IP: 8.8.8.8" > "${_TEST_RUN_DIR}/step-01/raw/test.txt"

  run bash "${REPO_ROOT}/scripts/redact-output.sh" --run "$run_name"
  [ "$status" -eq 0 ]

  grep -q "REDACTED:PUBLIC-IP" "${_TEST_RUN_DIR}/step-01/redacted/test.txt"
}

@test "redact-output.sh preserves RFC1918 IPs" {
  _TEST_RUN_DIR="$(mktemp -d "${RUNS_DIR}/bats-redact-XXXXXX")"
  local run_name
  run_name="$(basename "$_TEST_RUN_DIR")"

  mkdir -p "${_TEST_RUN_DIR}/step-01/raw"
  echo "Private IP: 192.168.1.1" > "${_TEST_RUN_DIR}/step-01/raw/test.txt"

  run bash "${REPO_ROOT}/scripts/redact-output.sh" --run "$run_name"
  [ "$status" -eq 0 ]

  grep -q "192.168.1.1" "${_TEST_RUN_DIR}/step-01/redacted/test.txt"
}

@test "redact-output.sh redacts full MAC addresses" {
  _TEST_RUN_DIR="$(mktemp -d "${RUNS_DIR}/bats-redact-XXXXXX")"
  local run_name
  run_name="$(basename "$_TEST_RUN_DIR")"

  mkdir -p "${_TEST_RUN_DIR}/step-01/raw"
  echo "MAC: E8:9F:80:12:34:56" > "${_TEST_RUN_DIR}/step-01/raw/test.txt"

  run bash "${REPO_ROOT}/scripts/redact-output.sh" --run "$run_name"
  [ "$status" -eq 0 ]

  # MAC suffix redaction replaces last 3 octets with XX:XX:XX;
  # verify the suffix is gone and the redacted form is present.
  grep -q "XX:XX:XX" "${_TEST_RUN_DIR}/step-01/redacted/test.txt"
  ! grep -q "12:34:56" "${_TEST_RUN_DIR}/step-01/redacted/test.txt"
}

@test "redact-output.sh preserves allowlisted hostnames" {
  _TEST_RUN_DIR="$(mktemp -d "${RUNS_DIR}/bats-redact-XXXXXX")"
  local run_name
  run_name="$(basename "$_TEST_RUN_DIR")"

  mkdir -p "${_TEST_RUN_DIR}/step-01/raw"
  echo "Visit linksyssmartwifi.com for setup" > "${_TEST_RUN_DIR}/step-01/raw/test.txt"

  run bash "${REPO_ROOT}/scripts/redact-output.sh" --run "$run_name"
  [ "$status" -eq 0 ]

  grep -q "linksyssmartwifi.com" "${_TEST_RUN_DIR}/step-01/redacted/test.txt"
}
