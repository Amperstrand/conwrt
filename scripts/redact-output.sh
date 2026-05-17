#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

ALLOWLIST_FILE="${SCRIPT_DIR}/redact-allowlist.txt"

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

[[ -n "$RUN_ID" ]] || conwrt::die "Usage: $0 --run <id-or-latest> [--step <NN>]"
RUN_DIR="$(conwrt::resolve_run_id "$RUN_ID")"

# ── Allowlist ────────────────────────────────────────────────────────────────

declare -A ALLOWLIST=()
if [[ -f "$ALLOWLIST_FILE" ]]; then
  while IFS= read -r _line || [[ -n "$_line" ]]; do
    [[ "$_line" =~ ^[[:space:]]*# ]] && continue
    [[ "$_line" =~ ^[[:space:]]*$ ]] && continue
    ALLOWLIST["$_line"]=1
  done < "$ALLOWLIST_FILE"
fi

is_allowlisted() {
  local candidate="${1:?}"
  local _pat
  for _pat in "${!ALLOWLIST[@]}"; do
    [[ "$candidate" =~ $_pat ]] && return 0
  done
  return 1
}

# ── Dependencies ─────────────────────────────────────────────────────────────

conwrt::require_cmd sed
conwrt::require_cmd jq
conwrt::require_cmd sha256sum
conwrt::require_cmd grep
conwrt::require_cmd perl

# ── Staging dir cleanup on exit ──────────────────────────────────────────────

_cleanup_tmpdir() {
  if [[ -n "${_REDACT_TMPDIR:-}" && -d "$_REDACT_TMPDIR" ]]; then
    rm -rf "$_REDACT_TMPDIR"
  fi
}
trap _cleanup_tmpdir EXIT

# ── Per-pattern redaction functions (stdin → stdout) ─────────────────────────
# Order follows docs/redaction.md §7 — more-specific patterns first.

# 10. PEM / SSH private key blocks (multiline; perl for lazy matching)
redact_pem_keys() {
  perl -0777 -pe \
    's/-----BEGIN (CERTIFICATE|RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END (CERTIFICATE|RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/<REDACTED:KEY>/gs'
}

# 8. Auth tokens, cookies, API keys
redact_auth() {
  # Double-quote sed expressions to avoid single-quote nesting issues.
  # [^<] prevents matching already-redacted tokens.
  sed -E \
    -e "s/(Authorization:[[:space:]]*Bearer[[:space:]]+)[^<[:space:]]+/\1<REDACTED:AUTH>/gi" \
    -e "s/(Cookie:[[:space:]]+)[^<[:space:]]+/\1<REDACTED:AUTH>/gi" \
    -e "s/(api[_-]?key[[:space:]]*[=:][[:space:]]*)[^<[:space:]]+/\1<REDACTED:AUTH>/gi"
}

# 7. Certificate fingerprints (≥40 hex chars after fingerprint keyword)
redact_fingerprint() {
  sed -E \
    -e "s/([Ss][Hh][Aa][[:digit:]]?[[:space:]]+[Ff]ingerprint[[:space:]]*[=:]?[[:space:]]*)[0-9A-Fa-f:]{40,}/\1<REDACTED:FINGERPRINT>/g"
}

# 5. Serial numbers (≥8 alphanumeric chars adjacent to serial keywords)
redact_serial() {
  sed -E \
    -e "s/([Ss]erial([[:space:]]+[Nn]umber)?[[:space:]]*[:]?[[:space:]]*)[A-Za-z0-9]{8,}/\1<REDACTED:SERIAL>/gi" \
    -e "s/(S\/N[[:space:]]*[:]?[[:space:]]*)[A-Za-z0-9]{8,}/\1<REDACTED:SERIAL>/g" \
    -e "s/(serialNumber[[:space:]]*[:]?[[:space:]]*)[A-Za-z0-9]{8,}/\1<REDACTED:SERIAL>/gi"
}

# 6. SSIDs (values adjacent to ssid/SSID/wlan_name/network_name keywords)
redact_ssid() {
  sed -E \
    -e "s/(\"(ssid|SSID|wlan_name|network_name)\"[[:space:]]*[:][[:space:]]*\")[^\"]+\"/\1<REDACTED:SSID>\"/gi" \
    -e "s/(ssid|SSID|wlan_name|network_name)[[:space:]]*[:=][[:space:]]+[^[:space:]]+/\1<REDACTED:SSID>/gi"
}

# 9. GPS coordinates (lat/lon decimal degree pairs)
redact_geo() {
  sed -E \
    -e "s/\"(lat(itude)?)\"[[:space:]]*[:][[:space:]]*[+-]?[0-9]{1,3}\.[0-9]+/\"\1\": <REDACTED:GEO>/gi" \
    -e "s/\"(lon(gitude)?)\"[[:space:]]*[:][[:space:]]*[+-]?[0-9]{1,3}\.[0-9]+/\"\1\": <REDACTED:GEO>/gi"
}

# 3. MAC address last 3 octets → XX:XX:XX (keep OUI)
redact_mac_suffix() {
  sed -E \
    -e "s/([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}):[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}/\1:XX:XX:XX/g"
}

# 2. Public IPv6 (keep ::1, fe80::, fc/fd/fe/fU)
redact_public_ipv6() {
  local _line
  while IFS= read -r _line || [[ -n "$_line" ]]; do
    if [[ "$_line" =~ [0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7} ]]; then
      local _matches=()
      while IFS= read -r _m; do
        [[ -n "$_m" ]] && _matches+=("$_m")
      done < <(grep -oP '[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}' <<< "$_line" 2>/dev/null || true)

      for _addr in "${_matches[@]}"; do
        local _skip=0
        [[ "$_addr" == "::1" ]] && _skip=1
        [[ "$_addr" =~ ^fe80: ]] && _skip=1
        [[ "$_addr" =~ ^f[cde][0-9a-fA-F]: ]] && _skip=1
        [[ "$_skip" -eq 0 ]] && _line="${_line//$_addr/<REDACTED:PUBLIC-IP6>}"
      done
    fi
    echo "$_line"
  done
}

# 1. Public IPv4 — keep RFC1918, loopback, link-local, RFC5737, multicast, broadcast
is_private_ipv4() {
  local ip="${1:?}"
  local IFS='.'
  # shellcheck disable=SC2162
  read -ra _oct <<< "$ip"
  local a="${_oct[0]}" b="${_oct[1]}" c="${_oct[2]}"

  # 127.x  loopback
  [[ "$a" -eq 127 ]] && return 0
  # 10.x   RFC1918
  [[ "$a" -eq 10 ]]  && return 0
  # 172.16–31.x  RFC1918
  [[ "$a" -eq 172 && "$b" -ge 16 && "$b" -le 31 ]] && return 0
  # 192.168.x  RFC1918
  [[ "$a" -eq 192 && "$b" -eq 168 ]] && return 0
  # 169.254.x  link-local
  [[ "$a" -eq 169 && "$b" -eq 254 ]] && return 0
  # 0.x  unspecified
  [[ "$a" -eq 0 ]] && return 0
  # 255.255.x.x  broadcast
  [[ "$a" -eq 255 && "$b" -eq 255 ]] && return 0
  # RFC5737 documentation ranges
  [[ "$a" -eq 192 && "$b" -eq 0   && "$c" -eq 2 ]]   && return 0
  [[ "$a" -eq 198 && "$b" -eq 51  && "$c" -eq 100 ]] && return 0
  [[ "$a" -eq 203 && "$b" -eq 0   && "$c" -eq 113 ]] && return 0
  # 224–239  multicast
  [[ "$a" -ge 224 && "$a" -le 239 ]] && return 0
  return 1
}

redact_public_ipv4() {
  local _line
  while IFS= read -r _line || [[ -n "$_line" ]]; do
    local _ips=()
    while IFS= read -r _m; do
      [[ -n "$_m" ]] && _ips+=("$_m")
    done < <(grep -oP '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' <<< "$_line" 2>/dev/null || true)

    for _ip in "${_ips[@]}"; do
      if ! is_private_ipv4 "$_ip" && ! is_allowlisted "$_ip"; then
        _line="${_line//$_ip/<REDACTED:PUBLIC-IP>}"
      fi
    done
    echo "$_line"
  done
}

# 4. Hostnames with non-public TLDs (respect allowlist)
redact_hostname() {
  local _line
  while IFS= read -r _line || [[ -n "$_line" ]]; do
    local _hosts=()
    while IFS= read -r _m; do
      [[ -n "$_m" ]] && _hosts+=("$_m")
    done < <(grep -oP '([a-zA-Z0-9][-a-zA-Z0-9]*\.)+(local|lan|internal|home|corp)' <<< "$_line" 2>/dev/null || true)

    for _h in "${_hosts[@]}"; do
      is_allowlisted "$_h" || _line="${_line//$_h/<REDACTED:HOSTNAME>}"
    done
    echo "$_line"
  done
}

# ── Full pipeline (order per spec) ──────────────────────────────────────────

apply_redaction_pipeline() {
  redact_pem_keys          \
    | redact_auth           \
    | redact_fingerprint    \
    | redact_serial         \
    | redact_ssid           \
    | redact_geo            \
    | redact_mac_suffix     \
    | redact_public_ipv6    \
    | redact_public_ipv4    \
    | redact_hostname
}

# ── Verification (re-scan redacted output for lingering PII) ─────────────────

verify_no_pii() {
  local _dir="${1:?}"
  local _fail=0

  while IFS= read -r -d '' _f; do
    while IFS= read -r _ip; do
      if [[ -n "$_ip" ]] && ! is_private_ipv4 "$_ip" && ! is_allowlisted "$_ip"; then
        conwrt::log "error" "Verification FAIL: public IP '$_ip' in $(basename "$_f")"
        _fail=$((_fail + 1))
      fi
    done < <(grep -oP '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$_f" 2>/dev/null || true)
  done < <(find "$_dir" -type f -print0 2>/dev/null)

  while IFS= read -r -d '' _f; do
    while IFS= read -r _mac; do
      local _tail="${_mac#*:*:*:}"
      if [[ "$_tail" != "XX:XX:XX" ]]; then
        conwrt::log "error" "Verification FAIL: unredacted MAC tail '$_mac' in $(basename "$_f")"
        _fail=$((_fail + 1))
      fi
    done < <(grep -oP '[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}' "$_f" 2>/dev/null || true)
  done < <(find "$_dir" -type f -print0 2>/dev/null)

  while IFS= read -r -d '' _f; do
    if grep -Pi '(serial[[:space:]]*(number)?|S/N|serialNumber)[:[:space:]]+[A-Za-z0-9]{8,}' "$_f" &>/dev/null; then
      conwrt::log "error" "Verification FAIL: serial number in $(basename "$_f")"
      _fail=$((_fail + 1))
    fi
  done < <(find "$_dir" -type f -print0 2>/dev/null)

  while IFS= read -r -d '' _f; do
    if grep -P '-----BEGIN (CERTIFICATE|RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----' "$_f" &>/dev/null; then
      conwrt::log "error" "Verification FAIL: PEM block in $(basename "$_f")"
      _fail=$((_fail + 1))
    fi
  done < <(find "$_dir" -type f -print0 2>/dev/null)

  return "$_fail"
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
  local _total_files=0
  local _num_patterns=10
  declare -a _step_dirs=()

  if [[ -n "$STEP_FILTER" ]]; then
    local _padded
    _padded="$(printf '%02d' "$STEP_FILTER")"
    local _cand="${RUN_DIR}/step-${_padded}"
    [[ -d "$_cand" ]] || conwrt::die "Step directory not found: ${_cand}"
    _step_dirs+=("$_cand")
  else
    while IFS= read -r -d '' _d; do
      [[ -d "${_d}/raw" ]] && _step_dirs+=("$_d")
    done < <(find "$RUN_DIR" -maxdepth 1 -mindepth 1 -type d -name 'step-*' -print0 | sort -z)
  fi

  [[ ${#_step_dirs[@]} -gt 0 ]] || conwrt::die "No step directories with raw/ found in ${RUN_DIR}"

  for _step_dir in "${_step_dirs[@]}"; do
    local _step_name raw_dir redacted_dir _step_files=0
    _step_name="$(basename "$_step_dir")"
    raw_dir="${_step_dir}/raw"
    redacted_dir="${_step_dir}/redacted"

    conwrt::log "info" "Processing ${_step_name} ..."

    rm -rf "$redacted_dir"
    mkdir -p "$redacted_dir"

    _REDACT_TMPDIR="$(mktemp -d "${_step_dir}/.redact-staging.XXXXXX")"

    while IFS= read -r -d '' _raw_file; do
      local _rel="${_raw_file#"${raw_dir}/"}"
      local _stage="${_REDACT_TMPDIR}/${_rel}"
      mkdir -p "$(dirname "$_stage")"

      if ! apply_redaction_pipeline < "$_raw_file" > "$_stage"; then
        conwrt::log "error" "Redaction FAILED for ${_rel} — aborting (fail-closed)"
        rm -rf "$redacted_dir" "$_REDACT_TMPDIR"
        _REDACT_TMPDIR=""
        exit 2
      fi
      _step_files=$((_step_files + 1))
    done < <(find "$raw_dir" -type f -print0 2>/dev/null)

    if ! verify_no_pii "$_REDACT_TMPDIR"; then
      conwrt::log "error" "Verification FAILED for ${_step_name} — PII still present"
      rm -rf "$redacted_dir" "$_REDACT_TMPDIR"
      _REDACT_TMPDIR=""
      exit 3
    fi

    local _manifest='{}'
    while IFS= read -r -d '' _raw_file; do
      local _rel="${_raw_file#"${raw_dir}/"}"
      local _stage="${_REDACT_TMPDIR}/${_rel}"
      local _rh _ah
      _rh="$(sha256sum "$_raw_file"  | cut -d' ' -f1)"
      _ah="$(sha256sum "$_stage"    | cut -d' ' -f1)"
      _manifest="$(echo "$_manifest" | jq \
        --arg p "$_rel" --arg r "$_rh" --arg a "$_ah" \
        '. + {($p): {raw_sha256: $r, redacted_sha256: $a}}')"
    done < <(find "$raw_dir" -type f -print0 2>/dev/null)

    echo "$_manifest" > "${_REDACT_TMPDIR}/.manifest.json"
    cp -a "$_REDACT_TMPDIR/." "$redacted_dir/"
    rm -rf "$_REDACT_TMPDIR"
    _REDACT_TMPDIR=""

    _total_files=$((_total_files + _step_files))
    echo "${_step_name}: ${_step_files} files redacted, ${_num_patterns} patterns applied"
  done

  conwrt::log "info" "Redaction complete: ${_total_files} files across ${#_step_dirs[@]} step(s)"
}

main "$@"
