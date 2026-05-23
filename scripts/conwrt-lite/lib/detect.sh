#!/bin/sh
# conwrt-lite detect library — link-up and passive fingerprinting
# Guard against double-source
[ -n "$_CONWRT_DETECT_LOADED" ] && return 0
_CONWRT_DETECT_LOADED=1

conwrt_detect_wait_link() {
    _port="$1"
    _timeout="${2:-120}"
    _elapsed=0
    while [ "$_elapsed" -lt "$_timeout" ]; do
        if ip link show "$_port" 2>/dev/null | grep -q "state UP"; then
            echo "link up on $_port after ${_elapsed}s"
            return 0
        fi
        sleep 1
        _elapsed=$((_elapsed + 1))
    done
    echo "timeout waiting for link on $_port (${_timeout}s)" >&2
    return 1
}

conwrt_detect_oui() {
    _mac="$1"
    _prefix=$(echo "$_mac" | awk -F: '{printf "%s:%s:%s", toupper($1), toupper($2), toupper($3)}')
    case "$_prefix" in
        00:04:96) echo "Extreme" ;;
        4C:9E:FF) echo "Zyxel" ;;
        BC:CF:4F) echo "Zyxel" ;;
        E8:37:7A) echo "Zyxel" ;;
        1C:69:7A) echo "D-Link" ;;
        94:83:C4) echo "GL.iNet" ;;
        E8:9F:80) echo "Linksys" ;;
        04:18:D6) echo "Ubiquiti" ;;
        50:C7:BF) echo "TP-Link" ;;
        *) echo "Unknown" ;;
    esac
}

conwrt_detect_passive() {
    _port="$1"
    _timeout="${2:-120}"
    _deadline=$(_conwrt_deadline "$_timeout")
    tcpdump -i "$_port" -c 50 -nn -l 2>/dev/null | while IFS= read -r _line; do
        [ "$(date +%s)" -gt "$_deadline" ] && break
        _mac=$(echo "$_line" | awk '{
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$/) {
                    print $i; exit
                }
            }
        }')
        if [ -n "$_mac" ]; then
            _vendor=$(conwrt_detect_oui "$_mac")
            echo "mac=$_mac vendor=$_vendor"
            return 0
        fi
    done
    echo "no device detected on $_port within ${_timeout}s" >&2
    return 1
}

_conwrt_deadline() {
    _now=$(date +%s)
    echo $((_now + $1))
}
