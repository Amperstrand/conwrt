#!/bin/sh
# conwrt-lite tftp library — TFTP server management
# Supports dnsmasq (OpenWrt default) and static binaries (tftp-now, utftp, etc.)
[ -n "${_CONWRT_TFTP_LOADED:-}" ] && return 0
_CONWRT_TFTP_LOADED=1

_CONWRT_TFTP_PID_FILE="/tmp/conwrt-lite-tftp.pid"
_CONWRT_TFTP_LOG="/tmp/conwrt-lite-tftp.log"

# Priority: CONWRT_TFTP_BIN env var > dnsmasq in PATH > /tmp/tftp-now
conwrt_tftp_find_bin() {
    if [ -n "${CONWRT_TFTP_BIN:-}" ] && [ -x "$CONWRT_TFTP_BIN" ]; then
        echo "$CONWRT_TFTP_BIN"
        return 0
    fi

    _bin=$(command -v dnsmasq 2>/dev/null) && { echo "$_bin"; return 0; }

    if [ -x "/tmp/tftp-now" ]; then
        echo "/tmp/tftp-now"
        return 0
    fi

    return 1
}

conwrt_tftp_start() {
    _listen_ip="$1"
    _image_dir="$2"

    if [ -f "$_CONWRT_TFTP_PID_FILE" ]; then
        _old_pid=$(cat "$_CONWRT_TFTP_PID_FILE")
        kill "$_old_pid" 2>/dev/null
        rm -f "$_CONWRT_TFTP_PID_FILE"
    fi

    _tftp_bin=$(conwrt_tftp_find_bin) || {
        echo "no tftp server found (set CONWRT_TFTP_BIN or install dnsmasq)" >&2
        return 1
    }

    : > "$_CONWRT_TFTP_LOG"

    case "$(basename "$_tftp_bin")" in
        dnsmasq)
            "$_tftp_bin" --port=0 --no-daemon --enable-tftp --tftp-root="$_image_dir" \
                --bind-interfaces --listen-address="0.0.0.0" > "$_CONWRT_TFTP_LOG" 2>&1 &
            ;;
        tftp-now|*)
            cd "$_image_dir" && "$_tftp_bin" --listen "$_listen_ip" --port 69 > "$_CONWRT_TFTP_LOG" 2>&1 &
            ;;
    esac
    _tftp_pid=$!
    echo "$_tftp_pid" > "$_CONWRT_TFTP_PID_FILE"

    sleep 1
    if ! kill -0 "$_tftp_pid" 2>/dev/null; then
        echo "tftp server failed to start (bin=$_tftp_bin)" >&2
        rm -f "$_CONWRT_TFTP_PID_FILE"
        return 1
    fi
    echo "tftp server started pid=$_tftp_pid ip=$_listen_ip bin=$_tftp_bin"
    return 0
}

conwrt_tftp_stop() {
    if [ -f "$_CONWRT_TFTP_PID_FILE" ]; then
        _pid=$(cat "$_CONWRT_TFTP_PID_FILE")
        if kill -0 "$_pid" 2>/dev/null; then
            kill "$_pid" 2>/dev/null
            echo "tftp server stopped pid=$_pid"
        fi
        rm -f "$_CONWRT_TFTP_PID_FILE"
    fi
}
