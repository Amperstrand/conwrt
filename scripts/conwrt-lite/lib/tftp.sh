#!/bin/sh
# conwrt-lite tftp library — TFTP server management
[ -n "$_CONWRT_TFTP_LOADED" ] && return 0
_CONWRT_TFTP_LOADED=1

_CONWRT_TFTP_PID_FILE="/tmp/conwrt-lite-tftp.pid"

conwrt_tftp_start() {
    _listen_ip="$1"
    _image_dir="$2"

    if [ -f "$_CONWRT_TFTP_PID_FILE" ]; then
        _old_pid=$(cat "$_CONWRT_TFTP_PID_FILE")
        kill "$_old_pid" 2>/dev/null
        rm -f "$_CONWRT_TFTP_PID_FILE"
    fi

    dnsmasq --port=0 --no-daemon --tftp-root="$_image_dir" --user=root --listen-address="$_listen_ip" &
    _tftp_pid=$!
    echo "$_tftp_pid" > "$_CONWRT_TFTP_PID_FILE"

    sleep 1
    if ! kill -0 "$_tftp_pid" 2>/dev/null; then
        echo "dnsmasq tftp server failed to start" >&2
        rm -f "$_CONWRT_TFTP_PID_FILE"
        return 1
    fi
    echo "tftp server started pid=$_tftp_pid ip=$_listen_ip"
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
