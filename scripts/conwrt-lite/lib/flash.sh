#!/bin/sh
# conwrt-lite flash library — TFTP and sysupgrade orchestration
[ -n "$_CONWRT_FLASH_LOADED" ] && return 0
_CONWRT_FLASH_LOADED=1

_CONWRT_SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

conwrt_flash_tftp() {
    _port="$1"
    _tftp_ip="$2"
    _bootfile="$3"
    _image_dir="$4"

    _script_dir="$(cd "$(dirname "$0")" && pwd)"
    . "$_script_dir/tftp.sh"

    conwrt_tftp_start "$_tftp_ip" "$_image_dir" || return 1
    echo "tftp server started on $_tftp_ip, serving $_image_dir"

    echo "waiting for device to tftp boot..."
    sleep 60

    conwrt_tftp_stop
    echo "tftp server stopped"
    return 0
}

conwrt_flash_sysupgrade() {
    _device_ip="$1"
    _image_path="$2"
    _image_name=$(basename "$_image_path")

    echo "uploading $_image_name to $_device_ip..."
    scp $_CONWRT_SSH_OPTS -O "$_image_path" "root@${_device_ip}:/tmp/$_image_name" || {
        echo "scp upload failed" >&2
        return 1
    }

    echo "running sysupgrade on $_device_ip..."
    ssh $_CONWRT_SSH_OPTS "root@${_device_ip}" "sysupgrade -n /tmp/$_image_name" || {
        echo "sysupgrade failed or connection lost (expected during reboot)" >&2
    }
    echo "sysupgrade initiated"
    return 0
}

conwrt_flash_wait_ssh() {
    _device_ip="$1"
    _timeout="${2:-120}"
    _elapsed=0
    while [ "$_elapsed" -lt "$_timeout" ]; do
        if ssh $_CONWRT_SSH_OPTS -o BatchMode=yes "root@${_device_ip}" "true" 2>/dev/null; then
            echo "ssh available on $_device_ip after ${_elapsed}s"
            return 0
        fi
        sleep 2
        _elapsed=$((_elapsed + 2))
    done
    echo "timeout waiting for ssh on $_device_ip (${_timeout}s)" >&2
    return 1
}
