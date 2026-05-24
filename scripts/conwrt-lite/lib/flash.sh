#!/bin/sh
# conwrt-lite flash library — TFTP and sysupgrade orchestration
[ -n "${_CONWRT_FLASH_LOADED:-}" ] && return 0
_CONWRT_FLASH_LOADED=1

_CONWRT_SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

conwrt_flash_backup() {
    _device_ip="$1"
    _backup_dir="${2:-/tmp/conwrt-backup}"

    ssh $_CONWRT_SSH_OPTS "root@${_device_ip}" "mkdir -p $_backup_dir" 2>/dev/null

    for _part in $(ssh $_CONWRT_SSH_OPTS "root@${_device_ip}" \
        "cat /proc/mtd | awk -F: '{print \$1}'" 2>/dev/null); do
        _name=$(ssh $_CONWRT_SSH_OPTS "root@${_device_ip}" \
            "grep \"\$_part\" /proc/mtd | awk '{print \$2}'" 2>/dev/null | tr -d '"')
        echo "backing up $_part ($_name)..."
        ssh $_CONWRT_SSH_OPTS "root@${_device_ip}" \
            "dd if=/dev/${_part} bs=4096 2>/dev/null" > "${_backup_dir}/${_part}-${_name}.bin" 2>/dev/null
    done
    echo "backup complete: $_backup_dir"
    return 0
}

conwrt_flash_tftp() {
    _port="$1"
    _tftp_ip="$2"
    _bootfile="$3"
    _image_dir="$4"
    _timeout="${5:-120}"

    _script_dir="$(cd "$(dirname "$0")" && pwd)"
    . "$_script_dir/tftp.sh"

    conwrt_tftp_start "$_tftp_ip" "$_image_dir" || return 1
    echo "tftp server started on $_tftp_ip, serving $_image_dir (bootfile=$_bootfile)"

    _elapsed=0
    while [ "$_elapsed" -lt "$_timeout" ]; do
        if grep -q "$_bootfile" "$_CONWRT_TFTP_LOG" 2>/dev/null; then
            echo "tftp request for $_bootfile detected after ${_elapsed}s"
            sleep 5
            conwrt_tftp_stop
            return 0
        fi
        sleep 2
        _elapsed=$((_elapsed + 2))
    done

    echo "timeout waiting for tftp request (${_timeout}s)" >&2
    conwrt_tftp_stop
    return 1
}

conwrt_flash_sysupgrade() {
    _device_ip="$1"
    _image_path="$2"
    _overlay_path="${3:-}"

    _image_name=$(basename "$_image_path")

    echo "uploading $_image_name to $_device_ip..."
    scp $_CONWRT_SSH_OPTS -O "$_image_path" "root@${_device_ip}:/tmp/$_image_name" || {
        echo "scp upload failed" >&2
        return 1
    }

    if [ -n "$_overlay_path" ] && [ -f "$_overlay_path" ]; then
        _overlay_name=$(basename "$_overlay_path")
        echo "uploading overlay $_overlay_name to $_device_ip..."
        scp $_CONWRT_SSH_OPTS -O "$_overlay_path" "root@${_device_ip}:/tmp/$_overlay_name" || {
            echo "scp overlay upload failed" >&2
            return 1
        }
        echo "running sysupgrade with overlay on $_device_ip..."
        ssh $_CONWRT_SSH_OPTS "root@${_device_ip}" \
            "sysupgrade -n -f /tmp/$_overlay_name /tmp/$_image_name" || true
    else
        echo "running sysupgrade on $_device_ip..."
        ssh $_CONWRT_SSH_OPTS "root@${_device_ip}" \
            "sysupgrade -n /tmp/$_image_name" || true
    fi
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

# Write permanent boot config (CFG1) to newly flashed OpenWrt device
# This is Phase 3: after sysupgrade, write CFG1 so device boots from flash
# instead of TFTP. Requires kmod-mtd-rw because OpenWrt DTS marks CFG partitions
# as read-only.
# Usage: conwrt_flash_write_permanent_bootcfg DEVICE_IP CFG1_BIN_PATH KMOD_IPK_PATH
conwrt_flash_write_permanent_bootcfg() {
    _device_ip="$1"
    _cfg1_bin="$2"
    _kmod_ipk="$3"

    [ -f "$_cfg1_bin" ] || { echo "cfg1 permanent binary not found: $_cfg1_bin" >&2; return 1; }
    [ -f "$_kmod_ipk" ] || { echo "kmod-mtd-rw ipk not found: $_kmod_ipk" >&2; return 1; }

    _cfg1_name=$(basename "$_cfg1_bin")
    _kmod_name=$(basename "$_kmod_ipk")

    echo "Phase 3: writing permanent boot config to $_device_ip..."

    echo "  uploading $_cfg1_name..."
    scp $_CONWRT_SSH_OPTS -O "$_cfg1_bin" "root@${_device_ip}:/tmp/$_cfg1_name" || {
        echo "scp cfg1 failed" >&2; return 1;
    }

    echo "  uploading $_kmod_name..."
    scp $_CONWRT_SSH_OPTS -O "$_kmod_ipk" "root@${_device_ip}:/tmp/$_kmod_name" || {
        echo "scp kmod failed" >&2; return 1;
    }

    echo "  installing kmod-mtd-rw and writing CFG1..."
    ssh $_CONWRT_SSH_OPTS "root@${_device_ip}" "
        opkg install /tmp/$_kmod_name &&
        insmod mtd-rw i_want_a_brick=1 &&
        mtd write /tmp/$_cfg1_name CFG1 &&
        echo WRITE_OK
    " || {
        echo "kmod-mtd-rw + mtd write failed" >&2; return 1;
    }

    echo "  permanent boot config written to $_device_ip"
    return 0
}
