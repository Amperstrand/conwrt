#!/bin/sh
# conwrt-lite stock_ssh library — stock firmware SSH preflight for Extreme AP3915i
[ -n "$_CONWRT_STOCK_SSH_LOADED" ] && return 0
_CONWRT_STOCK_SSH_LOADED=1

_CONWRT_STOCK_SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa -o KexAlgorithms=+diffie-hellman-group1-sha1"

conwrt_stock_wait_ssh() {
    _ip="$1"
    _timeout="${2:-120}"
    _elapsed=0
    while [ "$_elapsed" -lt "$_timeout" ]; do
        if sshpass -p new2day ssh $_CONWRT_STOCK_SSH_OPTS "admin@${_ip}" "true" 2>/dev/null; then
            echo "stock ssh available on $_ip after ${_elapsed}s"
            return 0
        fi
        sleep 2
        _elapsed=$((_elapsed + 2))
    done
    echo "timeout waiting for stock ssh on $_ip (${_timeout}s)" >&2
    return 1
}

conwrt_stock_disable_timeout() {
    _ip="$1"

    sshpass -p new2day ssh $_CONWRT_STOCK_SSH_OPTS "admin@${_ip}" \
        "cset sshtimeout 0 && capply && csave" 2>/dev/null || {
        echo "failed to disable ssh timeout on $_ip" >&2
        return 1
    }
    echo "ssh timeout disabled on $_ip"
    return 0
}

conwrt_stock_read_uboot_env() {
    _ip="$1"
    _output_file="$2"

    sshpass -p new2day ssh $_CONWRT_STOCK_SSH_OPTS "admin@${_ip}" \
        "rdwr_boot_cfg read_all" > "$_output_file" 2>/dev/null || {
        echo "failed to read uboot env from $_ip" >&2
        return 1
    }
    echo "$_output_file"
    return 0
}

conwrt_stock_write_uboot_env() {
    _ip="$1"
    _name="$2"
    _value="$3"

    sshpass -p new2day ssh $_CONWRT_STOCK_SSH_OPTS "admin@${_ip}" \
        "rdwr_boot_cfg write_var ${_name}=${_value}" 2>/dev/null || {
        echo "failed to write uboot env ${_name}=${_value} on $_ip" >&2
        return 1
    }
    return 0
}

conwrt_stock_configure_tftp_boot() {
    _ip="$1"
    _tftp_server_ip="$2"
    _temp_ap_ip="$3"
    _cfg1_bin="${4:-}"

    _backup_file="/tmp/conwrt-uboot-env-${_ip}.bak"
    conwrt_stock_read_uboot_env "$_ip" "$_backup_file" >/dev/null || {
        echo "warning: could not backup uboot env, continuing anyway" >&2
    }

    if [ -n "$_cfg1_bin" ]; then
        echo "using flashcp fallback for CFG1 on $_ip"
        conwrt_stock_flashcp_cfg1 "$_ip" "$_cfg1_bin" || return 1
    else
        conwrt_stock_write_uboot_env "$_ip" "AP_MODE" "0" || return 1
        conwrt_stock_write_uboot_env "$_ip" "MOSTRECENTKERNEL" "0" || return 1
        conwrt_stock_write_uboot_env "$_ip" "WATCHDOG_COUNT" "0" || return 1
        conwrt_stock_write_uboot_env "$_ip" "WATCHDOG_LIMIT" "0" || return 1
        conwrt_stock_write_uboot_env "$_ip" "AP_PERSONALITY" "identifi" || return 1
        conwrt_stock_write_uboot_env "$_ip" "boot_openwrt" \
            "sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000" || return 1
        conwrt_stock_write_uboot_env "$_ip" "serverip" "$_tftp_server_ip" || return 1
        conwrt_stock_write_uboot_env "$_ip" "ipaddr" "$_temp_ap_ip" || return 1
        conwrt_stock_write_uboot_env "$_ip" "bootcmd" "run boot_net" || return 1
    fi

    echo "tftp boot configured on $_ip (server=$_tftp_server_ip, ip=$_temp_ap_ip)"
    return 0
}

conwrt_stock_reboot() {
    _ip="$1"

    sshpass -p new2day ssh $_CONWRT_STOCK_SSH_OPTS "admin@${_ip}" \
        "reboot" 2>/dev/null || true
    echo "reboot initiated on $_ip"
    return 0
}

# Write a pre-built CFG1 binary to the stock firmware via flashcp
# Usage: conwrt_stock_flashcp_cfg1 STOCK_IP CFG1_BIN_PATH
# This is the fallback when rdwr_boot_cfg is broken (e.g. Unit 1 exit 255)
conwrt_stock_flashcp_cfg1() {
    _ip="$1"
    _cfg1_bin="$2"
    [ -f "$_cfg1_bin" ] || { echo "cfg1 binary not found: $_cfg1_bin" >&2; return 1; }
    _bin_name=$(basename "$_cfg1_bin")
    echo "uploading $_bin_name to stock firmware on $_ip..."
    sshpass -p new2day scp $_CONWRT_STOCK_SSH_OPTS -O "$_cfg1_bin" "admin@${_ip}:/tmp/$_bin_name" || {
        echo "scp cfg1 binary failed" >&2; return 1;
    }
    echo "writing CFG1 via flashcp on $_ip..."
    sshpass -p new2day ssh $_CONWRT_STOCK_SSH_OPTS "admin@${_ip}" \
        "flashcp /tmp/$_bin_name /dev/mtd1" || {
        echo "flashcp write failed" >&2; return 1;
    }
    echo "CFG1 written via flashcp on $_ip"
    return 0
}
