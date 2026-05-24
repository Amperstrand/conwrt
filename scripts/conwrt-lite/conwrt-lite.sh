#!/bin/sh
set -eu

_CONWRT_LIB_DIR="$(cd "$(dirname "$0")/lib" && pwd)"

. "$_CONWRT_LIB_DIR/detect.sh"
. "$_CONWRT_LIB_DIR/flash.sh"
. "$_CONWRT_LIB_DIR/postflash.sh"
. "$_CONWRT_LIB_DIR/poe.sh"
. "$_CONWRT_LIB_DIR/tftp.sh"
. "$_CONWRT_LIB_DIR/inventory.sh"
. "$_CONWRT_LIB_DIR/stock_ssh.sh"
. "$_CONWRT_LIB_DIR/overlay.sh"
. "$_CONWRT_LIB_DIR/bridge.sh"

_conwrt_usage() {
    cat <<'EOF'
conwrt-lite — POSIX shell flasher for OpenWrt switches

Usage:
  conwrt-lite.sh setup --ip IP --bundle PATH --image PATH [--tftp-bin PATH]
  conwrt-lite.sh flash --port PORT --model-id MODEL --image PATH [OPTIONS]
  conwrt-lite.sh detect --port PORT [--timeout SECONDS]
  conwrt-lite.sh postflash --ip IP --ssh-key PATH [--password PASS]
  conwrt-lite.sh help

Commands:
  setup     Deploy conwrt-lite + firmware to a freshly booted initramfs switch
  flash     Full flash workflow: power cycle, detect, TFTP, sysupgrade
  detect    Device detection via link-up and passive fingerprinting
  postflash Post-flash SSH configuration (keys, password, IP)
  help      Show this usage information

Options:
  --port PORT        Switch PoE port (e.g. lan5)
  --model-id MODEL   Device model identifier
  --image PATH       Sysupgrade firmware image (permanent install)
  --initramfs PATH   Initramfs image for TFTP boot (first phase of two-phase flash)
  --bootfile NAME    TFTP bootfile name the device requests (default: basename of --initramfs)
  --tftp-bin PATH    Static TFTP server binary for upload to switch
  --tftp-ip IP       IP for TFTP server on switch (default: 192.168.1.2)
  --target-ip IP     Target device IP (default: 192.168.1.1)
  --timeout SECS     Timeout in seconds (default: 120)
  --no-backup        Skip partition backup before flashing
  --stock-ip IP      Stock firmware IP for SSH preflight (triggers extreme-rdwr-tftp-initramfs mode)
  --stock-password PASS  Stock firmware SSH password (default: new2day)
  --disable-dhcp     Generate overlay tarball to disable DHCP on first boot
  --overlay-keys PATH    SSH public key to embed in overlay tarball
  --cfg1-tftp PATH        Pre-built CFG1 binary for TFTP boot (Phase 0, flashcp fallback)
  --cfg1-permanent PATH   Pre-built permanent CFG1 binary for flash boot (Phase 3)
  --kmod-mtd-rw PATH      kmod-mtd-rw .ipk for writing CFG partitions from OpenWrt
  --ip IP            Device IP address
  --ssh-key PATH     Path to SSH public key
  --password PASS    Root password to set
  --new-ip IP         Change device IP address (reboots network, connection drops)
  --bundle PATH      Path to conwrt-lite tar.gz bundle (for setup)
EOF
}

_conwrt_parse_opts() {
    _result_var="$1"
    shift
    _opts=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --) shift; _opts="$_opts $*"; break ;;
            *=*) _opts="$_opts $1" ;;
            --*) _key="${1#--}"; shift; _opts="$_opts --$_key=$1" ;;
            *) _opts="$_opts $1" ;;
        esac
        shift
    done
    eval "$_result_var=\"\$_opts\""
}

_conwrt_get_opt() {
    _needle="--$1="
    shift
    for _arg in "$@"; do
        case "$_arg" in
            "$_needle"*) echo "${_arg#$_needle}"; return 0 ;;
        esac
    done
    return 1
}

_conwrt_ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

_conwrt_cmd_setup() {
    _switch_ip=$(_conwrt_get_opt switch-ip "$@") || _switch_ip="192.168.1.1"
    _bundle=$(_conwrt_get_opt bundle "$@") || _bundle=""
    _image=$(_conwrt_get_opt image "$@") || { echo "missing --image" >&2; return 1; }
    _tftp_bin=$(_conwrt_get_opt tftp-bin "$@") || _tftp_bin=""

    [ -f "$_image" ] || { echo "image not found: $_image" >&2; return 1; }

    echo "setup: switch=$_switch_ip image=$_image"

    _remote="root@${_switch_ip}"

    echo "waiting for SSH on $_switch_ip..."
    _elapsed=0
    while [ "$_elapsed" -lt 120 ]; do
        if ssh $_conwrt_ssh_opts -o BatchMode=yes "$_remote" "true" 2>/dev/null; then
            echo "SSH available after ${_elapsed}s"
            break
        fi
        sleep 2
        _elapsed=$((_elapsed + 2))
    done
    if [ "$_elapsed" -ge 120 ]; then
        echo "timeout waiting for SSH on $_switch_ip" >&2
        return 1
    fi

    if [ -n "$_bundle" ] && [ -f "$_bundle" ]; then
        echo "uploading conwrt-lite bundle..."
        scp $_conwrt_ssh_opts -O "$_bundle" "${_remote}:/tmp/conwrt-lite.tar.gz" || {
            echo "scp bundle failed" >&2; return 1;
        }
        ssh $_conwrt_ssh_opts "$_remote" "cd /tmp && tar xzf conwrt-lite.tar.gz" || {
            echo "extract bundle failed" >&2; return 1;
        }
        echo "conwrt-lite deployed to $_switch_ip:/tmp/"
    fi

    echo "uploading firmware image..."
    _image_name=$(basename "$_image")
    scp $_conwrt_ssh_opts -O "$_image" "${_remote}:/tmp/${_image_name}" || {
        echo "scp image failed" >&2; return 1;
    }
    echo "firmware uploaded: /tmp/$_image_name"

    if [ -n "$_tftp_bin" ] && [ -f "$_tftp_bin" ]; then
        echo "uploading TFTP server binary..."
        _tftp_name=$(basename "$_tftp_bin")
        scp $_conwrt_ssh_opts -O "$_tftp_bin" "${_remote}:/tmp/${_tftp_name}" || {
            echo "scp tftp binary failed" >&2; return 1;
        }
        ssh $_conwrt_ssh_opts "$_remote" "chmod +x /tmp/${_tftp_name}" || {
            echo "chmod tftp binary failed" >&2; return 1;
        }
        echo "TFTP binary deployed: /tmp/$_tftp_name"
        echo "TFTP auto-detection: conwrt-lite will use /tmp/$_tftp_name"
    fi

    echo "setup complete — switch $_switch_ip ready for flashing"
    echo "run: sh /tmp/scripts/conwrt-lite/conwrt-lite.sh flash --port lan5 --image /tmp/$_image_name"
    return 0
}

_conwrt_cmd_flash() {
    _port=$(_conwrt_get_opt port "$@") || { echo "missing --port" >&2; return 1; }
    _model=$(_conwrt_get_opt model-id "$@") || { echo "missing --model-id" >&2; return 1; }
    _image=$(_conwrt_get_opt image "$@") || { echo "missing --image" >&2; return 1; }
    _initramfs=$(_conwrt_get_opt initramfs "$@") || _initramfs=""
    _bootfile=$(_conwrt_get_opt bootfile "$@") || _bootfile=""
    _tftp_ip=$(_conwrt_get_opt tftp-ip "$@") || _tftp_ip="192.168.1.2"
    _target_ip=$(_conwrt_get_opt target-ip "$@") || _target_ip="192.168.1.1"
    _stock_ip=$(_conwrt_get_opt stock-ip "$@") || _stock_ip=""
    _stock_password=$(_conwrt_get_opt stock-password "$@") || _stock_password="new2day"
    _overlay_keys=$(_conwrt_get_opt overlay-keys "$@") || _overlay_keys=""
    _cfg1_tftp=$(_conwrt_get_opt cfg1-tftp "$@") || _cfg1_tftp=""
    _cfg1_permanent=$(_conwrt_get_opt cfg1-permanent "$@") || _cfg1_permanent=""
    _kmod_mtd_rw=$(_conwrt_get_opt kmod-mtd-rw "$@") || _kmod_mtd_rw=""
    _no_backup=""
    _disable_dhcp=""
    for _arg in "$@"; do
        case "$_arg" in --no-backup) _no_backup=1 ;; esac
        case "$_arg" in --disable-dhcp) _disable_dhcp=1 ;; esac
    done

    [ -f "$_image" ] || { echo "image not found: $_image" >&2; return 1; }

    # Phase 0: Stock SSH preflight (extreme-rdwr-tftp-initramfs mode)
    if [ -n "$_stock_ip" ]; then
        [ -f "$_initramfs" ] || { echo "initramfs required with --stock-ip" >&2; return 1; }
        _bootfile="${_bootfile:-$(basename "$_initramfs")}"
        _image_dir=$(dirname "$_initramfs")
        echo "flash (extreme-rdwr-tftp-initramfs): port=$_port model=$_model"
        echo "  phase 0: stock ssh preflight on $_stock_ip"
        echo "  phase 1: tftp boot initramfs=$_initramfs bootfile=$_bootfile"
        echo "  phase 2: sysupgrade image=$_image"

        echo "stock ssh preflight on $_stock_ip..."
        conwrt_stock_wait_ssh "$_stock_ip" || { echo "stock ssh not available on $_stock_ip" >&2; return 1; }
        conwrt_stock_disable_timeout "$_stock_ip" || return 1
        conwrt_stock_read_uboot_env "$_stock_ip" /tmp/conwrt-uboot-env-backup.txt || return 1
        conwrt_stock_configure_tftp_boot "$_stock_ip" "$_tftp_ip" "$_target_ip" "$_cfg1_tftp" || return 1
        conwrt_stock_reboot "$_stock_ip"
    elif [ -n "$_initramfs" ]; then
        [ -f "$_initramfs" ] || { echo "initramfs not found: $_initramfs" >&2; return 1; }
        _bootfile="${_bootfile:-$(basename "$_initramfs")}"
        _image_dir=$(dirname "$_initramfs")
        echo "flash (two-phase): port=$_port model=$_model"
        echo "  phase 1: tftp boot initramfs=$_initramfs bootfile=$_bootfile"
        echo "  phase 2: sysupgrade image=$_image"
    else
        _image_dir=$(dirname "$_image")
        _bootfile=$(basename "$_image")
        echo "flash (single-phase): port=$_port model=$_model image=$_image"
    fi

    conwrt_poe_disable "$_port"
    conwrt_poe_wait 5
    conwrt_poe_enable "$_port"

    conwrt_detect_wait_link "$_port" 120 || return 1

    conwrt_flash_tftp "$_port" "$_tftp_ip" "$_bootfile" "$_image_dir" 120 || return 1

    conwrt_flash_wait_ssh "$_target_ip" 180 || return 1

    if [ -z "$_no_backup" ]; then
        _backup_dir="/tmp/conwrt-backup-$(date +%s)"
        conwrt_flash_backup "$_target_ip" "$_backup_dir" || echo "backup failed, continuing..."
    fi

    if [ -n "$_disable_dhcp" ]; then
        conwrt_overlay_build /tmp/conwrt-overlay.tar.gz "1" "${_overlay_keys:-}" || {
            echo "overlay build failed" >&2; return 1;
        }
        conwrt_flash_sysupgrade "$_target_ip" "$_image" /tmp/conwrt-overlay.tar.gz || return 1
    else
        conwrt_flash_sysupgrade "$_target_ip" "$_image" "" || return 1
    fi

    conwrt_flash_wait_ssh "$_target_ip" 180 || return 1

    # Phase 3: Write permanent boot config (if cfg1-permanent and kmod-mtd-rw provided)
    if [ -n "$_cfg1_permanent" ] && [ -n "$_kmod_mtd_rw" ]; then
        conwrt_flash_write_permanent_bootcfg "$_target_ip" "$_cfg1_permanent" "$_kmod_mtd_rw" || {
            echo "WARNING: permanent boot config write failed — device will TFTP boot on next reboot" >&2
        }
        echo "rebooting to verify flash boot..."
        ssh $_CONWRT_SSH_OPTS "root@${_target_ip}" "reboot" 2>/dev/null || true
        sleep 10
        conwrt_flash_wait_ssh "$_target_ip" 180 || {
            echo "ssh not available after flash boot — device may have TFTP-booted" >&2
            return 1
        }
        echo "flash boot verified"
    fi

    echo "flash complete"
    return 0
}

_conwrt_cmd_detect() {
    _port=$(_conwrt_get_opt port "$@") || { echo "missing --port" >&2; return 1; }
    _timeout=$(_conwrt_get_opt timeout "$@") || _timeout=120

    echo "detect: port=$_port timeout=$_timeout"

    conwrt_detect_wait_link "$_port" "$_timeout" || return 1
    conwrt_detect_passive "$_port" "$_timeout" || return 1
    return 0
}

_conwrt_cmd_postflash() {
    _ip=$(_conwrt_get_opt ip "$@") || { echo "missing --ip" >&2; return 1; }
    _ssh_key=$(_conwrt_get_opt ssh-key "$@") || { echo "missing --ssh-key" >&2; return 1; }
    _password=""
    _password=$(_conwrt_get_opt password "$@") || true
    _new_ip=""
    _new_ip=$(_conwrt_get_opt new-ip "$@") || true

    echo "postflash: ip=$_ip ssh-key=$_ssh_key"

    conwrt_postflash_install_key "$_ip" "$_ssh_key" || return 1

    if [ -n "$_password" ]; then
        conwrt_postflash_set_password "$_ip" "$_password" || return 1
    fi

    if [ -n "$_new_ip" ]; then
        conwrt_postflash_set_ip "$_ip" "$_new_ip" || return 1
        echo "waiting for device at new IP $_new_ip..."
        sleep 10
        _ip="$_new_ip"
    fi

    _priv_key="${_ssh_key%.pub}"
    if [ -f "$_priv_key" ]; then
        conwrt_postflash_verify "$_ip" "$_priv_key" || return 1
    fi

    echo "postflash complete"
    return 0
}

case "${1:-help}" in
    setup)
        shift
        _conwrt_cmd_setup "$@"
        ;;
    flash)
        shift
        _conwrt_cmd_flash "$@"
        ;;
    detect)
        shift
        _conwrt_cmd_detect "$@"
        ;;
    postflash)
        shift
        _conwrt_cmd_postflash "$@"
        ;;
    help|--help|-h)
        _conwrt_usage
        ;;
    *)
        echo "unknown command: $1" >&2
        _conwrt_usage >&2
        exit 1
        ;;
esac
