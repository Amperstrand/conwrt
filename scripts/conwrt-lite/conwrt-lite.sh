#!/bin/sh
set -eu

_CONWRT_LIB_DIR="$(cd "$(dirname "$0")/lib" && pwd)"

. "$_CONWRT_LIB_DIR/detect.sh"
. "$_CONWRT_LIB_DIR/flash.sh"
. "$_CONWRT_LIB_DIR/postflash.sh"
. "$_CONWRT_LIB_DIR/poe.sh"
. "$_CONWRT_LIB_DIR/tftp.sh"
. "$_CONWRT_LIB_DIR/inventory.sh"

_conwrt_usage() {
    cat <<'EOF'
conwrt-lite — POSIX shell flasher for OpenWrt switches

Usage:
  conwrt-lite.sh flash --port PORT --model-id MODEL --image PATH
  conwrt-lite.sh detect --port PORT [--timeout SECONDS]
  conwrt-lite.sh postflash --ip IP --ssh-key PATH [--password PASS]
  conwrt-lite.sh help

Commands:
  flash      Full flash workflow: power cycle, detect, TFTP, sysupgrade
  detect     Device detection via link-up and passive fingerprinting
  postflash  Post-flash SSH configuration (keys, password, IP)
  help       Show this usage information

Options:
  --port PORT        Switch port (e.g. LAN5)
  --model-id MODEL   Device model identifier
  --image PATH       Path to firmware image
  --timeout SECS     Timeout in seconds (default: 120)
  --ip IP            Device IP address
  --ssh-key PATH     Path to SSH public key
  --password PASS    Root password to set
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

_conwrt_cmd_flash() {
    _port=$(_conwrt_get_opt port "$@") || { echo "missing --port" >&2; return 1; }
    _model=$(_conwrt_get_opt model-id "$@") || { echo "missing --model-id" >&2; return 1; }
    _image=$(_conwrt_get_opt image "$@") || { echo "missing --image" >&2; return 1; }

    [ -f "$_image" ] || { echo "image not found: $_image" >&2; return 1; }

    echo "flash: port=$_port model=$_model image=$_image"

    conwrt_poe_disable "$_port"
    conwrt_poe_wait 5
    conwrt_poe_enable "$_port"

    conwrt_detect_wait_link "$_port" 120 || return 1

    _tftp_ip="192.168.1.100"
    _image_dir=$(dirname "$_image")
    _bootfile=$(basename "$_image")

    conwrt_flash_tftp "$_port" "$_tftp_ip" "$_bootfile" "$_image_dir" || return 1

    _device_ip="192.168.1.1"
    conwrt_flash_wait_ssh "$_device_ip" 180 || return 1
    conwrt_flash_sysupgrade "$_device_ip" "$_image" || return 1
    conwrt_flash_wait_ssh "$_device_ip" 180 || return 1

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

    echo "postflash: ip=$_ip ssh-key=$_ssh_key"

    conwrt_postflash_install_key "$_ip" "$_ssh_key" || return 1

    if [ -n "$_password" ]; then
        conwrt_postflash_set_password "$_ip" "$_password" || return 1
    fi

    _priv_key="${_ssh_key%.pub}"
    if [ -f "$_priv_key" ]; then
        conwrt_postflash_verify "$_ip" "$_priv_key" || return 1
    fi

    echo "postflash complete"
    return 0
}

case "${1:-help}" in
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
