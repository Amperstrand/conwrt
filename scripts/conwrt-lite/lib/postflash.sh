#!/bin/sh
# conwrt-lite postflash library — SSH key, password, IP config
[ -n "${_CONWRT_POSTFLASH_LOADED:-}" ] && return 0
_CONWRT_POSTFLASH_LOADED=1

_CONWRT_PF_SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

conwrt_postflash_install_key() {
    _ip="$1"
    _pubkey_path="$2"
    [ -f "$_pubkey_path" ] || { echo "public key not found: $_pubkey_path" >&2; return 1; }

    _pubkey=$(cat "$_pubkey_path")
    ssh $_CONWRT_PF_SSH_OPTS "root@${_ip}" \
        "mkdir -p /etc/dropbear && echo '$_pubkey' >> /etc/dropbear/authorized_keys && chmod 600 /etc/dropbear/authorized_keys" || {
        echo "failed to install ssh key on $_ip" >&2
        return 1
    }
    echo "ssh key installed on $_ip"
    return 0
}

conwrt_postflash_set_password() {
    _ip="$1"
    _pw="$2"

    ssh $_CONWRT_PF_SSH_OPTS "root@${_ip}" \
        "printf '%s\n%s\n' '$_pw' '$_pw' | passwd root" >/dev/null 2>&1 || {
        echo "failed to set password on $_ip" >&2
        return 1
    }
    echo "password set on $_ip"
    return 0
}

conwrt_postflash_set_ip() {
    _ip="$1"
    _new_ip="$2"

    ssh $_CONWRT_PF_SSH_OPTS "root@${_ip}" \
        "uci set network.lan.ipaddr='$_new_ip' && uci commit network && /etc/init.d/network restart" >/dev/null 2>&1 || true
    echo "ip change initiated from $_ip to $_new_ip (connection will drop)"
    return 0
}

conwrt_postflash_verify() {
    _ip="$1"
    _key_path="$2"

    ssh -i "$_key_path" $_CONWRT_PF_SSH_OPTS -o BatchMode=yes "root@${_ip}" "true" 2>/dev/null || {
        echo "key-based auth verification failed for $_ip" >&2
        return 1
    }
    echo "key-based auth verified on $_ip"
    return 0
}
