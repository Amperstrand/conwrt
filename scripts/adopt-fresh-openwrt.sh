#!/usr/bin/env bash
# adopt-fresh-openwrt.sh — idempotent post-flash adoption of a vanilla
# OpenWrt device onto its bench seat.
#
# Automates the flow proven manually on the x1860 (2026-10-21/22):
#   fresh device = blank-password root at 192.168.1.1, DHCP+RA ARMED
#   (a rogue on any shared segment — AGENTS.md rogue-DHCP discipline).
#
# No-op when the device is already adopted (key auth + seat values +
# rogue disarmed). Mutating path: install fleet key, disarm DHCP/RA,
# set seat ipaddr WITH netmask (the 2026-10-14 /32 postmortem — never
# one without the other), readback-gate every value, commit, reboot,
# wait for the seat address, verify.
#
# Usage:
#   scripts/adopt-fresh-openwrt.sh FRESH_IP SEAT_IP SEAT_NETMASK PRIVKEY PUBKEY
# e.g.
#   scripts/adopt-fresh-openwrt.sh 192.168.1.1 192.168.105.52 \
#       255.255.255.0 ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub

set -euo pipefail

FRESH_IP=${1:?usage: adopt-fresh-openwrt.sh FRESH_IP SEAT_IP SEAT_NETMASK PRIVKEY PUBKEY}
SEAT_IP=${2:?seat ip required}
NETMASK=${3:?seat netmask required}
PRIVKEY=${4:?private key path required}
PUBKEY=${5:?public key path required}
PUBKEY_LINE=$(cat "$PUBKEY")

ssh_wrap() { # ssh_wrap IP KEYORBLANK CMD
    local ip=$1 key=$2 cmd=$3
    if [[ $key == blank ]]; then
        sshpass -p '' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=8 "root@${ip}" "$cmd"
    else
        ssh -i "$key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
            -o BatchMode=yes -o ConnectTimeout=8 "root@${ip}" "$cmd"
    fi
}

echo "== adoption: fresh=${FRESH_IP} seat=${SEAT_IP}/${NETMASK} =="

# --- no-op gate: already adopted? (read-only) ---
if ssh_wrap "$SEAT_IP" "$PRIVKEY" \
    "test \"\$(uci get network.lan.ipaddr)\" = '$SEAT_IP' \
     && test \"\$(uci get network.lan.netmask)\" = '$NETMASK' \
     && test \"\$(uci get dhcp.lan.ignore)\" = '1' \
     && test \"\$(uci get dhcp.lan.ra)\" = 'disabled' \
     && test \"\$(uci get dhcp.lan.dhcpv6)\" = 'disabled' \
     && grep -qF '$PUBKEY_LINE' /etc/dropbear/authorized_keys" \
    >/dev/null 2>&1; then
    echo "already adopted at ${SEAT_IP} (key + seat + rogue-disarmed verified) — no-op"
    exit 0
fi

# --- mutating path (fresh device, blank root password) ---
echo "adopting fresh device at ${FRESH_IP} (blank-password door)"
ssh_wrap "$FRESH_IP" blank "
mkdir -p /etc/dropbear && chmod 700 /etc/dropbear
echo '$PUBKEY_LINE' > /etc/dropbear/authorized_keys && chmod 600 /etc/dropbear/authorized_keys
uci set dhcp.lan.ignore='1'
uci set dhcp.lan.ra='disabled'
uci set dhcp.lan.dhcpv6='disabled'
uci set network.lan.ipaddr='$SEAT_IP'
uci set network.lan.netmask='$NETMASK'
# readback gate (AGENTS.md): every staged value, or refuse to commit
ok=1
[ \"\$(uci get dhcp.lan.ignore)\" = '1' ] || { echo 'BAD dhcp.lan.ignore'; ok=0; }
[ \"\$(uci get dhcp.lan.ra)\" = 'disabled' ] || { echo 'BAD dhcp.lan.ra'; ok=0; }
[ \"\$(uci get dhcp.lan.dhcpv6)\" = 'disabled' ] || { echo 'BAD dhcp.lan.dhcpv6'; ok=0; }
[ \"\$(uci get network.lan.ipaddr)\" = '$SEAT_IP' ] || { echo 'BAD ipaddr'; ok=0; }
[ \"\$(uci get network.lan.netmask)\" = '$NETMASK' ] || { echo 'BAD netmask'; ok=0; }
grep -qF '$PUBKEY_LINE' /etc/dropbear/authorized_keys || { echo 'BAD key'; ok=0; }
[ \"\$ok\" = 1 ] || { echo 'READBACK FAILED — aborting before commit'; exit 3; }
uci commit dhcp && uci commit network && uci commit dropbear 2>/dev/null || true
echo COMMITTED
"

# --- wait for the seat address (dual-image boots can take ~20 min) ---
echo "waiting for key-auth SSH at ${SEAT_IP} (up to 25 min)..."
deadline=$((SECONDS + 1500))
while (( SECONDS < deadline )); do
    if ssh_wrap "$SEAT_IP" "$PRIVKEY" true >/dev/null 2>&1; then
        break
    fi
    sleep 10
done
if ! ssh_wrap "$SEAT_IP" "$PRIVKEY" true >/dev/null 2>&1; then
    echo "TIMEOUT: seat address never answered with key auth" >&2
    exit 4
fi

# --- final verification ---
ssh_wrap "$SEAT_IP" "$PRIVKEY" \
    ". /etc/openwrt_release
     test \"\$(uci get network.lan.ipaddr)\" = '$SEAT_IP'
     test \"\$(uci get network.lan.netmask)\" = '$NETMASK'
     test \"\$(uci get dhcp.lan.ignore)\" = '1'
     grep -qF '$PUBKEY_LINE' /etc/dropbear/authorized_keys
     echo \"ADOPTED: \${DISTRIB_RELEASE} at \$(uci get network.lan.ipaddr)/\$(uci get network.lan.netmask) rogue-disarmed key-installed\""
