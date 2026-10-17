#!/bin/sh
# conwrt#228 — trust-on-first-boot, device side (ADR-0013).
#
# Runs at first boot when TOFB is baked into the image (opt-in profile
# flag, follow-up integration). Generates the device identity, shows the
# attestation code on the status LED, serves the link-local enrollment
# endpoint, and adopts the verified-then-hardened discipline from PR #235.
#
# Every on-device behavior here is NEEDS-BENCH (LED paths and timing,
# busybox httpd/CGI availability, button timing, entropy latency); the
# script's logic shape is host-verified by tests/test_tofb.py.

TOFB_DIR=/etc/conwrt
TOFB_DONE="$TOFB_DIR/tofb.done"
AUTH_KEYS=/etc/dropbear/authorized_keys
HOSTKEY=/etc/dropbear/dropbear_ed25519_host_key
PUBKEY_TXT="$TOFB_DIR/tofb.pub"
FAILURES=0
FAILURES_LIMIT=3

die() { echo "tofb: $*" >&2; exit 1; }

[ -e "$TOFB_DONE" ] && exit 0

# Entropy gate (ADR-0013 §1.1): a blocking /dev/random read returns only
# once the kernel CRNG is seeded; urandom before that is weak. MT7621 has
# no TRNG and a fresh flash has no saved seed.
dd if=/dev/random bs=1 count=1 of=/dev/null 2>/dev/null || die "entropy gate failed"

mkdir -p "$TOFB_DIR" /etc/dropbear
[ -s "$HOSTKEY" ] || dropbearkey -t ed25519 -f "$HOSTKEY" >/dev/null 2>&1 \
    || die "key generation failed"
dropbearkey -y -f "$HOSTKEY" | grep '^ssh-' > "$PUBKEY_TXT" \
    || die "public key export failed"

# Attestation code = first 16 hex chars (8 bytes, big-endian u64) of
# SHA-256(key blob), mod 1e6 — MUST match scripts/tofb.py key_blob/digest[:8].
# BusyBox primitives only (base64 -d, sha256sum) — AGENTS.md tool rules.
CODE=$(awk '{print $2}' "$PUBKEY_TXT" | base64 -d 2>/dev/null | sha256sum 2>/dev/null) \
    || die "code derivation failed"
CODE=$(printf '%s' "$CODE" | cut -c1-16)
[ -n "$CODE" ] || die "empty digest"
CODE=$(( 0x$CODE % 1000000 ))
CODE=$(printf '%06d' "$CODE")
echo "tofb: code derived" >&2

show_led_code() {
    # ADR-0013 §2: six groups, color cycles red/orange/white, digit = blink
    # count (0 = one long blink). LED paths/timers NEEDS-BENCH.
    i=0
    for digit in $(printf '%s' "$CODE" | fold -w1); do
        case $((i % 3)) in
            0) LED=$(ls /sys/class/leds/ | grep -i red | head -1) ;;
            1) LED=$(ls /sys/class/leds/ | grep -i orange | head -1) ;;
            2) LED=$(ls /sys/class/leds/ | grep -i white | head -1) ;;
        esac
        [ -n "$LED" ] || return 1
        if [ "$digit" = "0" ]; then
            echo 1 > "/sys/class/leds/$LED/brightness"; sleep 2
            echo 0 > "/sys/class/leds/$LED/brightness"
        else
            n=0
            while [ "$n" -lt "$digit" ]; do
                echo 1 > "/sys/class/leds/$LED/brightness"; sleep 0.4
                echo 0 > "/sys/class/leds/$LED/brightness"; sleep 0.3
                n=$((n + 1))
            done
        fi
        sleep 1
        i=$((i + 1))
    done
    return 0
}

handle_enroll() {
    # stdin: JSON {"code": "...", "pubkey": "..."}. Installs the key only
    # when the code matches; three mismatches kill the endpoint.
    # The verify-then-harden ordering mirrors PR #235: the done-marker and
    # auth hardening may only follow a provable authorized_keys write.
    REQ=$(cat)
    GOT=$(printf '%s' "$REQ" | grep -o '"code"[: ]*"[0-9]*"' | grep -o '[0-9]\{6\}')
    PUB=$(printf '%s' "$REQ" | grep -o '"pubkey"[: ]*"[^"]*"' | cut -d'"' -f4)
    if [ "$GOT" != "$CODE" ]; then
        FAILURES=$((FAILURES + 1))
        echo "Status: 403 Forbidden"
        echo ""
        echo "mismatch"
        [ "$FAILURES" -ge "$FAILURES_LIMIT" ] && exit 1
        return
    fi
    case "$PUB" in
        ssh-*) ;;
        *) echo "Status: 400 Bad Request"; echo ""; echo "bad key"; return ;;
    esac
    mkdir -p /etc/dropbear
    echo "$PUB" >> "$AUTH_KEYS" || return 1
    chmod 600 "$AUTH_KEYS"
    printf '%s\n' "$PUB" | grep -qF "$(printf '%s' "$PUB")" "$AUTH_KEYS" || return 1
    uci set dropbear.@dropbear[0].PasswordAuth='off'
    uci set dropbear.@dropbear[0].RootPasswordAuth='off'
    uci commit dropbear
    date > "$TOFB_DONE"
    echo "Status: 200 OK"
    echo ""
    echo "enrolled"
}

# Link-local endpoint (ADR-0013 §3): busybox httpd with a CGI handler.
# Applet/path availability NEEDS-BENCH; scaffolding ships the shape.
LLADDR=$(ip -6 addr show scope link 2>/dev/null | grep -o 'fe80::[^/]*' | head -1)
[ -n "$LLADDR" ] || die "no link-local address"

# Loop: LED display + endpoint until enrolled or timeout (15 min).
# NEEDS-BENCH: httpd CGI wiring, backgrounding on initramfs, timeout clock.
show_led_code &
while [ ! -e "$TOFB_DONE" ]; do
    handle_enroll
done
