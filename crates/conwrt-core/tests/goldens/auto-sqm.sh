# golden: conwrt 1.x output of scripts/use_cases/auto_sqm.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- Auto-SQM ---

touch /etc/config/auto_sqm
uci set auto_sqm.config=auto_sqm
uci set auto_sqm.config.mode='static'
uci set auto_sqm.config.interface='wan'
uci set auto_sqm.config.device='eth0'
uci set auto_sqm.config.target_percent='90'
uci set auto_sqm.config.qdisc='cake'
uci set auto_sqm.config.script='piece_of_cake.qos'
uci set auto_sqm.config.measurement_mode='wget'
uci set auto_sqm.config.iperf3_host=''
uci set auto_sqm.config.iperf3_port='5201'
uci set auto_sqm.config.test_url='http://speedtest.tele2.net/10MB.zip'
uci set auto_sqm.config.download_kbps='0'
uci set auto_sqm.config.upload_kbps='0'
uci set auto_sqm.config.upload_fallback_kbps='5000'
uci set auto_sqm.config.hysteresis_percent='10'
uci set auto_sqm.config.dynamic_interval_hours='4'
uci commit auto_sqm

cat <<'AUTO_SQM_EOF' > /usr/sbin/auto-sqm
#!/bin/sh
# auto-sqm — measure WAN link speed and configure SQM

MODE=$(uci -q get auto_sqm.config.mode || echo "static")
INTERFACE=$(uci -q get auto_sqm.config.interface || echo "wan")
DEVICE=$(uci -q get auto_sqm.config.device || echo "eth0")
TARGET_PCT=$(uci -q get auto_sqm.config.target_percent || echo "90")
QDISC=$(uci -q get auto_sqm.config.qdisc || echo "cake")
QOS_SCRIPT=$(uci -q get auto_sqm.config.script || echo "piece_of_cake.qos")
MEAS_MODE=$(uci -q get auto_sqm.config.measurement_mode || echo "wget")
IPERF3_HOST=$(uci -q get auto_sqm.config.iperf3_host || echo "")
IPERF3_PORT=$(uci -q get auto_sqm.config.iperf3_port || echo "5201")
TEST_URL=$(uci -q get auto_sqm.config.test_url || echo "")
UPLOAD_FALLBACK=$(uci -q get auto_sqm.config.upload_fallback_kbps || echo "5000")
HYSTERESIS=$(uci -q get auto_sqm.config.hysteresis_percent || echo "10")

DL_SPEED=0
UL_SPEED=0

measure_wget() {
    [ -z "$DEVICE" ] && return 1
    [ -z "$TEST_URL" ] && return 1
    bytes_before=$(cat /sys/class/net/"$DEVICE"/statistics/rx_bytes 2>/dev/null) || return 1
    t1=$(date +%s)
    wget -O /dev/null -T 30 "$TEST_URL" 2>/dev/null || return 1
    t2=$(date +%s)
    bytes_after=$(cat /sys/class/net/"$DEVICE"/statistics/rx_bytes 2>/dev/null) || return 1
    elapsed=$((t2 - t1))
    [ "$elapsed" -eq 0 ] && elapsed=1
    speed_bps=$(( (bytes_after - bytes_before) * 8 / elapsed ))
    DL_SPEED=$((speed_bps / 1000))
    DL_SPEED=$((DL_SPEED * TARGET_PCT / 100))
}

measure_iperf3() {
    [ -z "$IPERF3_HOST" ] && return 1
    command -v iperf3 >/dev/null 2>&1 || return 1
    json_out=$(iperf3 -c "$IPERF3_HOST" -p "$IPERF3_PORT" -t 5 -J 2>/dev/null) || return 1
    speed_bps=$(echo "$json_out" | jsonfilter -e "@.end.sum_received.bits_per_second" 2>/dev/null) || return 1
    speed_bps=$(echo "$speed_bps" | cut -d. -f1)
    DL_SPEED=$((speed_bps / 1000))
    DL_SPEED=$((DL_SPEED * TARGET_PCT / 100))
}

apply_sqm() {
    dl=$1
    ul=$2
    [ "$dl" -eq 0 ] && return 1

    cur_dl=$(uci -q get sqm."$INTERFACE".download || echo "0")
    cur_ul=$(uci -q get sqm."$INTERFACE".upload || echo "0")

    if [ "$cur_dl" -gt 0 ] && [ "$cur_ul" -gt 0 ]; then
        lo=$((100 - HYSTERESIS))
        hi=$((100 + HYSTERESIS))
        pct_dl=$((cur_dl * 100 / dl))
        pct_ul=$((cur_ul * 100 / ul))
        if [ "$pct_dl" -ge "$lo" ] && [ "$pct_dl" -le "$hi" ] && [ "$pct_ul" -ge "$lo" ] && [ "$pct_ul" -le "$hi" ]; then
            echo "auto-sqm: change within hysteresis, skipping"
            return 0
        fi
    fi

    touch /etc/config/sqm

    uci set sqm.$INTERFACE=queue
    uci set sqm.$INTERFACE.interface="$INTERFACE"
    uci set sqm.$INTERFACE.enabled='1'
    uci set sqm.$INTERFACE.script="$QOS_SCRIPT"
    uci set sqm.$INTERFACE.qdisc="$QDISC"
    uci set sqm.$INTERFACE.linklayer='none'
    uci set sqm.$INTERFACE.overhead='0'
    uci set sqm.$INTERFACE.linklayer_adaptation_mechanism='default'
    uci set sqm.$INTERFACE.debug_logging='0'
    uci set sqm.$INTERFACE.verbosity='5'
    uci set sqm.$INTERFACE.download="$dl"
    uci set sqm.$INTERFACE.upload="$ul"
    uci commit sqm

    /etc/init.d/sqm enable
    /etc/init.d/sqm restart 2>/dev/null || true

    echo "auto-sqm: SQM applied ${dl}/${ul} kbit/s (${QDISC})"
}

STATIC_DL=$(uci -q get auto_sqm.config.download_kbps || echo "0")
STATIC_UL=$(uci -q get auto_sqm.config.upload_kbps || echo "0")

if [ "$MODE" = "static" ] && [ "$STATIC_DL" -gt 0 ]; then
    DL_SPEED=$((STATIC_DL * TARGET_PCT / 100))
    if [ "$STATIC_UL" -gt 0 ]; then
        UL_SPEED=$((STATIC_UL * TARGET_PCT / 100))
    else
        UL_SPEED=$UPLOAD_FALLBACK
    fi
else
    if [ "$MEAS_MODE" = "iperf3" ] && [ -n "$IPERF3_HOST" ]; then
        measure_iperf3 || measure_wget
    else
        measure_wget || measure_iperf3
    fi

    if [ "$DL_SPEED" -eq 0 ]; then
        echo "auto-sqm: measurement failed, will retry on next trigger" >&2
        exit 1
    fi

    if [ "$STATIC_UL" -gt 0 ]; then
        UL_SPEED=$((STATIC_UL * TARGET_PCT / 100))
    else
        UL_SPEED=$UPLOAD_FALLBACK
    fi
fi

apply_sqm "$DL_SPEED" "$UL_SPEED"
AUTO_SQM_EOF
chmod +x /usr/sbin/auto-sqm

mkdir -p /etc/hotplug.d/iface
cat <<'HOTPLUG_EOF' > /etc/hotplug.d/iface/10-sqm-autotune
#!/bin/sh
[ "$ACTION" = "ifup" ] && [ "$INTERFACE" = "wan" ] && /usr/sbin/auto-sqm &
HOTPLUG_EOF
chmod +x /etc/hotplug.d/iface/10-sqm-autotune

echo 'auto-sqm: will measure and configure on WAN ifup'
echo 'Auto-SQM configured'
