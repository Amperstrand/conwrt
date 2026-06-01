"""auto-sqm — Auto-measure WAN speed and configure SQM to eliminate bufferbloat."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register

_AUTO_SQM_SCRIPT = textwrap.dedent("""\
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
""")


def _build_auto_sqm(params: dict[str, Any]) -> str:
    mode = params.get("mode", "static")
    interface = params.get("interface", "wan")
    device = params.get("device", "eth0")
    target_percent = params.get("target_percent", 90)
    qdisc = params.get("qdisc", "cake")
    script = params.get("script", "piece_of_cake.qos")
    measurement_mode = params.get("measurement_mode", "wget")
    download_kbps = params.get("download_kbps", 0)
    upload_kbps = params.get("upload_kbps", 0)
    iperf3_host = params.get("iperf3_host", "")
    iperf3_port = params.get("iperf3_port", 5201)
    test_url = params.get("test_url", "http://speedtest.tele2.net/10MB.zip")
    upload_fallback_kbps = params.get("upload_fallback_kbps", 5000)
    hysteresis_percent = params.get("hysteresis_percent", 10)
    dynamic_interval_hours = params.get("dynamic_interval_hours", 4)

    lines = [
        "# --- Auto-SQM ---",
        "",
        "touch /etc/config/auto_sqm",
        "uci set auto_sqm.config=auto_sqm",
        f"uci set auto_sqm.config.mode='{mode}'",
        f"uci set auto_sqm.config.interface='{interface}'",
        f"uci set auto_sqm.config.device='{device}'",
        f"uci set auto_sqm.config.target_percent='{target_percent}'",
        f"uci set auto_sqm.config.qdisc='{qdisc}'",
        f"uci set auto_sqm.config.script='{script}'",
        f"uci set auto_sqm.config.measurement_mode='{measurement_mode}'",
        f"uci set auto_sqm.config.iperf3_host='{iperf3_host}'",
        f"uci set auto_sqm.config.iperf3_port='{iperf3_port}'",
        f"uci set auto_sqm.config.test_url='{test_url}'",
        f"uci set auto_sqm.config.download_kbps='{download_kbps}'",
        f"uci set auto_sqm.config.upload_kbps='{upload_kbps}'",
        f"uci set auto_sqm.config.upload_fallback_kbps='{upload_fallback_kbps}'",
        f"uci set auto_sqm.config.hysteresis_percent='{hysteresis_percent}'",
        f"uci set auto_sqm.config.dynamic_interval_hours='{dynamic_interval_hours}'",
        "uci commit auto_sqm",
        "",
        "cat <<'AUTO_SQM_EOF' > /usr/sbin/auto-sqm",
    ]

    for script_line in _AUTO_SQM_SCRIPT.strip().splitlines():
        lines.append(script_line)

    lines.append("AUTO_SQM_EOF")
    lines.append("chmod +x /usr/sbin/auto-sqm")
    lines.append("")
    lines.append("mkdir -p /etc/hotplug.d/iface")
    lines.append("cat <<'HOTPLUG_EOF' > /etc/hotplug.d/iface/10-sqm-autotune")
    lines.append("#!/bin/sh")
    lines.append(f'[ "$ACTION" = "ifup" ] && [ "$INTERFACE" = "{interface}" ] && /usr/sbin/auto-sqm &')
    lines.append("HOTPLUG_EOF")
    lines.append("chmod +x /etc/hotplug.d/iface/10-sqm-autotune")

    if mode == "dynamic":
        lines.append("")
        lines.append(f"echo '0 */{dynamic_interval_hours} * * * /usr/sbin/auto-sqm' >> /etc/crontabs/root")
        lines.append("/etc/init.d/cron enable")
        lines.append("/etc/init.d/cron restart 2>/dev/null || true")

    lines.append("")
    if mode == "static" and download_kbps > 0:
        lines.append("/usr/sbin/auto-sqm")
    else:
        lines.append("echo 'auto-sqm: will measure and configure on WAN ifup'")

    lines.append("echo 'Auto-SQM configured'")

    return textwrap.dedent("\n".join(lines))


register(UseCase(
    name="auto-sqm",
    description="Auto-measure WAN speed and configure SQM to eliminate bufferbloat",
    packages=[
        "sqm-scripts",
        "luci-app-sqm",
        "jsonfilter",
        "iperf3",
    ],
    packages_remove=[],
    params={
        "mode": ParamDef(type=str, default="static",
                         description="Mode: static (fixed speeds) or dynamic (auto-measure + cron re-tune)"),
        "interface": ParamDef(type=str, default="wan",
                              description="WAN interface name"),
        "device": ParamDef(type=str, default="eth0",
                           description="Physical device for byte counters"),
        "target_percent": ParamDef(type=int, default=90,
                                   description="Apply SQM at this % of measured speed"),
        "qdisc": ParamDef(type=str, default="cake",
                          description="Queue discipline: cake or fq_codel"),
        "script": ParamDef(type=str, default="piece_of_cake.qos",
                           description="QoS script"),
        "measurement_mode": ParamDef(type=str, default="wget",
                                     description="Measurement mode: wget or iperf3"),
        "download_kbps": ParamDef(type=int, default=0,
                                  description="Static download speed in Kbit/s (0 = measure on first boot)"),
        "upload_kbps": ParamDef(type=int, default=0,
                                description="Static upload speed in Kbit/s (0 = use upload_fallback)"),
        "iperf3_host": ParamDef(type=str, default="",
                                description="iperf3 server hostname (required if measurement_mode=iperf3)"),
        "iperf3_port": ParamDef(type=int, default=5201,
                                description="iperf3 server port"),
        "test_url": ParamDef(type=str, default="http://speedtest.tele2.net/10MB.zip",
                             description="wget test file URL for speed measurement"),
        "upload_fallback_kbps": ParamDef(type=int, default=5000,
                                         description="Fallback upload speed when can't measure"),
        "hysteresis_percent": ParamDef(type=int, default=10,
                                       description="Don't reconfigure if change < this %"),
        "dynamic_interval_hours": ParamDef(type=int, default=4,
                                           description="Re-tune interval in hours (dynamic mode)"),
    },
    build_configure=_build_auto_sqm,
    test_status="experimental",
    tested_notes="not validated on hardware",
    requires_capabilities=[],
))
