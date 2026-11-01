# golden: conwrt 1.x output of scripts/use_cases/openperf_client.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- openperf-client: WiFi Performance Test Client ---

# Create directories
mkdir -p /root/openperf/init.d
# Write STA autostart procd service
cat > /etc/init.d/openperf-autostart << 'OPENPERF_EOF'
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=98
STOP=1

start_service() {
    procd_open_instance
    procd_set_param respawn 3600 5 0
    procd_set_param env AP_IP=
    procd_set_param command /usr/bin/python3 /root/openperf/sta_autostart.py
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
OPENPERF_EOF
chmod +x /etc/init.d/openperf-autostart
# Configure 2.4 GHz STA to scan for openperf AP
for iface in sta_radio0 phy0_sta; do
    if uci -q get wireless.$iface >/dev/null 2>&1; then
        uci set wireless.$iface.ssid='openperf'
        uci set wireless.$iface.encryption='none'
        uci set wireless.$iface.network='wan'
        break
    fi
done
# Configure HaHalow STA if present
for iface in default_radio1; do
    if uci -q get wireless.$iface >/dev/null 2>&1; then
        uci set wireless.$iface.ssid='openperf-halow'
        uci set wireless.$iface.encryption='sae'
        uci set wireless.$iface.key='openperf-test'
        break
    fi
done
uci commit wireless
# Enable autostart service
/etc/init.d/openperf-autostart enable

# NOTE: Python files must be pushed to /root/openperf/ via install-openperf.sh.
# The autostart loop will wait for AP discovery via default gateway.