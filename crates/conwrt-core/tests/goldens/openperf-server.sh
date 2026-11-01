# golden: conwrt 1.x output of scripts/use_cases/openperf_server.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- openperf-server: Open WiFi Performance Testing ---

# Create directories
mkdir -p /root/openperf/init.d
# Write procd init script
cat > /etc/init.d/openperf-server << 'OPENPERF_EOF'
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
STOP=1

start_service() {
    procd_open_instance
    procd_set_param respawn 3600 5 0
    procd_set_param command /usr/bin/python3 /root/openperf/server.py
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param env PORT=7777
    procd_close_instance
}
OPENPERF_EOF
chmod +x /etc/init.d/openperf-server
# Set management SSID on first 2.4 GHz AP interface
for iface in phy0-ap0 default_radio0; do
    if uci -q get wireless.$iface >/dev/null 2>&1; then
        uci set wireless.$iface.ssid='openperf'
        uci set wireless.$iface.encryption='none'
        break
    fi
done
# Set HaHalow test SSID if present
for iface in default_radio1; do
    if uci -q get wireless.$iface >/dev/null 2>&1; then
        uci set wireless.$iface.ssid='openperf-halow'
        uci set wireless.$iface.encryption='sae'
        uci set wireless.$iface.key='openperf-test'
        break
    fi
done
uci commit wireless
# Enable and start service
/etc/init.d/openperf-server enable

# NOTE: Python files (server.py, protocol.py, radio_hal.py, radio_hal_iw.py)
# must be pushed to /root/openperf/ via install-openperf.sh or SCP.
# The service will fail to start until files are present, but procd will respawn.