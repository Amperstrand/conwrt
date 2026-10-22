# golden: conwrt 1.x output of scripts/use_cases/rescue_watchdog.py build_configure (target=192.168.105.10) — regenerate with the command in tests/use_case_goldens.rs
# --- rescue-watchdog (reboot if 192.168.105.10 unreachable 3x1min) ---
cat > /etc/init.d/rescue-watchdog << 'WD_EOF'
#!/bin/sh /etc/rc.common

START=99
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /bin/sh /usr/bin/rescue-watchdog-loop
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
WD_EOF
chmod +x /etc/init.d/rescue-watchdog

/usr/bin/rescue-watchdog-loop << 'WDL_EOF'
#!/bin/sh
TARGET="${WATCHDOG_TARGET:-192.168.105.10}"
GRACE=600
FAILS=0
while :; do
    UPTIME=$(cut -d. -f1 /proc/uptime)
    if [ "$UPTIME" -lt "$GRACE" ]; then
        FAILS=0
    elif ping -c1 -W3 "$TARGET" >/dev/null 2>&1; then
        FAILS=0
    else
        FAILS=$((FAILS+1))
        logger -t rescue-watchdog "target $TARGET unreachable ($FAILS/3)"
        if [ "$FAILS" -ge 3 ]; then
            logger -t rescue-watchdog "networking wedged - rebooting"
            sync
            reboot
        fi
    fi
    sleep 60
done
WDL_EOF
chmod +x /usr/bin/rescue-watchdog-loop

/etc/init.d/rescue-watchdog enable
/etc/init.d/rescue-watchdog restart

