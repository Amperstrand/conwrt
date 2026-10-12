"""rescue-watchdog — self-healing reboot for bench/lab devices.

A wedged router on a bench should recover itself instead of waiting for a
human power cycle. This watchdog pings a management target (typically the
bench host on the LAN) once a minute and force-reboots the device after
three consecutive failures — with a boot grace period so a slow firstboot
never triggers it.

Born from 2026-10-08: the x1860 wedged three times (kernel/driver level,
networking dead, wifi still beaconing) and every recovery needed hands on
the power plug. With this baked in, the box returns to its baked state
unattended within ~15 minutes.
"""
from __future__ import annotations

from typing import Any

from profile.ops import Comment, Op, ShellCommand

from . import ParamDef, UseCase, register

WATCHDOG_INIT = """cat > /etc/init.d/rescue-watchdog << 'WD_EOF'
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
TARGET="${WATCHDOG_TARGET:-__TARGET__}"
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
"""


def _build_ops(params: dict[str, Any]) -> str:
    from profile.ops import render_shell

    target = params.get("target", "192.168.1.254")
    script = WATCHDOG_INIT.replace("__TARGET__", target)
    ops: list[Op] = [
        Comment(text=f"--- rescue-watchdog (reboot if {target} unreachable 3x1min) ---"),
        ShellCommand(command=script),
    ]
    return render_shell(ops)


register(UseCase(
    name="rescue-watchdog",
    description="Self-healing reboot when the management target goes unreachable (bench images)",
    packages=[],
    packages_remove=[],
    params={
        "target": ParamDef(type=str, default="192.168.1.254",
                           description="Management IP pinged once a minute (bench host LAN address)"),
    },
    build_configure=_build_ops,
    test_status="untested",
    tested_notes="Design born from the 2026-10-08 wedges; verify the grace period and "
                 "reboot behavior on hardware before trusting it unattended.",
))
