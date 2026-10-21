"""openperf-client — WiFi performance test client (STA side).

Discovers an openperf AP via SSID, connects, and runs the test matrix.
Optionally tests WAN throughput (AP → internet uplink).
Installs the autonomous loop that runs on boot.
"""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    mgmt_ssid = str(params.get("mgmt_ssid", "openperf"))
    wan_test = str(params.get("wan_test", "1"))
    return {"mgmt_ssid": mgmt_ssid, "wan_test": wan_test}


def _build_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    ssid = r["mgmt_ssid"]
    return [
        Comment(text="--- openperf-client: WiFi Performance Test Client ---"),
        BlankLine(),

        Comment(text="Create directories"),
        ShellCommand(command="mkdir -p /root/openperf/init.d"),

        Comment(text="Write STA autostart procd service"),
        ShellCommand(command="""cat > /etc/init.d/openperf-autostart << 'OPENPERF_EOF'
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
chmod +x /etc/init.d/openperf-autostart"""),

        Comment(text="Configure 2.4 GHz STA to scan for openperf AP"),
        ShellCommand(command=f"""for iface in sta_radio0 phy0_sta; do
    if uci -q get wireless.$iface >/dev/null 2>&1; then
        uci set wireless.$iface.ssid='{ssid}'
        uci set wireless.$iface.encryption='none'
        uci set wireless.$iface.network='wan'
        break
    fi
done"""),

        Comment(text="Configure HaHalow STA if present"),
        ShellCommand(command=f"""for iface in default_radio1; do
    if uci -q get wireless.$iface >/dev/null 2>&1; then
        uci set wireless.$iface.ssid='{ssid}-halow'
        uci set wireless.$iface.encryption='sae'
        uci set wireless.$iface.key='openperf-test'
        break
    fi
done"""),

        UciCommit(config="wireless"),

        Comment(text="Enable autostart service"),
        ServiceAction(name="openperf-autostart", action="enable"),
        BlankLine(),
        Comment(text="NOTE: Python files must be pushed to /root/openperf/ via install-openperf.sh."),
        Comment(text="The autostart loop will wait for AP discovery via default gateway."),
    ]


register(UseCase(
    name="openperf_client",
    description="WiFi performance test client — discovers openperf AP via SSID, runs test matrix on boot",
    packages=[
        "python3",
        "iperf3",
    ],
    packages_remove=[],
    params={
        "mgmt_ssid": ParamDef(
            type=str, required=False, default="openperf",
            description="SSID to scan for (must match AP's openperf_server mgmt_ssid)",
        ),
        "wan_test": ParamDef(
            type=str, required=False, default="1",
            description="Also test WAN throughput (1=yes, 0=no)",
        ),
    },
    build_configure_ops=_build_ops,
    requires_capabilities=["wifi"],
))
