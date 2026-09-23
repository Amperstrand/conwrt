"""openperf-server — Open WiFi performance testing server.

Deploys the openperf JSON-RPC server on any OpenWrt router.
Clients connect and request radio performance tests.
The server applies requested configs, runs iperf3, then restores defaults.

Works with both HaHalow (Morse Micro) and standard WiFi (2.4/5 GHz).
"""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    mgmt_ssid = str(params.get("mgmt_ssid", "openperf"))
    port = int(params.get("port", 7777))
    return {"mgmt_ssid": mgmt_ssid, "port": port}


def _build_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    ssid = r["mgmt_ssid"]
    port = r["port"]
    return [
        Comment(text="--- openperf-server: Open WiFi Performance Testing ---"),
        BlankLine(),

        Comment(text="Create directories"),
        ShellCommand(command="mkdir -p /root/openperf/init.d"),

        Comment(text="Write procd init script"),
        ShellCommand(command=f"""cat > /etc/init.d/openperf-server << 'OPENPERF_EOF'
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
STOP=1

start_service() {{
    procd_open_instance
    procd_set_param respawn 3600 5 0
    procd_set_param command /usr/bin/python3 /root/openperf/server.py
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param env PORT={port}
    procd_close_instance
}}
OPENPERF_EOF
chmod +x /etc/init.d/openperf-server"""),

        Comment(text="Set management SSID on first 2.4 GHz AP interface"),
        ShellCommand(command=f"""for iface in phy0-ap0 default_radio0; do
    if uci -q get wireless.$iface >/dev/null 2>&1; then
        uci set wireless.$iface.ssid='{ssid}'
        uci set wireless.$iface.encryption='none'
        break
    fi
done"""),

        Comment(text="Set HaHalow test SSID if present"),
        ShellCommand(command=f"""for iface in default_radio1; do
    if uci -q get wireless.$iface >/dev/null 2>&1; then
        uci set wireless.$iface.ssid='{ssid}-halow'
        uci set wireless.$iface.encryption='sae'
        uci set wireless.$iface.key='openperf-test'
        break
    fi
done"""),

        UciCommit(config="wireless"),

        Comment(text="Enable and start service"),
        ServiceAction(name="openperf-server", action="enable"),
        BlankLine(),
        Comment(text="NOTE: Python files (server.py, protocol.py, radio_hal.py, radio_hal_iw.py)"),
        Comment(text="must be pushed to /root/openperf/ via install-openperf.sh or SCP."),
        Comment(text="The service will fail to start until files are present, but procd will respawn."),
    ]


register(UseCase(
    name="openperf_server",
    description="Open WiFi performance testing server (JSON-RPC on port 7777, supports HaHalow + 2.4/5 GHz)",
    packages=[
        "python3",
        "iperf3",
    ],
    packages_remove=[],
    params={
        "mgmt_ssid": ParamDef(
            type=str, required=False, default="openperf",
            description="Management SSID broadcast on 2.4 GHz for client discovery",
        ),
        "port": ParamDef(
            type=int, required=False, default=7777,
            description="TCP port for JSON-RPC server",
        ),
    },
    build_configure_ops=_build_ops,
    requires_capabilities=["wifi"],
))
