"""travelmate — travel router auto-connect for hotel/airport WiFi."""
from __future__ import annotations

import textwrap
from typing import Any

from profile.ops import Op, ServiceAction, ShellCommand, UciCommit, UciSet

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    radio = params.get("radio", "radio0")
    timeout = params.get("timeout", 60)
    retry = params.get("retry", 5)
    captive = params.get("captive", True)
    captive_flag = "1" if captive else "0"
    return {
        "radio": radio,
        "timeout": timeout,
        "retry": retry,
        "captive": captive,
        "captive_flag": captive_flag,
    }


def _build_travelmate_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    return [
        UciSet(config="travelmate", section="global", values={
            "trm_enabled": "1",
            "trm_automatic": "1",
            "trm_captive": r["captive_flag"],
            "trm_timeout": str(r["timeout"]),
            "trm_retry": str(r["retry"]),
            "trm_radio": r["radio"],
        }),
        UciCommit(config="travelmate"),
        ServiceAction(name="travelmate", action="enable"),
        ShellCommand(command="/etc/init.d/travelmate restart 2>/dev/null || true"),
    ]


def _build_travelmate(params: dict[str, Any]) -> str:
    r = _resolve_params(params)

    return textwrap.dedent(f"""\
        # --- Travelmate travel router ---
        uci set travelmate.global.trm_enabled='1'
        uci set travelmate.global.trm_automatic='1'
        uci set travelmate.global.trm_captive='{r["captive_flag"]}'
        uci set travelmate.global.trm_timeout='{r["timeout"]}'
        uci set travelmate.global.trm_retry='{r["retry"]}'
        uci set travelmate.global.trm_radio='{r["radio"]}'
        uci commit travelmate
        /etc/init.d/travelmate enable
        /etc/init.d/travelmate restart 2>/dev/null || true
        echo "Travelmate configured: auto-connect on {r["radio"]}"
    """)


register(UseCase(
    name="travelmate",
    description="Travel router auto-connect for captive portal WiFi (hotels, airports)",
    packages=[
        "travelmate",
        "luci-app-travelmate",
        "ca-bundle",
        "ca-certificates",
    ],
    packages_remove=[],
    params={
        "radio": ParamDef(type=str, default="radio0",
                          description="WiFi radio for upstream scanning"),
        "timeout": ParamDef(type=int, default=60,
                            description="Overall retry timeout in seconds"),
        "retry": ParamDef(type=int, default=5,
                          description="Retry count to find a suitable uplink"),
        "captive": ParamDef(type=bool, default=True,
                            description="Enable captive portal detection"),
    },
    build_configure=_build_travelmate,
    build_configure_ops=_build_travelmate_ops,
    test_status="experimental",
    tested_notes="wiki-based",
    requires_capabilities=["wifi"],
))
