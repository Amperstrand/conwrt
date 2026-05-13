"""travelmate — travel router auto-connect for hotel/airport WiFi."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register


def _build_travelmate(params: dict[str, Any]) -> str:
    radio = params.get("radio", "radio0")
    timeout = params.get("timeout", 60)
    retry = params.get("retry", 5)
    captive = params.get("captive", True)

    captive_flag = "1" if captive else "0"

    return textwrap.dedent(f"""\
        # --- Travelmate travel router ---
        uci set travelmate.global.trm_enabled='1'
        uci set travelmate.global.trm_automatic='1'
        uci set travelmate.global.trm_captive='{captive_flag}'
        uci set travelmate.global.trm_timeout='{timeout}'
        uci set travelmate.global.trm_retry='{retry}'
        uci set travelmate.global.trm_radio='{radio}'
        uci commit travelmate
        /etc/init.d/travelmate enable
        /etc/init.d/travelmate restart 2>/dev/null || true
        echo "Travelmate configured: auto-connect on {radio}"
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
    build_defaults=_build_travelmate,
    requires_capabilities=["wifi"],
    requires_post_flash=False,
))
