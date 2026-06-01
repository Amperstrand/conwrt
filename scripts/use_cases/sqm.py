"""sqm — Smart Queue Management (CAKE/fq_codel) to eliminate bufferbloat."""
from __future__ import annotations

import textwrap
from typing import Any

from shell_safe import int_range, interface_name, sh_quote, uci_name

from . import ParamDef, UseCase, register


def _build_sqm(params: dict[str, Any]) -> str:
    download_kbps = params.get("download_kbps", 10000)
    upload_kbps = params.get("upload_kbps", 5000)
    interface = uci_name(interface_name(params.get("interface", "wan"), "SQM interface"), "SQM interface")
    qdisc = str(params.get("qdisc", "cake"))
    script = str(params.get("script", "piece_of_cake.qos"))
    link_layer = str(params.get("link_layer", "none"))
    overhead = int_range(params.get("overhead", 0), "overhead", 0, 512)
    download_kbps = int_range(download_kbps, "download_kbps", 1)
    upload_kbps = int_range(upload_kbps, "upload_kbps", 1)

    return textwrap.dedent(f"""\
        # --- SQM Smart Queue Management ---
        uci -q delete sqm >/dev/null 2>&1 || true

        uci set sqm.{interface}=queue
        uci set sqm.{interface}.interface={sh_quote(interface)}
        uci set sqm.{interface}.enabled='1'
        uci set sqm.{interface}.script={sh_quote(script)}
        uci set sqm.{interface}.qdisc={sh_quote(qdisc)}
        uci set sqm.{interface}.linklayer={sh_quote(link_layer)}
        uci set sqm.{interface}.overhead={sh_quote(overhead)}
        uci set sqm.{interface}.download={sh_quote(download_kbps)}
        uci set sqm.{interface}.upload={sh_quote(upload_kbps)}
        uci set sqm.{interface}.linklayer_adaptation_mechanism='default'
        uci set sqm.{interface}.debug_logging='0'
        uci set sqm.{interface}.verbosity='5'
        uci commit sqm

        /etc/init.d/sqm enable
        /etc/init.d/sqm restart 2>/dev/null || true
        echo "SQM configured: {download_kbps}/{upload_kbps} kbit/s ({qdisc})"
    """)


register(UseCase(
    name="sqm",
    description="Smart Queue Management with CAKE to eliminate bufferbloat",
    packages=[
        "sqm-scripts",
        "luci-app-sqm",
    ],
    packages_remove=[],
    params={
        "download_kbps": ParamDef(type=int, required=True,
                                  description="Download speed in Kbit/s (set to 85-95% of actual)"),
        "upload_kbps": ParamDef(type=int, required=True,
                                description="Upload speed in Kbit/s (set to 85-95% of actual)"),
        "interface": ParamDef(type=str, default="wan",
                              description="WAN interface to shape"),
        "qdisc": ParamDef(type=str, default="cake",
                          description="Queue discipline: cake or fq_codel"),
        "script": ParamDef(type=str, default="piece_of_cake.qos",
                           description="QoS script (piece_of_cake.qos, layer_cake.qos)"),
        "link_layer": ParamDef(type=str, default="none",
                              description="Link layer adaptation: none, ethernet, atm"),
        "overhead": ParamDef(type=int, default=0,
                             description="Per-packet overhead in bytes"),
    },
    build_configure=_build_sqm,
    test_status="experimental",
    tested_notes="uci from OpenWrt wiki",
    requires_capabilities=[],
))
