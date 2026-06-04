"""sqm — Smart Queue Management (CAKE/fq_codel) to eliminate bufferbloat."""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell
from shell_safe import int_range, interface_name, uci_name

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    download_kbps = params.get("download_kbps", 10000)
    upload_kbps = params.get("upload_kbps", 5000)
    interface = uci_name(interface_name(params.get("interface", "wan"), "SQM interface"), "SQM interface")
    qdisc = str(params.get("qdisc", "cake"))
    script = str(params.get("script", "piece_of_cake.qos"))
    link_layer = str(params.get("link_layer", "none"))
    overhead = int_range(params.get("overhead", 0), "overhead", 0, 512)
    download_kbps = int_range(download_kbps, "download_kbps", 1)
    upload_kbps = int_range(upload_kbps, "upload_kbps", 1)
    return {
        "download_kbps": download_kbps,
        "upload_kbps": upload_kbps,
        "interface": interface,
        "qdisc": qdisc,
        "script": script,
        "link_layer": link_layer,
        "overhead": overhead,
    }


def _build_sqm_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    iface = r["interface"]
    return [
        Comment(text="--- SQM Smart Queue Management ---"),
        ShellCommand(command="uci -q delete sqm >/dev/null 2>&1 || true"),
        BlankLine(),
        ShellCommand(command=f"uci set sqm.{iface}=queue"),
        UciSet(config="sqm", section=iface, values={
            "interface": iface,
            "enabled": "1",
            "script": r["script"],
            "qdisc": r["qdisc"],
            "linklayer": r["link_layer"],
            "overhead": str(r["overhead"]),
            "download": str(r["download_kbps"]),
            "upload": str(r["upload_kbps"]),
            "linklayer_adaptation_mechanism": "default",
            "debug_logging": "0",
            "verbosity": "5",
        }),
        UciCommit(config="sqm"),
        BlankLine(),
        ServiceAction(name="sqm", action="enable"),
        ServiceAction(name="sqm", action="restart"),
        ShellCommand(command=f'echo "SQM configured: {r["download_kbps"]}/{r["upload_kbps"]} kbit/s ({r["qdisc"]})"'),
    ]


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
    build_configure=lambda p: render_shell(_build_sqm_ops(p)),
    build_configure_ops=_build_sqm_ops,
    test_status="experimental",
    tested_notes="uci from OpenWrt wiki",
    requires_capabilities=[],
))
