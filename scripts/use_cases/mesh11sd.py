"""Mesh11sd — automated 802.11s mesh networking via mesh11sd daemon."""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ShellCommand, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    return {
        "mesh_id": params["mesh_id"],
        "ssid": params.get("ssid", "MeshNet"),
        "encryption": params.get("encryption", "1"),
        "key": params.get("key", ""),
        "auto_config": params.get("auto_config", "0"),
    }


def _build_mesh11sd_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    values = {
        "auto_mesh_id": r["mesh_id"],
        "mesh_gate_base_ssid": r["ssid"],
        "mesh_gate_encryption": r["encryption"],
    }
    if r["key"]:
        values["mesh_gate_key"] = r["key"]
    values["auto_config"] = r["auto_config"]
    return [
        Comment(text="--- Mesh11sd 802.11s mesh ---"),
        ShellCommand(command="opkg remove wpad-basic-mbedtls wpad-basic-wolfssl wpad-basic-openssl wpad-basic 2>/dev/null || true"),
        ShellCommand(command="opkg install wpad-mbedtls 2>/dev/null || true"),
        ShellCommand(command="service wpad restart 2>/dev/null || true"),
        BlankLine(),
        UciSet(config="mesh11sd", section="setup", values=values),
        UciCommit(config="mesh11sd"),
        ShellCommand(command="service mesh11sd restart 2>/dev/null || true"),
        ShellCommand(command=f'echo "Mesh11sd configured: mesh_id={r["mesh_id"]} ssid={r["ssid"]}"'),
    ]


register(UseCase(
    name="mesh11sd",
    description="802.11s mesh networking with auto-config via mesh11sd",
    packages=[
        "mesh11sd",
        "ip-full",
        "kmod-nft-bridge",
        "vxlan",
    ],
    packages_remove=[
        "wpad-basic-mbedtls",
    ],
    params={
        "mesh_id": ParamDef(type=str, required=True,
                            description="Unique mesh network ID (must match on all nodes)"),
        "ssid": ParamDef(type=str, default="MeshNet",
                         description="Base SSID for the mesh gate AP"),
        "encryption": ParamDef(type=str, default="1",
                               description="0=none, 1=wpa3, 2=wpa2, 3=mixed"),
        "key": ParamDef(type=str, default="",
                        description="WiFi key for the mesh gate AP"),
        "auto_config": ParamDef(type=str, default="0",
                                description="0=disabled, 1=auto, 2=auto+commit"),
    },
    build_configure=lambda p: render_shell(_build_mesh11sd_ops(p)),
    build_configure_ops=_build_mesh11sd_ops,
    test_status="untested",
    tested_notes="",
    requires_capabilities=["wifi"],
))
