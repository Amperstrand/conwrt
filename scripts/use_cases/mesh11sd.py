"""Mesh11sd — automated 802.11s mesh networking via mesh11sd daemon."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register


def _build_mesh11sd(params: dict[str, Any]) -> str:
    mesh_id = params["mesh_id"]
    ssid = params.get("ssid", "MeshNet")
    encryption = params.get("encryption", "1")
    key = params.get("key", "")
    auto_config = params.get("auto_config", "0")

    lines = [
        "# --- Mesh11sd 802.11s mesh ---",
        "opkg remove wpad-basic-mbedtls wpad-basic-wolfssl wpad-basic-openssl wpad-basic 2>/dev/null || true",
        "opkg install wpad-mbedtls 2>/dev/null || true",
        "service wpad restart 2>/dev/null || true",
        "",
        f"uci set mesh11sd.setup.auto_mesh_id='{mesh_id}'",
        f"uci set mesh11sd.setup.mesh_gate_base_ssid='{ssid}'",
        f"uci set mesh11sd.setup.mesh_gate_encryption='{encryption}'",
    ]
    if key:
        lines.append(f"uci set mesh11sd.setup.mesh_gate_key='{key}'")
    lines.append(f"uci set mesh11sd.setup.auto_config='{auto_config}'")
    lines.extend([
        "uci commit mesh11sd",
        "service mesh11sd restart 2>/dev/null || true",
        f'echo "Mesh11sd configured: mesh_id={mesh_id} ssid={ssid}"',
    ])
    return "\n".join(lines) + "\n"


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
    build_defaults=_build_mesh11sd,
))
