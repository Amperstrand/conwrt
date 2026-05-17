"""OpenTollGate — Bitcoin Lightning payment gateway for selling internet access."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register


def _build_tollgate(params: dict[str, Any]) -> str:
    return textwrap.dedent("""\
        # --- OpenTollGate post-install ---
        # The tollgate-wrt binary and config are deployed post-flash via SSH
        # by conwrt (cross-compiled from source like zycast).
        # This script ensures nodogsplash and the init service are set up.

        # Enable and configure nodogsplash for captive portal
        uci set nodogsplash.@nodogsplash[0].enabled='1' 2>/dev/null || true
        uci commit nodogsplash 2>/dev/null || true
        /etc/init.d/nodogsplash enable 2>/dev/null || true
        /etc/init.d/nodogsplash restart 2>/dev/null || true

        # TollGate service will be started by post-flash SSH deploy
        echo "OpenTollGate: nodogsplash configured, awaiting binary deploy"
    """)


register(UseCase(
    name="tollgate",
    description="OpenTollGate Bitcoin/Lightning payment gateway (post-flash deploy)",
    packages=[
        "nodogsplash",
        "libustream-wolfssl",
        "ca-bundle",
        "ca-certificates",
    ],
    requires_post_flash=True,
    params={
        "mint_url": ParamDef(type=str, default="",
                             description="Cashu mint URL (e.g. https://mint.minibits.cash/Bitcoin)"),
        "lightning_address": ParamDef(type=str, default="",
                                      description="Lightning address for payouts"),
        "price_per_minute": ParamDef(type=int, default=1,
                                     description="Price in sats per minute"),
    },
    build_defaults=_build_tollgate,
))
