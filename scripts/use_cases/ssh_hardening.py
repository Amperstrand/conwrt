"""ssh-hardening — Optional Dropbear SSH hardening beyond core key/password setup."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register


def _build_ssh_hardening(params: dict[str, Any]) -> str:
    password_auth = "off" if params.get("disable_password_auth", True) else "on"
    root_password_auth = "off" if params.get("disable_password_auth", True) else "on"
    idle_timeout = params.get("idle_timeout", 300)
    max_auth_tries = params.get("max_auth_tries", 3)
    port = params.get("port", 22)
    gateway_ports = "no" if params.get("disable_gateway_ports", True) else "yes"

    return textwrap.dedent(f"""\
        # --- SSH hardening ---
        uci set dropbear.@dropbear[0].PasswordAuth='{password_auth}'
        uci set dropbear.@dropbear[0].RootPasswordAuth='{root_password_auth}'
        uci set dropbear.@dropbear[0].Port='{port}'
        uci set dropbear.@dropbear[0].IdleTimeout='{idle_timeout}'
        uci set dropbear.@dropbear[0].MaxAuthTries='{max_auth_tries}'
        uci set dropbear.@dropbear[0].GatewayPorts='{gateway_ports}'
        uci commit dropbear
        /etc/init.d/dropbear restart 2>/dev/null || true
        echo "SSH hardened: password_auth={password_auth} idle={idle_timeout}s max_tries={max_auth_tries} port={port}"
    """)


register(UseCase(
    name="ssh-hardening",
    description="Optional Dropbear hardening: disable password auth, idle timeout, rate limit",
    packages=[],
    packages_remove=[],
    params={
        "disable_password_auth": ParamDef(type=bool, default=True,
            description="Disable password authentication (key-only)"),
        "idle_timeout": ParamDef(type=int, default=300,
            description="Idle disconnect timeout in seconds (0 = no timeout)"),
        "max_auth_tries": ParamDef(type=int, default=3,
            description="Max authentication attempts per connection"),
        "port": ParamDef(type=int, default=22,
            description="SSH listen port"),
        "disable_gateway_ports": ParamDef(type=bool, default=True,
            description="Disable remote port forwarding (GatewayPorts)"),
    },
    build_configure=_build_ssh_hardening,
    test_status="untested",
    tested_notes="",
    requires_capabilities=[],
))
