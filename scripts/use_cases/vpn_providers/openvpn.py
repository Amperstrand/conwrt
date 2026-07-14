"""vpn-openvpn — Generic OpenVPN client for providers without WireGuard API.

Supports any provider that offers OpenVPN config files (ExpressVPN,
ProtonVPN via OpenVPN, CyberGhost, TunnelBear, PureVPN, etc.). The user
provides an inline .ovpn config and optional credentials.
"""
from __future__ import annotations

from typing import Any

from profile.ops import (
    BlankLine,
    Comment,
    Op,
    ServiceAction,
    ShellCommand,
    UciCommit,
    UciSet,
    render_shell,
)
from profile.uci_helpers import uci_cleanup_sections

from .. import ParamDef, UseCase, register
from .base import build_firewall_ops


def _build_openvpn_ops(params: dict[str, Any]) -> list[Op]:
    ovpn_config = params["ovpn_config"]
    username = params.get("username", "")
    password = params.get("password", "")
    proto = params.get("proto", "udp")
    kill_switch = params.get("kill_switch", True)

    # Write the OpenVPN config and credentials to the device
    cred_lines = ""
    if username and password:
        cred_lines = f"""
# Write credentials file
cat > /etc/openvpn/vpn-auth.txt << 'AUTHEOF'
{username}
{password}
AUTHEOF
chmod 600 /etc/openvpn/vpn-auth.txt"""

    setup_script = f"""# Write OpenVPN config
mkdir -p /etc/openvpn
cat > /etc/openvpn/vpn-client.ovpn << 'OVPNEOF'
{ovpn_config}
OVPNEOF
{cred_lines}
"""

    ops: list[Op] = [
        Comment(text=f"--- Generic OpenVPN VPN ({proto.upper()}) ---"),
        ShellCommand(command=setup_script),
        BlankLine(),
        Comment(text="--- Configure OpenVPN via UCI ---"),
        uci_cleanup_sections("openvpn", "config=openvpn"),
        ShellCommand(command="uci set openvpn.vpn_client=config-openvpn"),
        UciSet(config="openvpn", section="vpn_client", values={
            "config": "/etc/openvpn/vpn-client.ovpn",
            "enabled": "1",
        }),
    ]
    if username and password:
        ops.append(UciSet(config="openvpn", section="vpn_client", values={
            "auth_user_pass": "/etc/openvpn/vpn-auth.txt",
        }))

    ops.extend([
        UciCommit(config="openvpn"),
        BlankLine(),
        Comment(text="--- OpenVPN network interface ---"),
        uci_cleanup_sections("network", "proto='openvpn'"),
        ShellCommand(command="uci set network.vpn_if=interface"),
        UciSet(config="network", section="vpn_if", values={
            "proto": "openvpn",
            "config": "/etc/openvpn/vpn-client.ovpn",
        }),
        UciCommit(config="network"),
    ])

    # Firewall uses the OpenVPN interface (tun0 by default)
    ops.extend(build_firewall_ops(iface="tun0", kill_switch=kill_switch))

    ops.extend([
        UciCommit(config="firewall"),
        ServiceAction(name="openvpn", action="restart"),
        ServiceAction(name="network", action="restart"),
    ])

    return ops


register(UseCase(
    name="vpn-openvpn",
    description="Generic OpenVPN VPN client — for ExpressVPN, ProtonVPN, CyberGhost, "
                "TunnelBear, and any provider offering .ovpn config files",
    packages=["openvpn-openssl", "luci-app-openvpn"],
    packages_remove=[],
    params={
        "ovpn_config": ParamDef(type=str, required=True, allow_empty=False,
                                description="Inline .ovpn configuration text from your provider"),
        "username": ParamDef(type=str, default="",
                            description="VPN username (if required by config)"),
        "password": ParamDef(type=str, default="",
                            description="VPN password (if required by config)"),
        "proto": ParamDef(type=str, default="udp", choices=("udp", "tcp"),
                          description="Transport protocol"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block all non-VPN traffic if tunnel drops"),
    },
    build_configure=lambda p: render_shell(_build_openvpn_ops(p)),
    build_configure_ops=_build_openvpn_ops,
    test_status="untested",
    tested_notes="",
))
