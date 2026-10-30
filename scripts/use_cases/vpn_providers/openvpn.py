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
)
from profile.uci_helpers import uci_cleanup_sections

from .. import ParamDef, UseCase, register
from .base import build_firewall_ops, build_verify_ops


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    ovpn_config = str(params["ovpn_config"])
    username = str(params.get("username", ""))
    password = str(params.get("password", ""))
    proto = str(params.get("proto", "udp"))
    kill_switch = bool(params.get("kill_switch", True))

    # Heredoc-terminator injection (pbr-class, found by this port): the
    # inline config lands inside a single-quoted heredoc — a value
    # containing the delimiter LINE escapes the heredoc and runs as
    # live script. Gate the delimiter; credentials ride UCI
    # username/password (single-line gate — UCI stores one line per
    # option and the init script regenerates its own auth file);
    # plan.rs VpnOpenvpnProfile::validate mirrors these gates.
    if not ovpn_config:
        raise ValueError("ovpn_config is required (inline .ovpn text)")
    if any(line.strip() == "OVPNEOF" for line in ovpn_config.splitlines()):
        raise ValueError("ovpn_config must not contain a line 'OVPNEOF' (heredoc terminator)")
    for field, value in (("username", username), ("password", password)):
        if "\n" in value or "\r" in value:
            raise ValueError(f"{field} must be a single line")
    if proto not in ("udp", "tcp"):
        raise ValueError(f"proto must be udp or tcp, got {proto!r}")
    return {
        "ovpn_config": ovpn_config,
        "username": username,
        "password": password,
        "proto": proto,
        "kill_switch": kill_switch,
    }


def _build_openvpn_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    ovpn_config = r["ovpn_config"]
    username = r["username"]
    password = r["password"]
    proto = r["proto"]
    kill_switch = r["kill_switch"]

    setup_script = f"""# Write OpenVPN config
mkdir -p /etc/openvpn
cat > /etc/openvpn/vpn-client.ovpn << 'OVPNEOF'
{ovpn_config}
OVPNEOF
"""

    ops: list[Op] = [
        Comment(text=f"--- Generic OpenVPN VPN ({proto.upper()}) ---"),
        ShellCommand(command=setup_script),
        BlankLine(),
        Comment(text="--- Configure OpenVPN via UCI ---"),
        # the 1.x pattern 'config=openvpn' matched NOTHING (uci show
        # renders the old declaration as '=config-openvpn', hyphen not
        # equals; values are always quoted) — the cleanup was dead
        # code, so stale options (e.g. credentials from a previous
        # cred'd apply) survived re-applies. Match the real
        # declarations; the delete+recreate then clears stale options
        # (Codex #603 P2 round 2).
        uci_cleanup_sections("openvpn", "vpn_client=config-openvpn"),
        uci_cleanup_sections("openvpn", "vpn_client=openvpn"),
        # section type must be `openvpn` (Codex #603 P1): the OpenWrt
        # init script starts instances via
        # `config_foreach start_uci_instance 'openvpn'` — the 1.x type
        # `config-openvpn` was never started at all
        ShellCommand(command="uci set openvpn.vpn_client=openvpn"),
        UciSet(config="openvpn", section="vpn_client", values={
            "config": "/etc/openvpn/vpn-client.ovpn",
            "enabled": "1",
        }),
    ]
    if username and password:
        # UCI credential overrides (Codex #603 P1): with an external
        # `config` file the init script bypasses UCI option generation
        # and its credential override reads `username`/`password` —
        # the 1.x `auth_user_pass` file path was silently ignored
        ops.append(UciSet(config="openvpn", section="vpn_client", values={
            "username": username,
            "password": password,
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

    # Firewall zone attaches to the logical UCI interface (network.vpn_if),
    # not the raw tun0 device — zone.network references network sections
    ops.extend(build_firewall_ops(iface="vpn_if", kill_switch=kill_switch))

    ops.extend([
        UciCommit(config="firewall"),
        ServiceAction(name="openvpn", action="restart"),
        ServiceAction(name="network", action="restart"),
    ])

    # Fail-open verify (fixed with this port): every WireGuard sibling
    # pairs its kill switch with an auto-remove loop — this preset
    # forgot it, so a bad .ovpn config + kill_switch bricked WAN until
    # manual fix. base.py's ready-made openvpn verifier (45s tun check,
    # kill-switch auto-remove on failure) closes the same gap.
    ops.extend(build_verify_ops(iface="tun0", kill_switch=kill_switch, kind="openvpn"))

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
    build_configure_ops=_build_openvpn_ops,
    test_status="untested",
    tested_notes="",
))
