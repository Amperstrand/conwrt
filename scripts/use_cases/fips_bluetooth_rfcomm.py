"""fips-bluetooth-rfcomm — FIPS mesh networking over Bluetooth RFCOMM.

Deploys FIPS (Friend Identity Protocol Suite) mesh with RFCOMM transport
and TUN interface for IP-over-mesh connectivity. Star topology: one server
accepts connections, clients connect to it.

Requirements:
  - Device must have 'bluetooth' capability
  - FIPS binary must be deployed separately (SCP from host)
  - bt-agent handles pairing with PIN (default: 0000)
  - Server must start before clients (RFCOMM client connects once at startup)
"""
from __future__ import annotations

from typing import Any

from . import ParamDef, UseCase, register


def _echo_write(path: str, content: str) -> list[str]:
    """Generate echo commands to write multi-line content to a file.

    Uses echo with single-quote appending for BusyBox compatibility
    (no base64, no openssl needed). Empty lines are preserved.
    """
    file_lines = content.split("\n")
    if file_lines and file_lines[-1] == "":
        file_lines = file_lines[:-1]
    cmds: list[str] = []
    for i, line in enumerate(file_lines):
        op = ">" if i == 0 else ">>"
        escaped = line.replace("'", "'\\''")
        cmds.append(f"echo '{escaped}' {op} {path}")
    return cmds


def _build_fips_rfcomm(params: dict[str, Any]) -> str:
    role = params.get("role", "client")
    channel = params.get("channel", 1)
    tun_enabled = params.get("tun_enabled", True)
    tun_dns = params.get("tun_dns", True)
    tun_gateway = params.get("tun_gateway", True)
    bt_pin = params.get("bt_pin", "0000")
    peers = params.get("peers", [])

    # --- Build FIPS YAML config (matches live device format) ---
    yaml_parts: list[str] = []

    yaml_parts.append("node:")
    yaml_parts.append("  identity:")
    yaml_parts.append("    persistent: true")
    yaml_parts.append("")

    yaml_parts.append("tun:")
    yaml_parts.append(f"  enabled: {'true' if tun_enabled else 'false'}")
    yaml_parts.append("")

    if tun_dns:
        yaml_parts.append("dns:")
        yaml_parts.append("  enabled: true")
        yaml_parts.append("")

    # RFCOMM transport config
    yaml_parts.append("transports:")
    yaml_parts.append("  rfcomm:")
    yaml_parts.append(f'    mode: "{role}"')
    yaml_parts.append(f"    channel: {channel}")
    yaml_parts.append("    mtu: 1000")
    if role == "server":
        yaml_parts.append("    accept_connections: true")
    else:
        yaml_parts.append("    auto_connect: true")

    # RFCOMM peer MACs (transport-level)
    if peers:
        yaml_parts.append("    peers:")
        for peer in peers:
            bt_mac = peer.get("bt_mac", "")
            yaml_parts.append(f'      - mac: "{bt_mac}"')
    yaml_parts.append("")

    # Mesh peers (Noise protocol level)
    if peers:
        yaml_parts.append("peers:")
        for peer in peers:
            npub = peer.get("npub", "")
            bt_mac = peer.get("bt_mac", "")
            alias = peer.get("alias", "")
            peer_lines = [
                f'  - npub: "{npub}"',
            ]
            if alias:
                peer_lines.append(f'    alias: "{alias}"')
            peer_lines.extend([
                "    addresses:",
                "      - transport: serial",
                f'        addr: "{bt_mac}"',
                "    connect_policy: auto_connect",
            ])
            yaml_parts.extend(peer_lines)
    else:
        yaml_parts.append("peers: []")
    yaml_parts.append("")

    # Gateway config (server mode or when tun_gateway is true)
    if tun_gateway:
        yaml_parts.append("gateway:")
        yaml_parts.append("  enabled: true")
        yaml_parts.append('  pool: "fd01::/112"')
        yaml_parts.append('  lan_interface: "br-lan"')
        yaml_parts.append("  dns:")
        yaml_parts.append('    listen: "[::1]:5353"')
        yaml_parts.append('    upstream: "[::1]:5354"')
        yaml_parts.append("    ttl: 60")
        yaml_parts.append("")

    # Server mode: peers_allow
    if role == "server":
        yaml_parts.append("peers_allow: /etc/fips/peers.allow")
        yaml_parts.append("")

    yaml_content = "\n".join(yaml_parts)

    # --- Build peers.allow content (server only) ---
    peers_allow_content = ""
    if role == "server":
        peers_allow_lines = [p.get("npub", "") for p in peers if p.get("npub")]
        peers_allow_content = "\n".join(peers_allow_lines) + "\n"

    # --- Build bt-agent procd init script ---
    bt_agent_init = (
        "#!/bin/sh /etc/rc.common\n"
        "START=98\n"
        "STOP=10\n"
        "start() {\n"
        "    hciconfig hci0 up\n"
        "    command -v bt-agent >/dev/null 2>&1 && bt-agent -c NoInputNoOutput -p /etc/fips/bt-pin &\n"
        "}\n"
        "stop() {\n"
        "    killall bt-agent 2>/dev/null\n"
        "}\n"
    )

    # --- Build FIPS procd init script ---
    fips_init = (
        "#!/bin/sh /etc/rc.common\n"
        "START=99\n"
        "STOP=10\n"
        "start() {\n"
        "    fips -c /etc/fips/fips.yaml &\n"
        "}\n"
        "stop() {\n"
        "    killall fips 2>/dev/null\n"
        "}\n"
    )

    # --- Assemble shell commands (single-line, semicolon-safe) ---
    lines = ["mkdir -p /etc/fips"]
    lines.extend(_echo_write("/etc/fips/fips.yaml", yaml_content))
    lines.append(f"echo '{bt_pin}' > /etc/fips/bt-pin")

    if role == "server" and peers_allow_content.strip():
        lines.extend(_echo_write("/etc/fips/peers.allow", peers_allow_content))

    lines.extend(_echo_write("/etc/init.d/bt-agent", bt_agent_init))
    lines.append("chmod +x /etc/init.d/bt-agent")
    lines.append("/etc/init.d/bt-agent enable")
    lines.extend(_echo_write("/etc/init.d/fips", fips_init))
    lines.append("chmod +x /etc/init.d/fips")
    lines.append("/etc/init.d/fips enable")
    lines.append(f"echo 'FIPS Bluetooth RFCOMM configured ({role}, channel {channel}, {len(peers)} peer(s))'")

    return "\n".join(lines)


register(UseCase(
    name="fips-bluetooth-rfcomm",
    description="FIPS mesh networking over Bluetooth RFCOMM (star topology with TUN)",
    packages=[
        "bluez-libs",
        "bluez-utils",
        "bluez-utils-extra",
        "kmod-tun",
    ],
    packages_remove=[],
    params={
        "role": ParamDef(type=str, default="client",
                         choices=("server", "client"),
                         description="RFCOMM role: server accepts connections, client initiates"),
        "channel": ParamDef(type=int, default=1,
                            min_value=1, max_value=30,
                            description="RFCOMM channel number"),
        "binary_path": ParamDef(type=str, default="",
                                description="Local path to FIPS binary (host-side, for SCP deploy)"),
        "binaryctl_path": ParamDef(type=str, default="",
                                   description="Local path to fipsctl binary (host-side)"),
        "peers": ParamDef(type=list, default=[],
                          description="List of peer dicts with 'npub' and 'bt_mac' keys"),
        "tun_enabled": ParamDef(type=bool, default=True,
                                description="Enable TUN interface for IP-over-mesh"),
        "tun_dns": ParamDef(type=bool, default=True,
                            description="Enable DNS over TUN"),
        "tun_gateway": ParamDef(type=bool, default=True,
                                description="Enable gateway over TUN"),
        "bt_pin": ParamDef(type=str, default="0000",
                           description="Bluetooth pairing PIN"),
    },
    build_configure=_build_fips_rfcomm,
    packages_via="opkg",
    configure_via="ssh",
    test_status="experimental",
    tested_notes="ASUS Lyra MAP-AC2200, star topology, RFCOMM transport",
    requires_capabilities=["bluetooth"],
    requires_post_flash=True,
))
