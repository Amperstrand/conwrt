"""guest-wifi — Isolated guest WiFi network with firewall isolation."""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell
from profile.uci_helpers import uci_cleanup_sections
from shell_safe import sh_quote, uci_name

from . import ParamDef, UseCase, register


def _build_guest_wifi_ops(params: dict[str, Any]) -> list[Op]:
    ssid = sh_quote(str(params.get("ssid", "Guest")))
    encryption = str(params.get("encryption", "psk2"))
    key = sh_quote(str(params.get("key", ""))) if params.get("key") else ""
    band = str(params.get("band", "2.4ghz"))
    isolated = "1" if params.get("isolation", True) else "0"
    net = uci_name(str(params.get("network_name", "guest")), "guest network name")
    band_short = band[:1] + "g"

    ops: list[Op] = [
        Comment(text=f"--- Guest WiFi: {ssid} ---"),
    ]

    # Derive guest subnet from current LAN IP (third octet + 1).
    # Runs AFTER the LAN IP step, so network.lan.ipaddr is already set.
    ops.append(ShellCommand(
        command="_lan_ip=$(uci get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1')"))
    ops.append(ShellCommand(
        command='_guest_o3=$(echo "$_lan_ip" | cut -d. -f3)'))
    ops.append(ShellCommand(
        command='_guest_o3=$((_guest_o3 + 1))'))
    ops.append(ShellCommand(
        command='[ "$_guest_o3" -gt 255 ] && _guest_o3=0'))
    ops.append(ShellCommand(
        command='_guest_prefix=$(echo "$_lan_ip" | cut -d. -f1-2).$_guest_o3'))

    ops.append(BlankLine())

    ops.append(ShellCommand(command=f"uci set network.{net}=interface"))
    ops.append(ShellCommand(command=f'uci set network.{net}.ipaddr="$_guest_prefix.1"'))
    ops.append(UciSet(config="network", section=net, values={
        "proto": "static",
        "netmask": "255.255.255.0",
    }))
    ops.append(UciCommit(config="network"))

    ops.append(BlankLine())

    # Guest DHCP
    ops.append(ShellCommand(command=f"uci set dhcp.{net}=dhcp"))
    ops.append(UciSet(config="dhcp", section=net, values={
        "interface": net,
        "start": "100",
        "limit": "50",
        "leasetime": "1h",
    }))
    ops.append(UciCommit(config="dhcp"))

    ops.append(BlankLine())

    # Guest firewall zone (isolated, no LAN forwarding)
    # Named sections avoid duplicates across reconfigure runs.
    ops.append(ShellCommand(command=f"uci set firewall.{net}=zone"))
    ops.append(UciSet(config="firewall", section=net, values={
        "name": net,
        "network": net,
        "input": "REJECT",
        "output": "ACCEPT",
        "forward": "REJECT",
    }))
    ops.append(ShellCommand(command=f"uci set firewall.{net}_fwd=forwarding"))
    ops.append(UciSet(config="firewall", section=f"{net}_fwd", values={
        "src": net,
        "dest": "wan",
    }))
    ops.append(ShellCommand(command=f"uci set firewall.{net}_dns=rule"))
    ops.append(UciSet(config="firewall", section=f"{net}_dns", values={
        "name": f"Allow-DNS-{net}",
        "src": net,
        "dest_port": "53",
        "proto": "tcpudp",
        "target": "ACCEPT",
    }))
    ops.append(ShellCommand(command=f"uci set firewall.{net}_dhcp=rule"))
    ops.append(UciSet(config="firewall", section=f"{net}_dhcp", values={
        "name": f"Allow-DHCP-{net}",
        "src": net,
        "dest_port": "67-68",
        "proto": "udp",
        "target": "ACCEPT",
    }))
    ops.append(UciCommit(config="firewall"))

    ops.append(BlankLine())

    # Named WiFi VAP section (idempotent — overwrites on reconfigure).
    # Cleanup old anonymous sections from previous versions.
    ops.append(uci_cleanup_sections("wireless", f"network='{net}'"))
    ops.append(ShellCommand(
        command=
            f'_radio=""; '
            f'for _r in radio0 radio1 radio2 radio3; do '
            f'_b=$(uci get wireless.${{_r}}.band 2>/dev/null); '
            f'if [ "$_b" = "{band_short}" ]; then _radio=$_r; break; fi; '
            f'done; '
            f'if [ -n "$_radio" ]; then '
            f'uci set wireless.guest_ap=wifi-iface; '
            f'uci set wireless.guest_ap.device=$_radio; '
            f'uci set wireless.guest_ap.mode=ap; '
            f'uci set wireless.guest_ap.ssid={ssid}; '
            f'uci set wireless.guest_ap.encryption={encryption}; '
            + (f'uci set wireless.guest_ap.key={key}; ' if key else "") +
            f'uci set wireless.guest_ap.network={net}; '
            f'uci set wireless.guest_ap.isolate={isolated}; '
            f'fi',
    ))
    ops.append(UciCommit(config="wireless"))

    ops.append(BlankLine())
    ops.append(ServiceAction(name="network", action="restart"))
    ops.append(ServiceAction(name="firewall", action="restart"))
    ops.append(ShellCommand(
        command=f'echo "Guest WiFi configured: SSID={ssid} network={net} isolated={isolated}"',
    ))

    return ops


register(UseCase(
    name="guest-wifi",
    description="Isolated guest WiFi network with separate subnet, DHCP, and firewall zone",
    packages=[],
    packages_remove=[],
    params={
        "ssid": ParamDef(type=str, default="Guest",
            description="Guest network SSID"),
        "key": ParamDef(type=str, default="",
            description="WiFi password (leave empty for open network)"),
        "encryption": ParamDef(type=str, default="psk2",
            description="Encryption: psk2, psk-mixed, none (open)"),
        "band": ParamDef(type=str, default="2.4ghz",
            description="WiFi band: 2.4ghz, 5ghz"),
        "isolation": ParamDef(type=bool, default=True,
            description="Enable client isolation (guests can't see each other)"),
        "network_name": ParamDef(type=str, default="guest",
            description="UCI network interface name"),
    },
    build_configure=lambda p: render_shell(_build_guest_wifi_ops(p)),
    build_configure_ops=_build_guest_wifi_ops,
    requires_capabilities=["wifi"],
    test_status="tested",
    tested_notes="ops characterization + transport parity",
    configure_via="ssh",
))
