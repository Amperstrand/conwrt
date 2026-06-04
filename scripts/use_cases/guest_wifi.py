"""guest-wifi — Isolated guest WiFi network with firewall isolation."""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell
from shell_safe import sh_quote, uci_name

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    ssid = sh_quote(str(params.get("ssid", "Guest")))
    encryption = str(params.get("encryption", "psk2"))
    key = sh_quote(str(params.get("key", ""))) if params.get("key") else ""
    band = str(params.get("band", "2.4ghz"))
    isolated = "1" if params.get("isolation", True) else "0"
    network = uci_name(str(params.get("network_name", "guest")), "guest network name")
    return {
        "ssid": ssid,
        "encryption": encryption,
        "key": key,
        "band": band,
        "isolated": isolated,
        "network": network,
    }


def _build_guest_wifi_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    net = r["network"]
    enc = r["encryption"]
    key = r["key"]

    ops: list[Op] = [
        Comment(text=f"--- Guest WiFi: {r['ssid']} ---"),
    ]

    # Create guest network interface
    ops.append(ShellCommand(command=f"uci set network.{net}=interface"))
    ops.append(UciSet(config="network", section=net, values={
        "proto": "static",
        "ipaddr": "192.168.3.1",
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
    ops.append(ShellCommand(command=f"uci add firewall zone"))
    ops.append(UciSet(config="firewall", section="@zone[-1]", values={
        "name": net,
        "network": net,
        "input": "REJECT",
        "output": "ACCEPT",
        "forward": "REJECT",
    }))
    ops.append(ShellCommand(command=f"uci add firewall forwarding"))
    ops.append(UciSet(config="firewall", section="@forwarding[-1]", values={
        "src": net,
        "dest": "wan",
    }))
    # Allow DNS and DHCP to guest zone
    ops.append(ShellCommand(command=f"uci add firewall rule"))
    ops.append(UciSet(config="firewall", section="@rule[-1]", values={
        "name": f"Allow-DNS-{net}",
        "src": net,
        "dest_port": "53",
        "proto": "tcpudp",
        "target": "ACCEPT",
    }))
    ops.append(ShellCommand(command=f"uci add firewall rule"))
    ops.append(UciSet(config="firewall", section="@rule[-1]", values={
        "name": f"Allow-DHCP-{net}",
        "src": net,
        "dest_port": "67-68",
        "proto": "udp",
        "target": "ACCEPT",
    }))
    ops.append(UciCommit(config="firewall"))

    ops.append(BlankLine())

    # Guest WiFi SSID (on radio matching band — uses runtime detection)
    ops.append(ShellCommand(
        command="for _r in $(uci show wireless | grep '=wifi-iface' | cut -d. -f2 | cut -d= -f1); do "
                "_b=$(uci get wireless.${_r}.band 2>/dev/null); "
                f'if [ "$_b" = "{r["band"][:1]}"g ] ; then '
                f"uci set wireless.${{_r}}.ssid={r['ssid']} ; "
                f"uci set wireless.${{_r}}.encryption={enc} ; "
                + (f"uci set wireless.${{_r}}.key={key} ; " if key else "") +
                f"uci set wireless.${{_r}}.network={net} ; "
                f"uci set wireless.${{_r}}.isolate={r['isolated']} ; "
                "break ; fi ; done",
    ))
    ops.append(UciCommit(config="wireless"))

    ops.append(BlankLine())
    ops.append(ServiceAction(name="network", action="restart"))
    ops.append(ServiceAction(name="firewall", action="restart"))
    ops.append(ShellCommand(
        command=f'echo "Guest WiFi configured: SSID={r["ssid"]} network={net} isolated={r["isolated"]}"',
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
    test_status="untested",
    tested_notes="UCI from OpenWrt wiki guest WiFi guide",
    configure_via="ssh",
))
