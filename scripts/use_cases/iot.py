"""iot — Isolated IoT network: separate WiFi AP + firewall zone (#4).

Same machinery as guest-wifi (proven shape) with IoT-grade semantics:
a FIXED configurable subnet (deterministic — no derive-from-LAN), client
isolation on by default, longer leases, and an optional WAN cut-off
(wan_access=false drops the forwarding rule entirely — the classic
"IoT devices never phone home" posture; DNS+DHCP to the router stay
allowed either way so the devices remain usable). VLAN delivery
(tagged trunk) is a deliberate non-goal here: the separate-AP variant
is the issue's other arm and rides the tested guest-wifi machinery.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell
from profile.uci_helpers import uci_cleanup_sections
from shell_safe import sh_quote, uci_name

from . import ParamDef, UseCase, register


def _resolve_subnet(subnet: str) -> tuple[str, str]:
    """CIDR (a.b.c.d/24) -> (ipaddr, netmask); /24 only (documented)."""
    try:
        iface = ipaddress.IPv4Interface(subnet)
    except ValueError as exc:
        raise ValueError(f"subnet must be a.b.c.d/24: {subnet!r}") from exc
    if iface.network.prefixlen != 24:
        raise ValueError(f"subnet must be /24 (IoT preset contract): {subnet!r}")
    return str(iface.ip), str(iface.netmask)


def _build_iot_ops(params: dict[str, Any]) -> list[Op]:
    ssid = sh_quote(str(params.get("ssid", "IoT")))
    encryption = str(params.get("encryption", "psk2"))
    key = str(params.get("key", ""))
    if encryption != "none" and not key:
        raise ValueError("key is required unless encryption=none (IoT nets are never open)")
    key_q = sh_quote(key)
    band = str(params.get("band", "2.4ghz"))
    band_short = band[:1] + "g"
    isolated = "1" if params.get("isolation", True) else "0"
    net = uci_name(str(params.get("network_name", "iot")), "iot network name")
    ipaddr, netmask = _resolve_subnet(str(params.get("subnet", "192.168.9.1/24")))
    wan_access = bool(params.get("wan_access", True))

    ops: list[Op] = [Comment(text=f"--- IoT isolated network: {ssid} ---")]

    # Radio discovery + HARD GATE before any section is written (#454
    # class, guest-wifi's proven shape): a missing band aborts with
    # ZERO partial config.
    ops.append(ShellCommand(
        command=
            f'_radio=""; '
            f'for _r in radio0 radio1 radio2 radio3; do '
            f'_b=$(uci get wireless.${{_r}}.band 2>/dev/null || true); '
            f'if [ "$_b" = "{band_short}" ]; then _radio=$_r; break; fi; '
            f'done; '
            f'if [ -z "$_radio" ]; then '
            f'echo \'iot: no {band_short} radio found — aborting before any config changes\' >&2; '
            f'exit 1; '
            f'fi',
    ))
    ops.append(BlankLine())

    ops.append(ShellCommand(command=f"uci set network.{net}=interface"))
    ops.append(UciSet(config="network", section=net, values={
        "proto": "static",
        "ipaddr": ipaddr,
        "netmask": netmask,
    }))
    ops.append(UciCommit(config="network"))

    ops.append(BlankLine())
    # IoT DHCP: longer leases (devices renew, humans roam)
    ops.append(ShellCommand(command=f"uci set dhcp.{net}=dhcp"))
    ops.append(UciSet(config="dhcp", section=net, values={
        "interface": net,
        "start": "100",
        "limit": "150",
        "leasetime": "12h",
    }))
    ops.append(UciCommit(config="dhcp"))

    ops.append(BlankLine())
    # IoT firewall zone: no LAN reachability, ever
    ops.append(ShellCommand(command=f"uci set firewall.{net}=zone"))
    ops.append(UciSet(config="firewall", section=net, values={
        "name": net,
        "network": net,
        "input": "REJECT",
        "output": "ACCEPT",
        "forward": "REJECT",
    }))
    if wan_access:
        ops.append(ShellCommand(command=f"uci set firewall.{net}_fwd=forwarding"))
        ops.append(UciSet(config="firewall", section=f"{net}_fwd", values={
            "src": net,
            "dest": "wan",
        }))
    # DNS + DHCP to the router must punch through input REJECT or the
    # clients are unusable (guest-wifi's rule pair, named sections)
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
    # Named VAP (idempotent); cleanup old anonymous sections. $_radio is
    # guaranteed by the hard gate above.
    ops.append(uci_cleanup_sections("wireless", f"network='{net}'"))
    ops.append(ShellCommand(
        command=
            f'uci set wireless.iot_ap=wifi-iface; '
            f'uci set wireless.iot_ap.device=$_radio; '
            f'uci set wireless.iot_ap.mode=ap; '
            f'uci set wireless.iot_ap.ssid={ssid}; '
            f'uci set wireless.iot_ap.encryption={encryption}; '
            + (f'uci set wireless.iot_ap.key={key_q}; ' if key_q else "") +
            f'uci set wireless.iot_ap.network={net}; '
            f'uci set wireless.iot_ap.isolate={isolated}',
    ))
    ops.append(UciCommit(config="wireless"))

    ops.append(BlankLine())
    ops.append(ServiceAction(name="network", action="restart"))
    ops.append(ServiceAction(name="firewall", action="restart"))
    ops.append(ShellCommand(
        command=f'echo "IoT network configured: SSID={ssid} network={net} wan_access={"1" if wan_access else "0"} isolated={isolated}"',
    ))
    return ops


register(UseCase(
    name="iot",
    description="Isolated IoT network: separate WiFi AP, own subnet+DHCP, firewall zone, optional WAN cutoff (#4)",
    packages=[],
    params={
        "ssid": ParamDef(type=str, default="IoT",
                         description="IoT network SSID"),
        "key": ParamDef(type=str, required=True,
                        description="WiFi password (required unless encryption=none)"),
        "encryption": ParamDef(type=str, default="psk2",
                               description="Encryption: psk2, psk-mixed, none"),
        "band": ParamDef(type=str, default="2.4ghz",
                         description="WiFi band: 2.4ghz, 5ghz"),
        "isolation": ParamDef(type=bool, default=True,
                              description="Client isolation (IoT devices can't see each other)"),
        "network_name": ParamDef(type=str, default="iot",
                                 description="UCI network interface name"),
        "subnet": ParamDef(type=str, default="192.168.9.1/24",
                           description="Fixed IoT subnet, a.b.c.d/24 (deterministic, unlike guest-wifi's derive)"),
        "wan_access": ParamDef(type=bool, default=True,
                               description="Allow IoT -> WAN forwarding (false = devices can't phone home)"),
    },
    build_configure_ops=_build_iot_ops,
    requires_capabilities=["wifi"],
    test_status="untested",
    post_install_notes="Verify with: uci show firewall.iot; wifi status; an IoT client gets DNS but cannot reach 192.168.1.0/24.",
))
