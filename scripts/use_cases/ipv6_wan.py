"""ipv6-wan — IPv6 WAN with NAT66/ULA for stable LAN addressing (#3).

The problem: ISP-assigned global prefixes churn (DHCPv6-PD
reassignment), so every LAN v6 address — and every port forward,
DNS record, and firewall rule pinned to one — breaks on each change.
The recipe: WAN side takes DHCPv6 with prefix delegation; the LAN
keeps a STABLE ULA prefix (existing one preserved, else derived
deterministically from the device MAC — the OpenWrt generate_ula
shape); and the WAN firewall zone NATs v6 (masq6) so ULA-sourced
traffic still egresses while the global prefix rides along for
native paths. Config touches are idempotent sets only — never a
blanket `uci revert` on network/firewall (AGENTS.md).
"""
from __future__ import annotations

import re
from typing import Any

from profile.ops import Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register


_TOKEN_RE = re.compile(r"[A-Za-z0-9.:/_-]+")

# ULA derivation (only when neither the param nor the device carries
# one): fd + MAC byte0 with the U/L bit flipped, standard modified
# EUI-64 middle, last MAC bytes — the OpenWrt generate_ula shape.
# BusyBox-safe: cat, printf, $((0x.. ^ 2)).
_DERIVE_ULA = (
    "ula=$(uci -q get network.globals.ula_prefix) || ula=''; "
    "[ -n \"$ula\" ] || { "
    "mac=$(cat /sys/class/net/eth0/address); "
    "m1=$(echo $mac | cut -d: -f1); m2=$(echo $mac | cut -d: -f2); "
    "m3=$(echo $mac | cut -d: -f3); m4=$(echo $mac | cut -d: -f4); "
    "m5=$(echo $mac | cut -d: -f5); "
    "uci set network.globals.ula_prefix=\"fd$(printf %02x $((0x$m1 ^ 2))):${m2}ff:fe${m3}:${m4}${m5}::/64\"; "
    "}"
)

# masq6 on the zone NAMED wan (index-based @zone[1] breaks on customized
# firewall configs); single BusyBox pipeline finds the section id.
_MASQ6_WAN = (
    "z=$(uci show firewall | grep \"=zone\" | grep \"name='wan'\" | "
    "cut -d. -f2 | cut -d= -f1); "
    "[ -z \"$z\" ] || uci set firewall.$z.masq6='1'"
)


def _token(value: str, field: str) -> str:
    if value and not _TOKEN_RE.fullmatch(value):
        raise ValueError(f"{field} contains unsafe characters: {value!r}")
    return value


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    reqprefix = str(params.get("reqprefix", "auto"))
    if reqprefix not in ("auto", "no", "48", "56", "60", "64"):
        raise ValueError(f"reqprefix must be auto/no/48/56/60/64: {reqprefix!r}")
    r = {
        "reqprefix": reqprefix,
        "ula_prefix": _token(str(params.get("ula_prefix", "")), "ula_prefix"),
        "masq6": bool(params.get("masq6", True)),
        "lan_ip6assign": _token(str(params.get("lan_ip6assign", "64")), "lan_ip6assign"),
    }
    if r["ula_prefix"] and not r["ula_prefix"].endswith("/64"):
        raise ValueError("ula_prefix must be a /64 (stable LAN addressing)")
    if r["lan_ip6assign"] not in ("56", "60", "64"):
        raise ValueError(f"lan_ip6assign must be 56/60/64: {r['lan_ip6assign']!r}")
    return r


def _build_ipv6_wan_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    ops: list[Op] = [Comment(text="--- IPv6 WAN (NAT66/ULA stable LAN) ---")]
    # WAN6: DHCPv6 client with prefix delegation on the wan device.
    ops.append(ShellCommand(command="uci set network.wan6=interface"))
    ops.append(UciSet(config="network", section="wan6", values={
        "proto": "dhcpv6",
        "device": "@wan",
        "reqprefix": r["reqprefix"],
    }))
    # ULA: param wins, device's existing wins, else derive from MAC.
    if r["ula_prefix"]:
        ops.append(ShellCommand(
            command=f"uci set network.globals.ula_prefix='{r['ula_prefix']}'"))
    else:
        ops.append(ShellCommand(command=_DERIVE_ULA))
    # LAN: stable SLAAC assignment from the ULA.
    ops.append(UciSet(config="network", section="lan", values={
        "ip6assign": r["lan_ip6assign"],
    }))
    # NAT66 for ULA egress (opt-out).
    if r["masq6"]:
        ops.append(ShellCommand(command=_MASQ6_WAN))
    ops.append(UciCommit(config="network"))
    ops.append(UciCommit(config="firewall"))
    ops.append(ServiceAction(name="network", action="reload"))
    ops.append(ServiceAction(name="firewall", action="reload"))
    return ops


register(UseCase(
    name="ipv6-wan",
    description="IPv6 WAN via DHCPv6-PD with ULA + NAT66 for stable LAN addressing (#3)",
    packages=[],
    params={
        "reqprefix": ParamDef(type=str, default="auto",
                              description="requested prefix length (auto/no/48/56/60/64)",
                              choices=("auto", "no", "48", "56", "60", "64")),
        "ula_prefix": ParamDef(type=str, default="",
                               description="stable ULA /64 (default: keep or derive from MAC)"),
        "masq6": ParamDef(type=bool, default=True,
                          description="NAT66 masquerade on the wan zone for ULA egress"),
        "lan_ip6assign": ParamDef(type=str, default="64",
                                  description="LAN prefix assignment size (56/60/64)",
                                  choices=("56", "60", "64")),
    },
    build_configure_ops=_build_ipv6_wan_ops,
    test_status="untested",
    post_install_notes="Verify with: ifstatus wan6; ip -6 addr show br-lan (ULA present); ip6tables -t nat -L (masq6).",
))
