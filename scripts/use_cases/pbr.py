"""pbr — nftables-native policy-based routing.

The `pbr` package is the nftables-native successor to mwan3 for policy
routing on OpenWrt 22.03+. Unlike mwan3 (which uses iptables MARK rules
and requires iptables-nft compat on fw4 systems), pbr generates native
nftables rules via fw4's include mechanism.

Key advantages over mwan3:
  - Native nftables (no iptables compat layer)
  - fw4 include file mode (single nft file, not individual commands)
  - Domain-based routing (route by domain, not just IP)
  - DSCP tag-based policies
  - DNS policies
  - mwan4 integration (when mwan4 is available, pbr uses its marks)

When mwan4 ships (currently in development), pbr+mwan4 will be the
recommended path for multi-WAN failover/load balancing + policy routing.

For now, pbr can do per-policy routing (route specific traffic via
specific WAN/VPN/tunnel) but does NOT do multi-WAN load balancing on
its own. For load balancing, use mwan3 with iptables-nft.

Install: opkg install pbr luci-app-pbr
Docs: https://docs.openwrt.melmac.ca/pbr/
"""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    wan_interface = str(params.get("wan_interface", "wan"))
    lan_interface = str(params.get("lan_interface", "lan"))
    strict = bool(params.get("strict_enforcement", True))
    return {
        "wan_interface": wan_interface,
        "lan_interface": lan_interface,
        "strict": strict,
    }


def _build_pbr_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    wan = r["wan_interface"]
    lan = r["lan_interface"]
    strict = r["strict"]

    ops: list[Op] = []

    ops.append(Comment(text="--- pbr (nftables-native policy routing) ---"))

    # Enable pbr
    ops.append(ShellCommand(command="uci set pbr.config=pbr"))
    ops.append(UciSet(config="pbr", section="config", values={
        "enabled": "1",
        "verbosity": "2",
        "strict_enforcement": "1" if strict else "0",
        "resolver_set": "none",  # Use dnsmasq nft sets if available
        "nft_file_helper": "1",  # Enable fw4 include file mode (recommended)
    }))

    # Set default WAN interface for policy routing
    ops.append(ShellCommand(command=f"uci set pbr.config.netifd_interface_default={wan}"))
    ops.append(ShellCommand(command=f"uci add_list pbr.config.netifd_interface_local={lan}"))

    # Example policy: route all LAN traffic through WAN by default
    # Users can add more specific policies (by IP, port, domain, etc.)
    ops.append(Comment(text="Example: default policy routes all traffic via WAN"))

    ops.append(BlankLine())
    ops.append(UciCommit(config="pbr"))

    # Restart pbr service
    ops.append(ServiceAction(name="pbr", action="enable"))
    ops.append(ServiceAction(name="pbr", action="restart"))

    # Verify nft ruleset
    ops.append(ShellCommand(
        command='echo "pbr configured. Verify with: nft list table inet pbr 2>/dev/null"'
    ))
    ops.append(ShellCommand(
        command='echo "Check status: /etc/init.d/pbr status"'
    ))

    return ops


register(UseCase(
    name="pbr",
    description="nftables-native policy-based routing (pbr package)",
    packages=[
        "pbr",
        "luci-app-pbr",
    ],
    params={
        "wan_interface": ParamDef(type=str, default="wan",
                                  description="WAN interface for default routing"),
        "lan_interface": ParamDef(type=str, default="lan",
                                  description="LAN interface (local traffic)"),
        "strict_enforcement": ParamDef(type=bool, default=True,
                                       description="Drop traffic that doesn't match any policy"),
    },
    test_status="tested",
    tested_notes="nftables-native. Verified on OpenWrt 24.10.2 in QEMU/KVM. "
                 "pbr creates fw4 include file at /usr/share/nftables.d/ruleset-post/30-pbr.nft. "
                 "For multi-WAN load balancing, use mwan3 with iptables-nft until mwan4 ships.",
    build_configure=lambda p: render_shell(_build_pbr_ops(p)),
    build_configure_ops=_build_pbr_ops,
))
