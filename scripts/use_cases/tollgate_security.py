"""tollgate-security — RFC 1918 isolation for TollGate public WiFi.

Prevents authenticated public WiFi users from accessing devices on the
operator's upstream network (ISP router LAN, printers, TVs, NAS, etc.).

Adds DROP rules on the FORWARD chain: lan→wan traffic destined for
RFC 1918 private ranges is blocked. The router's own OUTPUT traffic
(payments, DNS, updates) is unaffected.

Also enables WiFi client isolation (isolate='1') to prevent public
clients from communicating with each other.

Pair with the 'tollgate' use case for full TollGate deployment.
"""
from __future__ import annotations

from typing import Any

from profile.ops import Comment, Op, ServiceAction, ShellCommand, UciSet, UciCommit, render_shell

from . import UseCase, register


def _build_security_ops(params: dict[str, Any]) -> list[Op]:
    ops: list[Op] = [
        Comment(text="--- TollGate Security: RFC 1918 isolation ---"),
    ]

    # RFC 1918 forwarding filters: block public WiFi → upstream private networks.
    # These DROP rules are evaluated BEFORE the general lan→wan forwarding ACCEPT
    # in OpenWrt's fw4 (explicit rules take precedence over forwarding sections).
    #
    # Safety: only affects FORWARD chain. Router's own OUTPUT (payments, DNS,
    # firmware updates) and INPUT (API, portal, DNS, DHCP) are NOT affected.
    rfc1918_ranges = [
        ("10", "10.0.0.0/8", "RFC 1918 private (class A)"),
        ("172", "172.16.0.0/12", "RFC 1918 private (class B)"),
        ("192", "192.168.0.0/16", "RFC 1918 private (class C — ISP router LAN)"),
        ("LL", "169.254.0.0/16", "RFC 3927 link-local (mDNS, SSDP)"),
    ]

    for suffix, cidr, description in rfc1918_ranges:
        name = f"Block-LAN-To-RFC1918-{suffix}"
        ops.append(ShellCommand(command=f"uci set firewall.{name}=rule"))
        ops.append(UciSet(config="firewall", section=name, values={
            "name": name,
            "src": "lan",
            "dest": "wan",
            "dest_ip": cidr,
            "proto": "all",
            "family": "ipv4",
            "target": "DROP",
        }))
        ops.append(Comment(text=f"  {name}: {description}"))

    ops.append(UciCommit(config="firewall"))
    # Activate: committed UCI alone leaves the RUNNING firewall wide
    # open until some later reload — restart fw4 so the block rules are
    # live before apply reports success (found by Codex #601 P1; fixed
    # with this port's Rust twin).
    ops.append(ServiceAction(name="firewall", action="restart"))

    # WiFi client isolation — prevent public clients from talking to each other.
    # Discovery over ALL wifi-iface sections (Codex #601 P2): the 1.x
    # hardcoded default_radio0/default_radio1 aborted mid-apply on
    # single-radio devices under set -e (firewall already activated,
    # isolation never applied); section names are factory defaults,
    # not a guarantee. `done; true` guards zero-iface devices.
    ops.append(Comment(text="--- WiFi client isolation ---"))
    ops.append(ShellCommand(
        command="for _s in $(uci show wireless 2>/dev/null | grep '=wifi-iface' "
                "| cut -d. -f2 | cut -d= -f1); do "
                "uci set wireless.$_s.isolate='1'; done; true"
    ))
    ops.append(ShellCommand(command="uci commit wireless"))
    # ... and activate the radio change too
    ops.append(ShellCommand(command="wifi reload"))

    return ops


register(UseCase(
    name="tollgate-security",
    description="RFC 1918 isolation: block public WiFi from upstream LAN + client isolation",
    packages=[],
    packages_remove=[],
    params={},
    build_configure=lambda p: render_shell(_build_security_ops(p)),
    build_configure_ops=_build_security_ops,
    test_status="tested",
    tested_notes="ops unit tests, UciSet validation",
    requires_capabilities=["wifi"],
))
