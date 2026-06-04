"""adguard — network-wide ad blocking via AdGuard Home."""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciAddList, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    listen_ip = str(params.get("listen_ip", "0.0.0.0"))
    web_port = params.get("web_port", 3000)
    dns_port = params.get("dns_port", 5353)
    return {
        "listen_ip": listen_ip,
        "web_port": web_port,
        "dns_port": dns_port,
    }


def _build_adguard_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    listen_ip = r["listen_ip"]
    web_port = r["web_port"]
    dns_port = r["dns_port"]

    return [
        Comment(text="--- AdGuard Home ---"),
        ShellCommand(command="uci set adguardhome.adguardhome=adguardhome"),
        UciSet(config="adguardhome", section="adguardhome", values={
            "enabled": "1",
            "http_address": f"{listen_ip}:{web_port}",
            "dns_port": str(dns_port),
        }),
        UciCommit(config="adguardhome"),
        ServiceAction(name="adguardhome", action="enable"),
        ShellCommand(command="/etc/init.d/adguardhome start 2>/dev/null || true"),
        BlankLine(),
        UciSet(config="dhcp", section="@dnsmasq[0]", values={
            "noresolv": "1",
        }),
        UciAddList(config="dhcp", section="@dnsmasq[0]", option="server", value=f"127.0.0.1#{dns_port}"),
        UciCommit(config="dhcp"),
        ShellCommand(command="/etc/init.d/dnsmasq restart 2>/dev/null || true"),
        ShellCommand(command=f'echo "AdGuard Home configured: DNS on port {dns_port}, web UI at {listen_ip}:{web_port}"'),
    ]


register(UseCase(
    name="adguard",
    description="Network-wide ad blocking via AdGuard Home (post-flash setup)",
    packages=["adguardhome", "luci-app-adguardhome"],
    packages_remove=[],
    params={
        "listen_ip": ParamDef(type=str, default="0.0.0.0",
                              description="Web UI listen address"),
        "web_port": ParamDef(type=int, default=3000,
                             description="Web UI port (initial setup, then 80)"),
        "dns_port": ParamDef(type=int, default=5353,
                             description="DNS listen port (avoid conflict with dnsmasq on 53)"),
        "bootstrap_dns": ParamDef(type=str, default="1.1.1.1,8.8.8.8",
                                  description="Upstream DNS for bootstrap"),
    },
    build_configure=lambda p: render_shell(_build_adguard_ops(p)),
    build_configure_ops=_build_adguard_ops,
    requires_capabilities=[],
    test_status="tested",
    tested_notes="ops characterization + transport parity",
    configure_via="ssh",
))
