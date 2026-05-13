"""adguard — network-wide ad blocking via AdGuard Home."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register


def _build_adguard(params: dict[str, Any]) -> str:
    listen_ip = params.get("listen_ip", "0.0.0.0")
    web_port = params.get("web_port", 3000)
    dns_port = params.get("dns_port", 5353)

    return textwrap.dedent(f"""\
        # --- AdGuard Home ---
        uci set adguardhome.adguardhome=adguardhome
        uci set adguardhome.adguardhome.enabled='1'
        uci set adguardhome.adguardhome.http_address='{listen_ip}:{web_port}'
        uci set adguardhome.adguardhome.dns_port='{dns_port}'
        uci commit adguardhome
        /etc/init.d/adguardhome enable
        /etc/init.d/adguardhome start 2>/dev/null || true

        uci set dhcp.@dnsmasq[0].noresolv='1'
        uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#{dns_port}'
        uci commit dhcp
        /etc/init.d/dnsmasq restart 2>/dev/null || true
        echo "AdGuard Home configured: DNS on port {dns_port}, web UI at {listen_ip}:{web_port}"
    """)


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
    build_defaults=_build_adguard,
    requires_capabilities=[],
    requires_post_flash=True,
))
