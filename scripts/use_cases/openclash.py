"""openclash — transparent proxy via Clash/Mihomo for censorship bypass."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register


def _build_openclash(params: dict[str, Any]) -> str:
    proxy_type = params.get("proxy_type", "ss")
    core_type = params.get("core_type", "Meta")
    dns_mode = params.get("dns_mode", "redir-host")

    return textwrap.dedent(f"""\
        # --- OpenClash transparent proxy ---
        mkdir -p /etc/openclash/config
        uci set openclash.config.enable='1'
        uci set openclash.config.config_path='/etc/openclash/config/config.yaml'
        uci set openclash.config.proxy_type='{proxy_type}'
        uci set openclash.config.core_type='{core_type}'
        uci set openclash.config.dashboard_type='Official'
        uci set openclash.config.dns_mode='{dns_mode}'
        uci set openclash.config.operation_mode='{dns_mode}'
        uci commit openclash
        /etc/init.d/openclash enable
        echo "OpenClash configured: {core_type} core, {proxy_type} proxy"
        echo "Post-flash: import your subscription config via the LuCI web UI"
    """)


register(UseCase(
    name="openclash",
    description="Transparent proxy via Clash/Mihomo for censorship bypass (post-flash config)",
    packages=[
        "luci-app-openclash",
        "coreutils-nohup",
        "bash",
        "iptables",
        "dnsmasq-full",
        "curl",
        "ca-certificates",
        "ca-bundle",
        "logd",
    ],
    packages_remove=[
        "dnsmasq",
    ],
    params={
        "proxy_type": ParamDef(
            type=str,
            default="ss",
            description="Default proxy protocol: ss, vmess, trojan, vless"
        ),
        "core_type": ParamDef(
            type=str,
            default="Meta",
            description="Clash core: Meta (Mihomo), Dev, Tun"
        ),
        "dns_mode": ParamDef(
            type=str,
            default="redir-host",
            description="DNS mode: redir-host or fake-ip"
        ),
    },
    build_defaults=_build_openclash,
    requires_capabilities=[],
    requires_post_flash=True,
))
