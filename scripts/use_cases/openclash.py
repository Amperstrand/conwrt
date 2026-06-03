"""openclash — transparent proxy via Clash/Mihomo for censorship bypass."""
from __future__ import annotations

import textwrap
from typing import Any

from profile.ops import Op, ServiceAction, ShellCommand, UciCommit, UciSet

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    return {
        "proxy_type": params.get("proxy_type", "ss"),
        "core_type": params.get("core_type", "Meta"),
        "dns_mode": params.get("dns_mode", "redir-host"),
    }


def _build_openclash_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    return [
        ShellCommand(command="mkdir -p /etc/openclash/config"),
        UciSet(config="openclash", section="config", values={
            "enable": "1",
            "config_path": "/etc/openclash/config/config.yaml",
            "proxy_type": r["proxy_type"],
            "core_type": r["core_type"],
            "dashboard_type": "Official",
            "dns_mode": r["dns_mode"],
            "operation_mode": r["dns_mode"],
        }),
        UciCommit(config="openclash"),
        ServiceAction(name="openclash", action="enable"),
    ]


def _build_openclash(params: dict[str, Any]) -> str:
    r = _resolve_params(params)

    return textwrap.dedent(f"""\
        # --- OpenClash transparent proxy ---
        mkdir -p /etc/openclash/config
        uci set openclash.config.enable='1'
        uci set openclash.config.config_path='/etc/openclash/config/config.yaml'
        uci set openclash.config.proxy_type='{r["proxy_type"]}'
        uci set openclash.config.core_type='{r["core_type"]}'
        uci set openclash.config.dashboard_type='Official'
        uci set openclash.config.dns_mode='{r["dns_mode"]}'
        uci set openclash.config.operation_mode='{r["dns_mode"]}'
        uci commit openclash
        /etc/init.d/openclash enable
        echo "OpenClash configured: {r['core_type']} core, {r['proxy_type']} proxy"
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
    build_configure=_build_openclash,
    build_configure_ops=_build_openclash_ops,
    requires_capabilities=[],
    test_status="untested",
    tested_notes="subscription import via LuCI",
    configure_via="ssh",
))
