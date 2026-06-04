"""openclash — transparent proxy via Clash/Mihomo for censorship bypass."""
from __future__ import annotations

from typing import Any

from profile.ops import Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell

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
        Comment(text="--- OpenClash transparent proxy ---"),
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
        ShellCommand(command=f'echo "OpenClash configured: {r["core_type"]} core, {r["proxy_type"]} proxy"'),
        ShellCommand(command='echo "Post-flash: import your subscription config via the LuCI web UI"'),
    ]


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
    build_configure=lambda p: render_shell(_build_openclash_ops(p)),
    build_configure_ops=_build_openclash_ops,
    requires_capabilities=[],
    test_status="untested",
    tested_notes="subscription import via LuCI",
    configure_via="ssh",
))
