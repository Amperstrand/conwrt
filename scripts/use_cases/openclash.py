"""openclash — transparent proxy via Clash/Mihomo for censorship bypass."""
from __future__ import annotations

import re
from typing import Any

from profile.ops import Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register

_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _token(value: str, field: str) -> str:
    if not _TOKEN_RE.fullmatch(value):
        raise ValueError(f"{field} contains unsafe characters: {value!r}")
    return value


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    # core_type/proxy_type interpolate into a DOUBLE-quoted echo line
    # below (the uci values ride safe single-quoting) — gate all three
    # with a token charset so a `"`/`$()`/backtick value cannot inject
    # shell (mwan3/#448 class; the Rust port applies the same gate,
    # plan.rs OpenClashProfile::validate).
    return {
        "proxy_type": _token(str(params.get("proxy_type", "ss")), "proxy_type"),
        "core_type": _token(str(params.get("core_type", "Meta")), "core_type"),
        "dns_mode": _token(str(params.get("dns_mode", "redir-host")), "dns_mode"),
    }


def _build_openclash_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    return [
        Comment(text="--- OpenClash transparent proxy ---"),
        ShellCommand(command="mkdir -p /etc/openclash/config"),
        # AGENTS.md staging-debris rule: an aborted earlier session may
        # have left uncommitted /tmp/.uci changes for openclash — the
        # commit below would otherwise make them permanent.
        ShellCommand(command="uci -q revert openclash 2>/dev/null || true"),
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
    test_status="tested",
    tested_notes="ops characterization + transport parity",
    configure_via="ssh",
))
