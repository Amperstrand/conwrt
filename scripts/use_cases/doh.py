"""doh — DNS-over-HTTPS via https-dns-proxy for encrypted DNS resolution."""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell
from shell_safe import sh_quote

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    provider = str(params.get("provider", "cloudflare"))
    listen_port = params.get("listen_port", 5053)
    return {
        "provider": provider,
        "listen_port": listen_port,
    }


_PROVIDERS: dict[str, str] = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/dns-query",
    "quad9": "https://dns.quad9.net/dns-query",
    "mullvad": "https://dns.mullvad.net/dns-query",
    "adguard": "https://dns.adguard-dns.com/dns-query",
}


def _build_doh_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    provider_url = _PROVIDERS.get(r["provider"], r["provider"])
    port = r["listen_port"]

    ops: list[Op] = [Comment(text=f"--- DNS-over-HTTPS ({r['provider']}) ---")]
    ops.append(ShellCommand(command="uci -q delete https-dns-proxy >/dev/null 2>&1 || true"))
    ops.append(BlankLine())
    ops.append(ShellCommand(command="uci set https-dns-proxy.main=https_dns_proxy"))
    ops.append(UciSet(config="https-dns-proxy", section="main", values={
        "bootstrap_dns": "1.1.1.1,8.8.8.8",
        "listen_addr": "127.0.0.1",
        "listen_port": str(port),
        "resolver_url": provider_url,
    }))
    ops.append(UciCommit(config="https-dns-proxy"))
    ops.append(ServiceAction(name="https-dns-proxy", action="enable"))
    ops.append(ShellCommand(command="/etc/init.d/https-dns-proxy restart 2>/dev/null || true"))

    ops.append(BlankLine())
    ops.append(Comment(text=f"--- Point dnsmasq to DoH proxy on port {port} ---"))
    ops.append(UciSet(config="dhcp", section="@dnsmasq[0]", values={
        "noresolv": "1",
    }))
    ops.append(ShellCommand(command=f"uci del_list dhcp.@dnsmasq[0].server >/dev/null 2>&1 || true"))
    ops.append(ShellCommand(command=f"uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#{port}'"))
    ops.append(UciCommit(config="dhcp"))
    ops.append(ShellCommand(command="/etc/init.d/dnsmasq restart 2>/dev/null || true"))
    ops.append(ShellCommand(
        command=f'echo "DoH configured: {r["provider"]} on port {port}"',
    ))

    return ops


register(UseCase(
    name="doh",
    description="DNS-over-HTTPS via https-dns-proxy for encrypted DNS resolution",
    packages=[
        "https-dns-proxy",
        "luci-app-https-dns-proxy",
    ],
    packages_remove=[],
    params={
        "provider": ParamDef(type=str, default="cloudflare",
            description="DNS provider: cloudflare, google, quad9, mullvad, adguard, or custom URL"),
        "listen_port": ParamDef(type=int, default=5053,
            description="Local DoH proxy listen port"),
    },
    build_configure=lambda p: render_shell(_build_doh_ops(p)),
    build_configure_ops=_build_doh_ops,
    requires_capabilities=[],
    test_status="untested",
    tested_notes="UCI from OpenWrt wiki DoH guide",
    configure_via="ssh",
))
