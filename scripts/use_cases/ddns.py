"""ddns — Dynamic DNS client via ddns-scripts (#5).

Keeps a hostname pointed at the router's dynamic WAN address: provider
map to ddns-scripts `service_name` values, token-charset validation on
everything that rides uci values, HTTPS-only updates, and the standard
check/force interval pair (300 s / 30 d defaults mirror the LuCI
defaults). Custom providers take an `update_url` instead of a mapped
service name.
"""
from __future__ import annotations

import re
from typing import Any

from profile.ops import Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register


# ddns-scripts service_name values (services directory).
_PROVIDERS: dict[str, str] = {
    "cloudflare": "cloudflare.com/v4",
    "duckdns": "duckdns.org",
    "noip": "noip.com",
    "dynu": "dynu.com",
    "desec": "desec.io",
}

_TOKEN_RE = re.compile(r"[A-Za-z0-9._:@/-]+")
# credentials may carry punctuation but no shell/uci quoting hazards
_SECRET_RE = re.compile(r"[A-Za-z0-9._:@/!#$%^&*+=~?<>|\\-]+")
_URL_RE = re.compile(r"https://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+")


def _token(value: str, field: str) -> str:
    if value and not _TOKEN_RE.fullmatch(value):
        raise ValueError(f"{field} contains unsafe characters: {value!r}")
    return value


def _secret(value: str, field: str) -> str:
    if not _SECRET_RE.fullmatch(value):
        raise ValueError(f"{field} contains unsafe characters: {value!r}")
    return value


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    provider = str(params.get("provider", "cloudflare"))
    if provider != "custom" and provider not in _PROVIDERS:
        raise ValueError(f"unknown ddns provider: {provider!r}")
    domain = _token(str(params["domain"]), "domain")
    if not domain:
        raise ValueError("domain is required")
    r: dict[str, Any] = {
        "provider": provider,
        "domain": domain,
        "username": _token(str(params.get("username", "")), "username"),
        "password": _secret(str(params["password"]), "password"),
        "check_interval": int(params.get("check_interval", 300)),
        "force_interval": int(params.get("force_interval", 2592000)),
    }
    if provider == "custom":
        url = str(params["update_url"])
        if not _URL_RE.fullmatch(url):
            raise ValueError(f"update_url must be an https URL token: {url!r}")
        r["update_url"] = url
    for k in ("check_interval", "force_interval"):
        if r[k] < 30:
            raise ValueError(f"{k} below the 30-second floor: {r[k]}")
    return r


def _build_ddns_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    ops: list[Op] = [Comment(text=f"--- Dynamic DNS ({r['provider']}) ---")]
    # fresh section: an aborted earlier session may have left a partial
    # ddns.myddns in /tmp/.uci (AGENTS.md staging-debris rule)
    ops.append(ShellCommand(command="uci -q delete ddns.myddns >/dev/null 2>&1 || true"))
    ops.append(ShellCommand(command="uci set ddns.myddns=service"))
    values: dict[str, Any] = {
        "enabled": "1",
        "domain": r["domain"],
        "username": r["username"],
        "password": r["password"],
        "use_https": "1",
        "lookup_host": r["domain"],
        "check_interval": str(r["check_interval"]),
        "check_unit": "seconds",
        "force_interval": str(r["force_interval"]),
        "force_unit": "seconds",
    }
    if r["provider"] == "custom":
        values["update_url"] = r["update_url"]
    else:
        values["service_name"] = _PROVIDERS[r["provider"]]
    ops.append(UciSet(config="ddns", section="myddns", values=values))
    ops.append(UciCommit(config="ddns"))
    ops.append(ServiceAction(name="ddns", action="enable"))
    ops.append(ServiceAction(name="ddns", action="restart"))
    return ops


register(UseCase(
    name="ddns",
    description="Dynamic DNS client (ddns-scripts) keeping a hostname on a dynamic WAN (#5)",
    packages=[
        "ddns-scripts",
        "luci-app-ddns",
        "curl",
        "ca-certificates",
    ],
    params={
        "provider": ParamDef(type=str, default="cloudflare",
                             description="ddns-scripts provider (or 'custom' with update_url)",
                             choices=tuple(_PROVIDERS) + ("custom",)),
        "domain": ParamDef(type=str, required=True,
                           description="FQDN to keep updated"),
        "username": ParamDef(type=str, default="",
                             description="account username (token for token providers)"),
        "password": ParamDef(type=str, required=True,
                             description="account password / API token"),
        "update_url": ParamDef(type=str, required=False,
                               description="custom provider update URL (provider='custom')"),
        "check_interval": ParamDef(type=int, default=300, min_value=30,
                                   description="IP check interval, seconds"),
        "force_interval": ParamDef(type=int, default=2592000, min_value=30,
                                   description="forced update interval, seconds"),
    },
    build_configure_ops=_build_ddns_ops,
    test_status="untested",
    post_install_notes="Verify with: logread -e ddns; the first update runs within check_interval.",
))
