"""Renderers that turn a Flow into a host shell script or Markdown instructions.

Each Step kind maps to router-side ``Op``\\s (applied over SSH) and/or host-side
shell commands (run on the operator's machine: curl/scp). The shell target wraps
router ops in an ``ssh root@$IP sh <<EOF`` heredoc; the Markdown target emits
them as fenced blocks. Command text always flows through ``render_shell`` so the
shell and Markdown transports cannot drift.
"""
from __future__ import annotations

import os
from typing import Any

from profile.ops import (
    Comment,
    Op,
    ServiceAction,
    ShellCommand,
    UciCommit,
    UciSet,
    render_shell,
)
from profile.render_markdown import render_markdown
from profile.target import derive_target_profile
from shell_safe import sh_quote

from . import Flow, Step

_BAND_TO_RADIO = {"2.4ghz": "radio0", "5ghz": "radio1", "6ghz": "radio2"}


def _band_radio(band: str) -> str:
    return _BAND_TO_RADIO.get(band, "radio1")


def _wifi_sta_ops(step: Step, params: dict[str, Any]) -> list[Op]:
    band = str(params.get("upstream_band") or step.band or "5ghz")
    radio = _band_radio(band)
    ssid = str(params.get(step.ssid_param, ""))
    key = str(params.get(step.key_param, ""))
    default_ap = f"default_{radio}"
    ops: list[Op] = [
        Comment(f"WiFi STA uplink ({band}) — join upstream SSID"),
        UciSet(config="wireless", section=radio, values={"disabled": "0"}),
        ShellCommand(command=f"uci -q delete wireless.sta1; uci set wireless.sta1=wifi-iface"),
        UciSet(config="wireless", section="sta1", values={
            "device": radio, "mode": "sta", "ssid": ssid,
            "encryption": step.encryption, "key": key, "network": "wwan",
        }),
        UciSet(config="wireless", section=default_ap, values={"disabled": "1"}),
        ShellCommand(command="uci -q delete network.wwan; uci set network.wwan=interface"),
        UciSet(config="network", section="wwan", values={"proto": "dhcp"}),
        UciCommit(config="wireless"),
        UciCommit(config="network"),
        ShellCommand(command="wifi reload"),
    ]
    return ops


def _install_package(step: Step, target: dict[str, Any]) -> tuple[list[str], list[Op]]:
    if step.artifact_urls:
        url = step.artifact_urls.get(target["arch"], "")
    else:
        url = step.artifact_url
    if not url:
        return ([f"# no artifact URL for arch={target['arch']} ({step.package})"], [])
    filename = url.rsplit("/", 1)[-1]
    ext = os.path.splitext(filename)[1] or ".ipk"
    remote = f"/tmp/{filename}"
    pm = target["pkg_manager"]
    install = f"apk add --allow-untrusted {remote}" if pm == "apk" else f"opkg install {remote}"
    host = [
        f"curl -L -o {sh_quote(filename)} {sh_quote(url)}",
        f"scp -O {sh_quote(filename)} root@{target['default_ip']}:{remote}",
    ]
    native_ext = ".apk" if pm == "apk" else ".ipk"
    router: list[Op] = [Comment(f"install {step.package} ({pm})")]
    if ext != native_ext:
        router.append(Comment(f"WARNING: artifact is {ext} but {target['model_id']} uses {pm}; needs a {native_ext} build"))
    router.append(ShellCommand(command=install))
    return host, router


def _apply_use_case_ops(step: Step) -> list[Op]:
    from use_cases import get as get_use_case

    uc = get_use_case(step.use_case)
    if uc is None or uc.build_configure_ops is None:
        return [Comment(f"use case '{step.use_case}' unavailable or has no ops")]
    return list(uc.build_configure_ops(step.use_case_params))


def _password_ops() -> list[Op]:
    return [
        Comment("set a random root password (printed once)"),
        ShellCommand(
            command="PW=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16) "
            "&& echo \"root:$PW\" | chpasswd && echo \"root password: $PW\""
        ),
    ]


def _set_password_ops(step: Step) -> list[Op]:
    return [
        Comment("set root password"),
        ShellCommand(command=f"echo 'root:{step.password}' | chpasswd"),
    ]


def _hostname_ops(step: Step) -> list[Op]:
    return [
        Comment(f"set hostname to {step.hostname}"),
        UciSet(config="system", section="@system[0]", values={"hostname": step.hostname}),
        UciCommit(config="system"),
        ShellCommand(command=f"echo {sh_quote(step.hostname)} > /proc/sys/kernel/hostname"),
    ]


def _wan_ssh_ops() -> list[Op]:
    return [
        Comment("enable SSH on the WAN port"),
        ShellCommand(command="uci -q delete firewall.wan_ssh; uci set firewall.wan_ssh=rule"),
        UciSet(config="firewall", section="wan_ssh",
               values={"src": "wan", "dest_port": "22", "proto": "tcp", "target": "ACCEPT"}),
        UciCommit(config="firewall"),
        ServiceAction(name="firewall", action="restart"),
    ]


def _set_lan_ip_ops(target: dict[str, Any]) -> list[Op]:
    gw = target.get("lan_gateway", "")
    subnet = target.get("lan_subnet", "")
    if not gw:
        return [Comment("skip LAN move — model has no lan_subnet defined")]
    return [
        Comment(f"move LAN off 192.168.1.1 → {gw} ({subnet})"),
        UciSet(config="network", section="lan", values={"ipaddr": gw, "netmask": "255.255.255.0"}),
        UciCommit(config="network"),
        ShellCommand(command=f"(/etc/init.d/network restart &) ; echo 'LAN moving to {gw} — reconnect on that subnet'"),
    ]


def _step_parts(step: Step, target: dict[str, Any], params: dict[str, Any]) -> tuple[list[str], list[Op]]:
    if step.kind == "wifi_sta":
        return ([], _wifi_sta_ops(step, params))
    if step.kind == "install_package":
        return _install_package(step, target)
    if step.kind == "apply_use_case":
        return ([], _apply_use_case_ops(step))
    if step.kind == "password":
        return ([], _password_ops())
    if step.kind == "set_password":
        return ([], _set_password_ops(step))
    if step.kind == "hostname":
        return ([], _hostname_ops(step))
    if step.kind == "wan_ssh":
        return ([], _wan_ssh_ops())
    if step.kind == "set_lan_ip":
        return ([], _set_lan_ip_ops(target))
    return ([], [])  # "flash" and unknowns are documentation-only


def render_flow_shell(flow: Flow, model: dict[str, Any], params: dict[str, Any],
                      version: str | None = None) -> str:
    target = derive_target_profile(model, version=version)
    ip = target["default_ip"]
    out: list[str] = [
        "#!/bin/sh",
        f"# conwrt flow: {flow.name} on {target['model_id']}",
        f"# OpenWrt {target['version']} · {target['arch']} · {target['pkg_manager']}",
        f"# firmware: {target['firmware_url']}",
        "set -e",
        f"IP=${{IP:-{ip}}}",
        "",
    ]
    for step in flow.steps:
        out.append(f"# --- {step.title} ---")
        if step.kind == "flash":
            out.append(f"# {step.detail}")
            out.append(f"# flash with conwrt, e.g.: python3 scripts/conwrt.py --model-id {target['model_id']} --image <{target['version']} image>")
            out.append("")
            continue
        host_cmds, router_ops = _step_parts(step, target, params)
        out.extend(host_cmds)
        if router_ops:
            out.append(f"ssh root@$IP sh <<'CONWRT_EOF'")
            out.append(render_shell(router_ops))
            out.append("CONWRT_EOF")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def render_flow_markdown(flow: Flow, model: dict[str, Any], params: dict[str, Any],
                         version: str | None = None) -> str:
    target = derive_target_profile(model, version=version)
    out: list[str] = [
        f"# {flow.name} on {model.get('description', target['model_id'])}",
        "",
        f"> OpenWrt **{target['version']}** · arch `{target['arch']}` · "
        f"package manager `{target['pkg_manager']}`",
        f">",
        f"> Firmware: `{target['firmware_url']}`",
        "",
    ]
    for step in flow.steps:
        out.append(f"## {step.title}")
        out.append("")
        if step.detail:
            out.append(step.detail)
            out.append("")
        if step.kind == "flash":
            out.append("```sh")
            out.append(f"# flash with conwrt, then SSH back in once the router is at {target['default_ip']}")
            out.append(f"python3 scripts/conwrt.py --model-id {target['model_id']} --image <firmware.bin>")
            out.append("```")
            out.append("")
            continue
        host_cmds, router_ops = _step_parts(step, target, params)
        if host_cmds:
            out.append("```sh")
            out.extend(host_cmds)
            out.append("```")
            out.append("")
        if router_ops:
            out.append(render_markdown(router_ops))
    return "\n".join(out).rstrip() + "\n"
