"""mwan3 — multi-WAN failover and load balancing."""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ShellCommand, UciAddList, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    primary = str(params.get("primary", "wan"))
    secondary = str(params.get("secondary", "usbwan"))
    policy = str(params.get("policy", "failover"))
    track_ips = params.get("track_ips", ["1.0.0.1", "1.1.1.1", "8.8.8.8", "8.8.4.4"])
    if isinstance(track_ips, str):
        track_ips = [track_ips]
    track_ips = [str(ip) for ip in track_ips]
    return {
        "primary": primary,
        "secondary": secondary,
        "policy": policy,
        "track_ips": track_ips,
    }


def _build_mwan3_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    primary = r["primary"]
    secondary = r["secondary"]
    policy = r["policy"]
    track_ips = r["track_ips"]

    if policy == "balanced":
        primary_metric, primary_weight = "1", "2"
        secondary_metric, secondary_weight = "1", "1"
    else:
        primary_metric, primary_weight = "1", "1"
        secondary_metric, secondary_weight = "2", "1"

    pm = f"{primary}_m{primary_metric}_w{primary_weight}"
    sm = f"{secondary}_m{secondary_metric}_w{secondary_weight}"
    pol_name = f"{primary}_policy"

    ops: list[Op] = []

    # Header
    ops.append(Comment(text="--- mwan3 multi-WAN ---"))

    # Delete existing config
    ops.append(ShellCommand(command="uci -q delete mwan3 >/dev/null 2>&1 || true"))
    ops.append(BlankLine())

    # --- Primary interface ---
    ops.append(ShellCommand(command="uci set mwan3.wan=interface"))
    ops.append(UciSet(config="mwan3", section="wan", values={"enabled": "1"}))
    for ip in track_ips:
        ops.append(ShellCommand(command=f"list track_ip '{ip}'"))
    ops.append(UciSet(config="mwan3", section="wan", values={
        "family": "ipv4",
        "reliability": "1",
        "count": "1",
        "timeout": "2",
        "interval": "5",
        "down": "3",
        "up": "8",
    }))
    ops.append(BlankLine())

    # --- Secondary interface ---
    ops.append(ShellCommand(command=f"uci set mwan3.{secondary}=interface"))
    ops.append(UciSet(config="mwan3", section=secondary, values={"enabled": "1"}))
    for ip in track_ips:
        ops.append(ShellCommand(command=f"list track_ip '{ip}'"))
    ops.append(UciSet(config="mwan3", section=secondary, values={
        "family": "ipv4",
        "reliability": "1",
        "count": "1",
        "timeout": "2",
        "interval": "5",
        "down": "3",
        "up": "8",
    }))
    ops.append(BlankLine())

    # --- Members ---
    ops.append(ShellCommand(command=f"uci set mwan3.{pm}=member"))
    ops.append(UciSet(config="mwan3", section=pm, values={
        "interface": primary,
        "metric": primary_metric,
        "weight": primary_weight,
    }))

    ops.append(ShellCommand(command=f"uci set mwan3.{sm}=member"))
    ops.append(UciSet(config="mwan3", section=sm, values={
        "interface": secondary,
        "metric": secondary_metric,
        "weight": secondary_weight,
    }))
    ops.append(BlankLine())

    # --- Policy ---
    ops.append(ShellCommand(command=f"uci set mwan3.{pol_name}=policy"))
    ops.append(UciAddList(config="mwan3", section=pol_name, option="use_member", value=pm))
    ops.append(UciAddList(config="mwan3", section=pol_name, option="use_member", value=sm))
    ops.append(UciSet(config="mwan3", section=pol_name, values={"last_resort": "default"}))

    ops.append(BlankLine())

    # --- Rules ---
    ops.append(ShellCommand(command="uci set mwan3.default_rule_v4=rule"))
    ops.append(UciSet(config="mwan3", section="default_rule_v4", values={
        "dest_ip": "0.0.0.0/0",
        "use_policy": pol_name,
        "family": "ipv4",
    }))

    ops.append(ShellCommand(command="uci set mwan3.https_rule=rule"))
    ops.append(UciSet(config="mwan3", section="https_rule", values={
        "dest_port": "443",
        "proto": "tcp",
        "sticky": "1",
        "use_policy": pol_name,
    }))

    ops.append(BlankLine())

    # --- Commit and restart ---
    ops.append(UciCommit(config="mwan3"))
    ops.append(ShellCommand(command="/etc/init.d/mwan3 restart 2>/dev/null || true"))
    ops.append(ShellCommand(command=f'echo "mwan3 configured: {primary} (primary) + {secondary} ({policy})"'))

    return ops


register(UseCase(
    name="mwan3",
    description="Multi-WAN failover or load balancing via mwan3",
    packages=[
        "mwan3",
    ],
    params={
        "primary": ParamDef(type=str, default="wan",
                            description="Primary WAN interface name"),
        "secondary": ParamDef(type=str, default="usbwan",
                              description="Secondary WAN interface name (e.g. usbwan from USB tethering)"),
        "policy": ParamDef(type=str, default="failover",
                           description="Routing policy: failover or balanced"),
        "track_ips": ParamDef(type=list, default=["1.0.0.1", "1.1.1.1", "8.8.8.8", "8.8.4.4"],
                              description="IPs to ping for connectivity tracking"),
    },
    test_status="untested",
    tested_notes="",
    build_configure=lambda p: render_shell(_build_mwan3_ops(p)),
    build_configure_ops=_build_mwan3_ops,
))
