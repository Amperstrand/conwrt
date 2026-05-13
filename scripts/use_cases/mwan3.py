"""mwan3 — multi-WAN failover and load balancing."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register


def _build_mwan3(params: dict[str, Any]) -> str:
    primary = params.get("primary", "wan")
    secondary = params.get("secondary", "usbwan")
    policy = params.get("policy", "failover")
    track_ips = params.get("track_ips", ["1.0.0.1", "1.1.1.1", "8.8.8.8", "8.8.4.4"])

    track_lines = "\n".join(
        f"\tlist track_ip '{ip}'" for ip in track_ips
    )

    if policy == "balanced":
        primary_metric, primary_weight = "1", "2"
        secondary_metric, secondary_weight = "1", "1"
    else:
        primary_metric, primary_weight = "1", "1"
        secondary_metric, secondary_weight = "2", "1"

    return textwrap.dedent(f"""\
        # --- mwan3 multi-WAN ---
        uci -q delete mwan3 >/dev/null 2>&1 || true

        uci set mwan3.wan=interface
        uci set mwan3.wan.enabled='1'
{track_lines}
        uci set mwan3.wan.family='ipv4'
        uci set mwan3.wan.reliability='1'
        uci set mwan3.wan.count='1'
        uci set mwan3.wan.timeout='2'
        uci set mwan3.wan.interval='5'
        uci set mwan3.wan.down='3'
        uci set mwan3.wan.up='8'

        uci set mwan3.{secondary}=interface
        uci set mwan3.{secondary}.enabled='1'
{track_lines}
        uci set mwan3.{secondary}.family='ipv4'
        uci set mwan3.{secondary}.reliability='1'
        uci set mwan3.{secondary}.count='1'
        uci set mwan3.{secondary}.timeout='2'
        uci set mwan3.{secondary}.interval='5'
        uci set mwan3.{secondary}.down='3'
        uci set mwan3.{secondary}.up='8'

        uci set mwan3.{primary}_m{primary_metric}_w{primary_weight}=member
        uci set mwan3.{primary}_m{primary_metric}_w{primary_weight}.interface='{primary}'
        uci set mwan3.{primary}_m{primary_metric}_w{primary_weight}.metric='{primary_metric}'
        uci set mwan3.{primary}_m{primary_metric}_w{primary_weight}.weight='{primary_weight}'

        uci set mwan3.{secondary}_m{secondary_metric}_w{secondary_weight}=member
        uci set mwan3.{secondary}_m{secondary_metric}_w{secondary_weight}.interface='{secondary}'
        uci set mwan3.{secondary}_m{secondary_metric}_w{secondary_weight}.metric='{secondary_metric}'
        uci set mwan3.{secondary}_m{secondary_metric}_w{secondary_weight}.weight='{secondary_weight}'

        uci set mwan3.{primary}_policy=policy
        uci add_list mwan3.{primary}_policy.use_member='{primary}_m{primary_metric}_w{primary_weight}'
        uci add_list mwan3.{primary}_policy.use_member='{secondary}_m{secondary_metric}_w{secondary_weight}'
        uci set mwan3.{primary}_policy.last_resort='default'

        uci set mwan3.default_rule_v4=rule
        uci set mwan3.default_rule_v4.dest_ip='0.0.0.0/0'
        uci set mwan3.default_rule_v4.use_policy='{primary}_policy'
        uci set mwan3.default_rule_v4.family='ipv4'

        uci set mwan3.https_rule=rule
        uci set mwan3.https_rule.dest_port='443'
        uci set mwan3.https_rule.proto='tcp'
        uci set mwan3.https_rule.sticky='1'
        uci set mwan3.https_rule.use_policy='{primary}_policy'

        uci commit mwan3
        /etc/init.d/mwan3 restart 2>/dev/null || true
        echo "mwan3 configured: {primary} (primary) + {secondary} ({policy})"
    """)


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
    build_defaults=_build_mwan3,
))
