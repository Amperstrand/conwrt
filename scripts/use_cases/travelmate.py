"""travelmate — travel router auto-connect for hotel/airport WiFi."""
from __future__ import annotations

import glob
import subprocess
from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciAddList, UciCommit, UciSet, render_shell
from profile.uci_helpers import uci_add_to_wan_zone, uci_cleanup_sections

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    radio = params.get("radio", "radio0")
    timeout = params.get("timeout", 60)
    retry = params.get("retry", 5)
    captive = params.get("captive", True)
    captive_flag = "1" if captive else "0"
    return {
        "radio": radio,
        "timeout": timeout,
        "retry": retry,
        "captive": captive,
        "captive_flag": captive_flag,
    }


def _host_saved_wifis() -> list[dict[str, str]]:
    """Uplinks from the deploying host's saved WiFi profiles.

    Reads NetworkManager keyfiles from /etc and /run (one passwordless
    ``sudo -n`` pass — the keyfiles are root-only). Personal networks
    only: WPA2-PSK (psk2), WPA3-SAE (sae), and open; enterprise (wpa-eap)
    and credential-less entries are skipped. SSIDs/passwords are used to
    build the device script and never logged.
    """
    try:
        out = subprocess.run(
            ["sudo", "-n", "sh", "-c",
             "for f in /etc/NetworkManager/system-connections/* "
             "/run/NetworkManager/system-connections/*; do "
             "echo ==F==; cat \"$f\"; done"],
            capture_output=True, text=True, check=True, timeout=30,
        ).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            "seed_from_host: cannot read NetworkManager profiles "
            "(needs passwordless sudo -n)"
        ) from exc
    uplinks: list[dict[str, str]] = []
    for stanza in out.split("==F=="):
        if "[wifi]" not in stanza:
            continue
        vals: dict[str, str] = {}
        for line in stanza.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                vals.setdefault(key.strip(), value.strip().strip('"'))
        ssid = vals.get("ssid", "")
        if not ssid:
            continue
        psk = vals.get("psk", "")
        key_mgmt = vals.get("key-mgmt", "")
        if key_mgmt == "sae":
            encryption = "sae"
        elif key_mgmt == "wpa-psk":
            encryption = "psk2"
        elif not key_mgmt and not psk:
            encryption = "none"
        else:
            continue  # wpa-eap and friends: not seedable
        if encryption != "none" and not psk:
            continue
        uplinks.append({
            "ssid": ssid,
            "psk": psk,
            "encryption": encryption,
            "radio": "radio1" if vals.get("band") == "a" else "radio0",
        })
    return uplinks


def _seeded_uplink_ops(uplinks: list[dict[str, Any]]) -> list[Op]:
    """Uplink sections in travelmate 2.4.x's own `setup` shape.

    Mirrors the 2.x Rust render op-for-op (trm_iface gate, trm_wwan +
    trm_wwan6 pair, wan-zone membership by NAME, one sta wifi-iface per
    saved network). Radio is literal — pick per-device in config.
    """
    ops: list[Op] = [
        Comment(text="--- Seeded uplinks (travelmate setup shape) ---"),
        ShellCommand(command="uci set network.trm_wwan=interface"),
        UciSet(config="network", section="trm_wwan", values={
            "proto": "dhcp",
            "metric": "100",
        }),
        ShellCommand(command="uci set network.trm_wwan6=interface"),
        UciSet(config="network", section="trm_wwan6", values={
            "device": "@trm_wwan",
            "proto": "dhcpv6",
        }),
        uci_add_to_wan_zone("trm_wwan"),
        uci_add_to_wan_zone("trm_wwan6"),
    ]
    for i, up in enumerate(uplinks, start=1):
        iface = f"trm_uplink{i}"
        values = {
            "device": up.get("radio", "radio0"),
            "mode": "sta",
            "network": "trm_wwan",
            "ssid": str(up["ssid"]),
            "encryption": up.get("encryption", "psk2"),
        }
        if values["encryption"] != "none":
            values["key"] = str(up.get("psk", ""))
        ops.append(ShellCommand(command=f"uci set wireless.{iface}=wifi-iface"))
        ops.append(UciSet(config="wireless", section=iface, values=values))
    ops.extend([
        UciCommit(config="network"),
        UciCommit(config="wireless"),
        ShellCommand(command="wifi reload; ubus call network.interface.trm_wwan up 2>/dev/null; true"),
        BlankLine(),
    ])
    return ops


def _build_travelmate_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)

    uplinks: list[dict[str, Any]] = [dict(u) for u in params.get("uplinks") or []]
    if params.get("seed_from_host"):
        uplinks.extend(_host_saved_wifis())

    global_values = {
        "trm_enabled": "1",
        "trm_automatic": "1",
        "trm_captive": r["captive_flag"],
        "trm_timeout": str(r["timeout"]),
        "trm_retry": str(r["retry"]),
        "trm_radio": r["radio"],
    }
    if uplinks:
        global_values["trm_iface"] = "trm_wwan"

    ops: list[Op] = [
        Comment(text="--- Travelmate travel router ---"),
        UciSet(config="travelmate", section="global", values=global_values),
    ]
    if uplinks:
        ops.extend(_seeded_uplink_ops(uplinks))
    ops.extend([
        UciCommit(config="travelmate"),
        ServiceAction(name="travelmate", action="enable"),
        ServiceAction(name="travelmate", action="restart"),
    ])
    if uplinks:
        ops.append(ShellCommand(
            command=f'echo "Travelmate configured: auto-connect on {r["radio"]} ({len(uplinks)} uplinks)"'))
    else:
        ops.append(ShellCommand(
            command=f'echo "Travelmate configured: auto-connect on {r["radio"]}"'))
    return ops


register(UseCase(
    name="travelmate",
    description="Travel router auto-connect for captive portal WiFi (hotels, airports)",
    packages=[
        "travelmate",
        "luci-app-travelmate",
        "ca-bundle",
        "ca-certificates",
    ],
    packages_remove=[],
    params={
        "radio": ParamDef(type=str, default="radio0",
                          description="WiFi radio for upstream scanning"),
        "timeout": ParamDef(type=int, default=60,
                            description="Overall retry timeout in seconds"),
        "retry": ParamDef(type=int, default=5,
                          description="Retry count to find a suitable uplink"),
        "captive": ParamDef(type=bool, default=True,
                            description="Enable captive portal detection"),
        "uplinks": ParamDef(type=list, default=[],
                            description="Hardcoded uplink networks: "
                            "[{ssid=..., psk=..., encryption=psk2|sae|none, radio=radio0}, ...] "
                            "(optional)"),
        "seed_from_host": ParamDef(type=bool, default=False,
                                   description="Seed uplinks from the deploying host's saved "
                                   "WiFi profiles (NetworkManager; needs passwordless sudo). "
                                   "Off by default — credentials never leave the host unless "
                                   "you ask"),
    },
    build_configure=lambda p: render_shell(_build_travelmate_ops(p)),
    build_configure_ops=_build_travelmate_ops,
    test_status="tested",
    tested_notes="Config generation verified. WiFi scanning needs physical hardware.",
    requires_capabilities=["wifi"],
))
