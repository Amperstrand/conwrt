"""Build a ProfilePlan from config.toml and optional model capabilities."""
from __future__ import annotations

import base64
import re
from typing import Optional

from config import ConwrtConfig, read_ssh_pubkey, strip_key_comment
from model_loader import load_model
from profile.ops import Op, ShellCommand, UciAdd, UciCommit, UciSet
from profile.plan import ProfileMode, ProfilePlan, ProfileStep, StepKind
from profile.wifi import (
    build_mgmt_wifi_script,
    wifi_ap_firstboot_script,
    wifi_sta_firstboot_script,
)
from ssh_utils import DROPBEAR_AUTH_KEYS_PATH
from shell_safe import sh_quote

_VALID_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')


def _ssh_key_firstboot(keys: list[str]) -> str:
    lines = [f"mkdir -p {DROPBEAR_AUTH_KEYS_PATH.rsplit('/', 1)[0]}"]
    for i, key in enumerate(keys):
        op = ">" if i == 0 else ">>"
        lines.append(f"echo '{key}' {op} {DROPBEAR_AUTH_KEYS_PATH}")
    lines.append(f"chmod 600 {DROPBEAR_AUTH_KEYS_PATH}")
    return "\n".join(lines)


def _ssh_key_ops(keys: list[str]) -> list[Op]:
    ops: list[Op] = [ShellCommand(f"mkdir -p {DROPBEAR_AUTH_KEYS_PATH.rsplit('/', 1)[0]}")]
    for i, key in enumerate(keys):
        op = ">" if i == 0 else ">>"
        ops.append(ShellCommand(f"echo '{key}' {op} {DROPBEAR_AUTH_KEYS_PATH}"))
    ops.append(ShellCommand(f"chmod 600 {DROPBEAR_AUTH_KEYS_PATH}"))
    return ops


def _password_firstboot(password: str) -> str:
    pw_b64 = base64.b64encode(password.encode()).decode()
    return (
        f"printf '%s\\n%s\\n' \"$(echo '{pw_b64}' | base64 -d)\" "
        f"\"$(echo '{pw_b64}' | base64 -d)\" | passwd root"
    )


def _password_ops(password: str) -> list[Op]:
    return [ShellCommand(_password_firstboot(password))]


_WAN_SSH_SCRIPT = "\n".join([
    "uci add firewall rule",
    "uci set firewall.@rule[-1].name='Allow-SSH-WAN'",
    "uci set firewall.@rule[-1].src='wan'",
    "uci set firewall.@rule[-1].dest_port='22'",
    "uci set firewall.@rule[-1].proto='tcp'",
    "uci set firewall.@rule[-1].target='ACCEPT'",
    "uci commit firewall",
    "uci set dropbear.@dropbear[0].PasswordAuth='off'",
    "uci set dropbear.@dropbear[0].RootPasswordAuth='off'",
    "uci commit dropbear",
])

_WAN_SSH_OPS: list[Op] = [
    UciAdd(config="firewall", type="rule", values={
        "name": "Allow-SSH-WAN",
        "src": "wan",
        "dest_port": "22",
        "proto": "tcp",
        "target": "ACCEPT",
    }),
    UciCommit(config="firewall"),
    UciSet(config="dropbear", section="@dropbear[0]", values={
        "PasswordAuth": "off",
        "RootPasswordAuth": "off",
    }),
    UciCommit(config="dropbear"),
]

_CELLULAR_QMI_SCRIPT = "\n".join([
    "uci set network.wan.device='/dev/cdc-wdm0'",
    "uci set network.wan.proto='qmi'",
    "uci set network.wan.apn='auto'",
    "uci set network.wan.delay='15'",
    "uci commit network",
])

_CELLULAR_QMI_OPS: list[Op] = [
    UciSet(config="network", section="wan", values={
        "device": "/dev/cdc-wdm0",
        "proto": "qmi",
        "apn": "auto",
        "delay": "15",
    }),
    UciCommit(config="network"),
]

_CELLULAR_QMI_SSH = " && ".join([
    "uci set network.wan.device='/dev/cdc-wdm0'",
    "uci set network.wan.proto='qmi'",
    "uci set network.wan.apn='auto'",
    "uci set network.wan.delay='15'",
    "uci commit network",
    "ifup wan",
])


def _uc_packages_for_mode(uc, mode: ProfileMode) -> tuple[list[str], list[str]]:
    """Return (packages, remove) for this use case and plan mode."""
    via = uc.packages_via
    if not uc.packages:
        return [], list(uc.packages_remove)
    if via == "image":
        if mode == "asu_build":
            return list(uc.packages), list(uc.packages_remove)
        return [], list(uc.packages_remove)
    if via == "opkg":
        if mode in ("post_install", "preview"):
            return list(uc.packages), list(uc.packages_remove)
        return [], list(uc.packages_remove)
    # auto
    if mode == "asu_build":
        return list(uc.packages), list(uc.packages_remove)
    return list(uc.packages), list(uc.packages_remove)


def _configure_script_for_mode(uc, resolved: dict, mode: ProfileMode) -> str:
    script = uc.build_configure(resolved)
    if not script or not script.strip():
        return ""
    via = uc.configure_via
    if via == "firstboot":
        return script if mode == "asu_build" else ""
    if via == "ssh":
        return script if mode in ("post_install", "preview") else ""
    return script


def _firstboot_for_mode(uc, resolved: dict, mode: ProfileMode) -> str:
    via = uc.configure_via
    script = uc.build_configure(resolved)
    if not script or not script.strip():
        return ""
    if via == "ssh":
        return ""
    if via == "firstboot" or via == "both":
        if mode in ("asu_build", "preview"):
            return script
    return ""


_DHCP_DISABLE_SCRIPT = "\n".join([
    "uci set dhcp.lan.ignore='1'",
    "uci commit dhcp",
])

_DHCP_DISABLE_OPS: list[Op] = [
    UciSet(config="dhcp", section="lan", values={"ignore": "1"}),
    UciCommit(config="dhcp"),
]


def build_plan(
    cfg: ConwrtConfig,
    mode: ProfileMode = "preview",
    model_capabilities: Optional[list[str]] = None,
    ssh_key_path: Optional[str] = None,
    password: Optional[str] = None,
    wan_ssh: bool = False,
    extra_pub_keys: Optional[list[str]] = None,
    disable_dhcp: bool = False,
    hostname: str = "",
    wifi_disable: bool = False,
    lan_ip_mode: str = "",
    hostname_pattern: str = "",
    model_id: str = "",
) -> ProfilePlan:
    """Build an ordered profile plan from operator config."""
    caps = list(model_capabilities or [])
    plan = ProfilePlan(mode=mode, model_capabilities=caps)
    steps: list[ProfileStep] = []

    effective_lan_ip_mode = lan_ip_mode or cfg.lan_ip_mode
    effective_hostname_pattern = hostname_pattern or cfg.hostname_pattern

    model_data: dict = {}
    if model_id:
        try:
            model_data = load_model(model_id)
        except FileNotFoundError:
            pass
    model_lan_subnet = model_data.get("lan_subnet", "")
    if model_lan_subnet and "/" in model_lan_subnet:
        model_lan_subnet = model_lan_subnet.split("/")[0]
        parts = model_lan_subnet.split(".")
        if len(parts) == 4:
            model_lan_subnet = ".".join(parts[:3])
    model_hostname_prefix = model_data.get("hostname_prefix", "")
    if not model_hostname_prefix and model_id:
        segments = model_id.split("-")
        for seg in segments[1:]:
            if not seg.isdigit() and len(seg) > 2:
                model_hostname_prefix = seg
                break

    if disable_dhcp:
        steps.append(ProfileStep(
            kind=StepKind.DHCP_DISABLE,
            label="Disable DHCP server on LAN",
            firstboot_script=_DHCP_DISABLE_SCRIPT,
            configure_script=_DHCP_DISABLE_SCRIPT.replace("\n", " && "),
            ops=_DHCP_DISABLE_OPS,
        ))

    effective_hostname = hostname or cfg.hostname
    if effective_hostname_pattern == "model_mac" and model_hostname_prefix:
        _mac_hostname_fb = "\n".join([
            "_mac=$(cat /sys/class/net/eth0/address 2>/dev/null)",
            "_suffix=$(echo \"$_mac\" | tr -d ':\\n' | tail -c6)",
            f"uci set system.@system[0].hostname=\"{model_hostname_prefix}_$_suffix\"",
            "uci commit system",
        ])
        _mac_hostname_ssh = " && ".join([
            "_mac=$(cat /sys/class/net/eth0/address 2>/dev/null)",
            "_suffix=$(echo \"$_mac\" | tr -d ':\\n' | tail -c6)",
            f"uci set system.@system[0].hostname=\"{model_hostname_prefix}_$_suffix\"",
            "uci commit system",
        ])
        steps.append(ProfileStep(
            kind=StepKind.HOSTNAME,
            label=f"Hostname: {model_hostname_prefix}_<mac>",
            firstboot_script=_mac_hostname_fb,
            configure_script=_mac_hostname_ssh,
            ops=[
                ShellCommand("_mac=$(cat /sys/class/net/eth0/address 2>/dev/null)"),
                ShellCommand("_suffix=$(echo \"$_mac\" | tr -d ':\\n' | tail -c6)"),
                ShellCommand(f"uci set system.@system[0].hostname=\"{model_hostname_prefix}_$_suffix\""),
                ShellCommand("uci commit system"),
            ],
        ))
    elif effective_hostname:
        if _VALID_HOSTNAME_RE.match(effective_hostname):
            steps.append(ProfileStep(
                kind=StepKind.HOSTNAME,
                label=f"Hostname: {effective_hostname}",
                firstboot_script="\n".join([
                    f"uci set system.@system[0].hostname='{effective_hostname}'",
                    "uci commit system",
                ]),
                configure_script=" && ".join([
                    f"uci set system.@system[0].hostname='{effective_hostname}'",
                    "uci commit system",
                ]),
                ops=[
                    UciSet(config="system", section="@system[0]", values={
                        "hostname": effective_hostname,
                    }),
                    UciCommit(config="system"),
                ],
            ))
        else:
            steps.append(ProfileStep(
                kind=StepKind.HOSTNAME,
                label=f"Hostname: {effective_hostname}",
                skipped_reason=f"invalid hostname (must be alphanumeric + hyphens, max 63 chars)",
                include_in_asu=False,
                include_in_post_install=False,
            ))

    all_keys: list[str] = []
    if ssh_key_path:
        cleaned, source = read_ssh_pubkey(ssh_key_path)
        all_keys.append(cleaned)
        plan.ssh_key_cleaned = cleaned
        plan.ssh_key_source = source
    elif cfg.ssh_public_key_text:
        all_keys.append(strip_key_comment(cfg.ssh_public_key_text))
        plan.ssh_key_cleaned = all_keys[0]
    if extra_pub_keys:
        for k in extra_pub_keys:
            stripped = strip_key_comment(k.strip())
            if stripped and stripped not in all_keys:
                all_keys.append(stripped)
    elif len(cfg.ssh_all_keys) > 1:
        for k in cfg.ssh_all_keys[1:]:
            stripped = strip_key_comment(k)
            if stripped and stripped not in all_keys:
                all_keys.append(stripped)

    if all_keys:
        steps.append(ProfileStep(
            kind=StepKind.SSH_KEY,
            label="SSH public key",
            firstboot_script=_ssh_key_firstboot(all_keys),
            include_in_post_install=False,
            ops=_ssh_key_ops(all_keys),
        ))

    if password:
        steps.append(ProfileStep(
            kind=StepKind.PASSWORD,
            label="Root password",
            firstboot_script=_password_firstboot(password),
            configure_script=_password_firstboot(password),
            ops=_password_ops(password),
        ))

    if wan_ssh:
        steps.append(ProfileStep(
            kind=StepKind.WAN_SSH,
            label="WAN SSH (key-only)",
            firstboot_script=_WAN_SSH_SCRIPT,
            configure_script=_WAN_SSH_SCRIPT.replace("\n", " && "),
            ops=_WAN_SSH_OPS,
        ))

    if "cellular" in caps:
        steps.append(ProfileStep(
            kind=StepKind.CELLULAR,
            label="Cellular WAN (QMI, auto APN)",
            firstboot_script=_CELLULAR_QMI_SCRIPT,
            configure_script=_CELLULAR_QMI_SSH,
            ops=_CELLULAR_QMI_OPS,
        ))

    if cfg.mgmt_wifi:
        mgmt = build_mgmt_wifi_script(txpower=cfg.mgmt_wifi_txpower)
        steps.append(ProfileStep(
            kind=StepKind.MGMT_WIFI,
            label="Management WiFi AP",
            firstboot_script=mgmt,
            configure_script=mgmt.replace("\n", " && "),
        ))

    if cfg.wifi_sta:
        sta = cfg.wifi_sta
        steps.append(ProfileStep(
            kind=StepKind.WIFI_STA,
            label=f"WiFi STA: {sta.ssid} ({sta.band})",
            firstboot_script=wifi_sta_firstboot_script(
                sta.band, sta.ssid, sta.encryption, key=sta.key, network="wan",
                country_code=cfg.country_code,
            ),
            wifi_detect_band=sta.band,
            wifi_role="sta",
            wifi_params={
                "ssid": sta.ssid,
                "encryption": sta.encryption,
                "key": sta.key,
                "network": "wan",
                "country_code": cfg.country_code,
            },
        ))

    for i, ap in enumerate(cfg.wifi_aps):
        steps.append(ProfileStep(
            kind=StepKind.WIFI_AP,
            label=f"WiFi AP: {ap.ssid} ({ap.band})",
            firstboot_script=wifi_ap_firstboot_script(
                ap.band, ap.ssid, ap.encryption,
                key=ap.key, channel=ap.channel, network="lan",
                country_code=cfg.country_code,
            ),
            wifi_detect_band=ap.band,
            wifi_role="ap",
            wifi_params={
                "ssid": ap.ssid,
                "encryption": ap.encryption,
                "key": ap.key,
                "channel": ap.channel,
                "network": "lan",
                "index": i,
                "country_code": cfg.country_code,
            },
        ))

    if wifi_disable or cfg.wifi_disable:
        steps.append(ProfileStep(
            kind=StepKind.WIFI_DISABLE,
            label="Disable all WiFi radios",
            firstboot_script="\n".join([
                "for radio in $(uci show wireless | grep -o 'radio[0-9]*' | sort -u); do",
                "  uci set wireless.$radio.disabled='1'",
                "done",
                "uci commit wireless",
            ]),
            configure_script=" && ".join([
                "for radio in $(uci show wireless | grep -o 'radio[0-9]*' | sort -u); do uci set wireless.$radio.disabled='1'; done",
                "uci commit wireless",
            ]),
        ))

    from use_cases import apply_defaults as _apply_defaults
    from use_cases import registry as _uc_registry

    uc_reg = _uc_registry()

    for uc_cfg in cfg.use_cases:
        uc = uc_reg.get(uc_cfg.name)
        if uc is None:
            steps.append(ProfileStep(
                kind=StepKind.USE_CASE,
                label=f"use case: {uc_cfg.name}",
                use_case_name=uc_cfg.name,
                skipped_reason="unknown use case",
                include_in_asu=False,
                include_in_post_install=False,
            ))
            continue

        if caps and uc.requires_capabilities:
            missing = set(uc.requires_capabilities) - set(caps)
            if missing:
                steps.append(ProfileStep(
                    kind=StepKind.USE_CASE,
                    label=f"use case: {uc.name}",
                    use_case_name=uc.name,
                    skipped_reason=f"missing capabilities: {', '.join(sorted(missing))}",
                    include_in_asu=False,
                    include_in_post_install=False,
                ))
                continue

        resolved = _apply_defaults(uc.name, uc_cfg.params)
        pkgs, remove = _uc_packages_for_mode(uc, mode)
        fb = _firstboot_for_mode(uc, resolved, mode)
        cfg_script = _configure_script_for_mode(uc, resolved, mode)

        uc_ops: list[Op] = []
        if uc.build_configure_ops is not None:
            uc_ops = uc.build_configure_ops(resolved)

        steps.append(ProfileStep(
            kind=StepKind.USE_CASE,
            label=f"use case: {uc.name}",
            use_case_name=uc.name,
            firstboot_script=fb,
            configure_script=cfg_script,
            ops=uc_ops,
            opkg_packages=pkgs,
            opkg_remove=remove,
            include_in_asu=bool(fb or pkgs),
            include_in_post_install=bool(cfg_script or pkgs),
        ))

    if effective_lan_ip_mode == "mac-hash" and model_lan_subnet:
        _mac_ip_fb = "\n".join([
            "_mac=$(cat /sys/class/net/eth0/address 2>/dev/null)",
            "_mac_clean=$(echo \"$_mac\" | tr -d ':\\n')",
            "_host=$(printf '%d' 0x$(echo \"$_mac_clean\" | md5sum | cut -c1-8))",
            "_host=$((_host % 200 + 2))",
            f"uci set network.lan.ipaddr=\"{model_lan_subnet}.$_host\"",
            "uci commit network",
        ])
        _mac_ip_ssh = " && ".join([
            "_mac=$(cat /sys/class/net/eth0/address 2>/dev/null)",
            "_mac_clean=$(echo \"$_mac\" | tr -d ':\\n')",
            "_host=$(printf '%d' 0x$(echo \"$_mac_clean\" | md5sum | cut -c1-8))",
            "_host=$((_host % 200 + 2))",
            f"uci set network.lan.ipaddr=\"{model_lan_subnet}.$_host\"",
            "uci commit network",
        ])
        steps.append(ProfileStep(
            kind=StepKind.LAN_IP_MAC_HASH,
            label=f"LAN IP → {model_lan_subnet}.<mac-hash>",
            firstboot_script=_mac_ip_fb,
            configure_script=_mac_ip_ssh,
            include_in_post_install=True,
            wifi_params={"lan_subnet": model_lan_subnet},
            ops=[
                ShellCommand("_mac=$(cat /sys/class/net/eth0/address 2>/dev/null)"),
                ShellCommand("_mac_clean=$(echo \"$_mac\" | tr -d ':\\n')"),
                ShellCommand("_host=$(printf '%d' 0x$(echo \"$_mac_clean\" | md5sum | cut -c1-8))"),
                ShellCommand("_host=$((_host % 200 + 2))"),
                ShellCommand(f"uci set network.lan.ipaddr=\"{model_lan_subnet}.$_host\""),
                ShellCommand("uci commit network"),
            ],
        ))
    elif cfg.lan_ip and mode in ("post_install", "preview"):
        steps.append(ProfileStep(
            kind=StepKind.LAN_IP,
            label=f"LAN IP → {cfg.lan_ip}",
                configure_script=f"uci set network.lan.ipaddr={sh_quote(cfg.lan_ip)}",
            include_in_asu=False,
            ops=[
                UciSet(config="network", section="lan", values={"ipaddr": cfg.lan_ip}),
            ],
        ))

    plan.steps = steps
    return plan
