"""Build a ProfilePlan from config.toml and optional model capabilities."""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional

from config import ConwrtConfig, _strip_key_comment
from profile.plan import ProfileMode, ProfilePlan, ProfileStep, StepKind
from profile.wifi import (
    build_mgmt_wifi_script,
    wifi_ap_firstboot_script,
    wifi_sta_firstboot_script,
)


def _read_ssh_pubkey(path: str) -> tuple[str, str]:
    key_path = Path(path).expanduser()
    raw = key_path.read_text().strip()
    parts = raw.split()
    if len(parts) >= 2:
        cleaned = f"{parts[0]} {parts[1]}"
    else:
        cleaned = raw
    return cleaned, key_path.name


def _ssh_key_firstboot(keys: list[str]) -> str:
    lines = ["mkdir -p /etc/dropbear"]
    for i, key in enumerate(keys):
        op = ">" if i == 0 else ">>"
        lines.append(f"echo '{key}' {op} /etc/dropbear/authorized_keys")
    lines.append("chmod 600 /etc/dropbear/authorized_keys")
    return "\n".join(lines)


def _password_firstboot(password: str) -> str:
    pw_b64 = base64.b64encode(password.encode()).decode()
    return (
        f"printf '%s\\n%s\\n' \"$(echo '{pw_b64}' | base64 -d)\" "
        f"\"$(echo '{pw_b64}' | base64 -d)\" | passwd root"
    )


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

_CELLULAR_QMI_SCRIPT = "\n".join([
    "uci set network.wan.device='/dev/cdc-wdm0'",
    "uci set network.wan.proto='qmi'",
    "uci set network.wan.apn='auto'",
    "uci set network.wan.delay='15'",
    "uci commit network",
])

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


def build_plan(
    cfg: ConwrtConfig,
    mode: ProfileMode = "preview",
    model_capabilities: Optional[list[str]] = None,
    ssh_key_path: Optional[str] = None,
    password: Optional[str] = None,
    wan_ssh: bool = False,
    extra_pub_keys: Optional[list[str]] = None,
) -> ProfilePlan:
    """Build an ordered profile plan from operator config."""
    caps = list(model_capabilities or [])
    plan = ProfilePlan(mode=mode, model_capabilities=caps)
    steps: list[ProfileStep] = []

    all_keys: list[str] = []
    if ssh_key_path:
        cleaned, source = _read_ssh_pubkey(ssh_key_path)
        all_keys.append(cleaned)
        plan.ssh_key_cleaned = cleaned
        plan.ssh_key_source = source
    elif cfg.ssh_public_key_text:
        all_keys.append(_strip_key_comment(cfg.ssh_public_key_text))
        plan.ssh_key_cleaned = all_keys[0]
    if extra_pub_keys:
        for k in extra_pub_keys:
            stripped = _strip_key_comment(k.strip())
            if stripped and stripped not in all_keys:
                all_keys.append(stripped)
    elif len(cfg.ssh_all_keys) > 1:
        for k in cfg.ssh_all_keys[1:]:
            stripped = _strip_key_comment(k)
            if stripped and stripped not in all_keys:
                all_keys.append(stripped)

    if all_keys:
        steps.append(ProfileStep(
            kind=StepKind.SSH_KEY,
            label="SSH public key",
            firstboot_script=_ssh_key_firstboot(all_keys),
            include_in_post_install=False,
        ))

    if password:
        steps.append(ProfileStep(
            kind=StepKind.PASSWORD,
            label="Root password",
            firstboot_script=_password_firstboot(password),
            configure_script=_password_firstboot(password),
        ))

    if wan_ssh:
        steps.append(ProfileStep(
            kind=StepKind.WAN_SSH,
            label="WAN SSH (key-only)",
            firstboot_script=_WAN_SSH_SCRIPT,
            configure_script=_WAN_SSH_SCRIPT.replace("\n", " && "),
        ))

    if "cellular" in caps:
        steps.append(ProfileStep(
            kind=StepKind.CELLULAR,
            label="Cellular WAN (QMI, auto APN)",
            firstboot_script=_CELLULAR_QMI_SCRIPT,
            configure_script=_CELLULAR_QMI_SSH,
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

        steps.append(ProfileStep(
            kind=StepKind.USE_CASE,
            label=f"use case: {uc.name}",
            use_case_name=uc.name,
            firstboot_script=fb,
            configure_script=cfg_script,
            opkg_packages=pkgs,
            opkg_remove=remove,
            include_in_asu=bool(fb or pkgs),
            include_in_post_install=bool(cfg_script or pkgs),
        ))

    if cfg.lan_ip and mode in ("post_install", "preview"):
        steps.append(ProfileStep(
            kind=StepKind.LAN_IP,
            label=f"LAN IP → {cfg.lan_ip}",
            configure_script=f"uci set network.lan.ipaddr='{cfg.lan_ip}'",
            include_in_asu=False,
        ))

    plan.steps = steps
    return plan
