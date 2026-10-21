"""Build a ProfilePlan from config.toml and optional model capabilities."""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path
from typing import Optional

from config import ConwrtConfig, read_ssh_pubkey, strip_key_comment
from model_loader import load_model
from profile.ops import Op, ServiceAction, ShellCommand, UciCommit, UciSet
from profile.uci_helpers import uci_cleanup_sections
from profile.plan import ProfileMode, ProfilePlan, ProfileStep, StepKind
from profile.wifi import (
    build_mgmt_wifi_script,
    wifi_ap_firstboot_script,
    wifi_sta_firstboot_script,
    wwan_setup_firstboot,
    wwan_setup_shell,
    wwan_setup_ops,
)
from ssh_utils import DROPBEAR_AUTH_KEYS_PATH
from shell_safe import sh_quote

_VALID_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')


def _ssh_key_firstboot(keys: list[str]) -> str:
    # Runs inside ONE /etc/uci-defaults script consumed by uci_apply_defaults
    # (base-files: `( . file ) && applied` -> rm -f on success). Two #229 rules:
    #  - exit non-zero unless the key provably landed: a failed script is
    #    retained and retried next boot; a consumed one never runs again.
    #  - never disable password auth before the key file is verified —
    #    a half-applied script must not brick SSH.
    dropbear_dir = DROPBEAR_AUTH_KEYS_PATH.rsplit("/", 1)[0]
    lines = [f"mkdir -p {dropbear_dir}", f"chmod 700 {dropbear_dir}"]
    for i, key in enumerate(keys):
        op = ">" if i == 0 else ">>"
        lines.append(f"printf '%s\\n' {sh_quote(key)} {op} {DROPBEAR_AUTH_KEYS_PATH}")
    if not keys:
        return "\n".join(lines)
    lines.append(f"chmod 600 {DROPBEAR_AUTH_KEYS_PATH}")
    # P1 (#253 review): dropbear rejects ALL keys when /etc/dropbear (or the
    # file) is non-root-owned — a preserved-overlay incident left it
    # 1000:1000 in the field, and chmod alone would not fix that.
    lines.append(f"chown 0:0 {dropbear_dir} {DROPBEAR_AUTH_KEYS_PATH}")
    lines.append(
        f"grep -qF {sh_quote(keys[0])} {DROPBEAR_AUTH_KEYS_PATH} 2>/dev/null"
        " || { echo 'conwrt-ssh: authorized_keys not applied;"
        " keeping password auth, will retry next boot' >&2; exit 1; }"
    )
    # Key verified => key-only auth (#155): the x1860 incident unit came up
    # with password-attempt surface enabled by default.
    lines += [
        "uci set dropbear.@dropbear[0].PasswordAuth='off'",
        "uci set dropbear.@dropbear[0].RootPasswordAuth='off'",
        "uci commit dropbear",
        # P2 (#253 review): gate on a VALUE READBACK, not the uci exit codes
        # — a failed commit must fail the script so uci_apply_defaults
        # retains it for retry instead of consuming a half-applied boot.
        "[ \"$(uci get dropbear.@dropbear[0].PasswordAuth 2>/dev/null)\" = 'off' ]"
        " || { echo 'conwrt-ssh: PasswordAuth readback failed;"
        " keeping script for retry' >&2; exit 1; }",
        # Defensive: uci-defaults normally run before dropbear starts, but a
        # re-executed (retained) script may meet a running dropbear (#229).
        "/etc/init.d/dropbear restart >/dev/null 2>&1 || true",
    ]
    return "\n".join(lines)


def _ssh_key_ops(keys: list[str]) -> list[Op]:
    # Ops mirror of _ssh_key_firstboot, incl. the #229 verify-gate: the
    # grep op carries its own `|| exit 1` because render_shell joins ops
    # as plain lines — without it a failed gate would not stop the uci
    # ops from disabling password auth.
    dropbear_dir = DROPBEAR_AUTH_KEYS_PATH.rsplit("/", 1)[0]
    ops: list[Op] = [
        ShellCommand(f"mkdir -p {dropbear_dir}"),
        ShellCommand(f"chmod 700 {dropbear_dir}"),
    ]
    for i, key in enumerate(keys):
        op = ">" if i == 0 else ">>"
        ops.append(ShellCommand(f"printf '%s\\n' {sh_quote(key)} {op} {DROPBEAR_AUTH_KEYS_PATH}"))
    if not keys:
        return ops
    ops.append(ShellCommand(f"chmod 600 {DROPBEAR_AUTH_KEYS_PATH}"))
    ops.append(
        ShellCommand(
            f"chown 0:0 {dropbear_dir} {DROPBEAR_AUTH_KEYS_PATH}"
        )
    )
    ops.append(
        ShellCommand(
            f"grep -qF {sh_quote(keys[0])} {DROPBEAR_AUTH_KEYS_PATH} 2>/dev/null || exit 1"
        )
    )
    ops += [
        UciSet(config="dropbear", section="@dropbear[0]", values={
            "PasswordAuth": "off",
            "RootPasswordAuth": "off",
        }),
        UciCommit(config="dropbear"),
        ShellCommand(
            "[ \"$(uci get dropbear.@dropbear[0].PasswordAuth 2>/dev/null)\" = 'off' ]"
            " || exit 1"
        ),
        ServiceAction(name="dropbear", action="restart"),
    ]
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
    "uci set firewall.allow_ssh_wan=rule",
    "uci set firewall.allow_ssh_wan.name='Allow-SSH-WAN'",
    "uci set firewall.allow_ssh_wan.src='wan'",
    "uci set firewall.allow_ssh_wan.dest_port='22'",
    "uci set firewall.allow_ssh_wan.proto='tcp'",
    "uci set firewall.allow_ssh_wan.target='ACCEPT'",
    "uci commit firewall",
    "uci set dropbear.@dropbear[0].PasswordAuth='off'",
    "uci set dropbear.@dropbear[0].RootPasswordAuth='off'",
    "uci commit dropbear",
])

_WAN_SSH_OPS: list[Op] = [
    uci_cleanup_sections("firewall", "name='Allow-SSH-WAN'"),
    ShellCommand(command="uci set firewall.allow_ssh_wan=rule"),
    UciSet(config="firewall", section="allow_ssh_wan", values={
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


# conwrt#228 (ADR-0013): opt-in TOFB image feature. The device script is
# NOT a one-shot uci-defaults shape — TOFB is marker-gated
# (/etc/conwrt/tofb.done absent) and must run at EVERY boot until enrolled,
# so the fragment installs a procd init service that carries the loop; the
# script self-no-ops (exit 0 on the marker) once enrolled.
TOFB_DEVICE_DEST = "/etc/conwrt/tofb-device.sh"
TOFB_INITD_DEST = "/etc/init.d/tofb"

_TOFB_DEVICE_SRC = Path(__file__).resolve().parent.parent / "tofb-device.sh"

_TOFB_INITD = """#!/bin/sh /etc/rc.common
# conwrt#228 — TOFB procd service (ADR-0013), installed by the profile
# uci-defaults fragment. Runs the marker-gated device script at every
# boot; after enrollment it is a cheap no-op exec. No respawn on purpose:
# endpoint-death semantics (3 wrong codes -> down until power cycle,
# ADR-0013 failure modes) outrank transient-restart comfort.
START=95
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /etc/conwrt/tofb-device.sh
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
"""


def _tofb_firstboot() -> str:
    """Build the uci-defaults fragment that installs + enables TOFB (#228).

    Verify-then-commit (#229/#235): each file write is checksum-gated
    against a digest baked at build time (sha256 of the exact bytes; host
    `sha256sum scripts/tofb-device.sh` prints the shipped device digest),
    and `enable` runs only after both files are proven intact. Any failure
    exits 1 so the uci-defaults script is retained and retried on the next
    boot instead of half-applying. On-device behaviors (init timing at
    START=95 vs link-local/dropbearkey availability, rc.common `enabled`
    semantics) are NEEDS-BENCH per ADR-0013.
    """
    device = _TOFB_DEVICE_SRC.read_bytes()
    initd = _TOFB_INITD.encode()
    return "\n".join([
        "mkdir -p /etc/conwrt",
        f"echo '{base64.b64encode(device).decode()}' | base64 -d > {TOFB_DEVICE_DEST}",
        f"[ \"$(sha256sum {TOFB_DEVICE_DEST} | awk '{{print $1}}')\" = '{hashlib.sha256(device).hexdigest()}' ] || exit 1",
        f"sh -n {TOFB_DEVICE_DEST} || exit 1",
        f"chmod 700 {TOFB_DEVICE_DEST}",
        f"echo '{base64.b64encode(initd).decode()}' | base64 -d > {TOFB_INITD_DEST}",
        f"[ \"$(sha256sum {TOFB_INITD_DEST} | awk '{{print $1}}')\" = '{hashlib.sha256(initd).hexdigest()}' ] || exit 1",
        f"chmod 755 {TOFB_INITD_DEST}",
        f"{TOFB_INITD_DEST} enable || exit 1",
        f"{TOFB_INITD_DEST} enabled || exit 1",
    ])


def build_plan(
    cfg: ConwrtConfig,
    mode: ProfileMode = "preview",
    model_capabilities: Optional[list[str]] = None,
    ssh_key_path: Optional[str] = None,
    password: Optional[str] = None,
    wan_ssh: bool = False,
    tofb: bool = False,
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
    effective_hostname_pattern = hostname_pattern or cfg.hostname_pattern or "model_mac"

    model_data: dict = {}
    if model_id:
        try:
            model_data = load_model(model_id)
        except FileNotFoundError:
            pass
    model_lan_subnet_raw = model_data.get("lan_subnet", "")
    model_lan_subnet = model_lan_subnet_raw
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
                skipped_reason="invalid hostname (must be alphanumeric + hyphens, max 63 chars)",
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
        # Create wwan interface for WiFi STA WAN
        wwan_fb = wwan_setup_firstboot()
        wwan_ssh = wwan_setup_shell()
        steps.append(ProfileStep(
            kind=StepKind.WWAN_SETUP,
            label="WWAN interface for WiFi STA",
            firstboot_script=wwan_fb,
            configure_script=wwan_ssh,
            ops=wwan_setup_ops(),
        ))
        steps.append(ProfileStep(
            kind=StepKind.WIFI_STA,
            label=f"WiFi STA: {sta.ssid} ({sta.band})",
            firstboot_script=wifi_sta_firstboot_script(
                sta.band, sta.ssid, sta.encryption, key=sta.key, network="wwan",
                country_code=cfg.country_code,
            ),
            wifi_detect_band=sta.band,
            wifi_role="sta",
            wifi_params={
                "ssid": sta.ssid,
                "encryption": sta.encryption,
                "key": sta.key,
                "network": "wwan",
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
            include_in_asu=True,
                    include_in_post_install=False,
                ))
                continue

        uc_params = dict(uc_cfg.params)
        resolved = _apply_defaults(uc.name, uc_params)
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

    if effective_lan_ip_mode == "keep":
        pass
    elif effective_lan_ip_mode == "mac-hash":
        # On DSA devices (most modern OpenWrt hardware), eth0 is the CPU-facing
        # port with an unstable MAC.  br-lan always carries the factory base MAC.
        _mac_src_fb = (
            "_mac=$(cat /sys/class/net/br-lan/address 2>/dev/null)"
            "; [ -z \"$_mac\" ] && _mac=$(cat /sys/class/net/eth0/address 2>/dev/null)"
        )
        _mac_src_ssh = (
            '_mac=$(cat /sys/class/net/br-lan/address 2>/dev/null)'
            '; [ -z "$_mac" ] && _mac=$(cat /sys/class/net/eth0/address 2>/dev/null)'
        )
        # Derive two subnet octets from MAC sha256 hash, last octet always 1.
        # Matches Python: mac_to_subnet_octets() in mac_hash.py
        _hash_derive = (
            "_mac_clean=$(printf '%s' \"$_mac\" | tr -d ':')"
            "; _hash=$(printf '%s' \"$_mac_clean\" | sha256sum)"
            "; _o2=$(printf '%d' 0x$(printf '%s' \"$_hash\" | cut -c1-8))"
            "; _o2=$((_o2 % 250 + 1))"
            "; _o3=$(printf '%d' 0x$(printf '%s' \"$_hash\" | cut -c9-16))"
            "; _o3=$((_o3 % 250 + 1))"
        )
        _mac_ip_fb = "\n".join([
            f"{_mac_src_fb}",
            _hash_derive.replace("; ", "\n"),
            'uci set network.lan.ipaddr="10.$_o2.$_o3.1"',
            # Netmask MUST be explicit: 24.10 netifd defaulted a missing
            # netmask to /24, but 25.12 defaults to /32 — which leaves the
            # device receive-only-silent (ARP answers, no on-link replies).
            # Incident: conwrt-lab x1860-1 incident_2026_10_13_recovery (#151).
            'uci set network.lan.netmask="255.255.255.0"',
            "uci commit network",
        ])
        _mac_ip_ssh = " ; ".join([
            f"{_mac_src_ssh}",
            _hash_derive,
            'uci set network.lan.ipaddr="10.$_o2.$_o3.1"',
            'uci set network.lan.netmask="255.255.255.0"',
            "uci commit network",
        ])
        steps.append(ProfileStep(
            kind=StepKind.LAN_IP_MAC_HASH,
            label="LAN IP → 10.<mac-hash>.<mac-hash>.1",
            firstboot_script=_mac_ip_fb,
            configure_script=_mac_ip_ssh,
            include_in_post_install=True,
            ops=[
                ShellCommand(f"{_mac_src_fb}"),
                ShellCommand("_mac_clean=$(printf '%s' \"$_mac\" | tr -d ':')"),
                ShellCommand("_hash=$(printf '%s' \"$_mac_clean\" | sha256sum)"),
                ShellCommand("_o2=$(printf '%d' 0x$(printf '%s' \"$_hash\" | cut -c1-8))"),
                ShellCommand("_o2=$((_o2 % 250 + 1))"),
                ShellCommand("_o3=$(printf '%d' 0x$(printf '%s' \"$_hash\" | cut -c9-16))"),
                ShellCommand("_o3=$((_o3 % 250 + 1))"),
                ShellCommand('uci set network.lan.ipaddr="10.$_o2.$_o3.1"'),
                ShellCommand('uci set network.lan.netmask="255.255.255.0"'),
                ShellCommand("uci commit network"),
            ],
        ))
    elif cfg.lan_ip:
        _lan_fb = (
            f"uci set network.lan.ipaddr={sh_quote(cfg.lan_ip)}"
            " && uci set network.lan.netmask='255.255.255.0'"
            " && uci commit network"
        )
        steps.append(ProfileStep(
            kind=StepKind.LAN_IP,
            label=f"LAN IP → {cfg.lan_ip}",
            firstboot_script=_lan_fb,
            configure_script=(
                f"uci set network.lan.ipaddr={sh_quote(cfg.lan_ip)}"
                " && uci set network.lan.netmask='255.255.255.0'"
            ),
            include_in_asu=True,
            ops=[
                UciSet(config="network", section="lan", values={
                    "ipaddr": cfg.lan_ip, "netmask": "255.255.255.0",
                }),
            ],
        ))

    if tofb:
        # Appended LAST on purpose: uci_apply_defaults deletes the whole
        # defaults file based on the LAST command's exit status, so a
        # failed TOFB install here retains every step for next-boot retry
        # (all earlier steps are idempotent re-runs) — the #229/#235
        # retention discipline.
        steps.append(ProfileStep(
            kind=StepKind.TOFB,
            label="TOFB first-boot enrollment service (opt-in)",
            firstboot_script=_tofb_firstboot(),
            include_in_post_install=False,
        ))

    plan.steps = steps
    return plan
