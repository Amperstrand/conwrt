#!/usr/bin/env python3
# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
"""Configure router with config.toml profile via SSH."""

from __future__ import annotations

import os

import sys
from dataclasses import replace
from pathlib import Path

from conwrt.device_inventory import auto_detect_interface
from conwrt.device_credentials import (
    blank_password_probe,
    generate as generate_password,
    is_blank,
    mac_probe,
    record as record_password,
    set_password_cmd,
)
from conwrt.postflash import (
    _apply_profile_post_flash,
    _cfg_install_ssh_key,
    _record_configure_inventory,
    _resolve_configure_options,
)
import argparse
from flash.context import log
from ssh_utils import run_ssh

from config import WifiSTAConfig, load_config as _load_config
from profile.apply import verify_persistence as _verify_persistence
from conwrt.postflash import _client_ip_for_subnet

_CONWRT_DIR = str(Path(__file__).resolve().parent.parent)
if _CONWRT_DIR not in sys.path:
    sys.path.insert(0, _CONWRT_DIR)


def _sta_config_from_args(args: argparse.Namespace, cfg) -> "WifiSTAConfig | None":
    """Build a WifiSTAConfig from --sta-* flags, or None when --sta-ssid is absent."""
    ssid = getattr(args, "sta_ssid", None)
    if not ssid:
        return None
    existing = cfg.wifi_sta
    return WifiSTAConfig(
        band=getattr(args, "sta_band", None) or (existing.band if existing else "2.4ghz"),
        ssid=ssid,
        encryption=(getattr(args, "sta_encryption", None)
                    or (existing.encryption if existing else "psk2")),
        key=getattr(args, "sta_key", None) or (existing.key if existing else ""),
    )


def _ensure_root_password(
    ip: str,
    ssh_key: str | None,
    provided: str | None,
    model_id: str,
    log_fn=log,
) -> bool:
    """No managed device left with a blank root password after configure.

    A blank root password is the bench recovery primitive, but with
    system-auth services (uhttpd/LuCI) listening it is a remote-root hole
    on any shared or mesh interface. Setting a password only ADDS an auth
    method — installed SSH keys keep working, so this cannot lock us out
    (we refuse to touch devices with no key installed and no key in use,
    i.e. the bench pre-adoption state whose only door IS the blank
    password). Every issued password lands in the gitignored credential
    file keyed by MAC. Returns False when hardening could not complete.
    """
    probe = run_ssh(ip, blank_password_probe(), key=ssh_key)
    if not is_blank(probe.stdout):
        if provided:
            record_password(provided, mac=run_ssh(ip, mac_probe(), key=ssh_key).stdout.strip(),
                            model=model_id, ip=ip, source="configure-explicit")
            log_fn("  root password already set (provided password recorded for recovery)")
        return True
    keys_installed = run_ssh(
        ip, "wc -l < /etc/dropbear/authorized_keys 2>/dev/null || echo 0", key=ssh_key,
    ).stdout.strip()
    if ssh_key is None and (not keys_installed.isdigit() or int(keys_installed) == 0):
        log_fn("  ⚠ blank root password left in place: no SSH key installed and none in use — "
               "this looks like the bench pre-adoption state (blank password is its only door). "
               "Install a key first, then re-run configure to harden.")
        return False
    password = provided or generate_password()
    run_ssh(ip, set_password_cmd(password), key=ssh_key)
    after = run_ssh(ip, blank_password_probe(), key=ssh_key)
    if is_blank(after.stdout):
        log_fn("  ⚠ failed to set root password (still blank) — check device state")
        return False
    mac = run_ssh(ip, mac_probe(), key=ssh_key).stdout.strip()
    path = record_password(password, mac=mac, model=model_id, ip=ip, source="configure")
    log_fn(f"  root password was BLANK — random password set and recorded to {path} (mac={mac})")
    return True


def cmd_configure(args: argparse.Namespace) -> int:
    """Apply config.toml settings to a running OpenWrt router via SSH."""
    ip = args.ip
    port = getattr(args, "port", None)
    if port is not None:
        # venue-fed port: every nested ssh/scp in the apply stack reads it
        os.environ["CONWRT_SSH_PORT"] = str(port)
    cfg = _load_config()

    sta = _sta_config_from_args(args, cfg)
    if sta is not None:
        cfg = replace(cfg, wifi_sta=sta)

    password, ssh_key_path, ssh_pub_path, ssh_key_text, wan_ssh = _resolve_configure_options(
        args, cfg,
    )
    model_id = args.model_id
    interface = args.interface or auto_detect_interface() or ""
    effective_hostname = args.hostname or cfg.hostname
    effective_wifi_disable = args.wifi_disable or cfg.wifi_disable
    effective_lan_ip_mode = args.lan_ip_mode or cfg.lan_ip_mode
    effective_hostname_pattern = args.hostname_pattern or cfg.hostname_pattern

    log(f"Configuring router at {ip}...")

    old_client_ip = ""
    if interface and not args.dry_run:
        if Path(f"/sys/class/net/{interface}").exists():
            r = run_ssh(ip, "uci get network.lan.ipaddr 2>/dev/null || echo ''", key=ssh_key_path)
            current_lan = r.stdout.strip().split("/")[0]
            old_client_ip = _client_ip_for_subnet(current_lan)

    if args.dry_run:
        log("  (dry run — no changes will be made)")
        ip = _apply_profile_post_flash(
            ip, ssh_key=ssh_key_path, cfg=cfg, model_id=model_id or "",
            interface=interface, old_client_ip=old_client_ip,
            password=password or None,
            wan_ssh=wan_ssh,
            ssh_key_path=ssh_pub_path or None,
            dry_run=True,
            hostname=effective_hostname,
            wifi_disable=effective_wifi_disable,
            lan_ip_mode=effective_lan_ip_mode,
            hostname_pattern=effective_hostname_pattern,
            transport=getattr(args, "transport", "ssh"),
            ubus_user=getattr(args, "ubus_user", "root"),
            ubus_password=getattr(args, "ubus_password", ""),
        )
        if ssh_pub_path or ssh_key_text:
            print("  # SSH key: idempotent install via authorized_keys check")
        return 0

    if ssh_pub_path or ssh_key_text:
        _cfg_install_ssh_key(ip, key_path=ssh_pub_path, auth_key=ssh_key_path, ssh_key=ssh_key_text)

    ip = _apply_profile_post_flash(
        ip, ssh_key=ssh_key_path, cfg=cfg, model_id=model_id or "",
        interface=interface, old_client_ip=old_client_ip,
        password=password or None,
        wan_ssh=wan_ssh,
        ssh_key_path=ssh_pub_path or None,
        dry_run=False,
        hostname=effective_hostname,
        wifi_disable=effective_wifi_disable,
        lan_ip_mode=effective_lan_ip_mode,
        hostname_pattern=effective_hostname_pattern,
        transport=getattr(args, "transport", "ssh"),
        ubus_user=getattr(args, "ubus_user", "root"),
        ubus_password=getattr(args, "ubus_password", ""),
    )

    if not ip and not args.dry_run:
        log("  ⚠ Profile application failed (no IP). Aborting configure.")
        return 1

    if not args.dry_run:
        try:
            if not _ensure_root_password(
                ip, ssh_key=ssh_key_path, provided=password or None,
                model_id=model_id or "", log_fn=log,
            ):
                log("  ⚠ password hardening incomplete — configure reported as failed")
                return 1
        except Exception as exc:  # noqa: BLE001 — the audit must never break configure
            log(f"  ⚠ password audit skipped (device unreachable: {exc})")

    if args.verify and not args.dry_run:
        _verify_persistence(
            ip, ssh_key=ssh_key_path,
            expected_hostname=effective_hostname,
            log=log,
        )

    if not args.dry_run:
        _record_configure_inventory(
            ip,
            password=password,
            serial=args.serial or "",
            model_id=model_id or "",
            ssh_key_path=ssh_key_path,
            wan_ssh=wan_ssh,
        )

    log(f"Configuration complete. Router at {ip}")
    return 0
