#!/usr/bin/env python3
# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
"""Configure router with config.toml profile via SSH."""

from __future__ import annotations

import sys
from pathlib import Path

from conwrt.device_inventory import auto_detect_interface
from conwrt.postflash import (
    _apply_profile_post_flash,
    _cfg_install_ssh_key,
    _record_configure_inventory,
    _resolve_configure_options,
)
import argparse
from flash.context import log
from ssh_utils import run_ssh

from config import load_config as _load_config
from profile.apply import verify_persistence as _verify_persistence
from conwrt.postflash import _client_ip_for_subnet

_CONWRT_DIR = str(Path(__file__).resolve().parent.parent)
if _CONWRT_DIR not in sys.path:
    sys.path.insert(0, _CONWRT_DIR)


def cmd_configure(args: argparse.Namespace) -> int:
    """Apply config.toml settings to a running OpenWrt router via SSH."""
    ip = args.ip
    cfg = _load_config()

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
