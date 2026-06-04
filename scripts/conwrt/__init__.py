#!/usr/bin/env python3
# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
"""conwrt — OpenWrt flasher with auto-detection, pcap monitoring, and ASU integration.

Reads device profiles from conwrt model JSON files via model_loader.
Auto-detects device state (OpenWrt running, U-Boot recovery, or offline) and
picks the appropriate flash method (SSH sysupgrade or U-Boot HTTP upload).

Usage:
    # Flash (auto-detects method):
    conwrt --request-image --wan-ssh
    conwrt flash --model-id dlink-covr-x1860-a1 --request-image --force-uboot

    # List supported models:
    conwrt list

    # Manage cached firmware:
    conwrt cache list
    conwrt cache clean --keep-latest
    conwrt cache clean --model-id dlink-covr-x1860-a1
"""

import argparse
import io
import json
import os
import queue
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

# Version — set by build_ipk.sh or derived from git at runtime
__version__ = "0.0.0-dev"

_CONWRT_DIR = str(Path(__file__).resolve().parent.parent)  # scripts/ — sibling modules live here
if _CONWRT_DIR not in sys.path:
    sys.path.insert(0, _CONWRT_DIR)
from ssh_utils import DROPBEAR_AUTH_KEYS_PATH, ssh_cmd, scp_cmd
from config import load_config as _load_config
from model_loader import load_model, list_models, openwrt_asu_profile, find_model_by_board_name
from flash.device_profile import build_profile_from_model as _build_profile_from_model
from flash.context import (
    DEFAULT_IP,
    Event,
    OemState,
    PcapMonitorConfig,
    REBOOT_TIMEOUT,
    SILENCE_TIMEOUT_DEFAULT,
    State,
    Timeline,
    get_link_state,
    log,
    say,
    sha256_file,
    ts,
    ts_str,
)
from flash.upload import detect_uboot_http, upload_firmware, trigger_flash
from flash.hnap import _flash_via_dlink_hnap
from flash.detect import detect_boot_state as _detect_boot_state
from flash.device_detect import (
    active_fingerprint as _active_fingerprint,
    match_models as _match_models,
)
from flash.oem_handlers import (
    oem_http_accept_reboot, oem_http_change_password, oem_http_login,
    oem_http_upload, oem_ftp_enable_service, oem_ftp_login, oem_ftp_upload,
    oem_has_prepare_step, oem_reboot_wait_and_install, get_oem_install_fn,
)
from sticker_creds import dump_and_extract_config2, apply_credentials_to_openwrt
from zycast import run_zycast_auto
import importlib
_firmware_manager = importlib.import_module("firmware-manager")
firmware_request = _firmware_manager.cmd_request
firmware_find = _firmware_manager.cmd_find
IMAGES_DIR = _firmware_manager.IMAGES_DIR
_router_fingerprint = importlib.import_module("router-fingerprint")
fingerprint_router = _router_fingerprint.fingerprint_router
save_fingerprint = _router_fingerprint.save_fingerprint

from platform_utils import detect_platform, is_root, has_scapy, has_tcpdump, check_external_deps, configure_interface_ip, remove_interface_ip
from flash.preflight import run_preflight_checks
from profile import apply_plan, apply_ubus, build_plan, print_plan
from profile.apply import verify_persistence as _verify_persistence
from profile.wifi import build_mgmt_wifi_script
from inventory import append_to_inventory as _append_to_inventory


from conwrt.extreme import (
    _ssh_with_password, _scp_with_password,
    _generate_zyxel_password, _parse_key_value_lines, _sanitize_filename_part,
    _extreme_tftp_server_ip, _extreme_stock_ssh_options,
    _resolve_extreme_uboot_value, _ensure_extreme_backup_dir,
    _extreme_confirm_or_fail, _extreme_openwrt_ssh,
    _extreme_openwrt_scp_from_remote, _extreme_openwrt_scp_to_remote,
    _write_json_file, _prepare_extreme_tftp_root, _cleanup_extreme_tftp_assets,
    _setup_interface_ips,
    _handle_extreme_stock_preflight, _handle_extreme_stock_writing_uboot,
    _handle_extreme_stock_rebooting, _handle_extreme_openwrt_initramfs_waiting,
    _handle_extreme_openwrt_backup, _handle_extreme_bootcmd_restore,
    _handle_extreme_sysupgrade_uploading, _handle_extreme_sysupgrade_flashing,
    _handle_port_isolation, _advance_past_port_isolation, _restore_port_isolation,
)


def _scp_upload(device_ip: str, firmware_path: str, ssh_key: Optional[str] = None) -> tuple[bool, str]:
    """Upload a file to a device via SCP. Returns (success, remote_path).

    Shared by _flash_via_sysupgrade, _flash_via_mtd_write, and others.
    """
    firmware_name = os.path.basename(firmware_path)
    remote_path = f"/tmp/{firmware_name}"
    size_mb = os.path.getsize(firmware_path) / 1024 / 1024

    scp_command = scp_cmd(device_ip, firmware_path, f"root@{device_ip}:{remote_path}",
                          key=ssh_key, connect_timeout=10)

    log(f"Uploading {firmware_name} ({size_mb:.1f} MB) via SCP to {device_ip}...")
    try:
        r = subprocess.run(scp_command, capture_output=True, text=True, timeout=120, check=False)
        if r.returncode != 0:
            stderr_hint = r.stderr[:300] if r.stderr else "(no stderr)"
            if "permission denied" in stderr_hint.lower():
                log(f"SCP failed (exit {r.returncode}): {stderr_hint}")
                log("Hint: check SSH key authentication — ensure the key is authorized on the device")
            else:
                log(f"SCP failed (exit {r.returncode}): {stderr_hint}")
            return False, remote_path
    except subprocess.TimeoutExpired:
        log("SCP upload timed out.")
        return False, remote_path
    except Exception as e:
        log(f"SCP error: {e}")
        return False, remote_path
    return True, remote_path


def _flash_via_sysupgrade(device_ip: str, firmware_path: str, ssh_key: Optional[str] = None) -> bool:
    """Upload firmware via SCP and run sysupgrade -n with optional post-flash overlay."""
    ok, remote_path = _scp_upload(device_ip, firmware_path, ssh_key)
    if not ok:
        return False

    from platform_utils import detect_platform
    on_openwrt = detect_platform() == "openwrt"
    overlay_path = None
    if on_openwrt:
        from profile.overlay import build_overlay_tarball
        overlay_path = build_overlay_tarball(disable_dhcp=True)
        try:
            overlay_name = os.path.basename(overlay_path)
            overlay_remote = f"/tmp/{overlay_name}"
            scp_result = subprocess.run(
                scp_cmd(device_ip, overlay_path, f"root@{device_ip}:{overlay_remote}",
                        key=ssh_key, connect_timeout=10),
                capture_output=True, text=True, timeout=30, check=False,
            )
            if scp_result.returncode == 0:
                log(f"Firmware uploaded. Running sysupgrade -n -f {overlay_remote} {remote_path}...")
                cmd = f"sysupgrade -n -f {overlay_remote} {remote_path}"
            else:
                log("Overlay upload failed, falling back to sysupgrade -n without overlay.")
                cmd = f"sysupgrade -n {remote_path}"
        except Exception:
            log("Overlay generation failed, falling back to sysupgrade -n without overlay.")
            cmd = f"sysupgrade -n {remote_path}"
        finally:
            if overlay_path:
                try:
                    os.unlink(overlay_path)
                except OSError:
                    pass
    else:
        log(f"Firmware uploaded. Running sysupgrade -n {remote_path}...")
        cmd = f"sysupgrade -n {remote_path}"
    ssh_command = ssh_cmd(device_ip, cmd, key=ssh_key, connect_timeout=10)

    try:
        r = subprocess.run(ssh_command, capture_output=True, text=True, timeout=30, check=False)
        combined = (r.stdout or "") + (r.stderr or "")
        if (r.returncode == 0
                or "Commencing upgrade" in combined
                or "Upgrading" in combined
                or "Rebooting" in combined):
            log("sysupgrade initiated successfully.")
            return True
        if r.returncode != 0 and not r.stdout and not r.stderr:
            log("sysupgrade initiated (connection closed by remote — expected).")
            return True
        if "Connection refused" in r.stderr or "Connection timed out" in r.stderr:
            log(f"SSH connection failed during sysupgrade: {r.stderr[:200]}")
            log("Hint: device may have rejected the firmware or SSH is not available")
            return False
        log(f"sysupgrade returned {r.returncode}: {r.stdout[:200]} {r.stderr[:200]}")
        return False
    except subprocess.TimeoutExpired:
        log("sysupgrade command timed out (may have started reboot).")
        return True
    except Exception as e:
        log(f"sysupgrade error: {e}")
        return False


def _flash_via_mtd_write(device_ip: str, firmware_path: str, ssh_key: Optional[str] = None,
                         mtd_command: str = "mtd -r write /tmp/firmware.bin firmware") -> bool:
    """Upload firmware via SCP and run mtd write (for devices where sysupgrade rejects images)."""
    ok, _ = _scp_upload(device_ip, firmware_path, ssh_key)
    if not ok:
        return False

    log(f"Firmware uploaded. Running {mtd_command}...")
    ssh_command = ssh_cmd(device_ip, mtd_command, key=ssh_key, connect_timeout=10)

    try:
        r = subprocess.run(ssh_command, capture_output=True, text=True, timeout=60, check=False)
        combined = (r.stdout or "") + (r.stderr or "")
        # mtd -r reboots after write; connection drop is expected success
        if (r.returncode == 0
                or "Rebooting" in combined
                or "Writing" in combined):
            log("mtd write initiated successfully.")
            return True
        if r.returncode != 0 and not r.stdout and not r.stderr:
            log("mtd write initiated (connection closed by remote — expected).")
            return True
        if "Connection refused" in r.stderr or "Connection timed out" in r.stderr:
            log(f"SSH connection failed during mtd write: {r.stderr[:200]}")
            return False
        log(f"mtd write returned {r.returncode}: {r.stdout[:200]} {r.stderr[:200]}")
        return False
    except subprocess.TimeoutExpired:
        log("mtd write command timed out (may have started reboot).")
        return True
    except Exception as e:
        log(f"mtd write error: {e}")
        return False


def _wait_for_sysupgrade_reboot(device_ip: str, timeout: int = 180) -> bool:
    """Wait for device to come back after sysupgrade reboot."""
    log(f"Waiting for device to reboot and SSH to come back at {device_ip}...")
    start = ts()
    while ts() - start < timeout:
        if check_ssh(device_ip):
            return True
        time.sleep(10)
    log(f"Device did not come back at {device_ip} within {timeout}s")
    log("Hint: the firmware may be incompatible with this device, or the device booted on a different subnet")
    return False


def _find_model_id_by_board(board_name: str) -> Optional[str]:
    model = find_model_by_board_name(board_name)
    return model["id"] if model else None


def _detect_ssh_key_path() -> str:
    cfg = _load_config()
    return cfg.ssh_private_key_path


def cmd_setup_mgmt_wifi(args: argparse.Namespace) -> int:
    ssh_key = _detect_ssh_key_path()
    if not ssh_key:
        print("ERROR: No SSH private key found. Set [ssh].key in config.toml or install ~/.ssh/id_ed25519 or ~/.ssh/id_rsa.", file=sys.stderr)
        return 1

    verify_cmd = " && ".join([
        "uci -q get network.mgmt.ipaddr | grep -qx '172.16.0.1'",
        "uci -q get dhcp.mgmt.interface | grep -qx 'mgmt'",
        "uci -q show firewall | grep -q \"\\.name='mgmt'\"",
        "uci -q show wireless | grep -q \"\\.network='mgmt'\"",
    ])
    verify_result = subprocess.run(
        ssh_cmd(args.ip, verify_cmd, key=ssh_key, connect_timeout=10),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if verify_result.returncode == 0:
        print(f"Management WiFi already configured on {args.ip}")
        return 0

    cfg = _load_config()
    script = build_mgmt_wifi_script(txpower=cfg.mgmt_wifi_txpower)
    ssh_command = ssh_cmd(args.ip, "sh -s", key=ssh_key, connect_timeout=10)

    try:
        result = subprocess.run(
            ssh_command,
            input=script,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"ERROR: Timed out configuring management WiFi on {args.ip}.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: Failed to run setup script over SSH: {exc}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        if result.stderr:
            print(result.stderr.strip(), file=sys.stderr)
        return result.returncode or 1

    verify_result2 = subprocess.run(
        ssh_cmd(args.ip, verify_cmd, key=ssh_key, connect_timeout=10),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if verify_result2.returncode != 0:
        if result.stdout.strip():
            print(result.stdout.strip())
        if verify_result2.stderr.strip():
            print(verify_result2.stderr.strip(), file=sys.stderr)
        print("ERROR: Management WiFi verification failed.", file=sys.stderr)
        return 1

    if result.stdout.strip():
        print(result.stdout.strip())
    print(f"Management WiFi configured on {args.ip}")
    return 0


from conwrt.monitors import check_ssh


def _apply_profile_post_flash(
    ip: str,
    ssh_key: str = "",
    cfg: object = None,
    model_id: str = "",
    interface: str = "",
    old_client_ip: str = "",
    *,
    password: Optional[str] = None,
    wan_ssh: Optional[bool] = None,
    ssh_key_path: Optional[str] = None,
    dry_run: bool = False,
    hostname: str = "",
    wifi_disable: bool = False,
    lan_ip_mode: str = "",
    hostname_pattern: str = "",
    transport: str = "ssh",
    ubus_user: str = "root",
    ubus_password: str = "",
) -> str:
    """Apply config.toml profile via unified plan (WiFi, use cases, LAN IP)."""
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return ip

    model_caps: list[str] = []
    if model_id:
        try:
            model = load_model(model_id)
            model_caps = model.get("capabilities", [])
        except FileNotFoundError:
            pass

    effective_wan_ssh = cfg.wan_ssh if wan_ssh is None else wan_ssh
    plan = build_plan(
        cfg,
        mode="preview" if dry_run else "post_install",
        model_capabilities=model_caps,
        ssh_key_path=ssh_key_path,
        password=password,
        wan_ssh=effective_wan_ssh,
        hostname=hostname,
        wifi_disable=wifi_disable,
        lan_ip_mode=lan_ip_mode,
        hostname_pattern=hostname_pattern,
        model_id=model_id,
    )
    if not dry_run:
        log(f"Applying profile via {transport}...")
    if transport == "ubus":
        ip = apply_ubus(
            plan, ip, username=ubus_user, password=ubus_password,
            dry_run=dry_run, log=log,
        )
    else:
        ip = apply_plan(plan, ip, ssh_key=ssh_key, dry_run=dry_run, log=log)

    # --- Post-apply: hostname read-back (SSH only) ---
    if transport == "ssh" and not dry_run:
        from profile.plan import StepKind as _SK
        has_hostname_step = any(s.kind == _SK.HOSTNAME and s.include_in_post_install for s in plan.steps)
        if has_hostname_step:
            r_host = _ssh_run(ip, "cat /proc/sys/kernel/hostname", key=ssh_key, timeout=10)
            if r_host.returncode == 0 and r_host.stdout.strip():
                resolved_hostname = r_host.stdout.strip()
                log(f"  Hostname resolved: {resolved_hostname}")

    # --- Post-apply: static LAN IP (SSH only) ---
    if transport == "ssh" and not dry_run and cfg.lan_ip and interface:
        new_ip = _apply_lan_ip_post_flash(
            ip, ssh_key=ssh_key, cfg=cfg,
            interface=interface, old_client_ip=old_client_ip,
        )
        if new_ip:
            ip = new_ip

    # --- Post-apply: MAC-hash LAN IP (SSH only) ---
    from profile.plan import StepKind
    from mac_hash import mac_to_lan_ip
    for step in plan.steps:
        if step.kind != StepKind.LAN_IP_MAC_HASH:
            continue
        if not step.include_in_post_install:
            continue
        if dry_run:
            log(f"  {step.label} (dry run)")
            continue
        if transport != "ssh":
            log(f"  ⚠ {step.label}: MAC-hash LAN IP requires SSH — skipped for ubus transport")
            continue

        script = (step.configure_script or "").replace(" && ", "; ")
        if not script:
            continue
        subnet = (step.wifi_params or {}).get("lan_subnet", "")
        if not subnet:
            log(f"  ⚠ {step.label}: no subnet configured — skipping")
            continue

        # Read eth0 MAC BEFORE changing IP so we can compute the new IP in Python
        r_mac = _ssh_run(ip, "cat /sys/class/net/eth0/address 2>/dev/null", key=ssh_key)
        if r_mac.returncode != 0 or not r_mac.stdout.strip():
            log(f"  ⚠ {step.label}: could not read eth0 MAC — skipping")
            continue
        eth0_mac = r_mac.stdout.strip()
        expected_ip = mac_to_lan_ip(eth0_mac, subnet)
        log(f"  {step.label}... (eth0={eth0_mac}, expected={expected_ip})")

        r = _ssh_run(ip, script, key=ssh_key)
        if r.returncode == 0:
            log(f"  ✓ {step.label} — IP set to {expected_ip}, rebooting...")
            _ssh_run(ip, "sync; sync; reboot", key=ssh_key, timeout=5)
            time.sleep(30)

            # Set up local interface on new subnet before reconnecting
            if interface:
                new_client_ip = _client_ip_for_subnet(expected_ip)
                if old_client_ip:
                    remove_interface_ip(interface, old_client_ip, "24")
                configure_interface_ip(interface, new_client_ip, "24")
                log(f"  Local interface {interface} configured with {new_client_ip}/24")

            # Wait for SSH on the new (known) IP
            for attempt in range(12):
                if check_ssh(expected_ip):
                    log(f"  ✓ Reconnected at {expected_ip}")
                    ip = expected_ip
                    break
                if attempt == 0:
                    log(f"  Waiting for device at {expected_ip}...")
                time.sleep(5)
            else:
                log(f"  ⚠ Device did not come back at {expected_ip} within 60s")
                log(f"  The IP was changed. Try: sudo ifconfig {interface} inet {_client_ip_for_subnet(expected_ip)}/24 alias")
        else:
            log(f"  ⚠ {step.label}: failed to set MAC-hash IP")

    return ip


def _apply_sticker_credentials_post_flash(
    ip: str, ssh_key: str = "", model_id: str = "", cfg: object = None,
) -> None:
    """Restore factory sticker WiFi credentials after flashing.

    Only activates when the model has a ``sticker_credentials`` section in
    its model JSON AND the user hasn't configured an explicit WiFi AP in
    config.toml (sticker creds are the fallback/default).
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return

    if cfg.wifi_ap:
        return

    if not model_id:
        return
    try:
        model = load_model(model_id)
    except FileNotFoundError:
        return
    if "sticker_credentials" not in model:
        return

    log("Restoring factory sticker WiFi credentials...")
    key = ssh_key or None
    try:
        data = dump_and_extract_config2(ip, key=key)
    except RuntimeError as exc:
        log(f"  ⚠ sticker creds: dump failed — {exc}")
        return

    wifi = data.get("wifi", {})
    macs = data.get("macs", {})
    ssid_24g = wifi.get("ssid_24g", "")
    ssid_5g = wifi.get("ssid_5g", "")
    log(f"  Extracted: 2.4G SSID={ssid_24g or '(none)'}, "
        f"5G SSID={ssid_5g or '(none)'}")
    if macs.get("factory_mac"):
        log(f"  Factory MAC: {macs['factory_mac']}")

    try:
        apply_credentials_to_openwrt(ip, wifi, key=key, model_id=model_id)
    except RuntimeError as exc:
        log(f"  ⚠ sticker creds: apply failed — {exc}")
        return

    log("  ✓ sticker credentials applied")


def _register_wireguard_post_flash(
    ip: str, ssh_key: str = "", cfg: object = None,
) -> str:
    """Read the auto-generated WireGuard public key from the router and
    register it with the VPN server.

    Returns the public key string, or empty string on failure.
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return ""
    if not cfg.wireguard or not cfg.wireguard.registration_server:
        return ""

    server = cfg.wireguard.registration_server
    wg_if = cfg.wireguard.wg_interface
    key = ssh_key or None

    # Try to read the public key directly (interface may already be up)
    r = subprocess.run(
        ssh_cmd(ip, "wg show wg0 public-key 2>/dev/null", key=key, connect_timeout=10),
        capture_output=True, text=True, timeout=15, check=False,
    )
    pub_key = r.stdout.strip()

    # If interface isn't up yet, derive from private key without leaking it
    # to the process table (pipe via stdin, not command-line args)
    if not pub_key or len(pub_key) < 40:
        r1 = subprocess.run(
            ssh_cmd(ip, "uci -q get network.wg0.private_key", key=key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
        priv_key = r1.stdout.strip()
        if not priv_key or priv_key == "generate":
            log("  WG: no private key found on router (WireGuard not configured)")
            return ""

        # Pipe private key through stdin to avoid exposing it in ps/process args
        r2 = subprocess.run(
            ssh_cmd(ip, "wg pubkey", key=key, connect_timeout=10),
            input=priv_key, capture_output=True, text=True, timeout=15, check=False,
        )
        pub_key = r2.stdout.strip()
        if not pub_key or len(pub_key) < 40:
            log(f"  ⚠ WG: could not derive public key (got {len(pub_key)} chars)")
            return ""

    log(f"  WG: public key = {pub_key}")

    # Read the tunnel address from the router
    r3 = subprocess.run(
        ssh_cmd(ip, "uci -q get network.wg0.addresses", key=key, connect_timeout=10),
        capture_output=True, text=True, timeout=15, check=False,
    )
    address = r3.stdout.strip()
    if not address:
        address = "0.0.0.0/0"

    # Register the peer with the VPN server
    log(f"  WG: registering peer {address} with {server}...")
    reg_cmd = f"wg set {wg_if} peer {pub_key} allowed-ips {address}"
    r4 = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10",
         server, reg_cmd],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if r4.returncode == 0:
        log(f"  ✓ WG: peer registered with {server}")
    else:
        log(f"  ⚠ WG: registration failed — {r4.stderr.strip()[:200]}")

    addr_host = address.split("/")[0]
    persist_cmd = (
        f"grep -q '{pub_key}' /etc/wireguard/{wg_if}.conf 2>/dev/null || "
        f"printf '\\n[Peer]\\nPublicKey = {pub_key}\\nAllowedIPs = {addr_host}/32\\n' "
        f">> /etc/wireguard/{wg_if}.conf"
    )
    subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10",
         server, persist_cmd],
        capture_output=True, text=True, timeout=15, check=False,
    )

    return pub_key


def _deploy_tollgate_post_flash(
    ip: str, ssh_key: str = "", cfg: object = None,
) -> None:
    """Deploy tollgate ipk to the router if the tollgate use case is enabled."""
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return

    tollgate_cfg = None
    for uc in cfg.use_cases:
        if uc.name == "tollgate":
            tollgate_cfg = uc.params
            break
    if tollgate_cfg is None:
        return

    from use_cases.tollgate import deploy_tollgate_post_flash
    deploy_tollgate_post_flash(
        ip,
        ssh_key=ssh_key,
        arch=tollgate_cfg.get("arch", ""),
        channel=tollgate_cfg.get("channel", "stable"),
        version=tollgate_cfg.get("version", "latest"),
        source=tollgate_cfg.get("source", "auto"),
        log=log,
    )


def _client_ip_for_subnet(router_ip: str) -> str:
    """Derive a client IP on the same /24 subnet as router_ip.

    Takes the first three octets from router_ip and uses .254 as the client.
    """
    octets = router_ip.split(".")
    if len(octets) != 4:
        return ""
    return f"{octets[0]}.{octets[1]}.{octets[2]}.254"


def _interface_exists(interface: str) -> bool:
    """Check if a network interface exists on this system."""
    r = subprocess.run(
        ["ifconfig", interface], capture_output=True, text=True, check=False,
    )
    return r.returncode == 0


def _apply_lan_ip_post_flash(
    ip: str, ssh_key: str = "", cfg: object = None,
    interface: str = "", old_client_ip: str = "",
) -> str:
    """Change the router's LAN IP and reconnect on the new subnet.

    This MUST be the last post-flash step — the network restart will drop SSH.
    After changing the router's LAN IP:
      1. Remove old client IP alias from the interface
      2. Add new client IP alias on the new subnet
      3. Wait for the router to come back on the new IP
      4. Verify SSH on the new IP

    Returns the new router IP, or empty string on failure.
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return ""
    if not cfg.lan_ip:
        return ""
    if not interface:
        log("  ⚠ LAN IP: no interface — skipping IP change")
        return ""

    new_ip = cfg.lan_ip
    if new_ip == ip:
        return new_ip

    new_client_ip = _client_ip_for_subnet(new_ip)
    if not new_client_ip:
        log(f"  ⚠ LAN IP: invalid target IP '{new_ip}'")
        return ""

    log(f"  Changing LAN IP from {ip} to {new_ip}...")
    key = ssh_key or None

    uci_commands = " && ".join([
        f"uci set network.lan.ipaddr='{new_ip}'",
        "uci commit network",
        "(/etc/init.d/network reload >/dev/null 2>&1) &",
        "exit 0",
    ])
    try:
        r = subprocess.run(
            ssh_cmd(ip, uci_commands, key=key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
        log(f"  LAN IP change command sent (rc={r.returncode})")
    except subprocess.TimeoutExpired:
        log("  LAN IP change: SSH session ended (expected — network restarting)")

    time.sleep(5)

    # Interface may have dropped during router network restart (USB adapter re-enumeration)
    if not _interface_exists(interface):
        log(f"  Interface {interface} dropped during network restart. Waiting for it to come back...")
        reappear_deadline = time.time() + 30
        while time.time() < reappear_deadline:
            if _interface_exists(interface):
                log(f"  Interface {interface} reappeared.")
                break
            time.sleep(1)
        else:
            # Interface didn't come back with same name — try auto-detect
            new_iface = auto_detect_interface()
            if new_iface and new_iface != interface:
                log(f"  Interface re-enumerated as {new_iface}")
                interface = new_iface
            else:
                log(f"  ⚠ LAN IP: interface {interface} disappeared and did not come back")
                log(f"  The router IP was changed to {new_ip}. Reconnect manually with: "
                    f"sudo ifconfig <interface> inet {new_client_ip}/24 alias")
                return ""

    if old_client_ip:
        remove_interface_ip(interface, old_client_ip, "24")

    plat = detect_platform()
    if plat == "darwin":
        subprocess.run(["sudo", "arp", "-d", ip], capture_output=True, check=False)
        subprocess.run(["sudo", "arp", "-d", new_ip], capture_output=True, check=False)
    else:
        subprocess.run(["ip", "neigh", "flush", "to", ip], capture_output=True, check=False)
        subprocess.run(["ip", "neigh", "flush", "to", new_ip], capture_output=True, check=False)

    configure_interface_ip(interface, new_client_ip, "24")

    log(f"  Waiting for router at {new_ip} (client IP {new_client_ip})...")
    if _wait_for_sysupgrade_reboot(new_ip, timeout=120):
        log(f"  ✓ LAN IP changed to {new_ip}")
        return new_ip
    else:
        log(f"  ⚠ LAN IP: router did not come back at {new_ip}")
        return ""


def verify_router(ip: str = DEFAULT_IP, wan_ssh_expected: bool = False,
                  mgmt_wifi_expected: bool = False) -> list[tuple[str, str]]:
    log("Verifying router state...")
    checks: list[tuple[str, str]] = []
    try:
        r = subprocess.run(
            ssh_cmd(ip,
                    "echo hostname=$(cat /proc/sys/kernel/hostname); "
                    "echo board=$(cat /etc/board.json | jsonfilter -e '@.model.id' 2>/dev/null || echo unknown); "
                    "echo kernel=$(uname -r); "
                    f"echo sshkey_count=$(wc -l < {DROPBEAR_AUTH_KEYS_PATH} 2>/dev/null || echo 0); "
                    f"echo sshkey_size=$(wc -c < {DROPBEAR_AUTH_KEYS_PATH} 2>/dev/null || echo 0); "
                    "echo wan_ssh=$(uci show firewall 2>/dev/null | grep Allow-SSH-WAN | wc -l); "
                    "echo uci_defaults=$(ls /etc/uci-defaults/ 2>/dev/null | wc -l); "
                    "echo mac_brlan=$(cat /sys/class/net/br-lan/address 2>/dev/null || echo ''); "
                    "echo 'mac_all='$(for f in /sys/class/net/*/address; do printf '%s=%s ' $(basename $(dirname $f)) $(cat $f 2>/dev/null); done); "
                    "echo mgmt_wifi=$(uci -q get network.mgmt.ipaddr || echo ''); "
                    "echo mgmt_ssid=$(uci -q get wireless.@wifi-iface[0].ssid || echo ''); "
                    "echo mgmt_radio=$(uci -q get wireless.radio0.disabled || echo ''); "
                    "echo nmap_ok=$(which nmap >/dev/null 2>&1 && echo yes || echo no); "
                    "echo ping_ok=$(ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && echo yes || echo no)",
                    connect_timeout=5),
            capture_output=True, text=True, timeout=20, check=False,
        )
        for line in r.stdout.strip().split('\n'):
            if '=' in line:
                key, val = line.split('=', 1)
                checks.append((key, val))
                log(f"  verify: {key}: {val}")

        d = dict(checks)

        uci_defaults = d.get("uci_defaults", "?")
        if uci_defaults == "0":
            log("  ✓ uci-defaults: all consumed (first boot complete)")
        else:
            log(f"  ⚠ uci-defaults: {uci_defaults} remaining")

        sshkey_count = d.get("sshkey_count", "0")
        if int(sshkey_count or 0) > 0:
            log(f"  ✓ SSH keys: {sshkey_count} authorized")
        else:
            log("  ⚠ SSH keys: none found")

        if wan_ssh_expected:
            wan_ssh = d.get("wan_ssh", "0")
            if int(wan_ssh or 0) > 0:
                log("  ✓ WAN SSH: firewall rule present")
            else:
                log("  ⚠ WAN SSH: no firewall rule found")

        if mgmt_wifi_expected:
            mgmt_ip = d.get("mgmt_wifi", "")
            mgmt_ssid = d.get("mgmt_ssid", "")
            if mgmt_ip:
                log(f"  ✓ mgmt WiFi: network configured ({mgmt_ip})")
            else:
                log("  ⚠ mgmt WiFi: network not configured")
            if mgmt_ssid.startswith("MGMT-"):
                log(f"  ✓ mgmt WiFi: SSID={mgmt_ssid}")
            else:
                log(f"  ⚠ mgmt WiFi: unexpected SSID '{mgmt_ssid}'")

        ping_ok = d.get("ping_ok", "no")
        if ping_ok == "yes":
            log("  ✓ network: connectivity confirmed (ping 8.8.8.8)")
        else:
            log("  ⚠ network: no connectivity")

        nmap_ok = d.get("nmap_ok", "no")
        if nmap_ok == "yes":
            log("  ✓ extra package: nmap installed")

    except Exception as e:
        log(f"Verification failed: {e}")
    return checks


from conwrt.monitors import (
    PcapMonitor, LinkMonitor, SSHMonitor,
    _setup_monitors, _teardown_monitors,
)


from conwrt.infrastructure import (
    TFTPServerManager, SerialUBootDriver, RecoveryContext,
    _auto_detect_serial_port, _generate_random_password, _validate_args,
)


def _resolve_asu_profile(model_id: str) -> str:
    return openwrt_asu_profile(load_model(model_id))


def _request_custom_image(
    model_id: str,
    ssh_key_path: Optional[str],
    password: Optional[str],
    wan_ssh: bool,
    flash_method: str,
    say_fn,
) -> tuple[Optional[str], dict]:
    asu_profile = _resolve_asu_profile(model_id)
    say_fn("Requesting custom firmware image from ASU...")
    log(f"ASU profile: {asu_profile}")

    model = load_model(model_id)
    target = model.get("openwrt", {}).get("target", "")
    version = model.get("openwrt", {}).get("version", "24.10.2")

    request_args = argparse.Namespace(
        profile=asu_profile,
        version=version,
        target=target or None,
        packages=None,
        ssh_key=ssh_key_path,
        password=password,
        wan_ssh=wan_ssh,
        model_capabilities=model.get("capabilities", []),
    )

    request_buf = io.StringIO()
    with redirect_stdout(request_buf):
        rc = firmware_request(request_args)
    if rc != 0:
        log("ERROR: ASU firmware request failed.")
        return None, {}

    recovery_methods = {
        "recovery-http",
        "uboot-http",
        "uboot-tftp",
        "zycast",
        "dlink-hnap",
        "mtd-write",
        "extreme-rdwr-tftp-initramfs",
        "oem-http",
    }
    if flash_method in recovery_methods:
        preferred_types = ["recovery", "factory", "initramfs"]
    else:
        preferred_types = ["sysupgrade"]

    image_path = None
    for img_type in preferred_types:
        find_args = argparse.Namespace(
            profile=asu_profile,
            type=img_type,
        )
        find_buf = io.StringIO()
        with redirect_stdout(find_buf):
            firmware_find(find_args)
        candidate = find_buf.getvalue().strip()
        if candidate and os.path.isfile(candidate):
            image_path = candidate
            break

    if not image_path:
        find_args = argparse.Namespace(
            profile=asu_profile,
            type=None,
        )
        find_buf = io.StringIO()
        with redirect_stdout(find_buf):
            firmware_find(find_args)
        image_path = find_buf.getvalue().strip()

    if not image_path or not os.path.isfile(image_path):
        profile_dir = IMAGES_DIR / asu_profile
        if profile_dir.exists():
            for hash_dir in sorted(profile_dir.iterdir(), reverse=True):
                if not hash_dir.is_dir():
                    continue
                for f in sorted(hash_dir.iterdir()):
                    if f.is_file() and f.suffix in (".bin", ".img", ".tar"):
                        image_path = str(f)
                        break
                if image_path and os.path.isfile(image_path):
                    break

    if not image_path or not os.path.isfile(image_path):
        log("ERROR: No firmware image file found after ASU request.")
        return None, {}

    metadata = {}
    try:
        image_obj = Path(image_path)
        meta_path = image_obj.parent / "build.metadata.json"
        if meta_path.is_file():
            metadata = json.loads(meta_path.read_text())
    except (OSError, json.JSONDecodeError):
        metadata = {}

    log(f"Firmware image: {image_path}")

    if flash_method in {"edgeos-kernel-swap", "extreme-rdwr-tftp-initramfs", "oem-http"}:
        initramfs_path = ""
        if image_path:
            image_dir = Path(image_path).parent
            for candidate in sorted(image_dir.iterdir()):
                if candidate.is_file() and "initramfs" in candidate.name:
                    initramfs_path = str(candidate)
                    log(f"Initramfs image: {initramfs_path}")
                    break
        if not initramfs_path:
            log("WARNING: No initramfs image found in build directory.")
        metadata["initramfs_path"] = initramfs_path

    return image_path, metadata


def _run_state_machine(
    ctx: RecoveryContext,
    event_queue: queue.Queue,
    pcap_monitor: Optional[PcapMonitor],
    link_monitor: LinkMonitor,
) -> int:
    ctx.timeline.recovery_start = ts()

    while ctx.state not in (State.COMPLETE, State.FAILED):
        if ctx.state == State.DETECTING:
            _handle_detecting(ctx, event_queue)
        elif ctx.state == State.SYSUPGRADE_UPLOADING:
            _handle_sysupgrade_uploading(ctx, event_queue)
        elif ctx.state == State.SYSUPGRADE_REBOOTING:
            _handle_sysupgrade_rebooting(ctx, event_queue)
        elif ctx.state == State.SYSUPGRADE_BOOTING:
            _handle_sysupgrade_booting(ctx, event_queue)
        elif ctx.state == State.WAITING_FOR_POWER_OFF:
            _handle_waiting_for_power_off(ctx, event_queue)
        elif ctx.state == State.WAITING_FOR_UBOOT:
            _handle_waiting_for_uboot(ctx, event_queue, link_monitor)
        elif ctx.state == State.UBOOT_UPLOADING:
            _handle_uboot_uploading(ctx, event_queue)
        elif ctx.state == State.UBOOT_FLASHING:
            _handle_uboot_flashing(ctx, event_queue, pcap_monitor)
        elif ctx.state == State.SERIAL_WAITING_FOR_BOOTMENU:
            _handle_serial_waiting_for_bootmenu(ctx, event_queue)
        elif ctx.state == State.SERIAL_UBOOT_INTERACTING:
            _handle_serial_uboot_interacting(ctx, event_queue)
        elif ctx.state == State.ZYCAST_WAITING_FOR_DEVICE:
            _handle_zycast_waiting(ctx, event_queue)
        elif ctx.state == State.ZYCAST_SENDING:
            _handle_zycast_sending(ctx, event_queue)
        elif ctx.state == State.REBOOTING:
            _handle_rebooting(ctx, event_queue)
        elif ctx.state == State.OPENWRT_BOOTING:
            _handle_openwrt_booting(ctx, event_queue)
        elif ctx.state == State.EDGEOS_STAGE1:
            _handle_edgeos_stage1(ctx, event_queue)
        elif ctx.state == State.EDGEOS_STAGE1_REBOOTING:
            _handle_edgeos_stage1_rebooting(ctx, event_queue)
        elif ctx.state == State.EDGEOS_PORT_SWAP:
            _handle_edgeos_port_swap(ctx, event_queue)
        elif ctx.state == State.EDGEOS_STAGE2_UPLOADING:
            _handle_edgeos_stage2_uploading(ctx, event_queue)
        elif ctx.state == State.EDGEOS_STAGE2_FLASHING:
            _handle_edgeos_stage2_flashing(ctx, event_queue)
        elif ctx.state == State.EXTREME_STOCK_PREFLIGHT:
            _handle_extreme_stock_preflight(ctx, event_queue)
        elif ctx.state == State.EXTREME_STOCK_WRITING_UBOOT:
            _handle_extreme_stock_writing_uboot(ctx, event_queue)
        elif ctx.state == State.EXTREME_STOCK_REBOOTING:
            _handle_extreme_stock_rebooting(ctx, event_queue)
        elif ctx.state == State.EXTREME_OPENWRT_INITRAMFS_WAITING:
            _handle_extreme_openwrt_initramfs_waiting(ctx, event_queue)
        elif ctx.state == State.EXTREME_OPENWRT_BACKUP:
            _handle_extreme_openwrt_backup(ctx, event_queue)
        elif ctx.state == State.EXTREME_BOOTCMD_RESTORE:
            _handle_extreme_bootcmd_restore(ctx, event_queue)
        elif ctx.state == State.EXTREME_SYSUPGRADE_UPLOADING:
            _handle_extreme_sysupgrade_uploading(ctx, event_queue)
        elif ctx.state == State.EXTREME_SYSUPGRADE_FLASHING:
            _handle_extreme_sysupgrade_flashing(ctx, event_queue)
        elif ctx.state == State.PORT_ISOLATION:
            _handle_port_isolation(ctx, event_queue)
        elif ctx.state == State.OEM_LOGIN:
            _handle_oem_login(ctx, event_queue)
        elif ctx.state == State.OEM_PREPARE:
            _handle_oem_prepare(ctx, event_queue)
        elif ctx.state == State.OEM_UPLOADING:
            _handle_oem_uploading(ctx, event_queue)
        elif ctx.state == State.OEM_REBOOTING:
            _handle_oem_rebooting(ctx, event_queue)
        else:
            log(f"Unknown state: {ctx.state}")
            ctx.state = State.FAILED

    if ctx.state == State.COMPLETE:
        _print_timeline(ctx)
        if ctx.no_upload:
            return 0
        cfg = _load_config()
        openwrt_ip = ctx.profile.openwrt_ip or ctx.profile.recovery_ip
        openwrt_ip = _apply_profile_post_flash(
            openwrt_ip,
            ssh_key=ctx.ssh_key_path,
            cfg=cfg,
            model_id=ctx.profile.name,
            interface=ctx.interface,
            old_client_ip=ctx.profile.openwrt_client_ip or ctx.profile.client_ip,
        )
        if openwrt_ip != (ctx.profile.openwrt_ip or ctx.profile.recovery_ip):
            ctx.profile = SimpleNamespace(**{**vars(ctx.profile), "openwrt_ip": openwrt_ip})
        _apply_sticker_credentials_post_flash(
            openwrt_ip, ssh_key=ctx.ssh_key_path,
            model_id=ctx.profile.name, cfg=cfg,
        )
        wg_pubkey = _register_wireguard_post_flash(
            openwrt_ip, ssh_key=ctx.ssh_key_path, cfg=cfg,
        )
        ctx.wireguard_pubkey = wg_pubkey
        _deploy_tollgate_post_flash(
            openwrt_ip, ssh_key=ctx.ssh_key_path, cfg=cfg,
        )
        _restore_port_isolation(ctx)
        _record_inventory(ctx)
        return 0

    _print_timeline(ctx)
    _restore_port_isolation(ctx)
    if ctx.image_path and ctx.sha256_before:
        log("Recording partial inventory (flash may still succeed).")
        _record_inventory(ctx)
    return 1


def _handle_detecting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    boot_state = _detect_boot_state(ctx.interface, ctx.profile)
    ctx.boot_state = boot_state
    if boot_state == "openwrt" and not ctx.force_uboot:
        if ctx.profile.flash_method == "mtd-write":
            ctx._say_fn("OpenWrt detected. Using mtd-write for flash.")
            log("Boot state: OpenWrt — using mtd-write path")
        else:
            ctx._say_fn("OpenWrt detected. Using sysupgrade for faster re-flash.")
            log("Boot state: OpenWrt — using sysupgrade path")
        ctx.state = State.SYSUPGRADE_UPLOADING
    elif boot_state == "stock-edgeos":
        ctx._say_fn("EdgeOS detected. Starting kernel swap flash.")
        log("Boot state: EdgeOS stock firmware — using edgeos-kernel-swap")
        ctx.state = State.EDGEOS_STAGE1
    elif boot_state == "stock-extreme":
        ctx._say_fn("Extreme stock firmware detected. Starting TFTP initramfs flash.")
        log("Boot state: Extreme stock firmware — using extreme-rdwr-tftp-initramfs")
        ctx.state = State.EXTREME_STOCK_PREFLIGHT
    elif boot_state == "stock-zyxel" or (ctx.profile and getattr(ctx.profile, 'flash_method', '').startswith('oem-')):
        ctx._say_fn("ZyXEL stock firmware detected. Uploading via OEM method.")
        log("Boot state: ZyXEL stock firmware — using OEM flash")
        ctx.state = State.OEM_LOGIN
    elif boot_state == "stock-hnap" or ctx.profile.flash_method == "dlink-hnap":
        ctx._say_fn("D-Link router detected. Uploading via HNAP.")
        log("Boot state: stock firmware with HNAP API — uploading directly")
        ctx.state = State.UBOOT_UPLOADING
    else:
        if boot_state == "uboot":
            log("Boot state: U-Boot recovery mode detected")
            recovery_ip = ctx.profile.recovery_ip
            found, detail = detect_uboot_http(recovery_ip)
            if found:
                log(f"Recovery HTTP already live at {recovery_ip} ({detail}) — skipping power cycle")
                ctx.timeline.uboot_http_first = ts()
                ctx.state = State.UBOOT_UPLOADING
                return
        if ctx.force_uboot:
            log("Boot state: forced to U-Boot recovery (--force-uboot)")
        else:
            log("Boot state: unknown — proceeding with U-Boot recovery")
        ctx.state = State.WAITING_FOR_POWER_OFF


def _handle_edgeos_stage1(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Stage 1: SSH to EdgeOS, swap boot kernel with OpenWrt initramfs."""
    import shutil as _shutil
    profile = ctx.profile
    edgeos_ip = profile.edgeos_ip
    edgeos_user = profile.edgeos_user
    edgeos_password = profile.edgeos_password
    initramfs_path = ctx.initramfs_path

    if not initramfs_path or not os.path.isfile(initramfs_path):
        log(f"ERROR: initramfs image not found: {initramfs_path}")
        ctx.state = State.FAILED
        return

    size_mb = os.path.getsize(initramfs_path) / 1024 / 1024
    log(f"Stage 1: Uploading initramfs ({size_mb:.1f} MB) to EdgeOS at {edgeos_ip}...")

    # SCP initramfs to EdgeOS /tmp (upload: local → remote with password auth)
    sshpass_bin = _shutil.which("sshpass")
    if not sshpass_bin:
        log("ERROR: sshpass not found. Install with: brew install hudochenkov/sshpass/sshpass")
        ctx.state = State.FAILED
        return

    remote_name = os.path.basename(initramfs_path)
    scp_upload_cmd = [
        sshpass_bin, "-p", edgeos_password,
        "scp", "-O",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        initramfs_path,
        f"{edgeos_user}@{edgeos_ip}:/tmp/{remote_name}",
    ]
    try:
        scp_result = subprocess.run(scp_upload_cmd, capture_output=True, text=True, timeout=120, check=False)
    except subprocess.TimeoutExpired:
        log("SCP to EdgeOS timed out.")
        ctx.state = State.FAILED
        return
    if scp_result.returncode != 0:
        log(f"SCP to EdgeOS failed (exit {scp_result.returncode}): {scp_result.stderr[:300]}")
        ctx.state = State.FAILED
        return

    log("Initramfs uploaded. Swapping boot kernel...")

    # Build the kernel swap script — must use sudo on EdgeOS
    boot_partition = profile.boot_partition
    kernel_path = profile.kernel_path
    md5_path = profile.md5_path
    swap_script = (
        f"set -ex; "
        f"mkdir -p /tmp/boot; "
        f"sudo mount -t vfat {boot_partition} /tmp/boot; "
        f"test -f /tmp/boot{kernel_path} || {{ echo 'ERROR: kernel not found'; exit 1; }}; "
        f"cp -a /tmp/boot{kernel_path} /tmp/boot{kernel_path}.bak; "
        f"cp -a /tmp/boot{md5_path} /tmp/boot{md5_path}.bak; "
        f"cp /tmp/{remote_name} /tmp/boot{kernel_path}; "
        f"md5sum /tmp/boot{kernel_path} | cut -d ' ' -f1 > /tmp/boot{md5_path}; "
        f"sync; "
        f"sudo umount /tmp/boot; "
        f"echo 'Kernel swap complete'; "
        f"sudo reboot"
    )
    ssh_result = _ssh_with_password(
        edgeos_ip, edgeos_user, edgeos_password,
        f"bash -c '{swap_script}'",
        timeout=60,
    )
    if ssh_result.returncode != 0:
        combined = (ssh_result.stdout or "") + (ssh_result.stderr or "")
        if "Kernel swap complete" in combined or "Connection closed" in combined:
            log("Kernel swap completed (connection closed during reboot — expected).")
        else:
            log(f"Kernel swap failed (exit {ssh_result.returncode}): {combined[:500]}")
            ctx.state = State.FAILED
            return

    ctx.sha256_before = sha256_file(ctx.image_path)
    ctx.timeline.upload_start = ts()
    ctx._say_fn("Stage 1 complete. Device rebooting into OpenWrt initramfs.")
    log("Stage 1 complete — EdgeOS rebooting into OpenWrt initramfs.")
    ctx.state = State.EDGEOS_STAGE1_REBOOTING


def _handle_edgeos_stage1_rebooting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Wait for EdgeOS to reboot into OpenWrt initramfs."""
    ctx._say_fn("Waiting for device to reboot. This takes about 90 seconds.")
    log("Waiting for initramfs boot (~90 seconds)...")
    time.sleep(10)

    if ctx.profile.port_swap_required:
        ctx.state = State.EDGEOS_PORT_SWAP
    else:
        ctx.state = State.EDGEOS_STAGE2_UPLOADING


def _handle_edgeos_port_swap(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Prompt user to move cable from eth0 (WAN) to eth1+ (LAN)."""
    port_note = ctx.profile.port_swap_note or "Move the ethernet cable to a LAN port."
    ctx._say_fn(f"Important! {port_note}")
    log(f"PORT SWAP: {port_note}")
    log("Waiting for SSH on 192.168.1.1...")

    openwrt_ip = ctx.profile.openwrt_ip
    timeout = 120
    start = time.time()
    while time.time() - start < timeout:
        if check_ssh(openwrt_ip):
            ctx.timeline.ssh_available = ts()
            log(f"SSH available at {openwrt_ip} — initramfs booted successfully.")
            ctx._say_fn("Initramfs is up. Starting stage 2.")
            event_queue.put((Event.EDGEOS_PORT_SWAP_DONE, ""))
            ctx.state = State.EDGEOS_STAGE2_UPLOADING
            return
        time.sleep(5)

    ctx._say_fn("Timed out waiting for initramfs SSH.")
    log(f"FAIL: SSH not available at {openwrt_ip} after {timeout}s.")
    ctx.state = State.FAILED


def _handle_edgeos_stage2_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Stage 2a: Upload sysupgrade.tar to OpenWrt initramfs."""
    openwrt_ip = ctx.profile.openwrt_ip
    image_path = ctx.image_path

    if not image_path or not os.path.isfile(image_path):
        log(f"ERROR: sysupgrade.tar not found: {image_path}")
        ctx.state = State.FAILED
        return

    size_mb = os.path.getsize(image_path) / 1024 / 1024
    log(f"Stage 2: Uploading sysupgrade.tar ({size_mb:.1f} MB) to initramfs at {openwrt_ip}...")

    remote_path = "/tmp/sysupgrade.tar"
    scp_command = scp_cmd(openwrt_ip, image_path, f"root@{openwrt_ip}:{remote_path}",
                          key=ctx.ssh_key_path or None, connect_timeout=10)
    try:
        r = subprocess.run(scp_command, capture_output=True, text=True, timeout=120, check=False)
        if r.returncode != 0:
            log(f"SCP to initramfs failed (exit {r.returncode}): {r.stderr[:300]}")
            ctx.state = State.FAILED
            return
    except subprocess.TimeoutExpired:
        log("SCP upload to initramfs timed out.")
        ctx.state = State.FAILED
        return

    log("sysupgrade.tar uploaded. Verifying...")
    # Verify upload via remote md5sum
    ssh_command = ssh_cmd(openwrt_ip,
                          f"md5sum {remote_path}",
                          key=ctx.ssh_key_path or None, connect_timeout=10)
    try:
        r = subprocess.run(ssh_command, capture_output=True, text=True, timeout=15, check=False)
        if r.returncode == 0 and r.stdout.strip():
            remote_hash = r.stdout.strip().split()[0]
            log(f"Remote MD5: {remote_hash}")
        else:
            log(f"Could not verify remote file: {r.stderr[:200]}")
    except Exception:
        pass  # Verification is best-effort

    ctx.timeline.upload_complete = ts()
    ctx._say_fn("Upload complete. Flashing firmware.")
    log("sysupgrade.tar uploaded successfully. Proceeding to flash.")
    ctx.state = State.EDGEOS_STAGE2_FLASHING


def _handle_edgeos_stage2_flashing(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Stage 2b: Manual dd — extract kernel+rootfs from tar and write to eMMC."""
    openwrt_ip = ctx.profile.openwrt_ip
    profile = ctx.profile
    model_id = profile.name

    # Build the device-specific tar member paths
    # OpenWrt tar structure: sysupgrade-DEVICE_NAME/kernel and sysupgrade-DEVICE_NAME/root
    # Device name uses underscores: ubnt_edgerouter-6p
    device_name = model_id.replace("-", "_")
    kernel_member = f"sysupgrade-{device_name}/kernel"
    root_member = f"sysupgrade-{device_name}/root"
    boot_partition = profile.boot_partition
    kernel_path = profile.kernel_path
    md5_path = profile.md5_path

    # The flash script — uses sh (not bash — initramfs only has ash)
    flash_script = (
        f"set -ex; "
        f"tar tf /tmp/sysupgrade.tar | head -5; "
        f"mkdir -p /boot; "
        f"mount -t vfat {boot_partition} /boot; "
        f"[ -f /boot{kernel_path} ] && mv /boot{kernel_path} /boot{kernel_path}.previous; "
        f"[ -f /boot{md5_path} ] && mv /boot{md5_path} /boot{md5_path}.previous; "
        f"tar xf /tmp/sysupgrade.tar {kernel_member} -O > /boot{kernel_path}; "
        f"md5sum /boot{kernel_path} | cut -f1 -d ' ' > /boot{md5_path}; "
        f"echo 'Kernel size:'; "
        f"ls -la /boot{kernel_path}; "
        f"echo 'Flashing rootfs to /dev/mmcblk0p2...'; "
        f"tar xf /tmp/sysupgrade.tar {root_member} -O | dd of=/dev/mmcblk0p2 bs=4096; "
        f"sync; "
        f"umount /boot; "
        f"echo 'Flash complete. Rebooting into permanent OpenWrt...'; "
        f"reboot -f"
    )

    log("Stage 2: Flashing squashfs kernel + rootfs to eMMC...")
    ctx._say_fn("Flashing firmware. Do not unplug.")

    ssh_command = ssh_cmd(openwrt_ip,
                          f"sh -c '{flash_script}'",
                          key=ctx.ssh_key_path or None, connect_timeout=10)
    try:
        r = subprocess.run(ssh_command, capture_output=True, text=True, timeout=120, check=False)
        combined = (r.stdout or "") + (r.stderr or "")
        if "Flash complete" in combined:
            log("Flash completed successfully.")
        elif r.returncode != 0 and not r.stdout and not r.stderr:
            log("Flash command sent (connection closed by remote during reboot — expected).")
        else:
            log(f"Flash output (exit {r.returncode}): {combined[:500]}")
    except subprocess.TimeoutExpired:
        log("Flash command timed out (may have started reboot).")

    ctx.timeline.flash_triggered = ts()
    ctx.state = State.OPENWRT_BOOTING


def _handle_sysupgrade_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip
    if ctx.profile.flash_method == "mtd-write":
        model = load_model(ctx.profile.name)
        mtd_cfg = model.get("flash_methods", {}).get("mtd-write", {})
        mtd_command = mtd_cfg.get("command", "mtd -r write /tmp/firmware.bin firmware")
        success = _flash_via_mtd_write(openwrt_ip, ctx.image_path, ctx.ssh_key_path or None,
                                       mtd_command=mtd_command)
    else:
        success = _flash_via_sysupgrade(openwrt_ip, ctx.image_path, ctx.ssh_key_path or None)
    if success:
        ctx.sha256_before = sha256_file(ctx.image_path)
        ctx.state = State.SYSUPGRADE_REBOOTING
    else:
        log("sysupgrade upload failed.")
        ctx.state = State.FAILED


def _handle_sysupgrade_rebooting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    method = "mtd-write" if ctx.profile.flash_method == "mtd-write" else "sysupgrade"
    ctx._say_fn("Firmware flashing. Do not unplug.")
    log(f"{method}: device is rebooting")
    ctx.state = State.SYSUPGRADE_BOOTING


def _handle_sysupgrade_booting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip
    method = "mtd-write" if ctx.profile.flash_method == "mtd-write" else "sysupgrade"
    if _wait_for_sysupgrade_reboot(openwrt_ip):
        ctx.timeline.ssh_available = ts()
        ctx._say_fn("Recovery complete! Router is back online.")
        log(f"SUCCESS — {method} recovery complete.")
        verify_router(openwrt_ip,
                     wan_ssh_expected=ctx.wan_ssh_enabled,
                     mgmt_wifi_expected=bool(ctx.defaults_script))
        ctx.state = State.COMPLETE
    else:
        ctx._say_fn("Device did not come back after flash.")
        log(f"FAIL: SSH not available after {method} reboot.")
        ctx.state = State.FAILED


def _handle_waiting_for_power_off(ctx: RecoveryContext, eq: queue.Queue) -> None:
    link_up = get_link_state(ctx.interface)
    if link_up:
        ctx._say_fn("Ready. Please unplug the power cable from the router now.")
        log("STEP 1: Unplug power (keep ethernet in LAN port)")

        _wait_for_event_or_timeout(
            eq, timeout=300,
            target_events={Event.LINK_DOWN},
            success_state=State.WAITING_FOR_UBOOT,
            fail_message="Timed out waiting for power off.",
            fail_say="Timed out. Please unplug the power cable from the router.",
            ctx=ctx,
        )
        if ctx.state == State.WAITING_FOR_UBOOT:
            ctx._say_fn("Power disconnected. Good.")
            ctx.timeline.power_off = ts()
    else:
        log("Router already powered off.")
        ctx._say_fn("Router is off. Good.")
        ctx.timeline.power_off = ts()
        ctx.state = State.WAITING_FOR_UBOOT


def _handle_waiting_for_uboot(ctx: RecoveryContext, eq: queue.Queue, link_monitor: LinkMonitor) -> None:
    print()
    profile = ctx.profile
    ctx._say_fn(profile.reset_instructions)
    log(f"STEP 2: {profile.reset_instructions}")
    time.sleep(4)

    ctx._say_fn("While still holding reset, plug in the power cable.")
    log("STEP 3: Plug in power WHILE STILL HOLDING reset")
    time.sleep(2)

    ctx._say_fn(
        f"Watch the LED. {profile.led_pattern}. "
        "Release reset when the LED shows the recovery pattern."
    )
    log(f"Waiting for recovery LED pattern: {profile.led_pattern}")
    print()

    got_link_up = _wait_for_event_or_timeout(
        eq, timeout=30,
        target_events={Event.LINK_UP},
        success_state=None,
        fail_message="Ethernet link did not come up.",
        fail_say="Ethernet link did not come up. Check the cable is in the LAN port.",
        ctx=ctx,
    )
    if got_link_up is None:
        ctx.state = State.FAILED
        return

    ctx.timeline.link_up = ts()
    ctx._say_fn("Link detected. Waiting for recovery mode.")
    log(f"Link up — waiting for recovery HTTP: {profile.led_pattern}")
    time.sleep(8)

    log("Scanning for recovery HTTP server...")
    uboot_found = False
    probe_start = ts()
    probe_timeout = 90

    while ts() - probe_start < probe_timeout:
        found, detail = detect_uboot_http(profile.recovery_ip)
        if found:
            log(f"Recovery mode detected: {detail}")
            ctx.timeline.uboot_http_first = ts()
            ctx._say_fn("Recovery mode detected. You can release the button now.")
            ctx.state = State.UBOOT_UPLOADING
            uboot_found = True
            break

        _drain_events(eq, ctx)

        time.sleep(1)

    if not uboot_found:
        ctx._say_fn(f"Recovery mode not found. Check the LED pattern: {profile.led_pattern}")
        log("FAIL: Recovery HTTP server not detected.")
        ctx.state = State.FAILED


def _handle_uboot_uploading(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    if ctx.no_upload:
        ctx._say_fn("Dry run. Recovery server is ready but not uploading.")
        log(f"DRY RUN: Recovery server ready at http://{profile.recovery_ip}")
        log(f"  Upload: curl -F {profile.upload_field}=@{ctx.image_path} http://{profile.recovery_ip}{profile.upload_endpoint}")
        if profile.trigger_flash_endpoint:
            log(f"  Flash:  curl http://{profile.recovery_ip}{profile.trigger_flash_endpoint}")
        ctx.state = State.COMPLETE
        return

    ctx.sha256_before = sha256_file(ctx.image_path)
    log(f"SHA-256 (before upload): {ctx.sha256_before}")

    ctx.timeline.upload_start = ts()

    if profile.flash_method == "dlink-hnap":
        ok, response = _flash_via_dlink_hnap(ctx.image_path, profile)
    else:
        ok, response = upload_firmware(ctx.image_path, profile)
    if not ok:
        ctx._say_fn(f"Upload failed. Try a browser at http://{profile.recovery_ip} instead.")
        ctx.state = State.FAILED
        return

    ctx.timeline.upload_complete = ts()
    eq.put((Event.UPLOAD_COMPLETE, ts(), response))

    ctx.sha256_after = sha256_file(ctx.image_path)
    if ctx.sha256_after != ctx.sha256_before:
        log("WARNING: SHA-256 mismatch! File may have been modified on disk during upload.")
    else:
        log(f"SHA-256 verified (after upload): {ctx.sha256_after}")

    if profile.flash_method != "dlink-hnap" and trigger_flash(profile):
        ctx.timeline.flash_triggered = ts()
        eq.put((Event.FLASH_TRIGGERED, ts(), ""))
    else:
        log("Flash trigger may have failed. Router may still flash on its own.")
        ctx.timeline.flash_triggered = ts()

    ctx._say_fn("Firmware flashing. Do not unplug.")
    ctx.state = State.UBOOT_FLASHING


def _handle_uboot_flashing(ctx: RecoveryContext, eq: queue.Queue, pcap_monitor: Optional[PcapMonitor]) -> None:
    if pcap_monitor is None:
        timeout = ctx.profile.flash_time_seconds + 30
        log(f"Waiting {timeout}s for flash to complete (polling-only mode)...")
        time.sleep(timeout)
        ctx.timeline.flash_complete = ts()
        ctx.state = State.REBOOTING
        return

    profile = ctx.profile
    timeout = profile.flash_time_seconds + 120
    result = _wait_for_event_or_timeout(
        eq, timeout=timeout,
        target_events={Event.UBOOT_ARP_192_168_1_2, Event.LINK_DOWN},
        success_state=State.REBOOTING,
        fail_message=f"Flash did not complete within {timeout}s.",
        fail_say="Flash is taking too long. Something went wrong.",
        ctx=ctx,
    )
    if result is None:
        ctx.state = State.FAILED
        return

    ctx.timeline.flash_complete = ts()
    log(f"Flash complete (event: {result})")
    if result == Event.LINK_DOWN:
        ctx._say_fn("Link down. Router is rebooting.")
    elif result == Event.UBOOT_ARP_192_168_1_2:
        ctx._say_fn("Firmware uploaded. Flashing in progress. Do not unplug.")


def _handle_serial_waiting_for_bootmenu(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    port = ctx.serial_port
    baud = ctx.serial_baud

    if not port:
        try:
            port = _auto_detect_serial_port()
            log(f"Auto-detected serial port: {port}")
        except FileNotFoundError as e:
            log(f"ERROR: {e}")
            ctx.state = State.FAILED
            return

    ctx._say_fn("Connect serial adapter and Ethernet cable to LAN2.")
    if profile.lan_port:
        log(f"IMPORTANT: Connect Ethernet cable to {profile.lan_port} port")
    log(f"Serial port: {port} at {baud} baud")

    ctx._say_fn("Power cycle the router now.")
    log("Power cycle the router now. Watching for U-Boot bootmenu...")

    driver = SerialUBootDriver(port, baud)
    ctx._serial_driver = driver

    got_prompt = driver.wait_for_bootmenu(
        timeout=profile.bootmenu_timeout,
        interrupt=profile.bootmenu_interrupt,
        console_option=profile.bootmenu_select_console,
        say_fn=ctx._say_fn,
    )

    if not got_prompt:
        ctx._say_fn("Failed to get U-Boot prompt. Check serial connection and try again.")
        driver.close()
        ctx.state = State.FAILED
        return

    eq.put((Event.SERIAL_UBOOT_READY, ts(), ""))
    ctx.timeline.uboot_http_first = ts()
    ctx.state = State.SERIAL_UBOOT_INTERACTING


def _handle_serial_uboot_interacting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    driver: SerialUBootDriver = ctx._serial_driver

    tftp_root = ctx.tftp_root
    if not tftp_root:
        tftp_root = os.path.join(os.path.dirname(ctx.image_path), "tftpboot")
        if not os.path.isdir(tftp_root):
            tftp_root = os.path.dirname(ctx.image_path)

    tftp_mgr = TFTPServerManager(tftp_root)
    ctx._tftp_manager = tftp_mgr

    if not tftp_mgr.start():
        log("WARNING: TFTP server not available — commands may fail")

    ctx._say_fn("Setting up network and starting flash process.")

    setup_interface_for_serial(ctx)

    commands = ctx.uboot_commands
    if not commands:
        commands = profile.uboot_commands

    if not commands:
        log("ERROR: No U-Boot commands defined in model JSON")
        ctx.state = State.FAILED
        tftp_mgr.stop()
        driver.close()
        return

    ctx.timeline.upload_start = ts()
    ctx.sha256_before = sha256_file(ctx.image_path) if ctx.image_path else ""

    success = driver.run_commands(
        commands, eq,
        say_fn=ctx._say_fn,
        flash_time_seconds=profile.flash_time_seconds,
    )

    tftp_mgr.stop()

    if success:
        ctx.timeline.flash_complete = ts()
        ctx.timeline.upload_complete = ts()
        log("All U-Boot commands executed successfully")
        ctx.state = State.REBOOTING
        driver.close()
    else:
        ctx._say_fn("Flash failed. Check serial output for details.")
        ctx.state = State.FAILED
        driver.close()


def setup_interface_for_serial(ctx: RecoveryContext) -> None:
    profile = ctx.profile
    interface = ctx.interface
    if not interface:
        return

    if profile.client_ip:
        configure_interface_ip(interface, profile.client_ip, "24")


def _handle_zycast_waiting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    ctx._say_fn("Power cycle the router now. Multicast flash will start automatically.")
    log("Waiting for ZyXEL Multiboot multicast packets...")

    multicast_group = getattr(profile, 'zycast_multicast_group', '225.0.0.0')
    multicast_port = getattr(profile, 'zycast_multicast_port', 5631)
    probe_timeout = 120
    probe_start = ts()

    while ts() - probe_start < probe_timeout:
        try:
            event, event_ts, detail = eq.get(timeout=1.0)
            if event == Event.ZYCAST_MULTICAST_DETECTED:
                ctx.timeline.uboot_http_first = ts()
                log(f"ZyXEL Multiboot detected: {detail}")
                ctx._say_fn("Multiboot detected. Starting multicast flash.")
                ctx.state = State.ZYCAST_SENDING
                return
            if event == Event.LINK_UP and ctx.timeline.link_up is None:
                ctx.timeline.link_up = event_ts
                log("Link up — watching for multicast")
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
        except queue.Empty:
            pass

        _drain_events(eq, ctx)

    ctx._say_fn("No Multiboot detected. Check that the router is powered on.")
    log(f"FAIL: No multicast packets from ZyXEL bootloader within {probe_timeout}s")
    ctx.state = State.FAILED


def _handle_zycast_sending(ctx: RecoveryContext, eq: queue.Queue) -> None:
    if ctx.no_upload:
        ctx._say_fn("Dry run. Multiboot detected but not flashing.")
        log("DRY RUN: Would flash via zycast multicast")
        ctx.state = State.COMPLETE
        return

    profile = ctx.profile
    ctx.sha256_before = sha256_file(ctx.image_path)
    log(f"SHA-256 (before zycast): {ctx.sha256_before}")

    multicast_group = getattr(profile, 'zycast_multicast_group', '225.0.0.0')
    multicast_port = getattr(profile, 'zycast_multicast_port', 5631)
    image_type = getattr(profile, 'zycast_image_type', 'ras')

    ctx.timeline.upload_start = ts()
    ctx._say_fn("Sending firmware via multicast. Do not unplug.")
    log(f"Starting zycast: {ctx.image_path} -> {multicast_group}:{multicast_port}")

    try:
        proc = run_zycast_auto(
            image_path=ctx.image_path,
            interface=ctx.interface,
            multicast_group=multicast_group,
            multicast_port=multicast_port,
            image_type=image_type,
        )
    except Exception as e:
        log(f"ERROR: Failed to start zycast: {e}")
        ctx.state = State.FAILED
        return

    ctx._zycast_proc = proc

    flash_timeout = getattr(profile, 'flash_time_seconds', 180) + 60
    start = ts()
    while ts() - start < flash_timeout:
        retcode = proc.poll()
        if retcode is not None:
            break
        try:
            event, event_ts, detail = eq.get(timeout=2.0)
            if event == Event.ZYCAST_MULTICAST_DETECTED:
                log(f"  multicast activity: {detail[:80]}")
        except queue.Empty:
            pass

    if proc.poll() is None:
        log("zycast still running after timeout — terminating")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    stdout_data = proc.stdout.read() if proc.stdout else ""
    stderr_data = proc.stderr.read() if proc.stderr else ""

    if stdout_data:
        for line in stdout_data.strip().split("\n")[:10]:
            log(f"  [zycast stdout] {line}")
    if stderr_data:
        for line in stderr_data.strip().split("\n")[:10]:
            log(f"  [zycast stderr] {line}")

    retcode = proc.returncode
    if retcode == 0:
        ctx.timeline.upload_complete = ts()
        ctx.timeline.flash_complete = ts()
        ctx.timeline.flash_triggered = ts()
        log("zycast completed successfully")
        ctx._say_fn("Multicast flash complete. Waiting for router to reboot.")
        ctx.state = State.REBOOTING
    else:
        log(f"zycast exited with code {retcode}")
        ctx._say_fn("Multicast flash may have failed. Check the console output.")
        ctx.timeline.flash_complete = ts()
        ctx.state = State.REBOOTING


def _handle_oem_login(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    method = profile.flash_method
    stock_ip = profile.stock_default_ip
    username = profile.stock_default_user
    password = profile.stock_default_password

    if not password:
        model_data = load_model(profile.name)
        creds = model_data.get("stock_default_creds", {})
        username = creds.get("username", "admin")
        password = creds.get("password", "1234")

    if not ctx.initramfs_path or not os.path.isfile(ctx.initramfs_path):
        log(f"ERROR: initramfs image not found: {ctx.initramfs_path}")
        ctx.state = State.FAILED
        return

    if method == "oem-http":
        log(f"Logging into ZyXEL OEM web UI at {stock_ip} (user={username})...")
        success, cookie = oem_http_login(stock_ip, username, password)
        if not success:
            log(f"ERROR: OEM HTTP login failed: {cookie}")
            ctx.state = State.FAILED
            return

        try:
            r_dash = subprocess.run(
                ["curl", "-s", "--max-time", "10", "-b", cookie, "-L",
                 f"http://{stock_ip}/cgi-bin/dispatcher.cgi?cmd=4"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            if "cmd=30" in r_dash.stdout or ("Password" in r_dash.stdout and "Change" in r_dash.stdout):
                new_password = "Zyxel2026!"
                log(f"Mandatory password change detected, changing to '{new_password}'...")
                pw_ok, pw_msg = oem_http_change_password(stock_ip, username, password, new_password, cookie)
                if pw_ok:
                    log(pw_msg)
                    success, cookie = oem_http_login(stock_ip, username, new_password)
                    if not success:
                        log(f"ERROR: Re-login after password change failed: {cookie}")
                        ctx.state = State.FAILED
                        return
                    password = new_password
                else:
                    log(f"WARNING: Password change failed: {pw_msg}")
        except Exception as e:
            log(f"WARNING: Password change check failed: {e}")

        ctx.oem_state["cookie"] = cookie
        ctx.oem_state["password"] = password
        log("OEM HTTP login successful")

    elif method == "oem-ftp":
        log(f"Logging into GS1920-24 OEM web UI at {stock_ip} (user={username})...")
        success, cookie_file = oem_ftp_login(stock_ip, username, password)
        if not success:
            log(f"ERROR: OEM FTP login failed: {cookie_file}")
            ctx.state = State.FAILED
            return
        ctx.oem_state["cookie_file"] = cookie_file
        ctx.oem_state["password"] = password
        log("OEM FTP login successful")

    else:
        log(f"ERROR: Unknown OEM method: {method}")
        ctx.state = State.FAILED
        return

    if oem_has_prepare_step(method):
        ctx.state = State.OEM_PREPARE
    else:
        ctx.state = State.OEM_UPLOADING


def _handle_oem_prepare(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    method = profile.flash_method
    stock_ip = profile.stock_default_ip

    if method == "oem-ftp":
        cookie_file = ctx.oem_state.get("cookie_file", "")
        log("Enabling FTP service on device...")
        success, msg = oem_ftp_enable_service(stock_ip, cookie_file)
        if not success:
            log(f"ERROR: FTP service enable failed: {msg}")
            ctx.state = State.FAILED
            return
        log("FTP service enabled")

    ctx.state = State.OEM_UPLOADING


def _handle_oem_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    method = profile.flash_method
    stock_ip = profile.stock_default_ip
    initramfs_path = ctx.initramfs_path

    if method == "oem-http":
        cookie = ctx.oem_state.get("cookie", "")
        upload_endpoint = profile.oem_http_upload_endpoint

        filename = os.path.basename(initramfs_path)
        upload_path = initramfs_path
        if len(filename) > 64:
            upload_path = os.path.join(tempfile.gettempdir(), "openwrt-initramfs.bin")
            shutil.copy2(initramfs_path, upload_path)
            log(f"Renamed initramfs (>{len(filename)} chars) to {os.path.basename(upload_path)} for v2.90 compatibility")

        timeout = profile.flash_time_seconds + 60
        success, response = oem_http_upload(stock_ip, cookie, upload_path, upload_endpoint, timeout=timeout)
        if upload_path != initramfs_path and os.path.exists(upload_path):
            os.unlink(upload_path)

        if not success:
            log(f"ERROR: OEM HTTP upload failed: {response}")
            ctx.state = State.FAILED
            return

        ctx.timeline.upload_start = ts()
        ctx.timeline.upload_complete = ts()
        log("Firmware uploaded. Accepting reboot dialog...")
        oem_http_accept_reboot(stock_ip, cookie)

    elif method == "oem-ftp":
        username = profile.stock_default_user
        password = ctx.oem_state.get("password", profile.stock_default_password)
        client_ip = profile.client_ip
        target = profile.oem_ftp_target

        success, response = oem_ftp_upload(stock_ip, username, password,
                                           initramfs_path, target=target,
                                           client_ip=client_ip)
        if not success:
            log(f"ERROR: OEM FTP upload failed: {response}")
            ctx.state = State.FAILED
            return

        ctx.timeline.upload_start = ts()
        ctx.timeline.upload_complete = ts()
        log("Firmware uploaded via FTP. Device will reboot...")

    else:
        log(f"ERROR: Unknown OEM method for upload: {method}")
        ctx.state = State.FAILED
        return

    ctx.timeline.flash_triggered = ts()
    ctx._say_fn("Firmware uploaded. Waiting for device to reboot.")
    ctx.state = State.OEM_REBOOTING


def _handle_oem_rebooting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    openwrt_ip = profile.openwrt_ip or "192.168.1.1"

    ctx._say_fn("Device is rebooting into OpenWrt initramfs.")
    install_fn = get_oem_install_fn(profile.flash_method)

    result = oem_reboot_wait_and_install(ctx, openwrt_ip, install_fn)
    if result is not None:
        ctx.state = result


def _handle_rebooting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    ctx._say_fn("Router is rebooting. Waiting for it to come back online.")

    # Phase 1: Wait for link to come back up (pcap may be dead, but LinkMonitor still works)
    link_result = _wait_for_event_or_timeout(
        eq, timeout=REBOOT_TIMEOUT,
        target_events={Event.LINK_UP},
        success_state=None,
        fail_message="Link did not come back up after reboot.",
        fail_say="Link did not come back up. Check the ethernet cable.",
        ctx=ctx,
    )
    if link_result is None:
        ctx.state = State.FAILED
        return

    ctx._say_fn("Link detected. Waiting for OpenWrt to boot.")
    log("Link up after reboot — waiting for OpenWrt")

    # Phase 2: Wait for ICMPv6/SSH via pcap events, with active SSH polling fallback.
    # First boot with luci on MIPS can take several minutes, so use a generous timeout
    # and actively poll SSH in case pcap events are missed.
    timeout_after_link = 600
    openwrt_ip = ctx.profile.openwrt_ip or ctx.profile.recovery_ip
    start = ts()
    while ts() - start < timeout_after_link:
        try:
            event, event_ts, detail = eq.get(timeout=5.0)
            if event == Event.ICMPV6_FROM_ROUTER:
                ctx.timeline.first_openwrt_packet = event_ts
                ctx._say_fn("OpenWrt is booting.")
                log("ICMPv6 from router MAC detected — OpenWrt is booting")
                break
            elif event == Event.SSH_UP:
                ctx.timeline.ssh_available = event_ts
                ctx._say_fn("Recovery complete! Router is back online.")
                log("SUCCESS — router recovered (SSH detected during reboot phase).")
                verify_router(openwrt_ip,
                             wan_ssh_expected=ctx.wan_ssh_enabled,
                             mgmt_wifi_expected=bool(ctx.defaults_script))
                ctx.state = State.COMPLETE
                return
            elif event == Event.LINK_UP and ctx.state == State.REBOOTING:
                pass
        except queue.Empty:
            pass
        if check_ssh(openwrt_ip):
            ctx.timeline.ssh_available = ts()
            ctx._say_fn("Recovery complete! Router is back online.")
            log("SUCCESS — router recovered (SSH poll detected).")
            verify_router(openwrt_ip,
                         wan_ssh_expected=ctx.wan_ssh_enabled,
                         mgmt_wifi_expected=bool(ctx.defaults_script))
            ctx.state = State.COMPLETE
            return
    else:
        log(f"OpenWrt did not appear within {timeout_after_link}s after link up.")
        ctx._say_fn("OpenWrt is taking longer than expected. Check the router.")
        ctx.state = State.FAILED
        return

    ctx.state = State.OPENWRT_BOOTING


def _handle_openwrt_booting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip or ctx.profile.recovery_ip
    ssh_monitor = SSHMonitor(openwrt_ip, eq, poll_interval=5.0)
    ssh_thread = threading.Thread(target=ssh_monitor.run, daemon=True)
    ssh_thread.start()

    timeout = 120
    result = _wait_for_event_or_timeout(
        eq, timeout=timeout,
        target_events={Event.SSH_UP, Event.LINK_UP},
        success_state=None,
        fail_message=f"SSH not available within {timeout}s.",
        fail_say="Router is taking longer than expected. Check SSH in a few minutes.",
        ctx=ctx,
    )

    ssh_monitor.stop()

    if result == Event.SSH_UP:
        ctx.timeline.ssh_available = ts()
        ctx._say_fn("Recovery complete! Router is back online.")
        log("SUCCESS — router recovered.")
        verify_router(openwrt_ip,
                     wan_ssh_expected=ctx.wan_ssh_enabled,
                     mgmt_wifi_expected=bool(ctx.defaults_script))
        ctx.state = State.COMPLETE
    else:
        if check_ssh(openwrt_ip):
            ctx.timeline.ssh_available = ts()
            ctx._say_fn("Recovery complete! Router is back online.")
            log("SUCCESS — router recovered (SSH fallback check).")
            verify_router(openwrt_ip,
                         wan_ssh_expected=ctx.wan_ssh_enabled,
                         mgmt_wifi_expected=bool(ctx.defaults_script))
            ctx.state = State.COMPLETE
        else:
            ctx.state = State.FAILED


def _wait_for_event_or_timeout(
    eq: queue.Queue,
    timeout: int,
    target_events: set[Event],
    success_state: Optional[State],
    fail_message: str,
    fail_say: str,
    ctx: RecoveryContext,
) -> Optional[Event]:
    """Wait for one of the target events or timeout.

    Returns the Event that was found, or None on timeout.
    Sets ctx.state to success_state on success, or State.FAILED on timeout.
    """
    start = ts()
    while ts() - start < timeout:
        try:
            event, event_ts, detail = eq.get(timeout=1.0)

            if event in target_events:
                if success_state is not None:
                    ctx.state = success_state
                return event

            if event == Event.LINK_UP and ctx.timeline.link_up is None:
                ctx.timeline.link_up = event_ts
                if ctx.state in (State.REBOOTING, State.OPENWRT_BOOTING):
                    ctx._say_fn("Link up. Waiting for OpenWrt to boot.")
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
            elif event == Event.ICMPV6_FROM_ROUTER and ctx.timeline.first_openwrt_packet is None:
                ctx.timeline.first_openwrt_packet = event_ts
                ctx._say_fn("OpenWrt is booting.")
            elif event == Event.SSH_UP:
                ctx.timeline.ssh_available = event_ts
                if success_state is not None:
                    ctx.state = success_state
                return event
            elif event == Event.UBOOT_HTTP and ctx.timeline.uboot_http_first is None:
                ctx.timeline.uboot_http_first = event_ts

        except queue.Empty:
            pass

    log(fail_message)
    ctx._say_fn(fail_say)
    if success_state is not None:
        ctx.state = State.FAILED
    return None


def _drain_events(eq: queue.Queue, ctx: RecoveryContext) -> None:
    """Non-blocking drain of any pending events to update timeline."""
    while True:
        try:
            event, event_ts, detail = eq.get_nowait()
            if event == Event.LINK_UP and ctx.timeline.link_up is None:
                ctx.timeline.link_up = event_ts
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
            elif event == Event.UBOOT_HTTP and ctx.timeline.uboot_http_first is None:
                ctx.timeline.uboot_http_first = event_ts
        except queue.Empty:
            break


from conwrt.device_inventory import _print_timeline, _record_inventory, auto_detect_interface


def _build_parser() -> argparse.ArgumentParser:
    try:
        available_ids = [m["id"] for m in list_models()]
    except Exception:
        available_ids = []

    parser = argparse.ArgumentParser(
        description="conwrt — flash OpenWrt firmware to routers",
    )
    parser.add_argument("--version", action="version", version=f"conwrt {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    flash_parser = subparsers.add_parser("flash",
        help="Flash firmware to device (default if no subcommand given)")
    flash_parser.add_argument("--model-id", required=False,
                        help=f"Model ID from models/ directory (e.g. glinet-mt3000, dlink-covr-x1860-a1). "
                             f"Auto-detected if device is running OpenWrt. "
                             f"Use 'conwrt list' to see all available. "
                             f"Known: {', '.join(sorted(available_ids)) or 'none loaded'}")

    firmware_group = flash_parser.add_mutually_exclusive_group()
    firmware_group.add_argument("--image", default=None,
                                help="Path to firmware image (vanilla or custom)")
    firmware_group.add_argument("--request-image", action="store_true",
                                help="Request custom image from ASU with baked-in settings")

    flash_parser.add_argument("--ssh-key", default=None,
                        help="Path to SSH public key (default: [ssh].key from config.toml)")
    flash_parser.add_argument("--password", default=None,
                        help="Set root password (default: random, printed once)")
    flash_parser.add_argument("--no-password", action="store_true",
                        help="Skip password (key-only auth)")
    flash_parser.add_argument("--wan-ssh", action="store_true",
                        help="Open SSH on WAN port (requires --ssh-key, disables password auth)")
    flash_parser.add_argument("--interface", default=None,
                        help="Ethernet interface (auto-detected if omitted)")
    flash_parser.add_argument("--no-voice", action="store_true", help="Disable voice guidance")
    flash_parser.add_argument("--no-upload", action="store_true",
                        help="Stop after detecting U-Boot (dry run)")
    flash_parser.add_argument("--yes", action="store_true",
                        help="Skip destructive-operation confirmations")
    flash_parser.add_argument("--no-pcap", action="store_true",
                        help="Disable pcap monitoring (polling-only mode, no scapy needed)")
    flash_parser.add_argument("--force-uboot", action="store_true",
                        help="Force U-Boot recovery mode even if OpenWrt is detected")
    flash_parser.add_argument("--capture", default=None,
                        help="Save pcap capture to file (auto-degrades if no root)")
    flash_parser.add_argument("--router-mac", default="",
                        help="Router's OpenWrt MAC address (for ICMPv6 detection)")
    flash_parser.add_argument("--uboot-mac", default="",
                        help="Router's U-Boot MAC address (for ARP detection)")
    flash_parser.add_argument("--silence-timeout", type=int, default=SILENCE_TIMEOUT_DEFAULT,
                        help="Seconds of no packets before silence event")
    flash_parser.add_argument("--serial-port", default=None,
                        help="Serial port for serial-tftp method (e.g. /dev/cu.usbserial-A50285BI). "
                             "Auto-detected if omitted.")
    flash_parser.add_argument("--flash-method", default=None,
                        help="Flash method to use (e.g. recovery-http, dlink-hnap, sysupgrade, mtd-write, zycast, extreme-rdwr-tftp-initramfs). "
                             "Auto-detected if omitted: sysupgrade if OpenWrt is running, "
                             "otherwise the first recovery method in the model JSON.")
    flash_parser.add_argument("--initramfs", default=None,
                        help="Path to OpenWrt initramfs image (for two-stage flash methods like extreme-rdwr-tftp-initramfs)")
    flash_parser.add_argument("--serial-method", default=None,
                        help="Serial flash method variant (e.g. openwrt-flash, stock-restore). "
                             "Selects the serial-tftp-{method} flash_method from model JSON.")
    flash_parser.add_argument("--serial-baud", type=int, default=115200,
                        help="Serial baud rate (default: 115200)")
    flash_parser.add_argument("--tftp-root", default=None,
                        help="TFTP server root directory. Defaults to image directory.")
    flash_parser.add_argument("--isolate-port", default="",
                        help="Switch port to isolate into VLAN before flashing (e.g. lan5). "
                             "Requires running on OpenWrt with port_isolation in model JSON.")

    subparsers.add_parser("list", help="List available device models")

    uc_parser = subparsers.add_parser("list-use-cases",
        help="List available use case presets")
    uc_parser.add_argument("--model-id", default=None,
        help="Show compatibility for a specific model")

    cache_parser = subparsers.add_parser("cache", help="Manage cached firmware images")
    cache_sub = cache_parser.add_subparsers(dest="cache_command")
    cache_sub.add_parser("list", help="List cached firmware images")
    cache_clean = cache_sub.add_parser("clean", help="Remove cached firmware images")
    cache_clean.add_argument("--model-id", default=None,
                        help="Only clean images for this model")
    cache_clean.add_argument("--keep-latest", action="store_true",
                        help="Keep only the latest build per model")
    cache_clean.add_argument("--yes", action="store_true",
                        help="Skip confirmation prompt")

    mgmt_parser = subparsers.add_parser("setup-mgmt-wifi",
        help="Configure management WiFi on a running router")
    mgmt_parser.add_argument("--ip", default="192.168.1.1",
        help="Router IP address")
    mgmt_parser.add_argument("--model-id", default=None,
        help="Model ID (for SSH key detection)")

    backup_parser = subparsers.add_parser("backup",
        help="Backup MTD flash partitions from a stock ZyXEL router via SSH")
    backup_parser.add_argument("--model-id", default="zyxel-nr7101",
        help="Model ID (default: zyxel-nr7101)")
    backup_parser.add_argument("--ip", default="192.168.1.1",
        help="Router IP address (default: 192.168.1.1)")
    backup_parser.add_argument("--serial", default=None,
        help="Device serial number (printed on unit label). Used to generate stock SSH password.")
    backup_parser.add_argument("--password", default=None,
        help="Stock SSH password (overrides --serial). Use if zyxel_pwgen is unavailable.")
    backup_parser.add_argument("--output-dir", default=None,
        help="Output directory for partition dumps (default: data/backups/<serial>)")
    backup_parser.add_argument("--partitions", default=None,
        help="Comma-separated list of MTD partitions to dump (e.g. '0,1,2'). Default: all partitions.")
    backup_parser.add_argument("--user", default="root",
        help="SSH username (default: root)")

    fp_parser = subparsers.add_parser("fingerprint",
        help="Fingerprint a device to identify its model")
    fp_parser.add_argument("ip", help="IP address of the device to fingerprint")
    fp_parser.add_argument("--timeout", type=float, default=10.0,
        help="Timeout for probes in seconds (default: 10)")
    fp_parser.add_argument("--json", action="store_true", dest="json_output",
        help="Output results as JSON")

    auto_parser = subparsers.add_parser("auto",
        help="Auto-detect connected router and offer to flash it")
    auto_parser.add_argument("--interface", default=None,
        help="Ethernet interface (auto-detected if omitted)")
    auto_parser.add_argument("--passive-timeout", type=int, default=10,
        help="Seconds to listen for passive detection (default: 10)")
    auto_parser.add_argument("--no-menu", action="store_true",
        help="Print detection results and exit (non-interactive)")

    nor_parser = subparsers.add_parser("setup-nor-recovery",
        help="Set up NOR flash as recovery partition on dual-flash devices (e.g. GL.iNet AR300M)")
    nor_parser.add_argument("--model-id", required=True,
        help="Model ID (e.g. glinet_gl-ar300m-nand)")
    nor_parser.add_argument("--i-want-a-brick", action="store_true",
        help="Safety acknowledgment: required to actually flash (not needed with --dry-run)")
    nor_parser.add_argument("--dry-run", action="store_true",
        help="Download and verify only, do not flash anything")
    nor_parser.add_argument("--skip-uboot", action="store_true",
        help="Skip U-Boot upgrade (only flash NOR firmware and set boot_env)")
    nor_parser.add_argument("--ip", default=None,
        help="Router IP address (default: from model JSON openwrt.default_ip)")
    nor_parser.add_argument("--no-voice", action="store_true",
        help="Disable voice guidance")

    cfg_parser = subparsers.add_parser("configure",
        help="Apply config.toml settings to a running OpenWrt router via SSH")
    cfg_parser.add_argument("--ip", default="192.168.1.1",
        help="Router IP address (default: 192.168.1.1)")
    cfg_parser.add_argument("--model-id", default=None,
        help="Model ID for capability filtering (auto-detected if omitted)")
    cfg_parser.add_argument("--interface", default=None,
        help="Ethernet interface (needed for LAN IP change; auto-detected if omitted)")
    cfg_parser.add_argument("--ssh-key", default=None,
        help="Path to SSH public key (default: [ssh].key from config.toml)")
    cfg_parser.add_argument("--password", default=None,
        help="Set root password (default: from config.toml)")
    cfg_parser.add_argument("--no-password", action="store_true",
        help="Skip password, key-only auth")
    cfg_parser.add_argument("--wan-ssh", action="store_true",
        help="Open SSH on WAN port")
    cfg_parser.add_argument("--hostname", default=None,
        help="Set router hostname (overrides config.toml [device].hostname)")
    cfg_parser.add_argument("--wifi-disable", action="store_true",
        help="Disable all WiFi radios")
    cfg_parser.add_argument("--verify", action="store_true",
        help="After applying config, reboot and verify persistence")
    cfg_parser.add_argument("--lan-ip-mode", default=None,
        choices=["static", "mac-hash"],
        help="LAN IP mode: 'static' (use [network] lan_ip) or 'mac-hash' (derive from MAC)")
    cfg_parser.add_argument("--hostname-pattern", default=None,
        choices=["static", "model_mac", "model_seq"],
        help="Hostname pattern: 'static', 'model_mac' (e.g. lyra_aabbcc), 'model_seq'")
    cfg_parser.add_argument("--serial", default=None,
        help="Device serial number (e.g. from sticker) for hostname and inventory")
    cfg_parser.add_argument("--dry-run", action="store_true",
        help="Print commands without executing")
    cfg_parser.add_argument("--transport", default="ssh",
        choices=["ssh", "ubus"],
        help="Transport: 'ssh' (default) or 'ubus' (HTTP JSON-RPC)")
    cfg_parser.add_argument("--ubus-user", default="root",
        help="ubus username (default: root)")
    cfg_parser.add_argument("--ubus-password", default="",
        help="ubus password")

    profile_parser = subparsers.add_parser("profile",
        help="Inspect operator profile (config.toml) plans")
    profile_sub = profile_parser.add_subparsers(dest="profile_command")
    plan_parser = profile_sub.add_parser("plan",
        help="Show what would be applied (ASU + post-install)")
    plan_parser.add_argument("--model-id", default=None,
        help="Model ID for capability filtering")
    profile_parser.set_defaults(profile_command="plan")

    reset_parser = subparsers.add_parser("reset",
        help="Factory reset an OpenWrt router (SSH firstboot or failsafe mode)")
    reset_parser.add_argument("--ip", default="192.168.1.1",
        help="Router IP address (default: 192.168.1.1)")
    reset_parser.add_argument("--interface", default=None,
        help="Ethernet interface for failsafe monitoring (auto-detected if omitted)")
    reset_parser.add_argument("--ssh-key", default=None,
        help="Path to SSH private key")
    reset_parser.add_argument("--no-voice", action="store_true",
        help="Disable voice guidance")
    reset_parser.add_argument("--dry-run", action="store_true",
        help="Show what would be done without executing")
    reset_parser.add_argument("--model-id", default=None,
        help="Model ID (for reference/documentation)")

    return parser


def _ssh_run(ip: str, command: str, key: str = "", timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ssh_cmd(ip, command, key=key or None, connect_timeout=10),
        capture_output=True, text=True, timeout=timeout, check=False,
    )


def _cfg_install_ssh_key(ip: str, key_path: str, auth_key: str = "", ssh_key: str = "") -> bool:
    """Idempotent SSH key installation. Skips if key already present.

    key_path: path to public key file (for reading the key to install).
    auth_key: private key path used for SSH authentication.
    ssh_key: public key text (alternative to key_path).

    IMPORTANT: This MUST be called BEFORE _cfg_set_password. OpenWrt allows
    passwordless root login by default — once a password is set, passwordless
    login stops. If SSH keys aren't installed first, you lose remote access.
    """
    pub_key = ""
    if ssh_key and ssh_key.startswith("ssh-"):
        pub_key = ssh_key.split("\n")[0].strip()
        parts = pub_key.split()
        if len(parts) >= 2:
            pub_key = f"{parts[0]} {parts[1]}"
    elif key_path:
        from pathlib import Path as _P
        raw = _P(key_path).expanduser().read_text().strip()
        parts = raw.split()
        if len(parts) >= 2:
            pub_key = f"{parts[0]} {parts[1]}"
    if not pub_key:
        log("  ⚠ SSH key: no key provided — skipping")
        return False

    log("  SSH key: checking current state...")
    r = _ssh_run(ip, f"cat {DROPBEAR_AUTH_KEYS_PATH} 2>/dev/null || echo ''", key=auth_key)
    current_keys = r.stdout.strip()
    if pub_key in current_keys:
        log("  ✓ SSH key: already installed")
        return True

    log("  SSH key: installing...")
    needs_create = "No such file" in r.stderr or not current_keys
    op = ">" if needs_create or not current_keys else ">>"
    escaped = pub_key.replace("'", "'\\''")
    auth_dir = DROPBEAR_AUTH_KEYS_PATH.rsplit('/', 1)[0]
    install_r = _ssh_run(
        ip,
        f"mkdir -p {auth_dir} && echo '{escaped}' {op} {DROPBEAR_AUTH_KEYS_PATH} && chmod 600 {DROPBEAR_AUTH_KEYS_PATH}",
        key=auth_key,
    )
    if install_r.returncode != 0:
        log(f"  ⚠ SSH key: install failed (rc={install_r.returncode})")
        return False

    verify_r = _ssh_run(ip, f"cat {DROPBEAR_AUTH_KEYS_PATH} 2>/dev/null || echo ''", key=auth_key)
    if pub_key in verify_r.stdout:
        log("  ✓ SSH key: installed and verified")
        return True
    log("  ⚠ SSH key: verification failed")
    return False


def _cfg_set_password(ip: str, password: str, ssh_key: str = "") -> bool:
    """Set root password. Always runs (idempotent — setting same password is fine)."""
    if not password:
        log("  Password: no password provided — skipping")
        return False

    log("  Password: setting...")
    import base64
    pw_b64 = base64.b64encode(password.encode()).decode()
    r = _ssh_run(
        ip,
        f"printf '%s\\n%s\\n' \"$(echo '{pw_b64}' | base64 -d)\" \"$(echo '{pw_b64}' | base64 -d)\" | passwd root",
        key=ssh_key,
    )
    if r.returncode != 0:
        log(f"  ⚠ Password: failed (rc={r.returncode})")
        return False
    log("  ✓ Password: set")
    return True


def _record_configure_inventory(
    ip: str,
    password: str = "",
    serial: str = "",
    model_id: str = "",
    ssh_key_path: str = "",
    wan_ssh: bool = False,
) -> None:
    """Fingerprint router and append configuration results to inventory.jsonl.

    Called from cmd_configure after successful configuration. Records the
    generated password, serial (if provided), MAC addresses, and device
    identity so we have a permanent record of what was configured.
    """
    fp = fingerprint_router(ip)
    if not fp:
        log("  ⚠ inventory: could not fingerprint router — skipping inventory write")
        return

    ident = fp.get("identity", {})
    fw = fp.get("firmware", {})
    net = fp.get("network", {})
    sec = fp.get("security", {})
    macs = net.get("macs", {})

    board = ident.get("board", "")
    fp_path = save_fingerprint(fp, board_id=board)

    openwrt_target = ""
    if model_id:
        try:
            model = load_model(model_id)
            openwrt_target = model.get("openwrt", {}).get("target", "")
        except FileNotFoundError:
            pass

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": "configure",
        "device_serial": serial or ident.get("serial", ""),
        "model": ident.get("model", ""),
        "model_id": model_id,
        "vendor": fw.get("DISTRIB_ID", "").strip("'\"") or ident.get("vendor", ""),
        "firmware_version": fw.get("version", "").strip("'\""),
        "openwrt_target": openwrt_target,
        "hostname": ident.get("hostname", ""),
        "board": board,
        "kernel": fw.get("kernel", ""),
        "mac_addresses": {k: v for k, v in macs.items() if v and k != "lo"},
        "ssh_key_fingerprint": sec.get("ssh_fingerprint", ""),
        "ssh_key_count": sec.get("ssh_key_count", 0),
        "wan_ssh_rules": sec.get("wan_ssh_rules", 0),
        "password_set": bool(password),
        "wan_ssh_enabled": wan_ssh,
        "flashed_by": os.environ.get("USER", ""),
        "fingerprint_file": str(fp_path) if fp_path else "",
        "notes": "Configured via conwrt configure",
    }

    inventory_path = Path(__file__).resolve().parent.parent / "data" / "inventory.jsonl"
    try:
        _append_to_inventory(entry, str(inventory_path))
        log(f"  ✓ inventory: entry appended to {inventory_path}")
        if password:
            log(f"  ✓ inventory: password recorded for serial={serial or '(unknown)'}")
    except Exception as e:
        log(f"  ⚠ inventory: failed to write — {e}")


def _resolve_configure_options(
    args: argparse.Namespace, cfg: object,
) -> tuple[str, str, str, str, bool]:
    """Resolve effective configure options (CLI overrides config.toml).

    Returns (password, ssh_private_key_path, ssh_pub_path, ssh_key_text, wan_ssh).
    Password is empty when --no-password or when not configured.
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return "", "", "", "", False

    ssh_key_path = args.ssh_key or cfg.ssh_private_key_path or ""
    ssh_pub_path = cfg.ssh_public_key_path
    ssh_key_text = cfg.ssh_public_key_text
    if args.ssh_key:
        from pathlib import Path as _P
        p = _P(args.ssh_key).expanduser()
        if p.is_file() and p.suffix == ".pub":
            ssh_pub_path = str(p)

    if args.no_password:
        password = ""
    elif args.password:
        password = args.password
    elif cfg.password_is_random:
        password = _generate_random_password()
    else:
        password = cfg.password_literal or ""

    wan_ssh = cfg.wan_ssh
    if args.wan_ssh:
        wan_ssh = True

    return password, ssh_key_path, ssh_pub_path, ssh_key_text, wan_ssh


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
        from pathlib import Path as _P
        if _P(f"/sys/class/net/{interface}").exists():
            r = _ssh_run(ip, "uci get network.lan.ipaddr 2>/dev/null || echo ''", key=ssh_key_path)
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


def cmd_reset(args: argparse.Namespace) -> int:
    """Factory reset an OpenWrt router via SSH firstboot or failsafe mode."""
    ip = args.ip

    # --- resolve SSH key ---
    ssh_key = args.ssh_key if args.ssh_key else _detect_ssh_key_path()

    # --- detect interface ---
    interface = args.interface or auto_detect_interface()
    if not interface:
        log("ERROR: No ethernet interface detected. Use --interface to specify.")
        return 1

    # --- try SSH first ---
    if check_ssh(ip):
        log(f"SSH available at {ip}. Running firstboot directly.")
        if args.dry_run:
            print(f"  ssh root@{ip} 'firstboot -y && reboot'")
            return 0
        r = _ssh_run(ip, "firstboot -y && reboot", key=ssh_key, timeout=15)
        if r.returncode != 0 and not r.stdout and not r.stderr:
            # Connection closed by remote — expected during reboot
            pass
        elif r.returncode != 0 and ("Connection refused" in r.stderr or "timed out" in r.stderr.lower()):
            log(f"firstboot failed: {r.stderr.strip()}")
            return 1
        log("Factory reset initiated. Device will reboot to defaults.")
        if not args.no_voice:
            say("Factory reset initiated. The router will reboot to default settings.")
        return 0

    # --- failsafe path ---
    log(f"SSH not available at {ip}. Entering failsafe mode.")
    if not args.no_voice:
        say("Cannot reach the router via SSH. We will use OpenWrt failsafe mode.")
        say("I need you to power cycle the router. Unplug the power cable now.")

    log("Waiting for link down...")
    link_was_up = get_link_state(interface)
    deadline = time.time() + 30
    while time.time() < deadline:
        if link_was_up and not get_link_state(interface):
            break
        if not link_was_up:
            break
        time.sleep(0.5)

    if not args.no_voice:
        say("Power disconnected. Now plug in the power cable.")

    # --- start tcpdump monitoring ---
    local_mac = ""
    try:
        mac_r = subprocess.run(
            ["ifconfig", interface], capture_output=True, text=True, check=False,
        )
        mac_line = [l for l in mac_r.stdout.splitlines() if "ether " in l]
        local_mac = mac_line[0].split("ether ")[1].split()[0] if mac_line else ""
    except Exception:
        pass

    tcpdump_filter = ["not", "ether", "src", local_mac] if local_mac else []
    tcpdump_proc: Optional[subprocess.Popen] = None
    boot_detected = False
    failsafe_prompt_detected = False

    try:
        tcpdump_proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", interface, "-n", "-A",
             "--immediate-mode", "-l", "port", "4919", "and", "udp"]
            + tcpdump_filter,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        if args.dry_run:
            log(f"  (dry run) would monitor: sudo tcpdump -i {interface} -n -A --immediate-mode -l port 4919 and udp")
            return 0

        if tcpdump_proc.stdout is not None:
            for line in tcpdump_proc.stdout:
                line = line.strip()
                if not line or line.startswith("tcpdump:"):
                    continue
                if not boot_detected and "Please press button" in line:
                    log("FAILSAFE PROMPT DETECTED")
                    if not args.no_voice:
                        say("PRESS AND HOLD THE RESET BUTTON NOW. Hold for 2 seconds then release.")
                    boot_detected = True
                    failsafe_deadline = time.time() + 5
                    continue
                if boot_detected and time.time() >= failsafe_deadline:
                    break
    except Exception as exc:
        log(f"tcpdump error: {exc}")
    finally:
        if tcpdump_proc is not None:
            tcpdump_proc.terminate()
            try:
                tcpdump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tcpdump_proc.kill()

    if not boot_detected:
        log("No boot packet detected. The device may not have powered on yet.")
        if not args.no_voice:
            say("No boot detected. Please try again.")
        return 1

    # --- wait then check failsafe ---
    log("Waiting 10 seconds for failsafe mode to activate...")
    time.sleep(10)

    ping_r = subprocess.run(
        ["ping", "-c", "3", "-t", "2", ip],
        capture_output=True, text=True, check=False,
    )
    if ping_r.returncode != 0:
        log("Failsafe mode not detected (no ping response).")
        if not args.no_voice:
            say("Failsafe mode not detected. Try power cycling again and press reset sooner.")
        return 1

    log("Failsafe mode detected. Configuring interface and connecting via SSH.")
    if not args.no_voice:
        say("Failsafe mode detected. Connecting via SSH.")

    client_ip = "192.168.1.2"
    configured = configure_interface_ip(interface, client_ip, "24")
    if not configured:
        log(f"ERROR: Could not configure {interface} with IP {client_ip}. "
            f"Run 'sudo -v' to cache sudo credentials, then retry.")
        return 1

    r = _ssh_run(ip, "firstboot -y && reboot", key=ssh_key, timeout=15)
    if r.returncode != 0 and (r.stdout or r.stderr):
        log(f"firstboot via failsafe SSH failed: {r.stderr.strip()}")
        return 1

    log("Factory reset complete. The router will reboot with default settings.")
    if not args.no_voice:
        say("Factory reset complete. The router will reboot with default settings.")

    remove_interface_ip(interface, client_ip, "24")
    return 0


def cmd_profile_plan(args: argparse.Namespace) -> int:
    """Print the profile plan from config.toml (dry-run preview)."""
    cfg = _load_config()
    model_caps: list[str] = []
    if args.model_id:
        try:
            model = load_model(args.model_id)
            model_caps = model.get("capabilities", [])
        except FileNotFoundError as exc:
            print(f"Warning: {exc}", file=sys.stderr)
    plan = build_plan(cfg, mode="preview", model_capabilities=model_caps)
    print_plan(plan)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    models = list_models()
    if not models:
        print("No models found in models/ directory.", file=sys.stderr)
        return 1

    print(f"{'Model ID':<40s}  {'Vendor':<12s}  {'Target':<22s}  {'Flash Methods':<20s}  Description")
    print("-" * 140)
    for model in models:
        model_id = model.get("id", "?")
        vendor = model.get("vendor", "?")
        target = model.get("openwrt", {}).get("target", "?")
        methods = ", ".join(model.get("flash_methods", {}).keys()) or "none"
        desc = model.get("description", "")
        print(f"{model_id:<40s}  {vendor:<12s}  {target:<22s}  [{methods}]  {desc}")
    return 0


def cmd_list_use_cases(args: argparse.Namespace) -> int:
    """List all available use case presets with optional model compatibility."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from use_cases import registry as _uc_registry

    uc_reg = _uc_registry()
    if not uc_reg:
        print("No use case presets found in scripts/use_cases/.", file=sys.stderr)
        return 1

    model_caps: list[str] = []
    model_name = ""
    if args.model_id:
        try:
            model = load_model(args.model_id)
            model_caps = model.get("capabilities", [])
            model_name = model.get("id", args.model_id)
        except Exception as e:
            print(f"Warning: could not load model '{args.model_id}': {e}", file=sys.stderr)

    print(f"{'Use Case':<25s}  {'Status':<14s}  {'Description':<40s}  {'Pkgs':<5s}  {'Caps':<12s}  Post")
    print("-" * 120)
    for name in sorted(uc_reg.keys()):
        uc = uc_reg[name]
        pkg_count = len(uc.packages)
        caps = ", ".join(uc.requires_capabilities) if uc.requires_capabilities else "-"
        post_flash = "yes" if uc.configure_via == "ssh" else "-"
        status = uc.test_status

        if model_caps and uc.requires_capabilities:
            missing = set(uc.requires_capabilities) - set(model_caps)
            status = "INCOMPAT" if missing else "ok"
        elif model_caps and not uc.requires_capabilities:
            status = "ok"
        else:
            status = ""

        line = f"{name:<25s}  {status:<14s}  {uc.description[:40]:<40s}  {pkg_count:<5d}  {caps:<12s}  {post_flash}"
        if status == "INCOMPAT":
            line += f"  ** incompatible with {model_name} **"
        elif status == "ok":
            line += f"  compatible"
        print(line)

    if model_name:
        print(f"\nModel: {model_name}  Capabilities: {', '.join(sorted(model_caps)) or 'none'}")

    print("\nConfig snippet:")
    print("  [use_cases]")
    names = ", ".join(f'"{n}"' for n in sorted(uc_reg.keys())[:3])
    print(f"  enabled = [{names}, ...]")
    for name in sorted(uc_reg.keys())[:3]:
        uc = uc_reg[name]
        required = [p for p, d in uc.params.items() if d.required]
        if required:
            print(f"  [use_cases.{name}]")
            for p in required:
                print(f"  # {p} = \"...\"  # {uc.params[p].description}")

    return 0


def cmd_cache(args: argparse.Namespace) -> int:
    images_dir = Path(__file__).resolve().parent.parent / "images"

    if args.cache_command == "list":
        return _cache_list(images_dir)
    elif args.cache_command == "clean":
        return _cache_clean(images_dir, args)
    else:
        print("Usage: conwrt cache <list|clean>", file=sys.stderr)
        return 1


def _cache_list(images_dir: Path) -> int:
    if not images_dir.is_dir():
        print("No images/ directory found.", file=sys.stderr)
        return 1

    entries = []
    for model_dir in sorted(images_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        for hash_dir in sorted(model_dir.iterdir()):
            if not hash_dir.is_dir():
                continue
            model_id = model_dir.name
            cache_key = hash_dir.name
            metadata_files = list(hash_dir.glob("*.metadata.json"))
            metadata = {}
            if metadata_files:
                try:
                    with open(metadata_files[0]) as f:
                        metadata = json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass

            bin_files = list(hash_dir.glob("*.bin"))
            image_types = []
            total_size = 0
            for bf in bin_files:
                if "sysupgrade" in bf.name:
                    image_types.append("sysupgrade")
                elif "recovery" in bf.name:
                    image_types.append("recovery")
                elif "factory" in bf.name:
                    image_types.append("factory")
                else:
                    image_types.append(bf.stem)
                total_size += bf.stat().st_size

            build_info = metadata.get("version", "?")
            if metadata.get("version_code"):
                build_info += f" ({metadata.get('version_code', '')[:20]})"

            entries.append({
                "model": model_id,
                "hash": cache_key[:12],
                "version": build_info,
                "types": ", ".join(sorted(set(image_types))) or "none",
                "size_mb": f"{total_size / 1024 / 1024:.1f}",
            })

    if not entries:
        print("No cached firmware images found.")
        return 0

    print(f"{'Model':<30s}  {'Hash':<14s}  {'Version':<35s}  {'Types':<30s}  {'Size':>8s}")
    print("-" * 130)
    for e in entries:
        print(f"{e['model']:<30s}  {e['hash']:<14s}  {e['version']:<35s}  {e['types']:<30s}  {e['size_mb']:>7s} MB")
    print(f"\nTotal: {len(entries)} cached build(s)")
    return 0


def _cache_clean(images_dir: Path, args: argparse.Namespace) -> int:
    if not images_dir.is_dir():
        print("No images/ directory found.", file=sys.stderr)
        return 1

    targets = []
    for model_dir in sorted(images_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        if args.model_id and model_dir.name != args.model_id and model_dir.name != args.model_id.replace("-", "_"):
            continue

        hash_dirs = sorted(model_dir.iterdir(), key=lambda d: d.stat().st_mtime)
        hash_dirs = [h for h in hash_dirs if h.is_dir()]

        if args.keep_latest and len(hash_dirs) > 1:
            targets.extend(hash_dirs[:-1])
        elif not args.keep_latest:
            targets.extend(hash_dirs)

    if not targets:
        if args.model_id:
            print(f"No cached images found for model '{args.model_id}'.")
        else:
            print("No cached images found.")
        return 0

    total_size = sum(
        f.stat().st_size
        for d in targets
        for f in d.iterdir()
        if f.is_file()
    )
    print(f"Will remove {len(targets)} cached build(s) ({total_size / 1024 / 1024:.1f} MB):")
    for d in targets:
        print(f"  {d.parent.name}/{d.name[:12]}...")

    if not args.yes:
        try:
            response = input("Continue? [y/N] ")
            if response.lower() not in ("y", "yes"):
                print("Cancelled.")
                return 0
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

    removed = 0
    for d in targets:
        shutil.rmtree(d)
        removed += 1

    print(f"Removed {removed} cached build(s) ({total_size / 1024 / 1024:.1f} MB freed).")
    return 0


def cmd_setup_nor_recovery(args: argparse.Namespace) -> int:
    """Set up NOR flash as a recovery OpenWrt partition on dual-flash devices."""
    model_id = args.model_id

    # Load model JSON
    try:
        model = load_model(model_id)
    except FileNotFoundError:
        print(f"ERROR: Model '{model_id}' not found in models/ directory.", file=sys.stderr)
        print("Use 'conwrt list' to see available models.", file=sys.stderr)
        return 1

    nor = model.get("nor_recovery")
    if not nor:
        print(f"ERROR: Model '{model_id}' does not have a 'nor_recovery' section.", file=sys.stderr)
        print("This device may not support dual-flash recovery setup.", file=sys.stderr)
        return 1

    # Resolve IP
    default_ip = model.get("openwrt", {}).get("default_ip", "192.168.1.1")
    ip = args.ip or default_ip

    # Safety check: --i-want-a-brick required unless --dry-run
    dry_run = args.dry_run
    if not dry_run and not args.i_want_a_brick:
        print("ERROR: NOR recovery involves flashing U-Boot (mtd0) which can brick the device.", file=sys.stderr)
        print("Add --i-want-a-brick to acknowledge this risk, or use --dry-run.", file=sys.stderr)
        return 1

    skip_uboot = args.skip_uboot
    no_voice = args.no_voice

    def _say(msg: str) -> None:
        if not no_voice:
            say(msg)

    uboot_cfg = nor.get("uboot_upgrade", {})
    nor_fw_cfg = nor.get("nor_firmware", {})
    boot_env_cfg = nor.get("boot_env", {})
    requires_kmod = nor.get("requires_kmod_mtd_rw", False)
    mtd_rw_param = nor.get("mtd_rw_module_param", "")

    # Print header
    log(f"NOR Recovery Setup — {model.get('vendor', '?')} {model.get('description', model_id)}")
    log(f"Router IP: {ip}")
    if dry_run:
        log("DRY RUN — no changes will be written to the router")
    if skip_uboot:
        log("Skipping U-Boot upgrade (--skip-uboot)")
    print()

    # Step 1: Verify SSH access
    log("Step 1: Verifying SSH access...")
    ssh_key = _detect_ssh_key_path()
    if not ssh_key:
        print("ERROR: No SSH private key found. Set [ssh].key in config.toml or install ~/.ssh/id_ed25519 or ~/.ssh/id_rsa.", file=sys.stderr)
        return 1

    try:
        r = subprocess.run(
            ssh_cmd(ip, "echo SSH_OK", key=ssh_key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"ERROR: SSH connection to {ip} timed out.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: SSH connection to {ip} failed: {exc}", file=sys.stderr)
        return 1

    if "SSH_OK" not in r.stdout:
        print(f"ERROR: Cannot reach router via SSH at {ip}.", file=sys.stderr)
        if r.stderr:
            print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
        return 1
    log("SSH access OK")

    # Step 2: Verify correct model (check board name)
    log("Step 2: Verifying device model...")
    try:
        r = subprocess.run(
            ssh_cmd(ip, "cat /tmp/sysinfo/board_name", key=ssh_key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
    except Exception as exc:
        print(f"ERROR: Failed to check board name: {exc}", file=sys.stderr)
        return 1

    board_name = r.stdout.strip()
    expected_device = model.get("openwrt", {}).get("device", "")
    if expected_device and board_name != expected_device:
        print(f"WARNING: Board name mismatch!", file=sys.stderr)
        print(f"  Expected: {expected_device}", file=sys.stderr)
        print(f"  Got:      {board_name}", file=sys.stderr)
        if not dry_run:
            print("Aborting. Use a different --model-id or verify the device.", file=sys.stderr)
            return 1
    log(f"Board: {board_name} — matches model")

    # Step 3: nor_recovery section already checked above
    log("Step 3: Model has nor_recovery section ✓")

    if dry_run:
        print()
        log("=== DRY RUN — would perform the following steps ===")
        if not skip_uboot and uboot_cfg:
            log(f"  4. Download U-Boot from: {uboot_cfg.get('url', '?')}")
            log(f"     Expected SHA256: {uboot_cfg.get('sha256', '?')}")
            log(f"     Flash: {uboot_cfg.get('flash_command', '?')}")
            log(f"     (reboot after, ~60-90s wait)")
        if nor_fw_cfg:
            log(f"  10. Download NOR firmware from: {nor_fw_cfg.get('url', '?')}")
            log(f"      Expected SHA256: {nor_fw_cfg.get('sha256', '?')}")
            log(f"      Flash: mtd write /tmp/nor-firmware.bin {nor_fw_cfg.get('mtd_partition', '?')}")
        if boot_env_cfg:
            log(f"  13. Set boot_dev={boot_env_cfg.get('boot_dev', '?')} via fw_setenv")

        # In dry-run, download locally and verify hashes
        print()
        log("Downloading files locally to verify hashes...")
        tmp_dir = "/tmp/conwrt-nor-dryrun"
        os.makedirs(tmp_dir, exist_ok=True)

        if not skip_uboot and uboot_cfg:
            uboot_url = uboot_cfg["url"]
            uboot_local = os.path.join(tmp_dir, "uboot-recovery.bin")
            log(f"  Downloading U-Boot to {uboot_local}...")
            try:
                urllib.request.urlretrieve(uboot_url, uboot_local)
                actual_sha256 = sha256_file(uboot_local)
                expected_sha256 = uboot_cfg["sha256"]
                if actual_sha256 == expected_sha256:
                    log(f"  U-Boot SHA256 verified ✓")
                else:
                    print(f"  WARNING: U-Boot SHA256 mismatch!", file=sys.stderr)
                    print(f"    Expected: {expected_sha256}", file=sys.stderr)
                    print(f"    Got:      {actual_sha256}", file=sys.stderr)
            except Exception as exc:
                log(f"  Failed to download U-Boot: {exc}")

        if nor_fw_cfg:
            nor_url = nor_fw_cfg["url"]
            nor_local = os.path.join(tmp_dir, "nor-firmware.bin")
            log(f"  Downloading NOR firmware to {nor_local}...")
            try:
                urllib.request.urlretrieve(nor_url, nor_local)
                actual_sha256 = sha256_file(nor_local)
                expected_sha256 = nor_fw_cfg["sha256"]
                if actual_sha256 == expected_sha256:
                    log(f"  NOR firmware SHA256 verified ✓")
                else:
                    print(f"  WARNING: NOR firmware SHA256 mismatch!", file=sys.stderr)
                    print(f"    Expected: {expected_sha256}", file=sys.stderr)
                    print(f"    Got:      {actual_sha256}", file=sys.stderr)
            except Exception as exc:
                log(f"  Failed to download NOR firmware: {exc}")

        print()
        log("DRY RUN complete. No changes were made to the router.")
        return 0

    # === LIVE MODE ===
    print()

    def _run_ssh(command: str, timeout: int = 60) -> subprocess.CompletedProcess:
        """Run SSH command on router (delegates to the module-level _ssh_run)."""
        return _ssh_run(ip, command, key=ssh_key, timeout=timeout)

    def _install_kmod_mtd_rw() -> bool:
        """Install kmod-mtd-rw with required module parameter. Returns True on success."""
        if not requires_kmod:
            return True
        log("  Installing kmod-mtd-rw...")
        r = _run_ssh("opkg update && opkg install kmod-mtd-rw")
        if r.returncode != 0:
            # Maybe already installed, try to load
            pass
        # Insert module with required param
        if mtd_rw_param:
            insmod_cmd = f"insmod mtd-rw {mtd_rw_param} 2>/dev/null || echo module_load_attempted"
            r = _run_ssh(insmod_cmd)
            if "module_load_attempted" not in r.stdout and r.returncode != 0:
                # Try rmmod then insmod in case it's already loaded without the param
                _run_ssh("rmmod mtd-rw 2>/dev/null")
                r = _run_ssh(f"insmod mtd-rw {mtd_rw_param}")
                if r.returncode != 0:
                    print(f"ERROR: Failed to load mtd-rw module with param '{mtd_rw_param}'.", file=sys.stderr)
                    if r.stderr:
                        print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
                    return False
        log("  kmod-mtd-rw installed and loaded")
        return True

    def _download_and_scp(url: str, local_name: str, remote_path: str,
                          expected_sha256: str) -> bool:
        """Download file locally, verify hash, SCP to router. Returns True on success."""
        local_path = os.path.join("/tmp", local_name)
        log(f"  Downloading {local_name}...")
        try:
            urllib.request.urlretrieve(url, local_path)
        except Exception as exc:
            print(f"ERROR: Failed to download {local_name}: {exc}", file=sys.stderr)
            return False
        actual = sha256_file(local_path)
        if actual != expected_sha256:
            print(f"ERROR: {local_name} SHA256 mismatch!", file=sys.stderr)
            print(f"  Expected: {expected_sha256}", file=sys.stderr)
            print(f"  Got:      {actual}", file=sys.stderr)
            return False
        log(f"  SHA256 verified ✓ ({actual[:16]}...)")
        scp_argv = ["scp", "-O", "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
                     "-i", ssh_key, local_path, f"root@{ip}:{remote_path}"]
        try:
            r = subprocess.run(scp_argv, capture_output=True, text=True, timeout=120, check=False)
        except subprocess.TimeoutExpired:
            print(f"ERROR: SCP of {local_name} timed out.", file=sys.stderr)
            return False
        if r.returncode != 0:
            print(f"ERROR: SCP of {local_name} failed.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            return False
        log(f"  Uploaded to {remote_path}")
        return True

    # Steps 4-8: U-Boot upgrade (unless --skip-uboot)
    if not skip_uboot and uboot_cfg:
        _say("Preparing to flash U-Boot. Do not disconnect power.")
        log("Step 4: Downloading U-Boot binary...")
        if not _download_and_scp(
            uboot_cfg["url"], "uboot-recovery.bin", "/tmp/uboot-recovery.bin",
            uboot_cfg["sha256"],
        ):
            return 1

        # Step 6: Install kmod-mtd-rw
        log("Step 6: Installing kmod-mtd-rw...")
        if not _install_kmod_mtd_rw():
            return 1

        # Step 7: Flash U-Boot
        _say("Flashing U-Boot. This is dangerous. Do not disconnect power.")
        flash_cmd = uboot_cfg.get("flash_command", "mtd -r write /tmp/uboot-recovery.bin /dev/mtd0")
        log(f"Step 7: Flashing U-Boot via: {flash_cmd}")
        print()
        print("  ⚠️  FLASHING U-BOOT — DO NOT DISCONNECT POWER ⚠️")
        print()
        try:
            # mtd -r causes reboot, so the SSH connection will be dropped
            r = subprocess.run(
                ssh_cmd(ip, flash_cmd, key=ssh_key, connect_timeout=10),
                capture_output=True, text=True, timeout=120, check=False,
            )
        except subprocess.TimeoutExpired:
            # Expected: mtd -r reboots the router, SSH drops
            pass
        except Exception as exc:
            # Connection reset is expected during reboot
            if "reset" not in str(exc).lower() and "broken" not in str(exc).lower():
                print(f"WARNING: Unexpected error during U-Boot flash: {exc}", file=sys.stderr)

        # Step 8: Wait for reboot
        _say("Waiting for router to reboot. This takes about 90 seconds.")
        log("Step 8: Waiting for router to reboot (60-90s)...")
        time.sleep(10)  # Brief wait before starting to poll
        reboot_timeout = 120
        reboot_start = time.time()
        ssh_back = False
        while time.time() - reboot_start < reboot_timeout:
            if check_ssh(ip):
                ssh_back = True
                break
            time.sleep(5)
        if not ssh_back:
            print(f"ERROR: Router did not come back after U-Boot flash within {reboot_timeout}s.", file=sys.stderr)
            print("The device may be bricked. Check via serial/UART.", file=sys.stderr)
            return 1
        elapsed = int(time.time() - reboot_start)
        log(f"  Router back online after {elapsed}s")

        # Step 9: Re-install kmod-mtd-rw (lost after reboot)
        log("Step 9: Re-installing kmod-mtd-rw (lost after reboot)...")
        if not _install_kmod_mtd_rw():
            return 1
    else:
        if skip_uboot:
            log("Steps 4-9: Skipped (--skip-uboot)")
        # Still need kmod-mtd-rw for NOR flash
        if requires_kmod:
            log("Installing kmod-mtd-rw...")
            if not _install_kmod_mtd_rw():
                return 1

    # Step 10: Download NOR sysupgrade image
    log("Step 10: Downloading NOR sysupgrade image...")
    if not _download_and_scp(
        nor_fw_cfg["url"], "nor-firmware.bin", "/tmp/nor-firmware.bin",
        nor_fw_cfg["sha256"],
    ):
        return 1

    log("Step 11: Verifying NOR firmware SHA256 on router...")
    r = _run_ssh("sha256sum /tmp/nor-firmware.bin")
    if r.returncode != 0:
        print("ERROR: Failed to compute SHA256 on router.", file=sys.stderr)
        return 1
    actual_hash = r.stdout.strip().split()[0]
    expected_hash = nor_fw_cfg["sha256"]
    if actual_hash != expected_hash:
        print("ERROR: NOR firmware SHA256 hash mismatch!", file=sys.stderr)
        print(f"  Expected: {expected_hash}", file=sys.stderr)
        print(f"  Got:      {actual_hash}", file=sys.stderr)
        return 1
    log(f"  SHA256 verified ✓")

    # Step 12: Flash NOR firmware (no -r, no reboot)
    _say("Flashing NOR recovery partition.")
    nor_mtd_partition = nor_fw_cfg.get("mtd_partition", "nor_firmware")
    log(f"Step 12: Flashing NOR firmware to '{nor_mtd_partition}' partition...")
    flash_nor_cmd = f"mtd write /tmp/nor-firmware.bin {nor_mtd_partition}"
    r = _run_ssh(flash_nor_cmd, timeout=120)
    if r.returncode != 0:
        print("ERROR: Failed to flash NOR firmware.", file=sys.stderr)
        if r.stderr:
            print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
        return 1
    log("  NOR firmware flashed ✓")

    # Step 12b: Note the recovery hostname for first NOR boot
    recovery_hostname = nor.get("recovery_hostname", "")

    # Step 12c: Fix bootargs for dual-boot compatibility
    bootargs_fix = nor.get("bootargs_fix")
    if bootargs_fix:
        log("Step 12c: Fixing U-Boot bootargs for dual-boot...")
        r = _run_ssh(f"fw_setenv bootargs '{bootargs_fix}'")
        if r.returncode != 0:
            print("ERROR: Failed to set bootargs via fw_setenv.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            return 1
        r = _run_ssh("fw_printenv bootargs")
        log(f"  bootargs: {r.stdout.strip()} ✓")

    # Step 12d: Set boot_local override for NOR boot selection
    boot_local_val = nor.get("boot_local", "")
    if boot_local_val:
        log(f"Step 12d: Setting boot_local={boot_local_val}...")
        r = _run_ssh(f"fw_setenv boot_local {boot_local_val}")
        if r.returncode != 0:
            print("ERROR: Failed to set boot_local via fw_setenv.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            return 1
        r = _run_ssh("fw_printenv boot_local")
        log(f"  {r.stdout.strip()} ✓")

    # Step 13: Set boot_env
    if boot_env_cfg:
        boot_dev_val = boot_env_cfg.get("boot_dev")
        if boot_dev_val:
            log(f"Step 13: Setting boot_dev={boot_dev_val} via fw_setenv...")
            r = _run_ssh(f"fw_setenv boot_dev {boot_dev_val}")
            if r.returncode != 0:
                print("ERROR: Failed to set boot_dev via fw_setenv.", file=sys.stderr)
                if r.stderr:
                    print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
                return 1
            log("  boot_dev set ✓")

            # Step 14: Verify
            log("Step 14: Verifying fw_printenv boot_dev...")
            r = _run_ssh("fw_printenv boot_dev")
            if r.returncode != 0:
                print("WARNING: fw_printenv boot_dev failed.", file=sys.stderr)
                if r.stderr:
                    print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            else:
                output = r.stdout.strip()
                if f"boot_dev={boot_dev_val}" in output:
                    log(f"  Verified: {output} ✓")
                else:
                    print(f"WARNING: boot_dev value unexpected: {output}", file=sys.stderr)
                    print(f"  Expected: boot_dev={boot_dev_val}", file=sys.stderr)
    else:
        log("Steps 13-14: No boot_env config in model JSON, skipping")

    # Step 15: Set bootcount to trigger NOR boot on next power cycle
    boot_method = nor.get("boot_method", {})
    if boot_method.get("recommended") == "bootcount":
        _say("Setting bootcount to trigger NOR boot on next power cycle.")
        log("Step 15: Setting bootcount=3 to trigger NOR boot on next power cycle...")
        r = _run_ssh("fw_setenv bootcount 3")
        if r.returncode != 0:
            print("WARNING: Failed to set bootcount via fw_setenv.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
        else:
            r = _run_ssh("fw_printenv bootcount")
            log(f"  {r.stdout.strip()} ✓")
            log("  On next power cycle: U-Boot will increment bootcount to 4,")
            log("  exceed bootlimit=3, set nand_boot_failed=1, and boot NOR.")
            log("  After NOR boot, reset with: fw_setenv bootcount 0 && reboot")
    else:
        log("Step 15: No bootcount method configured in model JSON, skipping")

    # Step 16: Summary
    print()
    print("=" * 60)
    log("NOR Recovery Setup Complete!")
    print("=" * 60)
    if not skip_uboot and uboot_cfg:
        print(f"  U-Boot:   upgraded to {uboot_cfg.get('version', 'unknown')}")
    else:
        print(f"  U-Boot:   skipped (--skip-uboot)")
    print(f"  NOR:      flashed {nor_fw_cfg.get('description', 'recovery firmware')}")
    if boot_env_cfg:
        print(f"  boot_dev: {boot_env_cfg.get('boot_dev', 'not set')}")
    if bootargs_fix:
        print(f"  bootargs: fixed for dual-boot")
    if boot_local_val:
        print(f"  boot_local: {boot_local_val}")
    print()
    print("Verification:")
    post = nor.get("post_setup_verification", {})
    for label, desc in post.items():
        print(f"  {label}: {desc}")
    print()
    print("To switch boot source:")
    print("  NAND (primary):  switch LEFT + fw_setenv bootcount 0 && reboot")
    print("  NOR  (recovery): fw_setenv bootcount 3 && reboot")
    print("                   (switch position does NOT reliably control boot — use bootcount)")
    if recovery_hostname:
        print()
        print(f"On first NOR boot, set the recovery hostname:")
        print(f"  uci set system.@system[0].hostname='{recovery_hostname}' && uci commit system")
    print()

    _say("NOR recovery setup is complete.")
    return 0


def cmd_flash(args: argparse.Namespace) -> int:
    parser = _build_parser()
    validation_error = _validate_args(args)
    if validation_error:
        parser.error(validation_error)

    # Platform detection — warn about missing deps on OpenWrt
    if detect_platform() == "openwrt":
        missing = check_external_deps()
        if missing:
            log(f"WARNING: missing dependencies: {', '.join(missing)}")
            log("Install via: opkg update && opkg install " + " ".join(missing))

    if args.request_image and not args.ssh_key:
        cfg = _load_config()
        if cfg.ssh_public_key_path:
            args.ssh_key = cfg.ssh_public_key_path
        else:
            parser.error("No SSH public key found. Set [ssh].key in config.toml or use --ssh-key.")

    _say_fn = (lambda m: None) if args.no_voice else say

    ssh_key_path = _detect_ssh_key_path()

    if not args.model_id:
        for probe_ip in ["192.168.1.1", "192.168.0.1"]:
            fp = fingerprint_router(probe_ip)
            if fp:
                board = fp.get("identity", {}).get("board", "")
                if board:
                    detected_id = _find_model_id_by_board(board)
                    if detected_id:
                        args.model_id = detected_id
                        log(f"Auto-detected model: {detected_id} (board={board})")
                        break

        if not args.model_id:
            for probe_ip in ["192.168.1.1", "192.168.0.1"]:
                log(f"Active fingerprinting {probe_ip}...")
                fp_result = _active_fingerprint(probe_ip, timeout=5.0)
                if fp_result.candidates:
                    matches = _match_models(fp_result)
                    if matches:
                        best = matches[0]
                        args.model_id = best.model_id
                        log(f"Auto-detected model: {best.model_id} "
                            f"(confidence={best.confidence}, "
                            f"evidence={', '.join(best.evidence)})")
                        break

        if not args.model_id:
            parser.error("--model-id is required when device is not reachable via SSH "
                         "and active fingerprinting did not identify the model.")

    try:
        profile = _build_profile_from_model(args.model_id,
                                             serial_method=args.serial_method or "",
                                             flash_method=getattr(args, 'flash_method', '') or "")
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    is_serial_tftp = getattr(profile, 'is_serial_tftp', False)
    is_zycast = getattr(profile, 'is_zycast', False)
    is_edgeos_ks = getattr(profile, 'is_edgeos_kernel_swap', False)
    is_extreme_rdwr_tftp = getattr(profile, 'is_extreme_rdwr_tftp', False)

    if is_serial_tftp and not args.serial_method:
        serial_methods = [k for k in load_model(args.model_id).get("flash_methods", {}).keys()
                          if k.startswith("serial-tftp-")]
        if len(serial_methods) == 1:
            method_suffix = serial_methods[0].replace("serial-tftp-", "")
            profile = _build_profile_from_model(args.model_id, serial_method=method_suffix,
                                                 flash_method=getattr(args, 'flash_method', '') or "")
            log(f"Auto-selected serial method: {serial_methods[0]}")
        elif len(serial_methods) > 1:
            print(f"ERROR: Multiple serial methods available: {serial_methods}. "
                  f"Use --serial-method to select one.", file=sys.stderr)
            return 1

    openwrt_ip = profile.openwrt_ip or profile.recovery_ip

    if is_serial_tftp or is_zycast:
        boot_state = "unknown"
        use_sysupgrade = False
    else:
        boot_state = _detect_boot_state("", profile)
        use_sysupgrade = boot_state == "openwrt" and not args.force_uboot

    generated_password = ""
    password_set = False
    auth_type = ""
    wan_ssh_enabled = False
    image_path = args.image
    request_metadata: dict = {}

    if args.request_image:
        cfg = _load_config()
        password = args.password
        if not args.no_password and not args.password:
            if cfg.password_is_key_only:
                password = None
                password_set = False
                auth_type = "key-only"
            elif cfg.password_is_random:
                generated_password = _generate_random_password()
                _say_fn("Random password generated. Check the console.")
                password = generated_password
                password_set = True
                auth_type = "key-and-password"
            elif cfg.password_literal:
                password = cfg.password_literal
                password_set = True
                auth_type = "key-and-password"
        elif args.password:
            password_set = True
            auth_type = "key-and-password"
        elif args.no_password:
            password_set = False
            auth_type = "key-only"

        wan_ssh_enabled = args.wan_ssh or cfg.wan_ssh

        if wan_ssh_enabled:
            if not args.ssh_key and not cfg.ssh_public_key_path:
                parser.error("--wan-ssh requires an SSH key. Set [ssh].key in config.toml or use --ssh-key.")
            if args.no_password and not args.ssh_key:
                parser.error("--wan-ssh with --no-password requires --ssh-key (no way to log in otherwise).")

        effective_flash_method = profile.flash_method
        if use_sysupgrade and effective_flash_method != "mtd-write":
            effective_flash_method = "sysupgrade"
        image_path, request_metadata = _request_custom_image(
            model_id=args.model_id,
            ssh_key_path=args.ssh_key,
            password=password,
            wan_ssh=wan_ssh_enabled,
            flash_method=effective_flash_method,
            say_fn=_say_fn,
        )
        if not image_path:
            print("ERROR: Failed to obtain firmware image.", file=sys.stderr)
            return 1

    if args.initramfs:
        request_metadata["initramfs_path"] = args.initramfs

    if not image_path:
        parser.error("One of --image or --request-image is required.")

    if not os.path.isfile(image_path):
        print(f"ERROR: image not found: {image_path}", file=sys.stderr)
        return 1

    initramfs_path = request_metadata.get("initramfs_path", "")
    if is_extreme_rdwr_tftp or is_edgeos_ks:
        if args.initramfs:
            initramfs_path = args.initramfs
        if not initramfs_path:
            print("ERROR: initramfs image required for this flash method. Use --initramfs or --request-image.", file=sys.stderr)
            return 1
        if not os.path.isfile(initramfs_path):
            print(f"ERROR: initramfs image not found: {initramfs_path}", file=sys.stderr)
            return 1

    interface = args.interface or auto_detect_interface()
    if not interface:
        print("ERROR: no active ethernet interface found. Use --interface.", file=sys.stderr)
        return 1

    # Pre-flight checks
    log("Running pre-flight checks...")
    preflight_results = run_preflight_checks(
        interface, profile, image_path,
        ssh_key_path=ssh_key_path,
        boot_state=boot_state,
        use_sysupgrade=use_sysupgrade,
        request_image=bool(args.request_image),
    )
    preflight_failed = False
    for r in preflight_results:
        if r.status == "pass":
            log(f"  \u2713 {r.name}: {r.message}")
        elif r.status == "warn":
            log(f"  \u26a0 {r.name}: {r.message}")
        else:
            log(f"  \u2717 {r.name}: {r.message}")
            preflight_failed = True
    if preflight_failed:
        print("Preflight checks failed. Fix the issues above and retry.", file=sys.stderr)
        return 1

    if args.capture:
        pcap_path = args.capture
    else:
        captures_dir = Path(__file__).resolve().parent.parent / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        pcap_path = str(captures_dir / f"{args.model_id}-{ts}.pcap")

    log(f"{profile.description} Recovery")
    log(f"Model:      {profile.name} ({profile.vendor})")
    log(f"Image:      {image_path}")
    log(f"Interface:  {interface}")
    log(f"Pcap:       {pcap_path}")
    log(f"Boot state: {boot_state}")
    if is_serial_tftp:
        log(f"Flash path: serial-tftp ({profile.flash_method})")
        log(f"Serial:     {args.serial_port or 'auto-detect'} @ {getattr(profile, 'serial_baud', 115200)} baud")
        if getattr(profile, 'lan_port', ''):
            log(f"LAN port:   {profile.lan_port} (for TFTP)")
    elif is_zycast and not use_sysupgrade:
        log(f"Flash path: zycast multicast ({profile.zycast_multicast_group}:{profile.zycast_multicast_port})")
    elif is_edgeos_ks and not use_sysupgrade:
        log(f"Flash path: edgeos-kernel-swap (2-stage SSH)")
    elif is_extreme_rdwr_tftp and not use_sysupgrade:
        log("Flash path: extreme-rdwr-tftp-initramfs (stock SSH + TFTP + initramfs sysupgrade)")
    else:
        log(f"Flash path: {'sysupgrade' if use_sysupgrade else 'U-Boot recovery'}")
    if not use_sysupgrade and not is_serial_tftp and not is_zycast:
        log(f"LED signal: {profile.led_pattern}")
    if args.request_image:
        log(f"Auth type:  {auth_type}")
        log(f"WAN SSH:    {wan_ssh_enabled}")
    print()

    fp = fingerprint_router(openwrt_ip) if use_sysupgrade else None
    if fp:
        ident = fp.get("identity", {})
        fw = fp.get("firmware", {})
        hw = fp.get("hardware", {})
        net = fp.get("network", {})
        sec = fp.get("security", {})
        log(f"Detected:   {ident.get('model', '?')} (board={ident.get('board', '?')})")
        log(f"Firmware:   {fw.get('version', '?')} {fw.get('target', '')}")
        log(f"Kernel:     {fw.get('kernel', '?')}")
        br_mac = net.get("macs", {}).get("br-lan", "")
        if br_mac:
            log(f"MAC:        {br_mac}")
            if not args.router_mac:
                args.router_mac = br_mac
        mem = hw.get("memory_mb", {})
        if mem:
            log(f"Memory:     {mem.get('total', '?')} kB total, {mem.get('free', '?')} kB free")
        pkgs = sec.get("packages_installed", 0)
        if pkgs:
            log(f"Packages:   {pkgs} installed")
        uptime = fp.get("diagnostics", {}).get("uptime", "")
        if uptime:
            log(f"Uptime:     {uptime}")
        print()
    else:
        log("No running router detected at this IP (expected — device needs recovery)")
        print()

    if is_serial_tftp:
        initial_state = State.SERIAL_WAITING_FOR_BOOTMENU
    elif is_zycast and not use_sysupgrade:
        initial_state = State.ZYCAST_WAITING_FOR_DEVICE
    elif is_edgeos_ks and not use_sysupgrade:
        initial_state = State.EDGEOS_STAGE1
    elif is_extreme_rdwr_tftp and not use_sysupgrade:
        initial_state = State.EXTREME_STOCK_PREFLIGHT if boot_state == "stock-extreme" else State.DETECTING
    elif use_sysupgrade:
        initial_state = State.SYSUPGRADE_UPLOADING
    elif boot_state == "uboot":
        found, detail = detect_uboot_http(profile.recovery_ip)
        if found:
            log(f"Recovery HTTP already live at {profile.recovery_ip} ({detail}) — skipping power cycle")
            initial_state = State.UBOOT_UPLOADING
        else:
            initial_state = State.WAITING_FOR_POWER_OFF
    else:
        initial_state = State.WAITING_FOR_POWER_OFF

    if args.isolate_port:
        initial_state = State.PORT_ISOLATION

    ctx = RecoveryContext(
        profile=profile,
        image_path=image_path,
        initramfs_path=initramfs_path,
        interface=interface,
        pcap_path=pcap_path,
        no_upload=args.no_upload,
        no_voice=args.no_voice,
        router_mac_openwrt=args.router_mac,
        router_mac_uboot=args.uboot_mac,
        generated_password=generated_password,
        password_set=password_set,
        auth_type=auth_type,
        wan_ssh_enabled=wan_ssh_enabled,
        force_uboot=args.force_uboot,
        no_pcap=getattr(args, 'no_pcap', False),
        boot_state=boot_state,
        ssh_key_path=ssh_key_path,
        serial_port=args.serial_port or "",
        serial_method=args.serial_method or "",
        serial_baud=args.serial_baud or getattr(profile, 'serial_baud', 115200),
        tftp_root=args.tftp_root or "",
        uboot_commands=getattr(profile, 'uboot_commands', []),
        request_hash=request_metadata.get("request_hash", ""),
        cache_key=request_metadata.get("cache_key", ""),
        packages=request_metadata.get("packages", []),
        defaults_script=request_metadata.get("defaults") or "",
        assume_yes=bool(getattr(args, "yes", False)),
        isolate_port=args.isolate_port or "",
        _say_fn=_say_fn,
        state=initial_state,
    )

    event_queue: queue.Queue = queue.Queue()

    if use_sysupgrade:
        _say_fn(f"Starting {profile.description} sysupgrade recovery.")
        _, _, link_mon, link_thr = _setup_monitors(
            interface, event_queue, pcap_path, profile, args, pcap_enabled=False)
        try:
            rc = _run_state_machine(ctx, event_queue, None, link_mon)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        finally:
            _teardown_monitors(None, None, link_mon, link_thr)
        return rc

    if is_edgeos_ks and not use_sysupgrade:
        _say_fn(f"Starting {profile.description} edgeos-kernel-swap flash.")
        _, _, link_mon, link_thr = _setup_monitors(
            interface, event_queue, pcap_path, profile, args, pcap_enabled=False)
        try:
            rc = _run_state_machine(ctx, event_queue, None, link_mon)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        finally:
            _teardown_monitors(None, None, link_mon, link_thr)
        return rc

    if is_extreme_rdwr_tftp and not use_sysupgrade:
        _say_fn(f"Starting {profile.description} extreme stock flash.")
        _, _, link_mon, link_thr = _setup_monitors(
            interface, event_queue, pcap_path, profile, args, pcap_enabled=False)
        try:
            rc = _run_state_machine(ctx, event_queue, None, link_mon)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        finally:
            _cleanup_extreme_tftp_assets(ctx)
            _teardown_monitors(None, None, link_mon, link_thr)
            openwrt_client_ip = getattr(profile, "openwrt_client_ip", "")
            if openwrt_client_ip and openwrt_client_ip != getattr(profile, "client_ip", ""):
                remove_interface_ip(interface, openwrt_client_ip, "24")
        return rc

    if is_serial_tftp:
        _say_fn(f"Starting {profile.description} serial recovery.")
        if getattr(profile, 'lan_port', ''):
            log(f"IMPORTANT: Connect Ethernet cable to {profile.lan_port} port")
        try:
            rc = _run_state_machine(ctx, event_queue, None, None)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        finally:
            driver = getattr(ctx, '_serial_driver', None)
            if driver:
                driver.close()
            tftp_mgr = getattr(ctx, '_tftp_manager', None)
            if tftp_mgr:
                tftp_mgr.stop()
        return rc

    if is_zycast:
        _say_fn(f"Starting {profile.description} multicast recovery.")
        log(f"Flash path: zycast multicast ({profile.zycast_multicast_group}:{profile.zycast_multicast_port})")

        pcap_mon, pcap_thr, link_mon, link_thr = _setup_monitors(
            interface, event_queue, pcap_path, profile, args, pcap_enabled=True)

        try:
            rc = _run_state_machine(ctx, event_queue, pcap_mon, link_mon)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        finally:
            _teardown_monitors(pcap_mon, pcap_thr, link_mon, link_thr)
            zycast_proc = getattr(ctx, '_zycast_proc', None)
            if zycast_proc and zycast_proc.poll() is None:
                zycast_proc.terminate()
        return rc

    _setup_interface_ips(interface, profile)

    pcap_mon, pcap_thr, link_mon, link_thr = _setup_monitors(
        interface, event_queue, pcap_path, profile, args, pcap_enabled=True)

    _say_fn(f"Starting {profile.description} recovery. Listen for instructions.")

    try:
        rc = _run_state_machine(ctx, event_queue, pcap_mon, link_mon)
    except KeyboardInterrupt:
        log("Interrupted by user.")
        rc = 1
    finally:
        _teardown_monitors(pcap_mon, pcap_thr, link_mon, link_thr)

    return rc



def cmd_backup(args: argparse.Namespace) -> int:
    if not args.model_id:
        print("ERROR: --model-id is required.", file=sys.stderr)
        return 1

    model = load_model(args.model_id)
    backup_config = model.get("backup", {})
    partition_layout = model.get("partition_layout", {})

    if not backup_config.get("method") == "ssh":
        print(f"ERROR: Model '{args.model_id}' does not support SSH backup.", file=sys.stderr)
        return 1

    password = args.password
    serial = args.serial

    if not password and serial:
        password = _generate_zyxel_password(serial)
        if password:
            log(f"Generated stock SSH password from serial {serial}")
        else:
            print("ERROR: --serial provided but zyxel_pwgen not found.", file=sys.stderr)
            print("  Install zyxel_pwgen or use --password to provide the password manually.", file=sys.stderr)
            return 1

    if not password:
        print("ERROR: Provide --serial (for auto password generation) or --password.", file=sys.stderr)
        return 1

    ip = args.ip
    user = args.user

    log(f"Connecting to {user}@{ip} (stock firmware SSH)...")

    list_result = _ssh_with_password(ip, user, password, "cat /proc/mtd", timeout=15)
    if list_result.returncode != 0:
        print(f"ERROR: SSH connection failed: {list_result.stderr.strip()}", file=sys.stderr)
        if "sshpass not found" in list_result.stderr:
            print("  Install sshpass: brew install hudochenkov/sshpass/sshpass", file=sys.stderr)
        return 1

    mtd_output = list_result.stdout.strip()
    if not mtd_output:
        print("ERROR: No MTD partitions found on device.", file=sys.stderr)
        return 1

    mtd_partitions = []
    for line in mtd_output.split("\n"):
        parts = line.split()
        if len(parts) >= 3:
            mtd_name = parts[0]
            mtd_size = parts[1]
            mtd_label = parts[2].strip('"')
            mtd_index = mtd_name.replace("mtd", "").replace(":", "")
            mtd_partitions.append({
                "index": mtd_index,
                "name": mtd_name.rstrip(":"),
                "size": mtd_size,
                "label": mtd_label,
                "device": f"/dev/{mtd_name.rstrip(':')}",
            })

    if args.partitions:
        requested = set(args.partitions.split(","))
        mtd_partitions = [p for p in mtd_partitions if p["index"] in requested]

    critical_names = set(backup_config.get("critical_partitions", []))

    output_dir = args.output_dir
    if not output_dir:
        base_dir = Path(__file__).resolve().parent.parent / "data" / "backups"
        device_id = serial or model.get("id", "unknown")
        output_dir = str(base_dir / device_id)

    os.makedirs(output_dir, exist_ok=True)
    log(f"Backing up {len(mtd_partitions)} MTD partitions to {output_dir}")

    print()
    print(f"{'MTD':<10s} {'Label':<15s} {'Size':<12s} {'Critical':<10s} {'Status'}")
    print("-" * 70)

    failed = []
    for part in mtd_partitions:
        label = part["label"]
        is_critical = label in critical_names
        critical_str = "*** YES ***" if is_critical else ""
        local_path = os.path.join(output_dir, f"mtd{part['index']}_{label}.bin")
        remote_path = f"/tmp/mtd{part['index']}.bin"

        dump_cmd = f"nanddump -f {remote_path} {part['device']}"
        if is_critical:
            log(f"Dumping CRITICAL partition {part['name']} ({label})...")

        dump_result = _ssh_with_password(ip, user, password, dump_cmd, timeout=60)
        if dump_result.returncode != 0:
            print(f"{part['name']:<10s} {label:<15s} {part['size']:<12s} {critical_str:<10s} FAILED (nanddump)")
            if dump_result.stderr:
                log(f"  nanddump error: {dump_result.stderr[:200]}")
            failed.append(part)
            continue

        scp_result = _scp_with_password(ip, user, password, remote_path, local_path, timeout=120)
        if scp_result.returncode != 0:
            print(f"{part['name']:<10s} {label:<15s} {part['size']:<12s} {critical_str:<10s} FAILED (scp)")
            if scp_result.stderr:
                log(f"  scp error: {scp_result.stderr[:200]}")
            failed.append(part)
            continue

        file_size = os.path.getsize(local_path)
        print(f"{part['name']:<10s} {label:<15s} {part['size']:<12s} {critical_str:<10s} OK ({file_size} bytes)")

        _ssh_with_password(ip, user, password, f"rm -f {remote_path}", timeout=10)

    print()
    if failed:
        log(f"WARNING: {len(failed)} partition(s) failed to backup:")
        for p in failed:
            log(f"  mtd{p['index']} ({p['label']})")
    else:
        log(f"All {len(mtd_partitions)} partitions backed up successfully to {output_dir}")

    if critical_names:
        missing_critical = critical_names - {p["label"] for p in mtd_partitions if p not in failed}
        if missing_critical:
            log(f"WARNING: Critical partitions NOT backed up: {missing_critical}")
            log("DO NOT flash this device until these partitions are backed up!")
            return 1

    return 1 if failed else 0


def cmd_fingerprint(args: argparse.Namespace) -> int:
    """Fingerprint a device to identify its model."""
    ip = args.ip
    log(f"Fingerprinting device at {ip}...")

    result = _active_fingerprint(ip, timeout=args.timeout)

    if not result.candidates:
        print(f"No device detected at {ip}.", file=sys.stderr)
        return 1

    matched = _match_models(result)

    if getattr(args, 'json_output', False):
        import json as _json
        output = {
            "ip": ip,
            "candidates": [
                {
                    "vendor": c.vendor,
                    "model_id": c.model_id,
                    "confidence": c.confidence,
                    "evidence": c.evidence,
                    "mac_oui": c.mac_oui,
                    "hostname": c.hostname,
                    "ssh_banner": c.ssh_banner,
                    "open_ports": c.open_ports,
                }
                for c in result.candidates
            ],
            "model_matches": [
                {
                    "model_id": c.model_id,
                    "vendor": c.vendor,
                    "confidence": c.confidence,
                    "evidence": c.evidence,
                }
                for c in matched
            ],
        }
        print(_json.dumps(output, indent=2))
    else:
        print()
        for c in result.candidates:
            print(f"  Vendor: {c.vendor}")
            if c.model_id:
                print(f"  Model:  {c.model_id}")
            print(f"  Confidence: {c.confidence}")
            print(f"  Evidence: {', '.join(c.evidence)}")
            if c.ssh_banner:
                print(f"  SSH Banner: {c.ssh_banner}")
            if c.open_ports:
                print(f"  Open Ports: {c.open_ports}")

        if matched:
            print()
            print("Model matches:")
            for m in matched:
                print(f"  {m.model_id} ({m.vendor}) — {m.confidence} confidence")
                print(f"    Evidence: {', '.join(m.evidence)}")
        else:
            print()
            print("No model matches found in models/ directory.")

    return 0


def cmd_auto(args: argparse.Namespace) -> int:
    from auto_detect import auto_detect, interactive_menu

    interface = args.interface or auto_detect_interface()
    if not interface:
        print("ERROR: no active ethernet interface found. Use --interface.", file=sys.stderr)
        return 1

    print(f"Auto-detecting routers on {interface}...")
    print()

    routers = auto_detect(interface, passive_timeout=args.passive_timeout)

    if not routers:
        print("No routers detected. Check that:")
        print("  - Ethernet cable is connected")
        print("  - Router is powered on")
        print("  - Interface is correct (use --interface)")
        return 1

    if args.no_menu:
        for r in routers:
            print(f"  IP: {r.ip}  MAC: {r.mac}  Vendor: {r.vendor}  "
                  f"Model: {r.model_name or '?'}  State: {r.firmware_state}  "
                  f"Confidence: {r.confidence}")
        return 0

    interactive_menu(routers)
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] not in (
        "flash", "list", "list-use-cases", "cache", "setup-mgmt-wifi", "backup",
        "auto", "setup-nor-recovery", "configure", "profile", "fingerprint", "reset", "-h", "--help",
        "--version", "-V",
    ):
        sys.argv.insert(1, "flash")

    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "list":
        return cmd_list(args)
    elif args.command == "list-use-cases":
        return cmd_list_use_cases(args)
    elif args.command == "cache":
        return cmd_cache(args)
    elif args.command == "setup-mgmt-wifi":
        return cmd_setup_mgmt_wifi(args)
    elif args.command == "configure":
        return cmd_configure(args)
    elif args.command == "profile":
        if getattr(args, "profile_command", None) == "plan":
            return cmd_profile_plan(args)
        _build_parser().print_help(sys.stderr)
        return 1
    elif args.command == "backup":
        return cmd_backup(args)
    elif args.command == "auto":
        return cmd_auto(args)
    elif args.command == "fingerprint":
        return cmd_fingerprint(args)
    elif args.command == "setup-nor-recovery":
        return cmd_setup_nor_recovery(args)
    elif args.command == "reset":
        return cmd_reset(args)
    else:
        return cmd_flash(args)


if __name__ == "__main__":
    sys.exit(main())
