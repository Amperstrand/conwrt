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
import os
import queue
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Optional

# Version — set by build_ipk.sh or derived from git at runtime
__version__ = "0.0.0-dev"

_CONWRT_DIR = str(Path(__file__).resolve().parent.parent)  # scripts/ — sibling modules live here
if _CONWRT_DIR not in sys.path:
    sys.path.insert(0, _CONWRT_DIR)
from ssh_utils import check_ssh, run_ssh, ssh_cmd
from config import load_config as _load_config
from model_loader import load_model, list_models
from flash.device_profile import build_profile_from_model as _build_profile_from_model
from flash.context import (
    DEFAULT_IP,
    Event,
    PROBE_IPS,
    REBOOT_TIMEOUT,
    SILENCE_TIMEOUT_DEFAULT,
    State,
    log,
    say,
    sha256_file,
    ts,
    wait_for_event,
)
from flash.upload import detect_uboot_http
from flash.detect import detect_boot_state as _detect_boot_state
from flash.device_detect import (
    active_fingerprint as _active_fingerprint,
    match_models as _match_models,
)
import importlib
_firmware_manager = importlib.import_module("firmware-manager")
firmware_request = _firmware_manager.cmd_request
firmware_find = _firmware_manager.cmd_find
IMAGES_DIR = _firmware_manager.IMAGES_DIR
_router_fingerprint = importlib.import_module("router-fingerprint")
fingerprint_router = _router_fingerprint.fingerprint_router
save_fingerprint = _router_fingerprint.save_fingerprint

from platform_utils import detect_platform, check_external_deps, remove_interface_ip
from flash.preflight import run_preflight_checks
from profile import build_plan, print_plan
from profile.apply import verify_persistence as _verify_persistence
from profile.wifi import build_mgmt_wifi_script


from conwrt.extreme import (
    _cleanup_extreme_tftp_assets,
    _setup_interface_ips,
    _resolve_extreme_uboot_value as _resolve_extreme_uboot_value,
    _handle_extreme_stock_preflight, _handle_extreme_stock_writing_uboot,
    _handle_extreme_stock_rebooting, _handle_extreme_openwrt_initramfs_waiting,
    _handle_extreme_openwrt_backup, _handle_extreme_bootcmd_restore,
    _handle_extreme_sysupgrade_uploading, _handle_extreme_sysupgrade_flashing,
    _handle_port_isolation, _restore_port_isolation,
)


from conwrt.flash_utils import (
    _flash_via_sysupgrade, _flash_via_mtd_write,
    _wait_for_sysupgrade_reboot, _find_model_id_by_board, _detect_ssh_key_path,
)

from conwrt.handlers_uboot import (
    _handle_waiting_for_power_off,
    _handle_waiting_for_uboot,
    _handle_uboot_uploading,
    _handle_uboot_flashing,
)
from conwrt.handlers_oem import (
    _handle_oem_login,
    _handle_oem_prepare,
    _handle_oem_uploading,
    _handle_oem_rebooting,
)
from conwrt.handlers_zycast import (
    _handle_zycast_waiting,
    _handle_zycast_sending,
)
from conwrt.handlers_serial import (
    _handle_serial_waiting_for_bootmenu,
    _handle_serial_uboot_interacting,
)
from conwrt.handlers_edgeos import (
    _handle_edgeos_stage1,
    _handle_edgeos_stage1_rebooting,
    _handle_edgeos_port_swap,
    _handle_edgeos_stage2_uploading,
    _handle_edgeos_stage2_flashing,
)


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


from conwrt.postflash import (
    _apply_profile_post_flash, _apply_sticker_credentials_post_flash,
    _register_wireguard_post_flash, _deploy_tollgate_post_flash,
    _client_ip_for_subnet,
    verify_router,
    _cfg_install_ssh_key,
    _record_configure_inventory, _resolve_configure_options,
)


from conwrt.monitors import (
    PcapMonitor, LinkMonitor, SSHMonitor,
    _setup_monitors, _teardown_monitors,
    monitor_lifecycle,
)


from conwrt.infrastructure import (
    RecoveryContext,
    _generate_random_password, _validate_args,
)


from conwrt.firmware import (
    _request_custom_image,
)

from conwrt.cmd_nor_recovery import cmd_setup_nor_recovery
from conwrt.cmd_backup import cmd_backup
from conwrt.cmd_reset import cmd_reset
from conwrt.cmd_info import cmd_list, cmd_list_use_cases, cmd_cache
from conwrt.cmd_detect import cmd_fingerprint, cmd_auto


@dataclass
class FlashModeConfig:
    initial_state: State
    pcap_enabled: bool = True
    has_monitors: bool = True        # serial mode has no monitors
    setup_interface: bool = False    # uboot mode needs _setup_interface_ips
    cleanup: Optional[Callable] = None


def _extreme_cleanup(ctx: RecoveryContext, profile: object, interface: str) -> None:
    _cleanup_extreme_tftp_assets(ctx)
    openwrt_client_ip = getattr(profile, "openwrt_client_ip", "")
    if openwrt_client_ip and openwrt_client_ip != getattr(profile, "client_ip", ""):
        remove_interface_ip(interface, openwrt_client_ip, "24")


def _serial_cleanup(ctx: RecoveryContext, profile: object, interface: str) -> None:
    driver = getattr(ctx, '_serial_driver', None)
    if driver:
        driver.close()
    tftp_mgr = getattr(ctx, '_tftp_manager', None)
    if tftp_mgr:
        tftp_mgr.stop()


def _zycast_cleanup(ctx: RecoveryContext, profile: object, interface: str) -> None:
    zycast_proc = getattr(ctx, '_zycast_proc', None)
    if zycast_proc and zycast_proc.poll() is None:
        zycast_proc.terminate()


FLASH_MODES: dict[str, FlashModeConfig] = {
    "sysupgrade": FlashModeConfig(State.SYSUPGRADE_UPLOADING, pcap_enabled=False),
    "edgeos": FlashModeConfig(State.EDGEOS_STAGE1, pcap_enabled=False),
    "extreme": FlashModeConfig(State.EXTREME_STOCK_PREFLIGHT, pcap_enabled=False, cleanup=_extreme_cleanup),
    "serial": FlashModeConfig(State.SERIAL_WAITING_FOR_BOOTMENU, has_monitors=False, cleanup=_serial_cleanup),
    "zycast": FlashModeConfig(State.ZYCAST_WAITING_FOR_DEVICE, cleanup=_zycast_cleanup),
    "uboot": FlashModeConfig(State.WAITING_FOR_POWER_OFF, setup_interface=True),
}


def _resolve_flash_mode(profile: object, boot_state: str, args: argparse.Namespace,
                         use_sysupgrade: bool) -> str:
    """Determine flash mode from profile attributes and boot state."""
    is_serial_tftp = getattr(profile, 'is_serial_tftp', False)
    is_zycast = getattr(profile, 'is_zycast', False)
    is_edgeos_ks = getattr(profile, 'is_edgeos_kernel_swap', False)
    is_extreme_rdwr_tftp = getattr(profile, 'is_extreme_rdwr_tftp', False)

    if use_sysupgrade:
        return "sysupgrade"
    if is_edgeos_ks:
        return "edgeos"
    if is_extreme_rdwr_tftp:
        return "extreme"
    if is_serial_tftp:
        return "serial"
    if is_zycast:
        return "zycast"
    return "uboot"


def _resolve_initial_state(mode: str, profile: object, boot_state: str) -> State:
    """Resolve the initial state for the state machine."""
    config = FLASH_MODES[mode]

    if mode == "uboot":
        if boot_state == "uboot":
            found, detail = detect_uboot_http(profile.recovery_ip)
            if found:
                log(f"Recovery HTTP already live at {profile.recovery_ip} ({detail}) — skipping power cycle")
                return State.UBOOT_UPLOADING
        return State.WAITING_FOR_POWER_OFF

    if mode == "extreme" and boot_state != "stock-extreme":
        return State.DETECTING

    return config.initial_state


def _run_state_machine(
    ctx: RecoveryContext,
    event_queue: queue.Queue,
    pcap_monitor: Optional[PcapMonitor],
    link_monitor: LinkMonitor,
) -> int:
    ctx.timeline.recovery_start = ts()

    def _uboot_with_link(c: RecoveryContext, eq: queue.Queue) -> None:
        _handle_waiting_for_uboot(c, eq, link_monitor)

    def _flashing_with_pcap(c: RecoveryContext, eq: queue.Queue) -> None:
        _handle_uboot_flashing(c, eq, pcap_monitor)

    _dispatch: dict[State, Callable[[RecoveryContext, queue.Queue], None]] = {
        State.DETECTING: _handle_detecting,
        State.SYSUPGRADE_UPLOADING: _handle_sysupgrade_uploading,
        State.SYSUPGRADE_REBOOTING: _handle_sysupgrade_rebooting,
        State.SYSUPGRADE_BOOTING: _handle_sysupgrade_booting,
        State.WAITING_FOR_POWER_OFF: _handle_waiting_for_power_off,
        State.WAITING_FOR_UBOOT: _uboot_with_link,
        State.UBOOT_UPLOADING: _handle_uboot_uploading,
        State.UBOOT_FLASHING: _flashing_with_pcap,
        State.SERIAL_WAITING_FOR_BOOTMENU: _handle_serial_waiting_for_bootmenu,
        State.SERIAL_UBOOT_INTERACTING: _handle_serial_uboot_interacting,
        State.ZYCAST_WAITING_FOR_DEVICE: _handle_zycast_waiting,
        State.ZYCAST_SENDING: _handle_zycast_sending,
        State.REBOOTING: _handle_rebooting,
        State.OPENWRT_BOOTING: _handle_openwrt_booting,
        State.EDGEOS_STAGE1: _handle_edgeos_stage1,
        State.EDGEOS_STAGE1_REBOOTING: _handle_edgeos_stage1_rebooting,
        State.EDGEOS_PORT_SWAP: _handle_edgeos_port_swap,
        State.EDGEOS_STAGE2_UPLOADING: _handle_edgeos_stage2_uploading,
        State.EDGEOS_STAGE2_FLASHING: _handle_edgeos_stage2_flashing,
        State.EXTREME_STOCK_PREFLIGHT: _handle_extreme_stock_preflight,
        State.EXTREME_STOCK_WRITING_UBOOT: _handle_extreme_stock_writing_uboot,
        State.EXTREME_STOCK_REBOOTING: _handle_extreme_stock_rebooting,
        State.EXTREME_OPENWRT_INITRAMFS_WAITING: _handle_extreme_openwrt_initramfs_waiting,
        State.EXTREME_OPENWRT_BACKUP: _handle_extreme_openwrt_backup,
        State.EXTREME_BOOTCMD_RESTORE: _handle_extreme_bootcmd_restore,
        State.EXTREME_SYSUPGRADE_UPLOADING: _handle_extreme_sysupgrade_uploading,
        State.EXTREME_SYSUPGRADE_FLASHING: _handle_extreme_sysupgrade_flashing,
        State.PORT_ISOLATION: _handle_port_isolation,
        State.OEM_LOGIN: _handle_oem_login,
        State.OEM_PREPARE: _handle_oem_prepare,
        State.OEM_UPLOADING: _handle_oem_uploading,
        State.OEM_REBOOTING: _handle_oem_rebooting,
    }

    while ctx.state not in (State.COMPLETE, State.FAILED):
        handler = _dispatch.get(ctx.state)
        if handler is None:
            log(f"Unhandled state: {ctx.state}")
            ctx.state = State.FAILED
        else:
            handler(ctx, event_queue)

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


def _handle_sysupgrade_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip or DEFAULT_IP
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
    openwrt_ip = ctx.profile.openwrt_ip or DEFAULT_IP
    method = "mtd-write" if ctx.profile.flash_method == "mtd-write" else "sysupgrade"
    if _wait_for_sysupgrade_reboot(openwrt_ip):
        ctx.mark_success(f"{method} recovery complete.", verify_fn=verify_router)
    else:
        ctx._say_fn("Device did not come back after flash.")
        log(f"FAIL: SSH not available after {method} reboot.")
        ctx.state = State.FAILED


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
            event, event_ts, _ = eq.get(timeout=5.0)
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
            ctx.mark_success("router recovered (SSH poll detected).", verify_fn=verify_router)
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
        ctx.mark_success("router recovered.", verify_fn=verify_router)
    else:
        if check_ssh(openwrt_ip):
            ctx.mark_success("router recovered (SSH fallback check).", verify_fn=verify_router)
        else:
            ctx.state = State.FAILED


_wait_for_event_or_timeout = wait_for_event


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
    mgmt_parser.add_argument("--ip", default=DEFAULT_IP,
        help="Router IP address")
    mgmt_parser.add_argument("--model-id", default=None,
        help="Model ID (for SSH key detection)")

    backup_parser = subparsers.add_parser("backup",
        help="Backup MTD flash partitions from a stock ZyXEL router via SSH")
    backup_parser.add_argument("--model-id", default="zyxel-nr7101",
        help="Model ID (default: zyxel-nr7101)")
    backup_parser.add_argument("--ip", default=DEFAULT_IP,
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
    cfg_parser.add_argument("--ip", default=DEFAULT_IP,
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
    reset_parser.add_argument("--ip", default=DEFAULT_IP,
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
        for probe_ip in PROBE_IPS:
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
            for probe_ip in PROBE_IPS:
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

    mode = _resolve_flash_mode(profile, boot_state, args, use_sysupgrade)
    config = FLASH_MODES[mode]

    initial_state = _resolve_initial_state(mode, profile, boot_state)

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

    if mode == "serial" and getattr(profile, 'lan_port', ''):
        log(f"IMPORTANT: Connect Ethernet cable to {profile.lan_port} port")
    if mode == "zycast":
        log(f"Flash path: zycast multicast ({profile.zycast_multicast_group}:{profile.zycast_multicast_port})")

    if config.has_monitors:
        if config.setup_interface:
            _setup_interface_ips(interface, profile)

        say_label = {
            "sysupgrade": "sysupgrade recovery",
            "edgeos": "edgeos-kernel-swap flash",
            "extreme": "extreme stock flash",
            "zycast": "multicast recovery",
        }.get(mode, "recovery. Listen for instructions")
        _say_fn(f"Starting {profile.description} {say_label}.")

        with monitor_lifecycle(
            interface, event_queue, pcap_path, profile, args,
            pcap_enabled=config.pcap_enabled,
        ) as (pcap, link):
            try:
                rc = _run_state_machine(ctx, event_queue, pcap, link)
            except KeyboardInterrupt:
                log("Interrupted by user.")
                rc = 1
    else:
        _say_fn(f"Starting {profile.description} serial recovery.")
        try:
            rc = _run_state_machine(ctx, event_queue, None, None)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1

    if config.cleanup:
        config.cleanup(ctx, profile, interface)

    return rc




_COMMANDS = {
    "list": cmd_list,
    "list-use-cases": cmd_list_use_cases,
    "cache": cmd_cache,
    "setup-mgmt-wifi": cmd_setup_mgmt_wifi,
    "configure": cmd_configure,
    "backup": cmd_backup,
    "auto": cmd_auto,
    "fingerprint": cmd_fingerprint,
    "setup-nor-recovery": cmd_setup_nor_recovery,
    "reset": cmd_reset,
}


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] not in (
        "flash", "list", "list-use-cases", "cache", "setup-mgmt-wifi", "backup",
        "auto", "setup-nor-recovery", "configure", "profile", "fingerprint", "reset", "-h", "--help",
        "--version", "-V",
    ):
        sys.argv.insert(1, "flash")

    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "profile":
        if getattr(args, "profile_command", None) == "plan":
            return cmd_profile_plan(args)
        _build_parser().print_help(sys.stderr)
        return 1

    handler = _COMMANDS.get(args.command, cmd_flash)
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
