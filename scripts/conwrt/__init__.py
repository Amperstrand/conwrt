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
import subprocess
import sys
from pathlib import Path

from conwrt._version import __version__

_CONWRT_DIR = str(Path(__file__).resolve().parent.parent)  # scripts/ — sibling modules live here
if _CONWRT_DIR not in sys.path:
    sys.path.insert(0, _CONWRT_DIR)
from ssh_utils import check_ssh, run_ssh, ssh_cmd
from config import load_config as _load_config
from model_loader import load_model, list_models
from flash.context import log
import importlib
_firmware_manager = importlib.import_module("firmware-manager")
firmware_request = _firmware_manager.cmd_request
firmware_find = _firmware_manager.cmd_find
IMAGES_DIR = _firmware_manager.IMAGES_DIR
_router_fingerprint = importlib.import_module("router-fingerprint")
fingerprint_router = _router_fingerprint.fingerprint_router
save_fingerprint = _router_fingerprint.save_fingerprint

from profile.apply import verify_persistence as _verify_persistence
from conwrt.commands_wifi import cmd_setup_mgmt_wifi
from conwrt.commands_profile import cmd_profile_plan


from conwrt.extreme import (
    _resolve_extreme_uboot_value as _resolve_extreme_uboot_value,
    _handle_extreme_stock_preflight, _handle_extreme_stock_writing_uboot,
    _handle_extreme_stock_rebooting, _handle_extreme_openwrt_initramfs_waiting,
    _handle_extreme_openwrt_backup, _handle_extreme_bootcmd_restore,
    _handle_extreme_sysupgrade_uploading, _handle_extreme_sysupgrade_flashing,
    _handle_port_isolation, _restore_port_isolation,
)
from conwrt.commands_configure import cmd_configure


from conwrt.flash_utils import (
    _detect_ssh_key_path,
)

from conwrt.handlers_oem import (
    _handle_oem_login,
    _handle_oem_prepare,
    _handle_oem_uploading,
    _handle_oem_rebooting,
)

from conwrt.postflash import (
    _apply_profile_post_flash,
    _cfg_install_ssh_key,
    _record_configure_inventory, _resolve_configure_options,
)


from conwrt.infrastructure import (
    RecoveryContext,
)


from conwrt.device_inventory import auto_detect_interface
from conwrt.cli import _build_parser

from conwrt.cmd_nor_recovery import cmd_setup_nor_recovery
from conwrt.cmd_backup import cmd_backup
from conwrt.cmd_reset import cmd_reset
from conwrt.cmd_info import cmd_list, cmd_list_use_cases, cmd_cache
from conwrt.cmd_detect import cmd_fingerprint, cmd_auto
from conwrt.cmd_probe import cmd_probe

from conwrt.flash_dispatcher import (
    FlashModeConfig, _run_state_machine, _resolve_flash_mode, _resolve_initial_state,
    cmd_flash, _extreme_cleanup,     _serial_cleanup, _zycast_cleanup,
    _handle_detecting, _handle_sysupgrade_uploading, _handle_sysupgrade_rebooting,
    _handle_sysupgrade_booting, _handle_rebooting, _handle_openwrt_booting,
)


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
    "probe": cmd_probe,
}


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] not in (
        "flash", "list", "list-use-cases", "cache", "setup-mgmt-wifi", "backup",
        "auto", "setup-nor-recovery", "configure", "profile", "fingerprint", "reset",
        "probe", "-h", "--help",
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
