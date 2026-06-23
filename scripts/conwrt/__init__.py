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

import sys
from pathlib import Path

_CONWRT_DIR = str(Path(__file__).resolve().parent.parent)  # scripts/ — sibling modules live here
if _CONWRT_DIR not in sys.path:
    sys.path.insert(0, _CONWRT_DIR)

from conwrt._version import __version__  # noqa: E402

# Re-exports needed by tests that do `conwrt.check_ssh`
from ssh_utils import check_ssh  # noqa: E402
from conwrt.cli import _build_parser  # noqa: E402


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] not in (
        "flash", "list", "list-use-cases", "cache", "setup-mgmt-wifi", "backup",
        "auto", "setup-nor-recovery", "configure", "profile", "fingerprint", "reset",
        "probe", "flow", "-h", "--help", "--version", "-V",
    ):
        sys.argv.insert(1, "flash")

    parser = _build_parser()
    args = parser.parse_args()

    command = args.command or "flash"

    # Profile subcommand
    if command == "profile":
        if getattr(args, "profile_command", None) == "plan":
            from conwrt.commands_profile import cmd_profile_plan
            return cmd_profile_plan(args)
        _build_parser().print_help(sys.stderr)
        return 1

    # Flash command (default) — heavy imports
    if command == "flash":
        from conwrt.flash_dispatcher import cmd_flash
        return cmd_flash(args)

    # All other commands — lightweight lazy imports
    _COMMAND_MAP = {
        "list": ("conwrt.cmd_info", "cmd_list"),
        "list-use-cases": ("conwrt.cmd_info", "cmd_list_use_cases"),
        "cache": ("conwrt.cmd_info", "cmd_cache"),
        "setup-mgmt-wifi": ("conwrt.commands_wifi", "cmd_setup_mgmt_wifi"),
        "configure": ("conwrt.commands_configure", "cmd_configure"),
        "backup": ("conwrt.cmd_backup", "cmd_backup"),
        "auto": ("conwrt.cmd_detect", "cmd_auto"),
        "fingerprint": ("conwrt.cmd_detect", "cmd_fingerprint"),
        "setup-nor-recovery": ("conwrt.cmd_nor_recovery", "cmd_setup_nor_recovery"),
        "reset": ("conwrt.cmd_reset", "cmd_reset"),
        "probe": ("conwrt.cmd_probe", "cmd_probe"),
        "flow": ("conwrt.cmd_flow", "cmd_flow"),
    }

    entry = _COMMAND_MAP.get(command)
    if entry:
        import importlib
        mod = importlib.import_module(entry[0])
        handler = getattr(mod, entry[1])
        return handler(args)

    # Fallback
    from conwrt.flash_dispatcher import cmd_flash
    return cmd_flash(args)


if __name__ == "__main__":
    sys.exit(main())
