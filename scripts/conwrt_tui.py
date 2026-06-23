#!/usr/bin/env python3
"""conwrt TUI -- Interactive Terminal UI for conwrt discovery.

A menu-driven interface that lets humans explore conwrt's capabilities
without memorizing CLI flags. All destructive operations default to
dry-run/preview mode -- no firmware is uploaded, no device is reconfigured.

Read-only actions (browse models, use cases, inventory) call the Python
APIs directly. Actions that would touch hardware (probe, fingerprint,
flash, configure) shell out to ``conwrt.py`` with dry-run flags.

Stdlib only -- no external dependencies (no rich, textual, curses).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# Ensure sibling modules (model_loader, inventory, use_cases) are importable.
sys.path.insert(0, str(Path(__file__).resolve().parent))

SCRIPTS_DIR = Path(__file__).resolve().parent
CONWRT_PY = SCRIPTS_DIR / "conwrt.py"

DOCS_URL = "https://amperstrand.github.io/conwrt/"


class Color:
    """ANSI escape codes for terminal coloring."""

    HEADER = "\033[95m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def clear_screen() -> None:
    """Clear the terminal."""
    os.system("clear" if os.name != "nt" else "cls")


def header(text: str) -> None:
    """Print a cyan section header."""
    print(f"\n{Color.CYAN}{Color.BOLD}{text}{Color.RESET}")
    print(f"{Color.CYAN}{'=' * len(text)}{Color.RESET}\n")


def success(text: str) -> None:
    print(f"{Color.GREEN}{text}{Color.RESET}")


def warning(text: str) -> None:
    print(f"{Color.YELLOW}{text}{Color.RESET}")


def error(text: str) -> None:
    print(f"{Color.RED}{text}{Color.RESET}")


def dim(text: str) -> str:
    return f"{Color.DIM}{text}{Color.RESET}"


def pause() -> None:
    """Wait for Enter before returning to the menu."""
    try:
        input("\nPress Enter to continue...")
    except (KeyboardInterrupt, EOFError):
        pass


def run_conwrt(args: list[str]) -> int:
    """Run ``conwrt.py`` with *args*, stream output, return exit code.

    Never raises -- prints errors and returns the process returncode.
    """
    cmd = [sys.executable, str(CONWRT_PY)] + args
    print(f"\n{Color.DIM}$ {' '.join(cmd)}{Color.RESET}\n")
    try:
        result = subprocess.run(cmd, capture_output=False, text=True)
    except FileNotFoundError:
        error(f"Could not find conwrt.py at {CONWRT_PY}")
        return 1
    except Exception as exc:  # pragma: no cover -- defensive
        error(f"Failed to run conwrt: {exc}")
        return 1
    if result.returncode != 0:
        warning(f"(conwrt exited with code {result.returncode})")
    return result.returncode


def run_conwrt_capture(args: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Run ``conwrt.py`` capturing stdout/stderr. Returns None on launch failure."""
    cmd = [sys.executable, str(CONWRT_PY)] + args
    print(f"\n{Color.DIM}$ {' '.join(cmd)}{Color.RESET}")
    try:
        return subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        error(f"Could not find conwrt.py at {CONWRT_PY}")
        return None
    except Exception as exc:  # pragma: no cover -- defensive
        error(f"Failed to run conwrt: {exc}")
        return None


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def action_browse_devices() -> None:
    """Item 1 -- list all supported device models."""
    from model_loader import list_models

    header("Supported Devices")
    try:
        models = list_models()
    except Exception as exc:
        error(f"Failed to load models: {exc}")
        return

    if not models:
        warning("No models found.")
        return

    # Compute column widths for alignment.
    for m in models:
        mid = m.get("id", "?")
        vendor = m.get("vendor", "?")
        desc = m.get("description", "")
        ow = m.get("openwrt", {})
        target = ow.get("target", "?")
        methods = ", ".join(m.get("flash_methods", {}).keys()) or "none"
        print(
            f"  [{mid}] {vendor} -- {desc} "
            f"{dim(f'({target}, {methods})')}"
        )

    print(f"\n{Color.GREEN}{len(models)} model(s) available.{Color.RESET}")


def action_browse_use_cases() -> None:
    """Item 2 -- list all use case presets."""
    from use_cases import registry

    header("Use Case Presets")
    try:
        presets = registry()
    except Exception as exc:
        error(f"Failed to load use cases: {exc}")
        return

    if not presets:
        warning("No use cases found.")
        return

    for name in sorted(presets):
        uc = presets[name]
        desc = getattr(uc, "description", "")
        status = getattr(uc, "test_status", "?")
        requires = getattr(uc, "requires_capabilities", [])
        req_str = f", requires: {', '.join(requires)}" if requires else ""
        print(
            f"  [{name}] {desc} "
            f"{dim(f'({status}{req_str})')}"
        )

    print(f"\n{Color.GREEN}{len(presets)} preset(s) available.{Color.RESET}")


def action_probe() -> None:
    """Item 3 -- probe an interface for connected routers."""
    header("Probe Interface for Routers")
    print(dim("This finds routers connected to your network interfaces."))
    try:
        iface = input("\nInterface to probe [auto-detect]: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.")
        return

    args = ["probe", "--json"]
    if iface:
        args += ["--interface", iface]

    result = run_conwrt_capture(args)
    if result is None:
        return

    if result.stdout.strip():
        # Try to parse JSON for pretty display; fall back to raw.
        try:
            data = json.loads(result.stdout)
            print(json.dumps(data, indent=2))
        except json.JSONDecodeError:
            print(result.stdout, end="")
    if result.stderr.strip():
        print(result.stderr, end="")
    if result.returncode != 0:
        warning(f"(probe exited with code {result.returncode})")
    else:
        success("\nProbe complete.")


def action_fingerprint() -> None:
    """Item 4 -- fingerprint a device via SSH."""
    header("Fingerprint a Device")
    print(dim("SSH to the device and collect its identity (model, MAC, services)."))
    try:
        ip = input("\nRouter IP address: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.")
        return

    if not ip:
        warning("An IP address is required for fingerprinting.")
        return

    result = run_conwrt_capture(["fingerprint", ip, "--json"])
    if result is None:
        return

    if result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            print(json.dumps(data, indent=2))
        except json.JSONDecodeError:
            print(result.stdout, end="")
    if result.stderr.strip():
        print(result.stderr, end="")
    if result.returncode != 0:
        warning(f"(fingerprint exited with code {result.returncode})")
    else:
        success("\nFingerprint complete.")


def action_auto_detect() -> None:
    """Item 5 -- passive auto-detect scan."""
    header("Auto-Detect Connected Router")
    warning("This is a passive scan that listens for ~10 seconds.")
    warning("Make sure the router is connected and powered on.\n")

    try:
        confirm = input("Start passive scan? [Y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.")
        return
    if confirm in ("n", "no"):
        print("Cancelled.")
        return

    result = run_conwrt_capture(["auto", "--no-menu"])
    if result is None:
        return

    if result.stdout.strip():
        print(result.stdout, end="")
    if result.stderr.strip():
        print(result.stderr, end="")
    if result.returncode != 0:
        warning(f"(auto-detect exited with code {result.returncode})")
    else:
        success("\nAuto-detect complete.")


def action_flash_preview() -> None:
    """Item 6 -- preview flash plan (dry run, --no-upload)."""
    header("Preview Flash Plan")
    warning("DRY RUN -- detects recovery mode but does NOT upload firmware.\n")

    # Show available models for reference.
    try:
        from model_loader import list_models

        models = list_models()
        ids = [m.get("id", "?") for m in models]
        print(dim("Available model IDs:"))
        for mid in ids:
            print(f"  {dim(mid)}")
        print()
    except Exception:
        pass

    try:
        model_id = input("Model ID: ").strip()
        if not model_id:
            warning("Model ID is required.")
            return
        print(dim("Enter path to firmware image, or 'request' to request from ASU:"))
        image = input("Image path [request]: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.")
        return

    args = ["flash", "--model-id", model_id, "--no-upload"]
    if image and image.lower() in ("request", "--request-image", "asu"):
        args.append("--request-image")
    elif image:
        args += ["--image", image]
    else:
        args.append("--request-image")

    run_conwrt(args)
    warning("\nDRY RUN -- no firmware was uploaded.")


def action_configure_preview() -> None:
    """Item 7 -- preview configure plan (profile plan)."""
    header("Preview Configure Plan")
    print(dim("Shows the UCI operations that would be applied to a running router.\n"))

    try:
        model_id = input("Model ID: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.")
        return
    if not model_id:
        warning("Model ID is required.")
        return

    run_conwrt(["profile", "plan", "--model-id", model_id])


def action_inventory() -> None:
    """Item 8 -- show device inventory."""
    from inventory import read_inventory

    header("Device Inventory")
    try:
        entries = read_inventory()
    except FileNotFoundError:
        warning("No devices in inventory yet.")
        return
    except Exception as exc:
        error(f"Failed to read inventory: {exc}")
        return

    if not entries:
        warning("No devices in inventory yet.")
        return

    for i, entry in enumerate(entries, 1):
        model = entry.get("model", "?")
        macs = ", ".join(entry.get("mac_addresses", [])) or "?"
        serial = entry.get("device_serial", "?")
        date = entry.get("timestamp", "?")
        print(f"  {i:>3}. {model} | {macs} | serial={serial} | {date}")

    print(f"\n{Color.GREEN}{len(entries)} device(s) in inventory.{Color.RESET}")


def action_cached_firmware() -> None:
    """Item 9 -- show cached firmware builds."""
    header("Cached Firmware")
    run_conwrt(["cache", "list"])


def action_help() -> None:
    """Item 10 -- help and about."""
    header("Help / About")

    print(f"{Color.BOLD}conwrt{Color.RESET} -- A framework for flashing routers with OpenWrt.")
    print()
    print("conwrt has a two-stage workflow:")
    print("  1. AI-assisted discovery for unknown routers (prompts/)")
    print("  2. Automated flashing for known models (scripts/ + models/)")
    print()
    print(f"{Color.CYAN}Safety Rules:{Color.RESET}")
    print(f"  {Color.RED}NEVER{Color.RESET} use 'sysupgrade -F' / '--force'.")
    print("  It bypasses hardware validation and can brick devices.")
    print("  Always verify the model and board name before flashing.")
    print()
    print(f"{Color.CYAN}Dry-Run by Default:{Color.RESET}")
    print("  This TUI only previews flash/configure actions.")
    print("  No firmware is uploaded, no device is reconfigured.")
    print()
    print(f"{Color.CYAN}Documentation:{Color.RESET}")
    print(f"  {DOCS_URL}")
    print()
    print(dim("Use the CLI (python3 scripts/conwrt.py) for real operations."))


def action_quit() -> bool:
    """Item 11 -- quit. Returns True to signal main loop to exit."""
    print(f"\n{Color.CYAN}Goodbye. Stay safe out there.{Color.RESET}\n")
    return True


# ---------------------------------------------------------------------------
# Menu display and dispatch
# ---------------------------------------------------------------------------

MENU_ITEMS: list[tuple[str, str, str]] = [
    ("1", "Browse supported devices", "(find your model)"),
    ("2", "Browse use case presets", "(tether, VPN, SQM, ...)"),
    ("3", "Probe interface for routers", "(find what's connected)"),
    ("4", "Fingerprint a device", "(SSH identify)"),
    ("5", "Auto-detect connected router", "(passive scan)"),
    ("6", "Preview flash plan", "(dry-run)"),
    ("7", "Preview configure plan", "(dry-run)"),
    ("8", "Show device inventory", ""),
    ("9", "Show cached firmware", ""),
    ("10", "Help / About", ""),
    ("11", "Quit", ""),
]


def show_menu() -> None:
    """Print the main menu."""
    print(f"{Color.CYAN}{Color.BOLD}conwrt TUI -- Interactive Discovery{Color.RESET}")
    print(f"{Color.YELLOW}All actions are dry-run/preview by default.{Color.RESET}")
    print()
    for key, label, hint in MENU_ITEMS:
        suffix = f" {dim(hint)}" if hint else ""
        print(f"  {key:>2}. {label}{suffix}")
    print()


def handle_choice(choice: str) -> bool:
    """Dispatch *choice* to the appropriate action.

    Returns True if the main loop should exit (quit selected).
    """
    actions = {
        "1": action_browse_devices,
        "2": action_browse_use_cases,
        "3": action_probe,
        "4": action_fingerprint,
        "5": action_auto_detect,
        "6": action_flash_preview,
        "7": action_configure_preview,
        "8": action_inventory,
        "9": action_cached_firmware,
        "10": action_help,
    }
    if choice == "11":
        return action_quit()
    handler = actions.get(choice)
    if handler is None:
        warning(f"Unknown option: {choice!r}. Enter a number 1-11.")
        return False
    try:
        handler()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as exc:  # pragma: no cover -- defensive
        error(f"Unexpected error: {exc}")
    pause()
    return False


def main() -> None:
    """Main loop -- show menu, read choice, dispatch, repeat."""
    while True:
        try:
            clear_screen()
            show_menu()
            choice = input("> ").strip()
            should_exit = handle_choice(choice)
            if should_exit:
                break
        except KeyboardInterrupt:
            print("\nInterrupted.")
            pause()
        except EOFError:
            print(f"\n{Color.CYAN}Goodbye.{Color.RESET}\n")
            break


if __name__ == "__main__":
    main()
