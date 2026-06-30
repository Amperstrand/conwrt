"""router_display — interactive display and menu for detected routers.

Extracted from auto_detect for modularity.
"""

from __future__ import annotations

import sys

from model_loader import load_model
from model_match import match_models_by_oui


SEPARATOR = "=" * 45


def _print_router(router) -> None:
    """Print a summary of a detected router."""
    print(f"\n{SEPARATOR}")
    print(f"Router detected at {router.ip}")
    print(f"MAC:        {router.mac}")
    vendor_source = ""
    if router.vendor:
        oui_models = match_models_by_oui(router.mac) if router.mac != "unknown" else []
        vendor_source = " (OUI match)" if oui_models else ""
    print(f"Vendor:     {router.vendor}{vendor_source}")

    if router.model_id:
        print(f"Model:      {router.model_name or router.model_id} ({router.confidence})")
    else:
        print(f"Model:      Not identified ({router.confidence})")

    fw_label = {
        "uboot": "U-Boot recovery mode",
        "openwrt": "OpenWrt",
        "glinet_stock": "GL.iNet stock firmware",
        "linksys_stock": "Linksys stock firmware",
        "dlink_stock": "Stock D-Link firmware",
        "zyxel_stock": "ZyXEL stock firmware",
        "unknown_http": "Unknown web interface",
        "unknown": "Unknown firmware state",
    }.get(router.firmware_state, router.firmware_state)
    print(f"Firmware:   {fw_label}")
    if router.stock_firmware_version:
        print(f"Stock FW:   {router.stock_firmware_version}")

    ssh_label = "Available" if router.ssh_available else "Not available"
    if router.ssh_available and router.ssh_info:
        board = router.ssh_info.get("model", "")
        if board:
            ssh_label += f" (board: {board})"
    print(f"SSH:        {ssh_label}")

    web_label = {
        "dlink_hnap": "D-Link admin panel (HNAP API detected)",
        "openwrt_luci": "OpenWrt LuCI web interface",
        "glinet_admin": "GL.iNet admin panel",
        "linksys": "Linksys admin panel (JNAP API)",
        "uboot": "U-Boot HTTP recovery page",
        "zyxel_stock": "ZyXEL admin panel (dispatcher.cgi)",
        "unknown": "Unknown web interface",
        "none": "No web interface detected",
    }.get(router.web_ui_type, router.web_ui_type)
    print(f"Web UI:     {web_label}")
    print(f"Confidence: {router.confidence}")

    readiness = router.readiness
    if readiness:
        status = "READY" if readiness.get("ready") else "NOT READY"
        print(f"Readiness:  {status}")
        for issue in readiness.get("issues", []):
            print(f"  ⚠ Issue:  {issue}")
        for warning in readiness.get("warnings", []):
            print(f"  ⚠ Note:   {warning}")

    if router.lldp_info:
        print(f"LLDP:       {router.lldp_info.chassis_name or router.lldp_info.chassis_mac}")

    print(f"{SEPARATOR}")


def interactive_menu(routers: list) -> None:
    """Interactive menu for selecting and acting on detected routers."""
    if not routers:
        print("\nNo routers detected.")
        return

    print(f"\n{'=' * 45}")
    print(f"  DETECTED {len(routers)} ROUTER(S)")
    print(f"{'=' * 45}")

    for router in routers:
        _print_router(router)

    while True:
        router = routers[0] if len(routers) == 1 else None
        if router is None:
            print("\nMultiple routers detected. Select one:")
            for i, r in enumerate(routers, 1):
                label = r.model_name or r.vendor or r.mac
                print(f"  [{i}] {r.ip} — {label}")
            choice = input("Router number (or q to quit): ").strip().lower()
            if choice == "q":
                return
            try:
                idx = int(choice) - 1
                router = routers[idx]
            except (ValueError, IndexError):
                print("Invalid selection.")
                continue

        print(f"\nWhat would you like to do with {router.ip}?")
        print("  [1] Flash with OpenWrt (request custom image from ASU)")
        print("  [2] Flash with existing firmware image")
        print("  [3] Enter recovery mode first, then flash")
        print("  [4] Show detailed detection info")
        print("  [5] Re-scan")
        print("  [q] Quit")

        choice = input("Choice: ").strip().lower()

        if choice == "1":
            model_flag = f"--model-id {router.model_id}" if router.model_id else ""
            iface = ""
            print(f"\n  conwrt flash {model_flag} {iface}--request-image")
            print("  (Edit config.toml for SSH keys, passwords, and use case presets)")
            input("\nPress Enter to continue...")

        elif choice == "2":
            image_path = input("Path to firmware image: ").strip()
            if image_path:
                model_flag = f"--model-id {router.model_id}" if router.model_id else ""
                print(f"\n  conwrt flash {model_flag} --image {image_path}")
            input("\nPress Enter to continue...")

        elif choice == "3":
            model_flag = f"--model-id {router.model_id}" if router.model_id else ""
            print(f"\n  conwrt flash {model_flag} --force-uboot")
            if router.model_id:
                model_def = None
                try:
                    model_def = load_model(router.model_id)
                except FileNotFoundError:
                    pass
                if model_def:
                    for method_name, method_cfg in model_def.get("flash_methods", {}).items():
                        if "reset_instructions" in method_cfg:
                            print(f"\n  Recovery instructions ({method_name}):")
                            for line in method_cfg["reset_instructions"].split(". "):
                                if line.strip():
                                    print(f"    {line.strip()}")
                            break
            input("\nPress Enter to continue...")

        elif choice == "4":
            print(f"\n{'─' * 45}")
            print(f"DETAILED INFO: {router.ip}")
            print(f"{'─' * 45}")
            print(f"MAC:            {router.mac}")
            print(f"Vendor:         {router.vendor}")
            print(f"Model ID:       {router.model_id or 'N/A'}")
            print(f"Model name:     {router.model_name or 'N/A'}")
            print(f"Firmware state: {router.firmware_state}")
            print(f"Web UI type:    {router.web_ui_type}")
            print(f"SSH available:  {router.ssh_available}")
            if router.ssh_info:
                for k, v in router.ssh_info.items():
                    print(f"  SSH {k}: {v}")
            print(f"DHCP server:    {router.dhcp_server}")
            if router.dhcp_info:
                for k, v in router.dhcp_info.items():
                    print(f"  DHCP {k}: {v}")
            print(f"Confidence:     {router.confidence}")
            print(f"Flash methods:  {', '.join(router.flash_methods) if router.flash_methods else 'N/A'}")
            if router.http_response_preview:
                print("\nHTTP preview (first 300 chars):")
                print(router.http_response_preview[:300])
            if router.http_headers:
                print("\nHTTP headers:")
                print(router.http_headers[:300])
            print("\nEvidence chain:")
            for ev in router.evidence:
                print(f"  {ev}")
            input("\nPress Enter to continue...")

        elif choice == "5":
            return

        elif choice == "q":
            sys.exit(0)

        else:
            print("Invalid choice.")
