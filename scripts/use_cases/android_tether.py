"""Android USB tethering — router gets WAN via USB from Android phone."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register


def _build_android_tether(params: dict[str, Any]) -> str:
    interface_name = params.get("interface", "usbwan")
    return textwrap.dedent(f"""\
        # --- Android USB tethering ---
        # Wait for USB network device to appear (up to 30s)
        USB_DEV=""
        for _ in $(seq 1 30); do
            for dev in /sys/class/net/*; do
                name=$(basename "$dev")
                case "$name" in
                    lo|br-lan|eth0|wlan*) continue ;;
                esac
                driver=$(readlink "$dev/device/driver" 2>/dev/null || true)
                if echo "$driver" | grep -qi "rndis\\|cdc_ether\\|usbnet"; then
                    USB_DEV="$name"
                    break 2
                fi
            done
            sleep 1
        done
        if [ -z "$USB_DEV" ]; then
            # Fallback: look for usb0 or any new ethX that appeared
            for cand in usb0 usb1 eth1 eth2; do
                [ -e "/sys/class/net/$cand" ] && USB_DEV="$cand" && break
            done
        fi
        if [ -n "$USB_DEV" ]; then
            uci set network.{interface_name}=interface
            uci set network.{interface_name}.proto='dhcp'
            uci set network.{interface_name}.device="$USB_DEV"
            uci set network.{interface_name}.metric='20'
            # Add to wan firewall zone
            for zone in $(uci show firewall 2>/dev/null | grep "=zone" | cut -d. -f2 | cut -d= -f1 || true); do
                name=$(uci -q get firewall.$zone.name || true)
                if [ "$name" = "wan" ]; then
                    uci add_list firewall.$zone.network='{interface_name}'
                    break
                fi
            done
            uci commit network
            uci commit firewall
            ifup {interface_name} 2>/dev/null || true
            echo "USB tethering enabled on $USB_DEV -> {interface_name}"
        else
            echo "USB tethering: no USB network device found, skipping" >&2
        fi
    """)


register(UseCase(
    name="android-tether",
    description="USB WAN from Android phone (RNDIS/CDC-ether)",
    packages=[
        "kmod-usb-net",
        "kmod-usb-net-rndis",
        "kmod-usb-net-cdc-ether",
        "kmod-usb2",
        "usbutils",
    ],
    params={
        "interface": ParamDef(type=str, default="usbwan",
                              description="OpenWrt network interface name for USB WAN"),
    },
    build_defaults=_build_android_tether,
    requires_capabilities=["usb"],
))
