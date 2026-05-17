"""iPhone USB tethering — router gets WAN via USB from iPhone."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register


def _build_iphone_tether(params: dict[str, Any]) -> str:
    interface_name = params.get("interface", "usbwan")
    return textwrap.dedent(f"""\
        # --- iPhone USB tethering ---
        # Start usbmuxd to poke iOS into sharing
        /usr/sbin/usbmuxd -v -U -f >/dev/null 2>&1 &
        USB_DEV=""
        for _ in $(seq 1 45); do
            for dev in /sys/class/net/*; do
                name=$(basename "$dev")
                case "$name" in
                    lo|br-lan|eth0|wlan*) continue ;;
                esac
                iface_desc=""
                if [ -e "$dev/device/interface" ]; then
                    iface_desc=$(cat "$dev/device/interface" 2>/dev/null || true)
                fi
                driver=$(readlink "$dev/device/driver" 2>/dev/null || true)
                if echo "$iface_desc" | grep -qi "apple\\|iphone" || echo "$driver" | grep -qi "ipheth"; then
                    USB_DEV="$name"
                    break 2
                fi
            done
            sleep 1
        done
        if [ -z "$USB_DEV" ]; then
            for cand in eth1 eth2 eth3 usb0; do
                [ -e "/sys/class/net/$cand" ] && USB_DEV="$cand" && break
            done
        fi
        if [ -n "$USB_DEV" ]; then
            uci set network.{interface_name}=interface
            uci set network.{interface_name}.proto='dhcp'
            uci set network.{interface_name}.device="$USB_DEV"
            uci set network.{interface_name}.metric='20'
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
            echo "iPhone tethering enabled on $USB_DEV -> {interface_name}"
        else
            echo "iPhone tethering: no iPhone USB device found, skipping" >&2
        fi
    """)


register(UseCase(
    name="iphone-tether",
    description="USB WAN from iPhone (ipheth + usbmuxd)",
    packages=[
        "kmod-usb-net",
        "kmod-usb-net-cdc-ether",
        "kmod-usb-net-ipheth",
        "usbmuxd",
        "libimobiledevice",
        "usbutils",
        "kmod-usb2",
    ],
    params={
        "interface": ParamDef(type=str, default="usbwan",
                              description="OpenWrt network interface name for USB WAN"),
    },
    build_defaults=_build_iphone_tether,
    requires_capabilities=["usb"],
))
