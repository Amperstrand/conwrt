"""USB tethering — router gets WAN via USB from Android and/or iPhone."""
from __future__ import annotations

import textwrap
from typing import Any

from . import ParamDef, UseCase, register

_ANDROID_PKGS = [
    "kmod-usb-net",
    "kmod-usb-net-rndis",
    "kmod-usb-net-cdc-ether",
    "kmod-usb2",
    "usbutils",
]

_IOS_PKGS = [
    "kmod-usb-net",
    "kmod-usb-net-ipheth",
    "kmod-usb-net-cdc-ether",
    "usbmuxd",
    "libimobiledevice",
    "usbutils",
    "kmod-usb2",
]

_ADB_PKG = ["adb"]


def _detect_usb_net_device(match_android: bool, match_ios: bool, timeout: int = 45) -> str:
    drivers = []
    if match_android:
        drivers += ["rndis", "cdc_ether", "usbnet"]
    if match_ios:
        drivers += ["ipheth"]
    driver_pattern = "\\|".join(drivers) if drivers else ""

    apple_grep = ""
    if match_ios:
        apple_grep = textwrap.dedent("""\
                iface_desc=""
                [ -e "$dev/device/interface" ] && iface_desc=$(cat "$dev/device/interface" 2>/dev/null || true)
                if echo "$iface_desc" | grep -qi "apple\\|iphone"; then
                    USB_DEV="$name"
                    break 2
                fi""")

    return textwrap.dedent(f"""\
        USB_DEV=""
        for _ in $(seq 1 {timeout}); do
            for dev in /sys/class/net/*; do
                name=$(basename "$dev")
                case "$name" in
                    lo|br-lan|eth0|wlan*) continue ;;
                esac
                driver=$(readlink "$dev/device/driver" 2>/dev/null || true)
                if echo "$driver" | grep -qi "{driver_pattern}"; then
                    USB_DEV="$name"
                    break 2
                fi
                {apple_grep}
            done
            sleep 1
        done
        if [ -z "$USB_DEV" ]; then
            for cand in usb0 usb1; do
                [ -e "/sys/class/net/$cand" ] && USB_DEV="$cand" && break
            done
        fi""")


def _setup_interface(iface: str) -> str:
    return textwrap.dedent(f"""\
        if [ -n "$USB_DEV" ]; then
            uci set network.{iface}=interface
            uci set network.{iface}.proto='dhcp'
            uci set network.{iface}.device="$USB_DEV"
            uci set network.{iface}.metric='20'
            for zone in $(uci show firewall 2>/dev/null | grep "=zone" | cut -d. -f2 | cut -d= -f1 || true); do
                name=$(uci -q get firewall.$zone.name || true)
                if [ "$name" = "wan" ]; then
                    uci add_list firewall.$zone.network='{iface}'
                    break
                fi
            done
            uci commit network
            uci commit firewall
            ifup {iface} 2>/dev/null || true
            echo "USB tethering enabled on $USB_DEV -> {iface}"
        else
            echo "USB tethering: no USB network device found, skipping" >&2
        fi""")


def _start_usbmuxd() -> str:
    return "/usr/sbin/usbmuxd -v -U -f >/dev/null 2>&1 &\n"


def _adb_hotplug_script() -> str:
    return textwrap.dedent("""\
        mkdir -p /etc/hotplug.d/usb
        cat > /etc/hotplug.d/usb/99-usb-tether-adb << 'HOTPLUG_EOF'
        [ "$ACTION" = "bind" ] || exit 0
        [ "$PRODUCT" ] || exit 0
        (
        HOME=/root
        export HOME
        command -v adb >/dev/null 2>&1 || exit 0
        DELAY=1
        for attempt in 1 2 3 4 5 6 7; do
            sleep $DELAY
            if ip addr show usb0 2>/dev/null | grep -q "inet "; then
                exit 0
            fi
            STATE=$(adb get-state 2>/dev/null)
            if [ "$STATE" = "device" ]; then
                adb shell svc usb setFunctions rndis 2>/dev/null
                sleep 3
                if ip addr show usb0 2>/dev/null | grep -q "inet "; then
                    logger -t usb-tether "ADB enabled tethering (attempt $attempt)"
                    exit 0
                fi
            fi
            DELAY=$((DELAY * 2))
        done
        logger -t usb-tether "ADB tethering gave up after $attempt attempts"
        ) &
        HOTPLUG_EOF
    """)


def _build_usb_tether(params: dict[str, Any]) -> str:
    iface = params.get("interface", "usbwan")
    return (
        "# --- USB tethering (Android + iPhone) ---\n"
        + _start_usbmuxd()
        + _detect_usb_net_device(match_android=True, match_ios=True)
        + "\n"
        + _setup_interface(iface)
        + "\n"
        + _adb_hotplug_script()
    )


def _build_android(params: dict[str, Any]) -> str:
    iface = params.get("interface", "usbwan")
    return (
        "# --- USB tethering (Android) ---\n"
        + _detect_usb_net_device(match_android=True, match_ios=False)
        + "\n"
        + _setup_interface(iface)
        + "\n"
    )


def _build_android_adb(params: dict[str, Any]) -> str:
    iface = params.get("interface", "usbwan")
    return (
        "# --- USB tethering (Android + ADB auto-enable) ---\n"
        + _detect_usb_net_device(match_android=True, match_ios=False)
        + "\n"
        + _setup_interface(iface)
        + "\n"
        + _adb_hotplug_script()
    )


def _build_ios(params: dict[str, Any]) -> str:
    iface = params.get("interface", "usbwan")
    return (
        "# --- USB tethering (iPhone) ---\n"
        + _start_usbmuxd()
        + _detect_usb_net_device(match_android=False, match_ios=True, timeout=45)
        + "\n"
        + _setup_interface(iface)
        + "\n"
    )


register(UseCase(
    name="usb-tether",
    description="USB WAN from Android or iPhone (auto-detects, includes ADB auto-enable for Android)",
    packages=_ANDROID_PKGS + _IOS_PKGS + _ADB_PKG,
    params={
        "interface": ParamDef(type=str, default="usbwan",
                              description="OpenWrt network interface name for USB WAN"),
    },
    build_defaults=_build_usb_tether,
    requires_capabilities=["usb"],
))

register(UseCase(
    name="usb-tether-android",
    description="USB WAN from Android phone (RNDIS/CDC-ether, user enables tethering manually)",
    packages=_ANDROID_PKGS,
    params={
        "interface": ParamDef(type=str, default="usbwan",
                              description="OpenWrt network interface name for USB WAN"),
    },
    build_defaults=_build_android,
    requires_capabilities=["usb"],
))

register(UseCase(
    name="usb-tether-android-adb",
    description="USB WAN from Android phone (RNDIS/CDC-ether + ADB auto-enable tethering)",
    packages=_ANDROID_PKGS + _ADB_PKG,
    params={
        "interface": ParamDef(type=str, default="usbwan",
                              description="OpenWrt network interface name for USB WAN"),
    },
    build_defaults=_build_android_adb,
    requires_capabilities=["usb"],
))

register(UseCase(
    name="usb-tether-ios",
    description="USB WAN from iPhone (ipheth + usbmuxd, user enables Personal Hotspot)",
    packages=_IOS_PKGS,
    params={
        "interface": ParamDef(type=str, default="usbwan",
                              description="OpenWrt network interface name for USB WAN"),
    },
    build_defaults=_build_ios,
    requires_capabilities=["usb"],
))
