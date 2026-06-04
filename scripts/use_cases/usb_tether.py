"""USB tethering presets — router gets WAN via USB from Android and/or iPhone.

This use case requires ShellCommand ops throughout because it depends on
runtime hardware discovery: the USB network device is detected by walking
/sys/class/net at boot time, and the uci commands inside the detection
script reference shell variables ($USB_DEV, $zone) that are not known at
op-generation time. This is the canonical example of a use case that
cannot be promoted to typed ops — it is a first-boot script that probes
hardware, not a static UCI configuration."""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ShellCommand, render_shell

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
        apple_grep = """\
                iface_desc=""
                [ -e "$dev/device/interface" ] && iface_desc=$(cat "$dev/device/interface" 2>/dev/null || true)
                if echo "$iface_desc" | grep -qi "apple\\|iphone"; then
                    USB_DEV="$name"
                    break 2
                fi"""

    return f"""\
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
fi"""


def _setup_interface(iface: str) -> str:
    return f"""\
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
fi"""


def _start_usbmuxd() -> str:
    return "/usr/sbin/usbmuxd -v -U -f >/dev/null 2>&1 &\n"


def _adb_hotplug_script() -> str:
    return """\
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
"""


_IFACE_PARAM = {
    "interface": ParamDef(type=str, default="usbwan",
                          description="OpenWrt network interface name for USB WAN"),
}


def _shell_lines_to_ops(text: str) -> list[Op]:
    lines = text.strip().splitlines()
    ops: list[Op] = []
    for ln in lines:
        s = ln.strip()
        if not s:
            ops.append(BlankLine())
        else:
            ops.append(ShellCommand(command=s))
    return ops


def _build_tether_ops(params: dict[str, Any]) -> list[Op]:
    iface = params.get("interface", "usbwan")
    ops: list[Op] = [Comment(text="--- USB tethering (auto-detect) ---")]
    script = (
        _start_usbmuxd()
        + _detect_usb_net_device(match_android=True, match_ios=True) + "\n"
        + _setup_interface(iface) + "\n"
        + _adb_hotplug_script()
    )
    ops.extend(_shell_lines_to_ops(script))
    return ops


def _build_tether_android_ops(params: dict[str, Any]) -> list[Op]:
    iface = params.get("interface", "usbwan")
    ops: list[Op] = [Comment(text="--- Android USB tethering (manual) ---")]
    script = (
        _detect_usb_net_device(match_android=True, match_ios=False) + "\n"
        + _setup_interface(iface) + "\n"
    )
    ops.extend(_shell_lines_to_ops(script))
    return ops


def _build_tether_android_adb_ops(params: dict[str, Any]) -> list[Op]:
    iface = params.get("interface", "usbwan")
    ops: list[Op] = [Comment(text="--- Android USB tethering (ADB auto-enable) ---")]
    script = (
        _detect_usb_net_device(match_android=True, match_ios=False) + "\n"
        + _setup_interface(iface) + "\n"
        + _adb_hotplug_script()
    )
    ops.extend(_shell_lines_to_ops(script))
    return ops


def _build_tether_ios_ops(params: dict[str, Any]) -> list[Op]:
    iface = params.get("interface", "usbwan")
    ops: list[Op] = [Comment(text="--- iPhone USB tethering ---")]
    script = (
        _start_usbmuxd()
        + _detect_usb_net_device(match_android=False, match_ios=True) + "\n"
        + _setup_interface(iface) + "\n"
    )
    ops.extend(_shell_lines_to_ops(script))
    return ops


register(UseCase(
    name="tether",
    description="Auto-detect Android or iPhone USB WAN. For Android, includes ADB auto-enable.",
    packages=_ANDROID_PKGS + _IOS_PKGS + _ADB_PKG,
    params=_IFACE_PARAM,
    build_configure=lambda p: render_shell(_build_tether_ops(p)),
    build_configure_ops=_build_tether_ops,
    test_status="tested",
    tested_notes="GL.iNet MT3000, Android RNDIS",
    requires_capabilities=["usb"],
))

register(UseCase(
    name="tether-android",
    description="USB WAN from Android phone. Enable tethering manually on the phone.",
    packages=_ANDROID_PKGS,
    params=_IFACE_PARAM,
    build_configure=lambda p: render_shell(_build_tether_android_ops(p)),
    build_configure_ops=_build_tether_android_ops,
    test_status="tested",
    tested_notes="GL.iNet MT3000",
    requires_capabilities=["usb"],
))

register(UseCase(
    name="tether-android-adb",
    description="USB WAN from Android phone with ADB auto-enable. Confirm on phone, tethering activates automatically.",
    packages=_ANDROID_PKGS + _ADB_PKG,
    params=_IFACE_PARAM,
    build_configure=lambda p: render_shell(_build_tether_android_adb_ops(p)),
    build_configure_ops=_build_tether_android_adb_ops,
    test_status="tested",
    tested_notes="GL.iNet MT3000",
    requires_capabilities=["usb"],
))

register(UseCase(
    name="tether-ios",
    description="USB WAN from iPhone. Enable Personal Hotspot manually on the phone.",
    packages=_IOS_PKGS,
    params=_IFACE_PARAM,
    build_configure=lambda p: render_shell(_build_tether_ios_ops(p)),
    build_configure_ops=_build_tether_ios_ops,
    test_status="experimental",
    tested_notes="wiki-based; needs hardware validation",
    requires_capabilities=["usb"],
))
