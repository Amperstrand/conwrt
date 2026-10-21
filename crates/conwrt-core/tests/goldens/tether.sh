# golden: conwrt 1.x output of scripts/use_cases/<plugin>.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- USB tethering (auto-detect) ---
/usr/sbin/usbmuxd -v -U -f >/dev/null 2>&1 &
USB_DEV=""
for _ in $(seq 1 45); do
for dev in /sys/class/net/*; do
name=$(basename "$dev")
case "$name" in
lo|br-lan|eth0|wlan*) continue ;;
esac
driver=$(readlink "$dev/device/driver" 2>/dev/null || true)
if echo "$driver" | grep -qi "rndis\|cdc_ether\|cdc_ncm\|usbnet\|ipheth"; then
USB_DEV="$name"
break 2
fi
iface_desc=""
[ -e "$dev/device/interface" ] && iface_desc=$(cat "$dev/device/interface" 2>/dev/null || true)
if echo "$iface_desc" | grep -qi "apple\|iphone"; then
USB_DEV="$name"
break 2
fi
done
sleep 1
done
if [ -z "$USB_DEV" ]; then
for cand in usb0 usb1; do
[ -e "/sys/class/net/$cand" ] && USB_DEV="$cand" && break
done
fi
if [ -n "$USB_DEV" ]; then
uci set network.usbwan=interface
uci set network.usbwan.proto='dhcp'
uci set network.usbwan.device="$USB_DEV"
uci set network.usbwan.metric='20'
for _z in $(uci show firewall 2>/dev/null | grep '=zone' | cut -d. -f2 | cut -d= -f1 || true); do if [ "$(uci -q get firewall."$_z".name)" = 'wan' ]; then uci -q del_list firewall."$_z".network='usbwan' 2>/dev/null; uci add_list firewall."$_z".network='usbwan'; else uci -q del_list firewall."$_z".network='usbwan' 2>/dev/null; fi; done; true
uci commit network
uci commit firewall
ifup usbwan 2>/dev/null || true
echo "USB tethering enabled on $USB_DEV -> usbwan"
else
echo "USB tethering: no USB network device found, skipping" >&2
fi
\
mkdir -p /etc/hotplug.d/usb
cat > /etc/hotplug.d/usb/99-usb-tether-adb << 'HOTPLUG_EOF'
[ "$ACTION" = "bind" ] || exit 0
[ "$PRODUCT" ] || exit 0
(
HOME=/root
export HOME
command -v adb >/dev/null 2>&1 || exit 0
DELAY=1
attempt=0
while [ $attempt -lt 7 ]; do
attempt=$((attempt + 1))
sleep $DELAY
if ip addr show usb0 2>/dev/null | grep -q "inet "; then
exit 0
fi
STATE=$(adb get-state 2>/dev/null)
if [ "$STATE" = "device" ]; then
adb shell svc usb setFunctions rndis 2>/dev/null
sleep 3
if ip addr show usb0 2>/dev/null | grep -q "inet "; then
logger -t usb-tether "ADB svc enabled tethering (attempt $attempt)"
exit 0
fi
adb shell input keyevent KEYCODE_WAKEUP 2>/dev/null
sleep 1
adb shell am start -a android.settings.TETHER_SETTINGS 2>/dev/null
sleep 3
adb shell uiautomator dump /sdcard/ui.xml 2>/dev/null
UI=$(adb shell cat /sdcard/ui.xml 2>/dev/null)
USB_ROW=$(echo "$UI" | grep -oE 'USB.tethering[^>]*bounds="\[[0-9]+,[0-9]+' | grep -oE '[0-9]+,[0-9]+' | head -1)
USB_Y=$(echo "$USB_ROW" | cut -d, -f2)
if [ -n "$USB_Y" ]; then
USB_Y_CENTER=$((USB_Y + 28))
SWITCH=$(echo "$UI" | grep -oE "Switch[^>]*bounds=\"\[[0-9]+,${USB_Y_CENTER}" | grep -oE '\[[0-9]+,' | grep -oE '[0-9]+' | head -1)
if [ -n "$SWITCH" ]; then
SWITCH_CENTER=$((SWITCH + 65))
adb shell input tap $SWITCH_CENTER $USB_Y_CENTER 2>/dev/null
sleep 3
if ip addr show usb0 2>/dev/null | grep -q "inet "; then
logger -t usb-tether "ADB UI toggle enabled tethering (attempt $attempt)"
exit 0
fi
fi
fi
fi
DELAY=$((DELAY * 2))
done
logger -t usb-tether "ADB tethering gave up after $attempt attempts"
) &
HOTPLUG_EOF