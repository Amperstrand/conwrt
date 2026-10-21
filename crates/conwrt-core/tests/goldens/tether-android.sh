# golden: conwrt 1.x output of scripts/use_cases/<plugin>.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- Android USB tethering (manual) ---
USB_DEV=""
for _ in $(seq 1 45); do
for dev in /sys/class/net/*; do
name=$(basename "$dev")
case "$name" in
lo|br-lan|eth0|wlan*) continue ;;
esac
driver=$(readlink "$dev/device/driver" 2>/dev/null || true)
if echo "$driver" | grep -qi "rndis\|cdc_ether\|cdc_ncm\|usbnet"; then
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