# --- cellular: WAN (wan) = modem ECM interface (dhcp from modem) ---
uci -q revert network.wan || true
uci set network.wan.proto='dhcp'
uci set network.wan.device='usb0'
uci set network.wan.metric='5'
uci commit network
G1="$(uci -q get network.wan.proto)"; G2="$(uci -q get network.wan.device)"; [ "$G1" = dhcp ] && [ "$G2" = usb0 ] || { echo "cellular: readback FAILED (proto=$G1 device=$G2)"; exit 1; }

# --- cellular: modem one-shot (ECM + slot + APN; detached, idempotent) ---
mkdir -p /usr/bin && printf '%s' '\
#!/bin/sh
# Cellular modem bring-up (one-shot, idempotent). Validated 2026-10-24.
# Timings: USB enum ~35-50s after CFUN; roaming registration up to ~135s.
# NEVER substitute uqmi status calls — the uqmi hang class hangs SSH
# sessions against this modem family; the AT port is the truth.
MARKER=/etc/cellular-modem.done
[ -f "$MARKER" ] && exit 0
(
  N=0
  while [ $N -lt 30 ]; do
    for p in /dev/ttyUSB0 /dev/ttyUSB1 /dev/ttyUSB2 /dev/ttyUSB3; do
      [ -c "$p" ] || continue
      f=/tmp/atdet.$$
      cat "$p" > "$f" &
      cp=$!
      sleep 1
      printf '\''AT\r'\'' > "$p"
      sleep 2
      kill $cp 2>/dev/null
      grep -q OK "$f" 2>/dev/null && { ATPORT=$p; rm -f "$f"; break; }
      rm -f "$f"
    done
    [ -n "${ATPORT:-}" ] && break
    N=$((N+1)); sleep 5
  done
  [ -z "${ATPORT:-}" ] && { logger -t cellular-setup "no AT port"; exit 1; }
  at() { f=/tmp/atcmd.$$;
         # watchdog-bounded read (L20/L21): never leak a reader, never block forever
         ( stty -F $ATPORT 115200 raw -echo min 1 time 5 2>/dev/null;
           dd bs=1 count=400 <$ATPORT >$f 2>/dev/null ) & c=$!; sleep 1;
         printf '\''%s\r'\'' "$1" > $ATPORT; sleep 4; kill $c 2>/dev/null; wait $c 2>/dev/null;
         grep -qE '\''^\+|^OK'\'' $f 2>/dev/null; rc=$?; rm -f $f; return $rc; }
  FAIL=0
  # ECM mode: auto-dial + DHCP inside the modem; persists in modem NVM.
  at '\''AT+QCFG="usbnet",1'\'' || { logger -t cellular-setup "usbnet set failed"; FAIL=1; }
  # SIM slot: dual-slot modems must point at the card with the profile.
  if [ -n "" ]; then at "AT+QUIMSLOT=" || { logger -t cellular-setup "slot set failed"; FAIL=1; }; fi
  # APN on cid 1 (matches the modem auto-dial in ECM mode).
  at '\''AT+CGDCONT=1,"IPV4V6","data.only"'\'' || { logger -t cellular-setup "apn set failed"; FAIL=1; }
  # Reset applies mode+slot; USB re-enumerates (~40s); registration <=135s.
  at '\''AT+CFUN=1,1'\'' || { logger -t cellular-setup "cfun reset failed"; FAIL=1; }
  sleep 45
  ifup wan 2>/dev/null
  # Marker only on full success — a failed setup must retry on next boot.
  if [ "$FAIL" = 0 ]; then
    touch "$MARKER"
    logger -t cellular-setup "modem setup complete (at=$ATPORT)"
  else
    logger -t cellular-setup "modem setup FAILED — will retry on next boot"
  fi
) &
exit 0
' > /usr/bin/cellular-setup && chmod +x /usr/bin/cellular-setup && ( /usr/bin/cellular-setup || true )

# --- cellular: hotplug re-up (usb0 ifup -> wan) ---
mkdir -p /etc/hotplug.d/iface && printf '%s' '#!/bin/sh
[ "$ACTION" = ifup ] || exit 0
[ "$INTERFACE" = "usb0" ] || exit 0
ifup wan 2>/dev/null
' > /etc/hotplug.d/iface/96-cellular-up && chmod +x /etc/hotplug.d/iface/96-cellular-up
/etc/init.d/network reload