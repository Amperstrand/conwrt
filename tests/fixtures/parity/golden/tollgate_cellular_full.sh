# --- cellular: WAN (wan) = modem ECM interface (dhcp from modem) ---
uci -q revert network.wan || true
uci -q revert network.lan || true
uci set network.wan.proto='dhcp'
uci set network.wan.device='usb0'
uci set network.wan.metric='5'
# --- cellular: keep a mgmt door on the wired side ---
uci set network.lan.ipaddr='192.168.77.1'
uci commit network
G1="$(uci -q get network.wan.proto)"; G2="$(uci -q get network.wan.device)"; [ "$G1" = dhcp ] && [ "$G2" = usb0 ] || { echo "cellular: readback FAILED (proto=$G1 device=$G2)"; exit 1; }
G3="$(uci -q get network.lan.ipaddr)"; [ "$G3" = 192.168.77.1 ] || { echo "cellular: lan readback FAILED ($G3)"; exit 1; }

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
  if [ -n "1" ]; then at "AT+QUIMSLOT=1" || { logger -t cellular-setup "slot set failed"; FAIL=1; }; fi
  # APN on cid 1 (matches the modem auto-dial in ECM mode).
  at '\''AT+CGDCONT=1,"IPV4V6","bench.apn"'\'' || { logger -t cellular-setup "apn set failed"; FAIL=1; }
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

# --- cellular: SIM identity + balance tooling ---
mkdir -p /etc/tollgate && printf '%s' '{"provider":"TestTel","iccid":"89470000001234567890","eid":"89049032000001000000000000000000","balance_api":"https://api.testtel.example/balance/{{iccid}}","modem_if":"usb0"}' > /etc/tollgate/sim.json
printf '%s' '#!/bin/sh
# Three meters in one command: provider API (delayed), modem counters
# (since-boot truth), NDS per-client view. See sim.json for credentials.
CONF=/etc/tollgate/sim.json
ICCID=$(jq -r .iccid $CONF 2>/dev/null) || { echo "no sim.json"; exit 1; }
API=$(jq -r .balance_api $CONF | sed "s/{{iccid}}/$ICCID/")
IFACE=$(jq -r .modem_if $CONF)
echo "=== provider ($(jq -r .provider $CONF); usage is DELAYED ~1-3min) ==="
uclient-fetch -q -T 15 -O- "$API" 2>/dev/null | jq '\''.data.usageSummary // .data'\'' | head -8
echo "=== modem aggregate ($IFACE, since-boot) ==="
awk -v i="$IFACE" '\''$1 ~ i":" {print "rx_bytes="$2" tx_bytes="$10}'\'' /proc/net/dev
echo "=== NDS clients (live gate view) ==="
ndsctl json 2>/dev/null | jq '\''[.clients[]? | {mac, ip, state, downloaded, uploaded}]'\'' | head -20
' > /usr/bin/sim-balance && chmod +x /usr/bin/sim-balance

# --- cellular: hotplug re-up (usb0 ifup -> wan) ---
mkdir -p /etc/hotplug.d/iface && printf '%s' '#!/bin/sh
[ "$ACTION" = ifup ] || exit 0
[ "$INTERFACE" = "usb0" ] || exit 0
ifup wan 2>/dev/null
' > /etc/hotplug.d/iface/96-cellular-up && chmod +x /etc/hotplug.d/iface/96-cellular-up
/etc/init.d/network reload