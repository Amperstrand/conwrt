//! Verbatim 1.x script bodies for `tollgate-cellular`
//! (extracted byte-exact from scripts/use_cases/tollgate_cellular.py —
//! regenerate rather than hand-edit; sentinels {SIMSLOT}/{APN}/
//! {WANIFACE}/{USBIFACE} are substituted in plan_tollgate_cellular).

/// One-shot idempotent modem bring-up (AT-port probing, ECM, slot, APN,
/// CFUN reset; marker only on full success). RAW string: the `\r` in AT
/// commands is a literal backslash-r, exactly as 1.x's r-string.
pub(super) const MODEM_SETUP_SH: &str = r#"#!/bin/sh
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
      printf 'AT\r' > "$p"
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
         printf '%s\r' "$1" > $ATPORT; sleep 4; kill $c 2>/dev/null; wait $c 2>/dev/null;
         grep -qE '^\+|^OK' $f 2>/dev/null; rc=$?; rm -f $f; return $rc; }
  FAIL=0
  # ECM mode: auto-dial + DHCP inside the modem; persists in modem NVM.
  at 'AT+QCFG="usbnet",1' || { logger -t cellular-setup "usbnet set failed"; FAIL=1; }
  # SIM slot: dual-slot modems must point at the card with the profile.
  if [ -n "{SIMSLOT}" ]; then at "AT+QUIMSLOT={SIMSLOT}" || { logger -t cellular-setup "slot set failed"; FAIL=1; }; fi
  # APN on cid 1 (matches the modem auto-dial in ECM mode).
  at 'AT+CGDCONT=1,"IPV4V6","{APN}"' || { logger -t cellular-setup "apn set failed"; FAIL=1; }
  # Reset applies mode+slot; USB re-enumerates (~40s); registration <=135s.
  at 'AT+CFUN=1,1' || { logger -t cellular-setup "cfun reset failed"; FAIL=1; }
  sleep 45
  ifup {WANIFACE} 2>/dev/null
  # Marker only on full success — a failed setup must retry on next boot.
  if [ "$FAIL" = 0 ]; then
    touch "$MARKER"
    logger -t cellular-setup "modem setup complete (at=$ATPORT)"
  else
    logger -t cellular-setup "modem setup FAILED — will retry on next boot"
  fi
) &
exit 0
"#;

/// Three meters in one command (provider API / modem counters / NDS view).
pub(super) const SIM_BALANCE_SH: &str = r#"#!/bin/sh
# Three meters in one command: provider API (delayed), modem counters
# (since-boot truth), NDS per-client view. See sim.json for credentials.
CONF=/etc/tollgate/sim.json
ICCID=$(jq -r .iccid $CONF 2>/dev/null) || { echo "no sim.json"; exit 1; }
API=$(jq -r .balance_api $CONF | sed "s/{{iccid}}/$ICCID/")
IFACE=$(jq -r .modem_if $CONF)
echo "=== provider ($(jq -r .provider $CONF); usage is DELAYED ~1-3min) ==="
uclient-fetch -q -T 15 -O- "$API" 2>/dev/null | jq '.data.usageSummary // .data' | head -8
echo "=== modem aggregate ($IFACE, since-boot) ==="
awk -v i="$IFACE" '$1 ~ i":" {print "rx_bytes="$2" tx_bytes="$10}' /proc/net/dev
echo "=== NDS clients (live gate view) ==="
ndsctl json 2>/dev/null | jq '[.clients[]? | {mac, ip, state, downloaded, uploaded}]' | head -20
"#;

/// Hotplug re-up: usb iface ifup -> wan iface ifup.
pub(super) const HOTPLUG_SH: &str = r#"#!/bin/sh
[ "$ACTION" = ifup ] || exit 0
[ "$INTERFACE" = "{USBIFACE}" ] || exit 0
ifup {WANIFACE} 2>/dev/null
"#;
