"""TollGate cellular upstream — NR7101-class 5G modem as the paid uplink.

Pairs with the 'tollgate' preset (enable both). Brings the Quectel
RG502Q-EA-class modem up as an ECM (cdc_ether) WAN, switches the active
SIM slot, sets the APN, and stages the balance/usage tooling. All
procedures and timings were validated end-to-end on a bench NR7101
(2026-10-24; see conwrt-bench sessions/2026-10-23-nr7101-a6e4-sim-bringup).

Why ECM and not QMI: the stock qmi_wwan/uqmi path hangs against this
modem family on 25.x ("SIM in illegal state" = uqmi lockup class) and
lacks QMAP aggregation (USB bus crashes at speed on MT7621). ECM moves
session management into the modem firmware — one ifup brings the link
up. Ceiling ~240 Mbps on 5G modules; far above roaming-LTE reality.
"""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciSet, UciCommit, render_shell

from . import ParamDef, UseCase, register

_MODEM_SETUP = r"""\
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
         ( stty -F $ATPORT 115200 raw -echo min 0 time 5 2>/dev/null;
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
"""

_SIM_BALANCE = """\
#!/bin/sh
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
"""


_HOTPLUG = """\
#!/bin/sh
[ "$ACTION" = ifup ] || exit 0
[ "$INTERFACE" = "{USBIFACE}" ] || exit 0
ifup {WANIFACE} 2>/dev/null
"""


def _build_ops(params: dict[str, Any]) -> list[Op]:
    apn = str(params.get("apn", ""))
    sim_slot = str(params.get("sim_slot", ""))
    wan_iface = str(params.get("wan_iface", "wan"))
    usb_iface = str(params.get("usb_iface", "usb0"))
    iccid = str(params.get("iccid", ""))
    provider = str(params.get("provider", ""))
    eid = str(params.get("eid", ""))
    balance_api = str(params.get("balance_api", ""))
    setup_mgmt_ip = str(params.get("management_ip", ""))

    ops: list[Op] = []

    ops.append(Comment(text=f"--- cellular: WAN ({wan_iface}) = modem ECM interface (dhcp from modem) ---"))
    # Section-scoped staging revert first (bench canon: never commit debris
    # from aborted sessions; surgical scope avoids touching other presets'
    # network staging in the same rendered script).
    ops.append(ShellCommand(command=f"uci -q revert network.{wan_iface} || true"))
    if setup_mgmt_ip:
        ops.append(ShellCommand(command="uci -q revert network.lan || true"))
    ops.append(UciSet(config="network", section=wan_iface, values={
        "proto": "dhcp",
        "device": usb_iface,
        "metric": "5",
    }))
    if setup_mgmt_ip:
        ops.append(Comment(text="--- cellular: keep a mgmt door on the wired side ---"))
        ops.append(UciSet(config="network", section="lan", values={
            "ipaddr": setup_mgmt_ip,
        }))
    ops.append(UciCommit(config="network"))
    # Value readbacks (bench canon: gate on readback, never on set-shape).
    ops.append(ShellCommand(
        command=f'G1="$(uci -q get network.{wan_iface}.proto)"; G2="$(uci -q get network.{wan_iface}.device)"; '
                f'[ "$G1" = dhcp ] && [ "$G2" = {usb_iface} ] '
                f'|| {{ echo "cellular: readback FAILED (proto=$G1 device=$G2)"; exit 1; }}'
    ))
    if setup_mgmt_ip:
        ops.append(ShellCommand(
            command=f'G3="$(uci -q get network.lan.ipaddr)"; [ "$G3" = {setup_mgmt_ip} ] '
                    f'|| {{ echo "cellular: lan readback FAILED ($G3)"; exit 1; }}'
        ))

    ops.append(BlankLine())
    ops.append(Comment(text="--- cellular: modem one-shot (ECM + slot + APN; detached, idempotent) ---"))
    setup = (_MODEM_SETUP
             .replace("{SIMSLOT}", sim_slot)
             .replace("{APN}", apn)
             .replace("{WANIFACE}", wan_iface))
    escaped = setup.replace("'", "'\\''")
    ops.append(ShellCommand(
        command=f"mkdir -p /usr/bin && printf '%s' '{escaped}' > /usr/bin/cellular-setup "
                f"&& chmod +x /usr/bin/cellular-setup "
                f"&& ( /usr/bin/cellular-setup || true )"
    ))

    if iccid:
        ops.append(BlankLine())
        ops.append(Comment(text="--- cellular: SIM identity + balance tooling ---"))
        sim_json = (
            '{"provider":"' + provider + '","iccid":"' + iccid + '","eid":"' + eid + '",'
            '"balance_api":"' + balance_api + '","modem_if":"' + usb_iface + '"}'
        )
        ops.append(ShellCommand(
            command=f"mkdir -p /etc/tollgate && printf '%s' '{sim_json}' > /etc/tollgate/sim.json"
        ))
        bal = _SIM_BALANCE.replace("'", "'\\''")
        ops.append(ShellCommand(
            command=f"printf '%s' '{bal}' > /usr/bin/sim-balance && chmod +x /usr/bin/sim-balance"
        ))

    ops.append(BlankLine())
    ops.append(Comment(text=f"--- cellular: hotplug re-up ({usb_iface} ifup -> {wan_iface}) ---"))
    hotplug = _HOTPLUG.replace("{USBIFACE}", usb_iface).replace("{WANIFACE}", wan_iface)
    hp_escaped = hotplug.replace("'", "'\\''")
    ops.append(ShellCommand(
        command=f"mkdir -p /etc/hotplug.d/iface && printf '%s' '{hp_escaped}' "
                f"> /etc/hotplug.d/iface/96-cellular-up && chmod +x /etc/hotplug.d/iface/96-cellular-up"
    ))
    ops.append(ServiceAction(name="network", action="reload"))

    return ops


register(UseCase(
    name="tollgate-cellular",
    description=(
        "Cellular upstream for the TollGate: brings the Quectel "
        "RG502Q-EA-class 5G modem up as an ECM WAN (auto-dial inside the "
        "modem), switches the active SIM slot, sets the APN, and stages "
        "sim.json + sim-balance (provider usage API + modem counters + NDS "
        "clients in one command). Pairs with the 'tollgate' preset — enable "
        "both. ECM chosen over QMI from bench evidence: stock uqmi hangs "
        "against this modem family and lacks QMAP aggregation."
    ),
    packages=[
        "kmod-usb-net-cdc-ether",  # the ECM kmod — NOT in stock NR7101 images
    ],
    params={
        "apn": ParamDef(type=str, default="",
            description="APN for cid 1 (e.g. 'data.esim'). Written via AT+CGDCONT before the ECM auto-dial."),
        "sim_slot": ParamDef(type=str, default="",
            description="Active SIM slot ('1' or '2') for dual-slot modems. Persists in modem NVM (AT+QUIMSLOT)."),
        "wan_iface": ParamDef(type=str, default="wan",
            description="Name of the OpenWrt WAN interface to re-point at the modem."),
        "usb_iface": ParamDef(type=str, default="usb0",
            description="ECM netdev name (cdc_ether default: usb0)."),
        "iccid": ParamDef(type=str, default="",
            description="ICCID of the SIM profile (staged to /etc/tollgate/sim.json for balance tooling)."),
        "provider": ParamDef(type=str, default="",
            description="Provider name for sim.json (e.g. 'nadanada')."),
        "eid": ParamDef(type=str, default="",
            description="EID of the eUICC, if the card is an eSIM (staged to sim.json)."),
        "balance_api": ParamDef(type=str, default="",
            description="Balance/usage API URL template with {{iccid}} placeholder (e.g. provider esim API)."),
        "management_ip": ParamDef(type=str, default="",
            description="Optional static br-lan IP to keep a wired management door alongside the modem WAN."),
    },
    build_configure=lambda p: render_shell(_build_ops(p)),
    build_configure_ops=_build_ops,
    test_status="tested",
    tested_notes="provision end-to-end on bench NR7101 2026-10-24 (ECM+slot+APN+tooling); see conwrt-bench sessions/2026-10-23-nr7101-a6e4-sim-bringup",
    configure_via="ssh",
    post_install_notes=(
        "kmod-usb-net-cdc-ether MUST be in the image (this preset adds it). "
        "If the modem was in QMI mode, the one-shot script switches it to "
        "ECM (~40s USB re-enumeration after first boot). Registration on "
        "roaming profiles takes up to ~135s — do not gate on the first "
        "minutes. sim-balance output: provider API is eventually-consistent "
        "(1-3 min lag), modem counters are since-boot truth."
    ),
))
