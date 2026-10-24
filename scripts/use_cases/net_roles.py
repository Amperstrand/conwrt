"""net-roles — interface role assignment for constrained single-port/single-radio devices.

Assigns the three roles a TollGate-style device needs — internet uplink
(ordered, metric-based failover), serving LAN, and management access — on
hardware like the Zyxel NR7101 (1x GigE PoE + 1x 2.4GHz radio + 5G modem).

Uplink ordering renders as netifd interface metrics (5, 100, 200, ...):
passive failover for new flows, zero extra packages. Stack the `mwan3` preset
for health-checked per-flow failover (mwan3 requires unique interface metrics
anyway — this preset provides them).

Role conflicts are validated at build time, not on the device:
- untagged ethernet uplink consumes the only port -> requires
  serve_ethernet=false
- a VLAN-tagged ethernet uplink shares the port with the serving LAN
  (upstream switch must trunk the tag and supply PoE)
- wifi uplink takes the single radio -> serving APs on that radio are
  disabled (concurrent STA+AP is channel-locked and unreliable on mt76)
- optional mgmt VLAN (eth0.N static) keeps an SSH door when the untagged
  side is gated or repurposed

Composability: `sim` uplink entries only assign the metric — the interface
itself is owned by the `tollgate-cellular` preset. Enable `net-roles` AFTER
`tollgate-cellular` so the metric pass runs last (apply order follows the
enabled list).
"""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell
from shell_safe import interface_name

from . import ParamDef, UseCase, register

_UPLINK_TYPES = ("sim", "wifi", "ethernet")
_METRICS = (5, 100, 200, 300, 400)
_DEFAULT_IFACES = {"sim": "wan", "wifi": "wwan", "ethernet": "waneth"}
_WIFI_ENCRYPTIONS = ("none", "psk2", "sae", "sae-mixed")
_PRICE_PARAM_BY_TYPE = {"sim": "price_sim_sats_per_mib", "wifi": "price_wifi_sats_per_mib",
                        "ethernet": "price_eth_sats_per_mib"}

# tollgate-mode daemon. Paths are env-overridable purely for host-side
# behavioral testing; on-device the defaults apply.
_MODE_DAEMON = r"""#!/bin/sh
# Watches the configured uplinks; when the active (lowest-metric live)
# uplink changes, rewrites tollgate pricing for it. The WPS button
# rotates a manual override (auto -> uplink1 -> uplink2 -> ... -> auto).
# Network failover itself is netifd metrics — this adapts the TOLLGATE
# to whichever uplink is winning, e.g. cheap/free eth primary with the
# metered SIM priced higher once it takes over.
CONF=${TOLLGATE_MODE_CONF:-/etc/tollgate/mode.conf}
OVR=${TOLLGATE_MODE_OVERRIDE:-/etc/tollgate/mode.override}
STATE=${TOLLGATE_MODE_STATE:-/tmp/tollgate-mode.state}
TGJSON=${TOLLGATE_MODE_JSON:-/etc/tollgate/config.json}
log() { ${TOLLGATE_MODE_LOGGER:-logger} -t tollgate-mode "$@"; }

apply_price() {
    [ "$1" = "-" ] && return 0
    [ -f "$TGJSON" ] || return 0
    CUR=$(sed -n 's/.*"price_per_step":[ ]*\([0-9][0-9]*\).*/\1/p' "$TGJSON" | head -1)
    [ "$CUR" = "$1" ] && return 0
    SS=$(sed -n 's/.*"step_size":[ ]*\([0-9][0-9]*\).*/\1/p' "$TGJSON" | head -1)
    [ -n "$SS" ] || SS=1048576
    P=$(( ( $1 * SS + 1048575 ) / 1048576 ))
    sed -i "s/\"price_per_step\":[ ]*[0-9]*/\"price_per_step\": $P/g" "$TGJSON" \
        && { /etc/init.d/tollgate-wrt restart >/dev/null 2>&1 || true; } \
        && log "price -> $1 sat/MiB (step_size $SS -> $P)" \
        || log "price patch FAILED"
}

iface_up() {
    ubus call network.interface."$1" status 2>/dev/null | grep -q '"up":[ ]*true'
}

pick_active() {
    OVRN=$(cat "$OVR" 2>/dev/null)
    if [ -n "$OVRN" ] && [ "$OVRN" != "auto" ]; then
        iface_up "$OVRN" && { echo "$OVRN"; return 0; }
        log "override $OVRN is down — falling back to auto"
    fi
    sort -k2 -n "$CONF" | while read IF M PR; do
        iface_up "$IF" && { echo "$IF"; return 0; }
    done
}

evaluate() {
    LAST=$(cat "$STATE" 2>/dev/null)
    A=$(pick_active)
    [ -n "$A" ] || { log "no live uplink — holding last state"; return 0; }
    [ "$A" = "$LAST" ] && return 0
    echo "$A" > "$STATE"
    PR=$(awk -v i="$A" '$1 == i {print $3}' "$CONF")
    [ -n "$PR" ] || PR=-
    apply_price "$PR"
    log "active uplink: $A (price $PR)"
}

rotate_button() {
    CUR=$(cat "$OVR" 2>/dev/null)
    [ -n "$CUR" ] || CUR=auto
    N=auto
    PREV=""
    for i in auto $(awk '{printf "%s ", $1}' "$CONF"); do
        if [ -n "$PREV" ] && [ "$PREV" = "$CUR" ]; then N=$i; break; fi
        PREV=$i
    done
    echo "$N" > "$OVR"
    log "button: override -> $N"
    evaluate
}

case "$1" in
    --button) rotate_button ;;
    --watch)
        while true; do
            evaluate
            sleep ${TOLLGATE_MODE_INTERVAL:-10}
        done
        ;;
    *) evaluate ;;
esac
"""

_MODE_INIT = """\
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/tollgate-mode --watch
    procd_set_param env TOLLGATE_MODE_INTERVAL=__INTERVAL__
    procd_set_param respawn 3600 5 0
    procd_close_instance
}
"""

_MODE_HOTPLUG = """\
#!/bin/sh
[ "$ACTION" = "ifup" ] || [ "$ACTION" = "ifdown" ] || exit 0
/usr/bin/tollgate-mode >/dev/null 2>&1 &
"""

_MODE_BUTTON = """\
#!/bin/sh
[ "$BUTTON" = "wps" ] || exit 0
/usr/bin/tollgate-mode --button >/dev/null 2>&1 &
exit 0
"""


def _stage_file_ops(ops: list[Op], path: str, content: str, mode: str) -> None:
    escaped = content.replace("'", "'\\''")
    ops.append(ShellCommand(
        command=f"mkdir -p \"$(dirname {path})\" && printf '%s' '{escaped}' > {path} && chmod {mode} {path}"
    ))


def _resolve_uplinks(raw: list[Any]) -> list[dict[str, Any]]:
    if not raw:
        return []
    if len(raw) > len(_METRICS):
        raise ValueError(f"net-roles: at most {len(_METRICS)} uplinks supported")
    seen_ifaces: set[str] = set()
    seen_radios: set[str] = set()
    uplinks: list[dict[str, Any]] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"net-roles: uplinks[{i}] must be a table")
        u = dict(entry)
        u["type"] = str(u.get("type", ""))
        if u["type"] not in _UPLINK_TYPES:
            raise ValueError(f"net-roles: uplinks[{i}].type must be one of {', '.join(_UPLINK_TYPES)}")
        u["iface"] = interface_name(str(u.get("iface") or _DEFAULT_IFACES[u["type"]]), f"uplinks[{i}] interface")
        if u["iface"] in seen_ifaces:
            raise ValueError(f"net-roles: duplicate interface '{u['iface']}' in uplinks")
        seen_ifaces.add(u["iface"])
        u["metric"] = _METRICS[i]
        if u["type"] == "wifi":
            u["ssid"] = str(u.get("ssid", ""))
            if not u["ssid"]:
                raise ValueError(f"net-roles: uplinks[{i}] wifi requires ssid")
            u["key"] = str(u.get("key", ""))
            u["encryption"] = str(u.get("encryption", "psk2"))
            if u["encryption"] not in _WIFI_ENCRYPTIONS:
                raise ValueError(f"net-roles: uplinks[{i}].encryption must be one of {', '.join(_WIFI_ENCRYPTIONS)}")
            if u["encryption"] != "none" and not u["key"]:
                raise ValueError(f"net-roles: uplinks[{i}] encryption '{u['encryption']}' requires key")
            u["radio"] = str(u.get("radio", "radio0"))
            if u["radio"] in seen_radios:
                raise ValueError(f"net-roles: radio '{u['radio']}' used by two wifi uplinks (one STA per radio)")
            seen_radios.add(u["radio"])
        if u["type"] == "ethernet":
            vlan = u.get("vlan", 0)
            if vlan not in (0,) and not (isinstance(vlan, int) and 2 <= vlan <= 4094 and not isinstance(vlan, bool)):
                raise ValueError(f"net-roles: uplinks[{i}].vlan must be an int in 2..4094 or unset (untagged)")
            u["vlan"] = vlan
        uplinks.append(u)
    return uplinks


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    uplinks = _resolve_uplinks(list(params.get("uplinks") or []))
    serve_ethernet = bool(params.get("serve_ethernet", True))
    serve_wifi = bool(params.get("serve_wifi", True))
    mgmt_vlan = int(params.get("mgmt_vlan", 0))
    mgmt_ip = str(params.get("mgmt_ip", ""))
    mgmt_netmask = str(params.get("mgmt_netmask", "255.255.255.0"))

    untagged_eth = [u for u in uplinks if u["type"] == "ethernet" and not u["vlan"]]
    if untagged_eth and serve_ethernet:
        raise ValueError(
            "net-roles: untagged ethernet uplink consumes the only port — set serve_ethernet=false, "
            "or give the uplink a vlan (tagged) so eth0 can stay in the serving bridge"
        )
    if mgmt_vlan:
        if not (isinstance(mgmt_vlan, int) and 2 <= mgmt_vlan <= 4094):
            raise ValueError("net-roles: mgmt_vlan must be an int in 2..4094 (0 = off)")
        if not mgmt_ip:
            raise ValueError("net-roles: mgmt_vlan requires mgmt_ip")
        if any(u["type"] == "ethernet" and u["vlan"] == mgmt_vlan for u in uplinks):
            raise ValueError("net-roles: mgmt_vlan must differ from the ethernet uplink vlan")
    auto_switch = bool(params.get("auto_switch", False))
    switch_interval = int(params.get("switch_interval", 10))
    wifi_shared_radio = bool(params.get("wifi_shared_radio", False))
    prices = {
        t: int(params.get(_PRICE_PARAM_BY_TYPE[t], 0)) for t in _UPLINK_TYPES
    }
    if any(p < 0 for p in prices.values()):
        raise ValueError("net-roles: price params must be >= 0")
    if any(p > 0 for p in prices.values()) and not auto_switch:
        raise ValueError("net-roles: price params require auto_switch=true")
    if auto_switch and not uplinks:
        raise ValueError("net-roles: auto_switch requires at least one uplink")
    if wifi_shared_radio and not any(u["type"] == "wifi" for u in uplinks):
        raise ValueError("net-roles: wifi_shared_radio requires a wifi uplink")
    if not (5 <= switch_interval <= 120):
        raise ValueError("net-roles: switch_interval must be in 5..120 seconds")
    return {
        "uplinks": uplinks,
        "serve_ethernet": serve_ethernet,
        "serve_wifi": serve_wifi,
        "mgmt_vlan": mgmt_vlan,
        "mgmt_ip": mgmt_ip,
        "mgmt_netmask": mgmt_netmask,
        "auto_switch": auto_switch,
        "switch_interval": switch_interval,
        "wifi_shared_radio": wifi_shared_radio,
        "prices": prices,
    }


def _zone_add(iface: str, zone: str) -> str:
    return (
        f"for z in $(uci -q show firewall | sed -n 's/^firewall\\.\\([^.]*\\)=zone$/\\1/p'); do "
        f"if [ \"$(uci -q get firewall.$z.name)\" = \"{zone}\" ]; then "
        f"uci -q get firewall.$z.network 2>/dev/null | tr ' ' '\\n' | grep -qxF '{iface}' "
        f"|| uci add_list firewall.$z.network='{iface}'; fi; done"
    )


def _build_net_roles_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    uplinks = r["uplinks"]
    mgmt_vlan = r["mgmt_vlan"]
    uplink_summary = " ".join(f"{u['iface']}(m{u['metric']})" for u in uplinks) or "none"

    ops: list[Op] = []
    ops.append(Comment(text=(
        f"--- net-roles: uplinks={uplink_summary} "
        f"serve_eth={r['serve_ethernet']} serve_wifi={r['serve_wifi']} "
        f"mgmt_vlan={mgmt_vlan or 'off'} ---"
    )))

    for u in uplinks:
        if u["type"] != "ethernet":
            continue
        device = f"eth0.{u['vlan']}" if u["vlan"] else "eth0"
        if u["vlan"]:
            ops.append(Comment(text=f"--- net-roles: ethernet uplink {u['iface']} on tagged {device} ---"))
            ops.append(ShellCommand(command=f"uci set network.dev_{u['iface']}=device"))
            ops.append(UciSet(config="network", section=f"dev_{u['iface']}", values={
                "type": "8021q", "name": device, "ifname": "eth0", "vid": str(u["vlan"]),
            }))
        else:
            ops.append(Comment(text=f"--- net-roles: ethernet uplink {u['iface']} on the untagged port ---"))
        if not r["serve_ethernet"] and not u["vlan"]:
            ops.append(ShellCommand(command=(
                "for s in $(uci -q show network | sed -n 's/^network\\.\\([^.]*\\)=device$/\\1/p'); do "
                "[ \"$(uci -q get network.$s.name)\" = \"br-lan\" ] "
                "&& uci -q del_list network.$s.ports='eth0'; done; true"
            )))
        ops.append(ShellCommand(command=f"uci set network.{u['iface']}=interface"))
        ops.append(ShellCommand(command=f"uci -q revert network.{u['iface']} || true"))
        ops.append(UciSet(config="network", section=u["iface"], values={"proto": "dhcp", "device": device}))
        ops.append(ShellCommand(command=_zone_add(u["iface"], "wan")))

    for u in uplinks:
        if u["type"] != "wifi":
            continue
        ops.append(Comment(text=f"--- net-roles: wifi uplink {u['iface']} (STA on {u['radio']}) ---"))
        ops.append(ShellCommand(command=f"uci set network.{u['iface']}=interface"))
        ops.append(ShellCommand(command=f"uci -q revert network.{u['iface']} || true"))
        ops.append(UciSet(config="network", section=u["iface"], values={"proto": "dhcp"}))
        sta_values: dict[str, str] = {
            "device": u["radio"], "mode": "sta", "network": u["iface"],
            "ssid": u["ssid"], "encryption": u["encryption"],
        }
        if u["encryption"] != "none":
            sta_values["key"] = u["key"]
        ops.append(ShellCommand(command=f"uci set wireless.{u['iface']}sta=wifi-iface"))
        ops.append(ShellCommand(command=f"uci -q revert wireless.{u['iface']}sta || true"))
        ops.append(UciSet(config="wireless", section=f"{u['iface']}sta", values=sta_values))
        ops.append(UciSet(config="wireless", section=u["radio"], values={"disabled": "0"}))
        ops.append(ShellCommand(command=_zone_add(u["iface"], "wan")))
        if r["wifi_shared_radio"]:
            ops.append(Comment(text=(
                f"--- net-roles: wifi_shared_radio — APs on {u['radio']} stay up alongside the STA "
                "(same-channel locked, ~half throughput, AP follows STA association; travelmate-class caveat) ---"
            )))
        else:
            ops.append(ShellCommand(command=(
                f"for w in $(uci -q show wireless | sed -n 's/^wireless\\.\\([^.]*\\)=wifi-iface$/\\1/p'); do "
                f"[ \"$(uci -q get wireless.$w.device)\" = \"{u['radio']}\" ] "
                f"&& [ \"$w\" != \"{u['iface']}sta\" ] && uci set wireless.$w.disabled=1; done; true"
            )))

    if not r["serve_wifi"]:
        ops.append(Comment(text="--- net-roles: serving disabled — take all AP vifs off the air ---"))
        ops.append(ShellCommand(command=(
            "for w in $(uci -q show wireless | sed -n 's/^wireless\\.\\([^.]*\\)=wifi-iface$/\\1/p'); do "
            "[ \"$(uci -q get wireless.$w.mode)\" = \"ap\" ] && uci set wireless.$w.disabled=1; done; true"
        )))

    untagged_eth_uplink = any(u["type"] == "ethernet" and not u["vlan"] for u in uplinks)
    if not r["serve_ethernet"] and not untagged_eth_uplink:
        ops.append(Comment(text="--- net-roles: serving disabled — eth0 leaves the serving bridge ---"))
        ops.append(ShellCommand(command=(
            "for s in $(uci -q show network | sed -n 's/^network\\.\\([^.]*\\)=device$/\\1/p'); do "
            "[ \"$(uci -q get network.$s.name)\" = \"br-lan\" ] "
            "&& uci -q del_list network.$s.ports='eth0'; done; true"
        )))

    if mgmt_vlan:
        ops.append(Comment(text=f"--- net-roles: mgmt door eth0.{mgmt_vlan} (static, lan zone) ---"))
        ops.append(ShellCommand(command="uci set network.mgmtdev=device"))
        ops.append(UciSet(config="network", section="mgmtdev", values={
            "type": "8021q", "name": f"eth0.{mgmt_vlan}", "ifname": "eth0", "vid": str(mgmt_vlan),
        }))
        ops.append(ShellCommand(command="uci set network.mgmt=interface"))
        ops.append(ShellCommand(command="uci -q revert network.mgmt || true"))
        ops.append(UciSet(config="network", section="mgmt", values={
            "proto": "static", "device": f"eth0.{mgmt_vlan}",
            "ipaddr": r["mgmt_ip"], "netmask": r["mgmt_netmask"],
        }))
        ops.append(ShellCommand(command=_zone_add("mgmt", "lan")))

    if uplinks:
        ops.append(Comment(text="--- net-roles: failover metrics (lower wins; sim section may be owned by tollgate-cellular) ---"))
        for u in uplinks:
            ops.append(UciSet(config="network", section=u["iface"], values={"metric": str(u["metric"])}))

    ops.append(Comment(text="--- net-roles: readbacks (gate the commits — staged values are visible to uci get) ---"))
    for u in uplinks:
        if u["type"] == "ethernet":
            device = f"eth0.{u['vlan']}" if u["vlan"] else "eth0"
            ops.append(ShellCommand(command=(
                f'[ "$(uci -q get network.{u["iface"]}.device)" = "{device}" ] '
                f'&& [ "$(uci -q get network.{u["iface"]}.proto)" = dhcp ] '
                f'|| {{ echo "net-roles: {u["iface"]} readback FAILED"; exit 1; }}'
            )))
        ops.append(ShellCommand(command=(
            f'[ "$(uci -q get network.{u["iface"]}.metric)" = "{u["metric"]}" ] '
            f'|| {{ echo "net-roles: {u["iface"]} metric readback FAILED"; exit 1; }}'
        )))
    if mgmt_vlan:
        ops.append(ShellCommand(command=(
            f'[ "$(uci -q get network.mgmt.ipaddr)" = "{r["mgmt_ip"]}" ] '
            f'|| {{ echo "net-roles: mgmt readback FAILED"; exit 1; }}'
        )))

    ops.append(UciCommit(config="network"))
    if any(u["type"] == "wifi" for u in uplinks) or not r["serve_wifi"]:
        ops.append(UciCommit(config="wireless"))
    ops.append(UciCommit(config="firewall"))

    ops.append(BlankLine())
    if any(u["type"] == "wifi" for u in uplinks):
        ops.append(ServiceAction(name="network", action="reload"))
        ops.append(ShellCommand(command="wifi reload 2>/dev/null; true"))
    else:
        ops.append(ServiceAction(name="network", action="reload"))
    ops.append(ShellCommand(command=(
        f'echo "net-roles applied: uplinks={len(uplinks)} '
        f'serve_eth={r["serve_ethernet"]} serve_wifi={r["serve_wifi"]} mgmt={mgmt_vlan or "lan"}"'
    )))

    if r["auto_switch"]:
        ops.append(BlankLine())
        ops.append(Comment(text="--- net-roles: tollgate-mode engine (active-uplink price switch + WPS button override) ---"))
        mode_conf_lines = []
        for u in uplinks:
            price = r["prices"][u["type"]]
            mode_conf_lines.append(f"{u['iface']} {u['metric']} {price if price > 0 else '-'}")
        mode_conf = "\n".join(mode_conf_lines) + "\n"
        _stage_file_ops(ops, "/etc/tollgate/mode.conf", mode_conf, "600")
        _stage_file_ops(ops, "/usr/bin/tollgate-mode", _MODE_DAEMON, "755")
        _stage_file_ops(ops, "/etc/init.d/tollgate-mode",
                        _MODE_INIT.replace("__INTERVAL__", str(r["switch_interval"])), "755")
        _stage_file_ops(ops, "/etc/hotplug.d/iface/90-tollgate-mode", _MODE_HOTPLUG, "755")
        _stage_file_ops(ops, "/etc/rc.button/wps", _MODE_BUTTON, "755")
        ops.append(ShellCommand(command="rm -f /etc/tollgate/mode.override /tmp/tollgate-mode.state"))
        ops.append(ServiceAction(name="tollgate-mode", action="enable"))
        ops.append(ServiceAction(name="tollgate-mode", action="restart"))
        ops.append(ShellCommand(command=(
            '[ -x /usr/bin/tollgate-mode ] && [ -f /etc/tollgate/mode.conf ] '
            '|| { echo "net-roles: tollgate-mode staging FAILED"; exit 1; }'
        )))
    return ops


register(UseCase(
    name="net-roles",
    description=(
        "Interface role assignment for constrained devices (NR7101 class): ordered "
        "uplinks (sim/wifi/ethernet) rendered as netifd metrics for passive failover, "
        "optional tagged-VLAN ethernet uplink or mgmt door on the single port, and "
        "single-radio STA/AP exclusivity. Stack mwan3 for health-checked failover. "
        "Enable AFTER tollgate-cellular (metric pass must run last)."
    ),
    packages=[],
    params={
        "uplinks": ParamDef(type=list, default=[],
            description=(
                "Ordered uplink tables: {type='sim'|'wifi'|'ethernet', iface='wan' (optional override), "
                "wifi: ssid/key/encryption/radio, ethernet: vlan (0/absent = untagged, consumes the port)}. "
                "Metrics auto-assigned 5,100,200,... sim entries only set the metric "
                "(interface owned by tollgate-cellular)."
            )),
        "serve_ethernet": ParamDef(type=bool, default=True,
            description="Keep eth0 in the serving bridge (must be false for an untagged ethernet uplink)"),
        "serve_wifi": ParamDef(type=bool, default=True,
            description="Keep serving APs (a wifi uplink disables other ifaces on its radio regardless — single radio)"),
        "mgmt_vlan": ParamDef(type=int, default=0, min_value=0, max_value=4094,
            description="VLAN id for a static mgmt door on eth0 (0 = off; requires mgmt_ip)"),
        "mgmt_ip": ParamDef(type=str, default="",
            description="Static IP for the mgmt VLAN interface (e.g. 192.168.50.1)"),
        "mgmt_netmask": ParamDef(type=str, default="255.255.255.0",
            description="Netmask for the mgmt VLAN interface"),
        "auto_switch": ParamDef(type=bool, default=False,
            description="Install the tollgate-mode engine: watches uplink liveness, rewrites tollgate "
                        "pricing when the active uplink changes, WPS button rotates a manual override"),
        "switch_interval": ParamDef(type=int, default=10, min_value=5, max_value=120,
            description="tollgate-mode watch loop interval in seconds (hotplug events react instantly)"),
        "price_sim_sats_per_mib": ParamDef(type=int, default=0, min_value=0,
            description="Price applied while the sim uplink is active (sats/MiB; 0 = leave unchanged)"),
        "price_wifi_sats_per_mib": ParamDef(type=int, default=0, min_value=0,
            description="Price applied while the wifi uplink is active (sats/MiB; 0 = leave unchanged)"),
        "price_eth_sats_per_mib": ParamDef(type=int, default=0, min_value=0,
            description="Price applied while the ethernet uplink is active (sats/MiB; 0 = leave unchanged)"),
        "wifi_shared_radio": ParamDef(type=bool, default=False,
            description="Keep serving APs up alongside the wifi STA on the same radio "
                        "(channel-locked to the STA's BSS, roughly half throughput, AP dies with the STA — "
                        "travelmate-class repeater caveat)"),
    },
    test_status="experimental",
    tested_notes="renders validated (multi-mode sh -n); hardware run pending next TollGate build",
    build_configure=lambda p: render_shell(_build_net_roles_ops(p)),
    build_configure_ops=_build_net_roles_ops,
))
