"""openvpn-pia — Private Internet Access (PIA) OpenVPN client for OpenWrt.

Provider: Private Internet Access.
Login method: **username (p-number) + password**, written to an OpenVPN
``auth-user-pass`` file. No OAuth/token exchange is required for the OpenVPN
protocol (PIA's token API is used for WireGuard / API access, not this path).

Tested approach (validated on hardware — GL.iNet GL-MT3000, OpenWrt 25.12.5):

* Endpoint pool + ``remote-random`` so a dead server does not stall reconnect.
* ``pull-filter ignore "route-ipv6"`` / ``"ifconfig-ipv6"`` — PIA pushes a
  ``route-ipv6 2000::/3`` onto a v4-only ``tun0`` which blackholes IPv6 and
  breaks IPv6-preferring apps (e.g. Signal).
* ``data-ciphers`` instead of the singular ``cipher`` (ignored by OpenVPN 2.7).
* **no ``persist-tun``** — a dead tunnel must tear down its routes instead of
  silently blackholing LAN traffic.
* IPv6 disabled at the kernel and on the LAN.
* DNS locked to PIA in-tunnel resolvers (``10.0.0.241/242/243``).
* A **functional** health probe + watchdog: restart → rotate endpoint → fail
  open during a validation window, then fail closed once stable.

Phased posture:
* ``validation`` (default): if the tunnel cannot recover within
  ``fail_open_timeout`` seconds, the WAN fallback + normal DNS are restored so
  the router is never stranded; the watchdog re-enforces once healthy again.
* ``enforced``: the WAN fallback is removed (strict kill switch); the watchdog
  only rotates/restarts and never falls back to the ISP.
"""
from __future__ import annotations

from typing import Any

from profile.ops import (
    BlankLine,
    Comment,
    ServiceAction,
    ShellCommand,
    UciAddList,
    UciCommit,
    UciSet,
    WriteFile,
    render_shell,
)
from profile.uci_helpers import uci_cleanup_sections
from shell_safe import validate_host, validate_port

from . import ParamDef, UseCase, register

# Validated US endpoint pool (PIA public server list, UDP 8080).
DEFAULT_REMOTES = ",".join(
    [
        "151.241.122.99:8080",   # US East (New Jersey)
        "37.19.197.168:8080",    # US East (New Jersey)
        "151.241.119.192:8080",  # US East (New Jersey)
        "37.19.220.37:8080",     # US Washington DC
        "181.41.206.48:8080",    # US Denver
        "102.129.153.205:8080",  # US Florida
        "145.79.182.176:8080",   # US Atlanta
        "193.56.117.160:8080",   # US Chicago
        "191.96.106.197:8080",   # US California
        "173.239.198.91:8080",   # US Seattle
    ]
)
DEFAULT_CA_URL = (
    "https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt"
)
DEFAULT_DNS = "10.0.0.241,10.0.0.242,10.0.0.243"

AUTH_FILE = "/etc/openvpn/pia-auth.txt"
OVPN_FILE = "/etc/openvpn/pia.ovpn"
CA_FILE = "/etc/openvpn/ca.rsa.4096.crt"
WATCHDOG_STATE = "/tmp/pia"


# -- On-device helper scripts (embedded verbatim; BusyBox-only) ----------------

PIA_HEALTH_SH = r"""#!/bin/sh
# PIA VPN functional health check. exit 0 = HEALTHY, 2 = DEGRADED, 1 = DOWN
IFACE=tun0
TARGET=1.1.1.1
PIA_DNS="10.0.0.241 10.0.0.242 10.0.0.243"
PROBE_HOST=privateinternetaccess.com

proc_ok=0
pgrep -f '/usr/sbin/openvpn' >/dev/null 2>&1 && proc_ok=1

route_line=$(ip route get "$TARGET" 2>/dev/null)
route_ok=0
echo "$route_line" | grep -q "dev $IFACE" && route_ok=1
gw=$(echo "$route_line" | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')

ping_ok=0
[ -n "$gw" ] && ping -c1 -W3 "$gw" >/dev/null 2>&1 && ping_ok=1

bounded_ns() {
	nslookup "$1" "$2" >/dev/null 2>&1 &
	_p=$!
	( sleep 4; kill -9 "$_p" 2>/dev/null ) >/dev/null 2>&1 &
	_k=$!
	wait "$_p" 2>/dev/null
	_rc=$?
	kill "$_k" 2>/dev/null
	return $_rc
}

dns_ok=0
for ns in $PIA_DNS; do
	if bounded_ns "$PROBE_HOST" "$ns"; then dns_ok=1; break; fi
done

if [ "$proc_ok" = 1 ] && [ "$route_ok" = 1 ] && { [ "$ping_ok" = 1 ] || [ "$dns_ok" = 1 ]; }; then
	echo "HEALTHY proc=$proc_ok route=$route_ok ping=$ping_ok dns=$dns_ok gw=${gw:-?}"
	exit 0
fi
if [ "$proc_ok" = 1 ] && [ "$route_ok" = 1 ]; then
	echo "DEGRADED proc=$proc_ok route=$route_ok ping=$ping_ok dns=$dns_ok gw=${gw:-?}"
	exit 2
fi
echo "DOWN proc=$proc_ok route=$route_ok ping=$ping_ok dns=$dns_ok"
exit 1
"""

PIA_FAILOPEN_SH = r"""#!/bin/sh
# Validation-phase fail-open: WAN fallback + normal DNS; OpenVPN keeps retrying.
mkdir -p __WATCHDOG_STATE__
uci -q set firewall.wan_fallback=forwarding
uci -q set firewall.wan_fallback.src=lan
uci -q set firewall.wan_fallback.dest=wan
uci -q set dhcp.@dnsmasq[0].noresolv=0
uci -q delete dhcp.@dnsmasq[0].server
uci -q commit firewall
uci -q commit dhcp
/etc/init.d/firewall reload 2>/dev/null
/etc/init.d/dnsmasq restart 2>/dev/null
date +%s > __WATCHDOG_STATE__/failopen
logger -t pia-watchdog "FAIL-OPEN: WAN fallback + normal DNS restored"
"""

PIA_ENFORCE_SH = r"""#!/bin/sh
# Re-enforce tunnel preference: DNS lock. Enforced phase also drops the WAN fallback.
mkdir -p __WATCHDOG_STATE__
uci -q set openvpn.pia.enabled=1
uci -q set dhcp.@dnsmasq[0].noresolv=1
uci -q delete dhcp.@dnsmasq[0].server
uci -q add_list dhcp.@dnsmasq[0].server=10.0.0.241
uci -q add_list dhcp.@dnsmasq[0].server=10.0.0.242
uci -q add_list dhcp.@dnsmasq[0].server=10.0.0.243
phase=$(uci -q get pia.settings.phase 2>/dev/null || echo validation)
if [ "$phase" = enforced ]; then
	uci -q delete firewall.wan_fallback
	uci -q commit firewall
	/etc/init.d/firewall reload 2>/dev/null
fi
uci -q commit dhcp
uci -q commit openvpn
/etc/init.d/dnsmasq restart 2>/dev/null
rm -f __WATCHDOG_STATE__/failopen
logger -t pia-watchdog "ENFORCE: DNS lock on (phase=$phase)"
"""

PIA_WATCHDOG_SH = r"""#!/bin/sh
# PIA VPN watchdog (cron: every minute).
# health -> restart / rotate -> fail open (validation) -> fail closed (enforced).
STATE=__WATCHDOG_STATE__
LOG=/tmp/pia-watchdog.log
PROFILE=__OVPN_FILE__
mkdir -p "$STATE"
exec >>"$LOG" 2>&1

now=$(date +%s)
enabled=$(uci -q get pia.settings.enabled 2>/dev/null || echo 1)
phase=$(uci -q get pia.settings.phase 2>/dev/null || echo validation)
fail_open_timeout=$(uci -q get pia.settings.fail_open_timeout 2>/dev/null || echo __FAIL_OPEN_TIMEOUT__)
require_stable=$(uci -q get pia.settings.require_stable_seconds 2>/dev/null || echo 86400)

[ "$enabled" = 1 ] || exit 0

last_run=$(cat "$STATE/last_run" 2>/dev/null || echo "$now")
stable_total=$(cat "$STATE/stable_total" 2>/dev/null || echo 0)
last_healthy=$(cat "$STATE/last_healthy" 2>/dev/null || echo "$now")
restart_count=$(cat "$STATE/restart_count" 2>/dev/null || echo 0)
restart_window=$(cat "$STATE/restart_window" 2>/dev/null || echo "$now")
failed_open=0
[ -f "$STATE/failopen" ] && failed_open=1

verdict=$(/usr/bin/pia-health 2>&1)
rc=$?
echo "----- $(date) phase=$phase rc=$rc failopen=$failed_open :: $verdict"

if [ "$rc" -eq 0 ]; then
	echo "$now" > "$STATE/last_healthy"
	if [ "$failed_open" = 1 ]; then
		fo_since=$(cat "$STATE/failopen_since" 2>/dev/null || echo "$now")
		if [ $((now - fo_since)) -ge 60 ]; then /usr/bin/pia-enforce; failed_open=0; fi
	fi
	prev=$(cat "$STATE/last_verdict" 2>/dev/null || echo healthy)
	if [ "$prev" = healthy ]; then
		dt=$((now - last_run))
		if [ "$dt" -gt 0 ] && [ "$dt" -lt 300 ]; then stable_total=$((stable_total + dt)); fi
	fi
	echo "$stable_total" > "$STATE/stable_total"
	echo healthy > "$STATE/last_verdict"
	if [ "$phase" = validation ] && [ "$stable_total" -ge "$require_stable" ]; then
		uci -q set pia.settings.phase=enforced
		uci -q commit pia
		logger -t pia-watchdog "phase -> enforced after ${stable_total}s healthy"
		/usr/bin/pia-enforce
	fi
	echo "$now" > "$STATE/last_run"
	exit 0
fi

echo unhealthy > "$STATE/last_verdict"
down=$((now - last_healthy))
echo "$now" > "$STATE/last_run"
echo "down for ${down}s"

if [ "$down" -gt 60 ]; then
	if [ $((now - restart_window)) -gt 300 ]; then restart_count=0; restart_window=$now; fi
	restart_count=$((restart_count + 1))
	echo "$restart_count" > "$STATE/restart_count"
	echo "$restart_window" > "$STATE/restart_window"
	logger -t pia-watchdog "unhealthy ${down}s -> restarting openvpn (attempt $restart_count)"
	if [ "$restart_count" -ge 3 ]; then
		bad=$(logread 2>/dev/null | grep 'Peer Connection Initiated with' | tail -1 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
		[ -z "$bad" ] && bad=$(logread 2>/dev/null | grep 'UDPv4 link remote' | tail -1 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
		if [ -n "$bad" ]; then
			remaining=$(grep -c '^remote ' "$PROFILE")
			if [ "$remaining" -gt 3 ]; then
				cp "$PROFILE" "$PROFILE.bak"
				grep -v "^remote $bad " "$PROFILE" > "$PROFILE.tmp" && mv "$PROFILE.tmp" "$PROFILE"
				logger -t pia-watchdog "removed unreliable remote $bad (was $remaining)"
			fi
		fi
	fi
	/etc/init.d/openvpn restart 2>/dev/null
fi

if [ "$phase" = validation ] && [ "$down" -gt "$fail_open_timeout" ] && [ "$failed_open" = 0 ]; then
	logger -t pia-watchdog "down ${down}s > timeout ${fail_open_timeout}s -> FAIL OPEN"
	/usr/bin/pia-failopen
	echo "$now" > "$STATE/failopen_since"
fi
exit 0
"""


def _script(template: str, fail_open_timeout: int) -> str:
    return (
        template.replace("__WATCHDOG_STATE__", WATCHDOG_STATE)
        .replace("__OVPN_FILE__", OVPN_FILE)
        .replace("__FAIL_OPEN_TIMEOUT__", str(fail_open_timeout))
    )


def _parse_remotes(raw: str) -> list[str]:
    out: list[str] = []
    for item in raw.replace("\n", ",").split(","):
        item = item.strip()
        if not item:
            continue
        host, _, port_s = item.partition(":")
        host = validate_host(host, "remote_host")
        port = validate_port(int(port_s) if port_s else 8080, "remote_port")
        out.append(f"{host} {port}")
    if not out:
        raise ValueError("at least one remote host is required")
    return out


def _build_profile(remotes: list[str], dns_servers: list[str]) -> str:
    lines = ["client", "dev tun0", "proto udp"]
    lines += [f"remote {r}" for r in remotes]
    lines += [
        "remote-random",
        "resolv-retry infinite",
        "nobind",
        "persist-key",
        "data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC",
        "data-ciphers-fallback AES-256-CBC",
        "auth sha256",
        "tls-client",
        "remote-cert-tls server",
        "reneg-sec 0",
        "disable-occ",
        "mssfix 1420",
        "auth-nocache",
        "verb 3",
        f"auth-user-pass {AUTH_FILE}",
        'pull-filter ignore "route-ipv6"',
        'pull-filter ignore "ifconfig-ipv6"',
        f"ca {CA_FILE}",
    ]
    _ = dns_servers  # DNS is applied via dnsmasq, not the OpenVPN profile
    return "\n".join(lines) + "\n"


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    username = str(params.get("username", "")).strip()
    password = str(params.get("password", ""))
    remotes = _parse_remotes(str(params.get("remote_hosts", DEFAULT_REMOTES)))
    dns_servers = [
        validate_host(s.strip(), "dns_server")
        for s in str(params.get("dns_servers", DEFAULT_DNS)).split(",")
        if s.strip()
    ]
    fail_open_timeout = int(params.get("fail_open_timeout", 180))
    if fail_open_timeout < 30 or fail_open_timeout > 3600:
        raise ValueError("fail_open_timeout must be 30-3600 seconds")
    phase = str(params.get("phase", "validation"))
    if phase not in ("validation", "enforced"):
        raise ValueError("phase must be 'validation' or 'enforced'")
    return {
        "username": username,
        "password": password,
        "remotes": remotes,
        "dns_servers": dns_servers,
        "ca_url": str(params.get("ca_url", DEFAULT_CA_URL)),
        "kill_switch": bool(params.get("kill_switch", True)),
        "ipv6_disable": bool(params.get("ipv6_disable", True)),
        "fail_open_timeout": fail_open_timeout,
        "phase": phase,
    }


def _build_openvpn_pia_ops(params: dict[str, Any]) -> list:
    r = _resolve_params(params)
    ops: list = [
        Comment(text="--- Private Internet Access (OpenVPN) ---"),
        # Credentials (p-number + password) -> auth-user-pass file
        WriteFile(path=AUTH_FILE, content=f"{r['username']}\n{r['password']}\n", mode="600"),
        # RSA-4096 CA
        ShellCommand(command=f"wget -q -O {CA_FILE} '{r['ca_url']}'"),
    ]

    # OpenVPN profile + instance
    ops += [
        WriteFile(path=OVPN_FILE, content=_build_profile(r["remotes"], r["dns_servers"]), mode="600"),
        BlankLine(),
        Comment(text="--- OpenVPN UCI instance ---"),
        ShellCommand(command="uci -q delete openvpn.pia || true"),
        ShellCommand(command="uci set openvpn.pia=openvpn"),
        UciSet(config="openvpn", section="pia", values={
            "enabled": "1",
            "config": OVPN_FILE,
            "dev_type": "tun",
            "dev": "tun0",
        }),
        UciCommit(config="openvpn"),
    ]

    # Tunnel interface as a firewall-taggable logical interface
    ops += [
        BlankLine(),
        Comment(text="--- vpnclient interface (maps tun0 into a firewall zone) ---"),
        ShellCommand(command="uci set network.vpnclient=interface"),
        UciSet(config="network", section="vpnclient", values={
            "proto": "none",
            "device": "tun0",
        }),
        UciCommit(config="network"),
    ]

    # DNS lock through PIA in-tunnel resolvers
    ops += [
        BlankLine(),
        Comment(text="--- DNS lock (dnsmasq upsteam = PIA in-tunnel resolvers) ---"),
        UciSet(config="dhcp", section="@dnsmasq[0]", values={"noresolv": "1"}),
        ShellCommand(command="uci -q delete dhcp.@dnsmasq[0].server 2>/dev/null || true"),
    ]
    for ns in r["dns_servers"]:
        ops.append(UciAddList(config="dhcp", section="@dnsmasq[0]", option="server", value=ns))
    ops.append(UciCommit(config="dhcp"))

    # IPv6 off (PIA is v4-only)
    if r["ipv6_disable"]:
        ops += [
            BlankLine(),
            Comment(text="--- Disable IPv6 (kernel + LAN) ---"),
            UciSet(config="dhcp", section="lan", values={
                "dhcpv6": "disabled",
                "ra": "disabled",
                "ndp": "disabled",
            }),
            UciCommit(config="dhcp"),
            ShellCommand(command=(
                "grep -q '^net.ipv6.conf.all.disable_ipv6=1' /etc/sysctl.conf 2>/dev/null || "
                "echo 'net.ipv6.conf.all.disable_ipv6=1' >> /etc/sysctl.conf"
            )),
            ShellCommand(command=(
                "grep -q '^net.ipv6.conf.default.disable_ipv6=1' /etc/sysctl.conf 2>/dev/null || "
                "echo 'net.ipv6.conf.default.disable_ipv6=1' >> /etc/sysctl.conf"
            )),
            ShellCommand(command="sysctl -w net.ipv6.conf.all.disable_ipv6=1"),
            ShellCommand(command="sysctl -w net.ipv6.conf.default.disable_ipv6=1"),
        ]

    # Firewall: vpn zone + forwarding; WAN fallback only during validation
    ops += [
        BlankLine(),
        Comment(text="--- Firewall: vpn zone + forwarding ---"),
        uci_cleanup_sections("firewall", "name='vpn_zone'"),
        uci_cleanup_sections("firewall", "dest='vpn_zone'"),
        ShellCommand(command="uci set firewall.pia_vpn=zone"),
        UciSet(config="firewall", section="pia_vpn", values={
            "name": "vpn_zone",
            "network": "vpnclient",
            "input": "REJECT",
            "output": "ACCEPT",
            "forward": "REJECT",
            "masq": "1",
            "mtu_fix": "1",
        }),
        ShellCommand(command="uci set firewall.pia_fwd=forwarding"),
        UciSet(config="firewall", section="pia_fwd", values={"src": "lan", "dest": "vpn_zone"}),
    ]
    if r["kill_switch"]:
        ops.append(Comment(text="--- Kill switch: remove any LAN->WAN forwarding ---"))
        ops.append(uci_cleanup_sections("firewall", "dest='wan'"))
        if r["phase"] == "validation":
            ops.append(Comment(text="validation phase: keep WAN fallback (watchdog fails open)"))
            ops.append(ShellCommand(command="uci set firewall.wan_fallback=forwarding"))
            ops.append(UciSet(config="firewall", section="wan_fallback", values={
                "src": "lan", "dest": "wan",
            }))
    ops.append(UciCommit(config="firewall"))

    # Policy + watchdog scripts
    ops += [
        BlankLine(),
        Comment(text="--- PIA watchdog policy + scripts ---"),
        WriteFile(
            path="/etc/config/pia",
            content=(
                "config settings\n"
                "\toption enabled '1'\n"
                f"\toption phase '{r['phase']}'\n"
                f"\toption fail_open_timeout '{r['fail_open_timeout']}'\n"
                "\toption require_stable_seconds '86400'\n"
            ),
            mode="600",
        ),
        WriteFile(path="/usr/bin/pia-health", content=PIA_HEALTH_SH, mode="755"),
        WriteFile(path="/usr/bin/pia-failopen", content=_script(PIA_FAILOPEN_SH, r["fail_open_timeout"]), mode="755"),
        WriteFile(path="/usr/bin/pia-enforce", content=_script(PIA_ENFORCE_SH, r["fail_open_timeout"]), mode="755"),
        WriteFile(path="/usr/bin/pia-watchdog", content=_script(PIA_WATCHDOG_SH, r["fail_open_timeout"]), mode="755"),
        ShellCommand(command=(
            "touch /etc/crontabs/root; "
            "grep -v pia-watchdog /etc/crontabs/root > /tmp/crontab.pia 2>/dev/null || true; "
            "echo '* * * * * /usr/bin/pia-watchdog' >> /tmp/crontab.pia; "
            "mv /tmp/crontab.pia /etc/crontabs/root; chmod 600 /etc/crontabs/root"
        )),
        ServiceAction(name="cron", action="enable"),
        BlankLine(),
        ServiceAction(name="network", action="reload"),
        ServiceAction(name="firewall", action="reload"),
        ServiceAction(name="dnsmasq", action="restart"),
        ServiceAction(name="openvpn", action="restart"),
        ServiceAction(name="cron", action="restart"),
        BlankLine(),
        ShellCommand(command="logger -t conwrt 'openvpn-pia configured (phase=%s)'" % r["phase"]),
    ]
    return ops


register(UseCase(
    name="openvpn-pia",
    description=(
        "Private Internet Access (PIA) OpenVPN client — full tunnel with "
        "fail-open validation then fail-closed, server rotation and IPv6 disabled"
    ),
    packages=[
        "openvpn-openssl",
        "luci-app-openvpn",
        "kmod-tun",
        "kmod-udptunnel4",
        "kmod-udptunnel6",
    ],
    packages_remove=[],
    params={
        "username": ParamDef(type=str, required=True, allow_empty=False,
                             description="PIA username (the p-number, e.g. p1234567)"),
        "password": ParamDef(type=str, required=True, allow_empty=False,
                             description="PIA password"),
        "remote_hosts": ParamDef(type=str, default=DEFAULT_REMOTES,
                                 description="Comma-separated host:port pool (remote-random failover)"),
        "dns_servers": ParamDef(type=str, default=DEFAULT_DNS,
                                description="Comma-separated PIA in-tunnel DNS resolvers"),
        "ca_url": ParamDef(type=str, default=DEFAULT_CA_URL,
                           description="URL of PIA's RSA-4096 CA certificate"),
        "kill_switch": ParamDef(type=bool, default=True,
                                description="Block non-VPN traffic (removed in validation on tunnel failure)"),
        "ipv6_disable": ParamDef(type=bool, default=True,
                                  description="Disable IPv6 at the kernel and on the LAN"),
        "fail_open_timeout": ParamDef(type=int, default=180, min_value=30, max_value=3600,
                                      description="Seconds of downtime before failing open (validation phase)"),
        "phase": ParamDef(type=str, default="validation",
                          choices=("validation", "enforced"),
                          description="validation = fail open on outage; enforced = strict fail closed"),
    },
    build_configure_ops=_build_openvpn_pia_ops,
    build_configure=lambda p: render_shell(_build_openvpn_pia_ops(p)),
    test_status="experimental",
    tested_notes=(
        "GL.iNet GL-MT3000 (glinet,gl-mt3000), OpenWrt 25.12.5 — validated on hardware: "
        "tunnel establishment, DNS-through-tunnel, IPv6-off, functional health probe, "
        "fail-open + automatic re-enforce, endpoint rotation. Automated phased fail-closed "
        "switch not yet observed for a full 24h window."
    ),
    requires_capabilities=[],
))
